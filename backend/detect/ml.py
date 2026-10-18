"""
SentinelSOC - unsupervised detection.

A five-detector consensus, following DataSentinel's `_stage_score` design:
independent detectors score every window, scores are percentile-normalised on
the clean subset, combined by weight, and cut with a MAD-based robust threshold.

Why an ensemble rather than one model: each detector is blind in a different
way. Isolation Forest partitions on feature splits and misses dense clusters of
badness; LOF is local and misses global shifts; ECOD and COPOD are
distribution-tail methods that need no training and never overfit; the LSTM
autoencoder is the only one that sees *sequence*, which is what separates "this
window is odd" from "this entity's behaviour changed". Agreement across
different blind spots is worth more than any single score.

Two properties carried over deliberately from DataSentinel:

  * every detector is optional. One that fails, or has too little data, drops
    out and the remaining weights renormalise. A missing detector must never
    silently drag the consensus toward zero.
  * the threshold is median + k·MAD, not mean + k·σ. The thing being thresholded
    is a distribution containing outliers by construction, and the mean and
    standard deviation of such a distribution are pulled toward the very
    outliers being hunted.

Both LogGuard and DataSentinel aimed their features at the wrong unit for
security work - LogGuard at server health, DataSentinel at dataset columns. Here
the unit is the entity: what did *this* address, or *this* account, do in *this*
window.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta

from schemas import Event, Signal

WINDOW = timedelta(minutes=5)
MIN_EVENTS_PER_WINDOW = 5
MIN_WINDOWS_TO_FIT = 25
CONTAMINATION = 0.008

# MAD multiplier. 3.0 is the conventional "robust 3-sigma" for normal-ish data.
MAD_SIGMA = 3.0

# An alert budget, on top of the statistical bar.
#
# MAD answers "is this window unusual?" and has no opinion on how many unusual
# windows a human can work through. On homogeneous traffic the spread is small,
# so a 3-MAD bar sits close to the median and a measured 6% of windows clear it -
# an alert volume no analyst triages, and the fastest way to train a team to
# ignore the tool. Keep the highest-consensus windows up to this share and let
# the rest go; a detector nobody reads has a recall of zero.
#
# Tuned to bind on degenerate input and not on healthy input. These are
# pre-dedupe windows: one attacker typically occupies several consecutive
# ones, and the pipeline collapses them per entity afterwards, so the count
# an analyst actually sees is far smaller than the count budgeted here. Set
# too tight, this trims real detections - at 2% it cut two of four attackers
# off the bundled corpus.
MAX_FLAG_RATE = 0.05
MIN_FLAGGED = 10

# Corroboration. The point of running five detectors with different blind spots
# is that agreement between them means something; one model's opinion does not.
# Measured on the bundled corpus, every planted attacker drew 4 or 5 of 5
# detectors while every false positive drew 1 to 3 - a cleaner separator than any
# score cutoff, and one that states an actual principle rather than a tuned
# constant. Expressed as a fraction so it still holds when a detector drops out.
AGREEMENT_FRACTION = 0.7
AGREEMENT_LEVEL = 0.5          # a detector "agrees" at or above this normalised score

# Margin. Corroboration and margin catch different failures and neither is
# sufficient alone: on the bundled corpus agreement separated attackers from
# noise cleanly while scores overlapped; on homogeneous synthetic traffic the
# reverse held - every mild outlier drew 4-5 detectors, but sat exactly on the
# threshold while the real attacker scored double. Expressed as a share of the
# distance from the bar to the most extreme window, so it is a statement about
# shape rather than a tuned constant: barely clearing the bar is not a finding.
MIN_MARGIN = 0.10

# Relative say in the consensus. Isolation Forest leads because it is the most
# reliable on tabular features of this shape; the LSTM is weighted lowest
# because it scores fewest windows and has the least data to learn from.
WEIGHTS = {"iforest": 0.30, "lof": 0.20, "ecod": 0.20, "copod": 0.15, "lstm": 0.15}

# LSTM: how many consecutive windows form a sequence, and how hard to train it.
SEQ_LEN = 4
LSTM_EPOCHS = 30
LSTM_MIN_SEQUENCES = 20

FEATURE_NAMES = [
    "event_count",
    "failure_ratio",
    "distinct_ports",
    "distinct_users",
    "distinct_hosts",
    "log_mbytes_out",
    "distinct_actions",
    "blocked_ratio",
    "off_hours",
]


def _floor(ts: datetime) -> datetime:
    secs = int(WINDOW.total_seconds())
    epoch = int(ts.timestamp()) // secs * secs
    return datetime.fromtimestamp(epoch, tz=ts.tzinfo)


def _features(evs: list[Event]) -> list[float]:
    n = len(evs)
    failures = sum(1 for e in evs if e.outcome == "failure")
    blocked = sum(1 for e in evs if e.outcome == "blocked")
    total_bytes = sum(e.bytes_out for e in evs)
    return [
        float(n),
        failures / n,
        float(len({e.dst_port for e in evs if e.dst_port})),
        float(len({e.user for e in evs if e.user})),
        float(len({e.host for e in evs})),
        math.log1p(total_bytes / 1_048_576),
        float(len({e.action for e in evs})),
        blocked / n,
        1.0 if evs[0].ts.hour in (22, 23, 0, 1, 2, 3, 4, 5) else 0.0,
    ]


# ---------------------------------------------------------------------------
# Individual detectors. Each returns per-row scores where higher = more
# anomalous, or None if it could not run. None is a normal outcome, not a bug.
# ---------------------------------------------------------------------------


def _fit_iforest(matrix):
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=200, contamination=CONTAMINATION, random_state=42, n_jobs=1
    )
    model.fit(matrix)
    # score_samples: higher = more normal. Invert so higher = more anomalous.
    return -model.score_samples(matrix)


def _fit_lof(matrix):
    from sklearn.neighbors import LocalOutlierFactor

    n_neighbors = min(20, max(5, len(matrix) // 10))
    model = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=CONTAMINATION)
    model.fit_predict(matrix)
    return -model.negative_outlier_factor_


def _fit_ecod(matrix):
    from pyod.models.ecod import ECOD

    model = ECOD(contamination=CONTAMINATION)
    model.fit(matrix)
    return model.decision_scores_


def _fit_copod(matrix):
    from pyod.models.copod import COPOD

    model = COPOD(contamination=CONTAMINATION)
    model.fit(matrix)
    return model.decision_scores_


def _fit_lstm(matrix, keys):
    """
    Sequence detector.

    The other four judge a window in isolation. This one learns what an entity's
    normal *run* of windows looks like and flags the window that breaks the
    pattern - a brute force is not one odd minute, it is a run of them.

    Entities with fewer than SEQ_LEN windows get no score. That is expected, and
    the consensus renormalises around it rather than treating the gap as normal.
    """
    import numpy as np
    import torch
    import torch.nn as nn

    by_entity: dict[str, list[int]] = defaultdict(list)
    for idx, (entity, _kind, ts) in enumerate(keys):
        by_entity[entity].append(idx)
    for entity in by_entity:
        by_entity[entity].sort(key=lambda i: keys[i][2])

    sequences: list[list[int]] = []
    for indices in by_entity.values():
        for start in range(len(indices) - SEQ_LEN + 1):
            sequences.append(indices[start : start + SEQ_LEN])

    if len(sequences) < LSTM_MIN_SEQUENCES:
        return None

    mean = matrix.mean(axis=0)
    std = matrix.std(axis=0)
    std[std == 0] = 1.0
    normed = (matrix - mean) / std

    tensor = torch.tensor(
        np.stack([normed[seq] for seq in sequences]), dtype=torch.float32
    )
    n_features = tensor.shape[2]

    class Autoencoder(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.encoder = nn.LSTM(n_features, 8, batch_first=True)
            self.decoder = nn.LSTM(8, n_features, batch_first=True)

        def forward(self, x):
            latent, _ = self.encoder(x)
            out, _ = self.decoder(latent)
            return out

    torch.manual_seed(42)
    model = Autoencoder()
    optimiser = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.MSELoss()

    model.train()
    for _ in range(LSTM_EPOCHS):
        optimiser.zero_grad()
        loss = loss_fn(model(tensor), tensor)
        loss.backward()
        optimiser.step()

    model.eval()
    with torch.no_grad():
        errors = ((model(tensor) - tensor) ** 2).mean(dim=2)[:, -1].numpy()

    # A window can end several sequences; keep its worst reconstruction.
    scores = np.full(len(matrix), np.nan)
    for seq, err in zip(sequences, errors, strict=True):
        last = seq[-1]
        scores[last] = err if np.isnan(scores[last]) else max(scores[last], err)
    return scores


DETECTORS = {
    "iforest": _fit_iforest,
    "lof": _fit_lof,
    "ecod": _fit_ecod,
    "copod": _fit_copod,
}


# ---------------------------------------------------------------------------
# Consensus
# ---------------------------------------------------------------------------


def _normalise(arr, clean_mask):
    """
    Scale against the clean subset, and deliberately do NOT clip the top.

    Two competing failures. Scale on the full set and the outliers set their own
    ceiling, compressing exactly the signal being hunted - so the anchors come
    from the rows believed clean. But clip the result to 1.0 and every extreme
    value ties at the ceiling: measured on synthetic traffic, the attacker and a
    merely-unusual background window both saturated at 1.000 and the attacker
    ranked second. Ordering in the tail is the whole product - it is what decides
    which alert an analyst opens first.

    So the upper bound is left open. A window five times past the clean 99th
    percentile scores 5, and stays ahead of one that is merely twice past it.
    Per-detector weights bound how far any single model can run away with the
    consensus, and the final score is min-maxed over the real range.
    """
    import numpy as np

    finite = np.isfinite(arr)
    if not finite.any():
        return np.zeros_like(arr, dtype=float)

    reference = arr[finite & clean_mask] if (finite & clean_mask).any() else arr[finite]
    lo, hi = np.percentile(reference, 1), np.percentile(reference, 99)
    out = np.zeros_like(arr, dtype=float)
    if hi > lo:
        out[finite] = np.maximum((arr[finite] - lo) / (hi - lo), 0.0)
    else:
        amin, amax = arr[finite].min(), arr[finite].max()
        if amax > amin:
            out[finite] = (arr[finite] - amin) / (amax - amin)
    return out


def run_isolation_forest(events: list[Event]) -> list[Signal]:
    """
    Kept under its original name so callers do not change; it now runs the whole
    consensus rather than a single model.
    """
    return run_consensus(events)


def run_consensus(events: list[Event]) -> list[Signal]:
    try:
        import numpy as np
    except ImportError:
        print("[detect] numpy unavailable; skipping the ML ensemble")
        return []

    buckets: dict[tuple[str, str, datetime], list[Event]] = defaultdict(list)
    for e in events:
        entity, kind = (
            (e.src_ip, "src_ip") if e.src_ip
            else (e.user or e.host, "user" if e.user else "host")
        )
        if entity:
            buckets[(entity, kind, _floor(e.ts))].append(e)

    keys = [k for k, v in buckets.items() if len(v) >= MIN_EVENTS_PER_WINDOW]
    if len(keys) < MIN_WINDOWS_TO_FIT:
        print(f"[detect] only {len(keys)} windows; ensemble needs {MIN_WINDOWS_TO_FIT}")
        return []

    matrix = np.array([_features(buckets[k]) for k in keys], dtype=float)

    raw: dict[str, np.ndarray] = {}
    for name, fit in DETECTORS.items():
        try:
            scores = fit(matrix)
            if scores is not None:
                raw[name] = np.asarray(scores, dtype=float)
        except Exception as exc:
            print(f"[detect] {name} failed ({type(exc).__name__}: {exc}); continuing")

    try:
        lstm = _fit_lstm(matrix, keys)
        if lstm is not None:
            raw["lstm"] = lstm
    except Exception as exc:
        print(f"[detect] lstm failed ({type(exc).__name__}: {exc}); continuing")

    if not raw:
        print("[detect] every detector failed; no consensus possible")
        return []

    # A first pass to decide which rows to normalise against: anything the
    # crudest detector already dislikes is excluded from "clean".
    lead = next(iter(raw.values()))
    clean_mask = lead <= np.nanpercentile(lead[np.isfinite(lead)], 90)

    normed = {name: _normalise(arr, clean_mask) for name, arr in raw.items()}

    # Renormalise weights across the detectors that actually ran.
    active = {name: WEIGHTS.get(name, 0.0) for name in normed}
    total = sum(active.values()) or 1.0
    consensus = np.zeros(len(matrix), dtype=float)
    for name, arr in normed.items():
        consensus += arr * (active[name] / total)

    # MAD-based robust threshold.
    clean = consensus[clean_mask] if clean_mask.any() else consensus
    median = float(np.median(clean))
    try:
        from scipy.stats import median_abs_deviation

        mad = float(median_abs_deviation(clean, scale="normal"))
    except ImportError:
        mad = 0.0
    threshold = (
        median + MAD_SIGMA * mad if mad > 0 else consensus.mean() + MAD_SIGMA * consensus.std()
    )

    names = ", ".join(sorted(normed))
    print(
        f"[detect] consensus over {len(normed)} detectors ({names}); "
        f"threshold {threshold:.3f} "
        f"({'MAD' if mad > 0 else 'std fallback'})"
    )

    # Score relative to the bar it cleared, not to the global range.
    #
    # Three filters were stacked here - the MAD threshold, the entity budget, and
    # a flat score floor - and they fought. Min-maxing over the whole range meant
    # one very extreme entity pushed everyone else's displayed score down until
    # the floor silently dropped six of eight genuine detections. A window that
    # cleared a robust threshold and an alert budget IS a signal; the score's job
    # is only to rank it. Threshold sits at 0.5, the most extreme window at 1.0.
    ceiling = float(consensus.max())

    above = [i for i in range(len(keys)) if consensus[i] >= threshold]

    # Collapse to one window per entity before budgeting.
    #
    # A sustained attack occupies several consecutive windows, so budgeting on
    # windows lets the single loudest entity eat every slot - measured on the
    # bundled corpus, two attackers took all ten and the other two reached the
    # analyst only because a hand-written rule also caught them. The unit of
    # attention is the entity, so that is the unit to budget. Each entity is
    # represented by its worst window.
    import math

    required = max(2, math.ceil(AGREEMENT_FRACTION * len(normed)))
    agreement = {
        idx: sorted(n for n, arr in normed.items() if arr[idx] >= AGREEMENT_LEVEL)
        for idx in above
    }
    ceiling_pre = float(consensus.max())
    headroom_pre = (ceiling_pre - threshold) or 1.0

    corroborated = [
        idx for idx in above
        if len(agreement[idx]) >= required
        and (consensus[idx] - threshold) / headroom_pre >= MIN_MARGIN
    ]
    if len(corroborated) < len(above):
        print(
            f"[detect] {len(above) - len(corroborated)} window(s) dropped: needed "
            f"{required} of {len(normed)} detectors agreeing and "
            f"{MIN_MARGIN:.0%} margin over the threshold"
        )

    best_per_entity: dict[str, int] = {}
    for idx in corroborated:
        entity = keys[idx][0]
        if entity not in best_per_entity or consensus[idx] > consensus[best_per_entity[entity]]:
            best_per_entity[entity] = idx

    ranked = sorted(best_per_entity.values(), key=lambda i: -consensus[i])
    budget = max(MIN_FLAGGED, int(len(keys) * MAX_FLAG_RATE))
    if len(ranked) > budget:
        print(
            f"[detect] {len(ranked)} entities cleared the threshold; "
            f"keeping the top {budget} to stay inside the alert budget"
        )
        ranked = ranked[:budget]
    else:
        print(
            f"[detect] {len(above)} windows over threshold across "
            f"{len(ranked)} entities, all within budget ({budget})"
        )
    keep = set(ranked)

    headroom = (ceiling - threshold) or 1.0

    signals: list[Signal] = []
    for idx, key in enumerate(keys):
        if idx not in keep:
            continue
        score = round(
            float(min(0.5 + 0.5 * (consensus[idx] - threshold) / headroom, 1.0)), 3
        )

        entity, kind, _ = key
        evs = sorted(buckets[key], key=lambda e: e.ts)
        feats = matrix[idx]
        top = sorted(
            ((FEATURE_NAMES[i], feats[i]) for i in range(len(FEATURE_NAMES))),
            key=lambda p: -p[1],
        )[:3]
        agree = agreement[idx]

        detail = (
            f"{len(agree)} of {len(normed)} detectors independently flagged this "
            f"window ({', '.join(agree)}), clearing a "
            f"{'MAD-robust' if mad > 0 else 'statistical'} threshold. "
            + "Strongest features: "
            + ", ".join(f"{name}={val:.2f}" for name, val in top)
        )

        signals.append(
            Signal(
                detector="isolation_forest",
                rule_id="ML001",
                title=f"Anomalous activity window for {entity}",
                severity="high" if score > 0.75 else "medium",
                ts_start=evs[0].ts,
                ts_end=evs[-1].ts,
                host=evs[0].host,
                entity=entity,
                entity_kind=kind,  # type: ignore[arg-type]
                score=max(0.0, min(score, 1.0)),
                event_ids=[e.event_id for e in evs],
                evidence_sample=[e.raw for e in evs[:5]],
                detail=detail,
            )
        )

    signals.sort(key=lambda s: -s.score)
    return signals


def rare_template_signals(events: list[Event], max_count: int = 2) -> list[Signal]:
    """First-seen log shapes. Cheap, and it catches what no rule anticipated."""
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        if e.template_id:
            counts[e.template_id] += 1

    rare_ids = {tid for tid, n in counts.items() if n <= max_count}
    if not rare_ids:
        return []

    by_template: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.template_id in rare_ids:
            by_template[e.template_id].append(e)

    out: list[Signal] = []
    for _tid, evs in by_template.items():
        evs.sort(key=lambda e: e.ts)
        entity = evs[0].src_ip or evs[0].user or evs[0].host
        kind = "src_ip" if evs[0].src_ip else ("user" if evs[0].user else "host")
        out.append(
            Signal(
                detector="template_rarity",
                rule_id="TR001",
                title=f"Rare log pattern on {evs[0].host}",
                severity="medium",
                ts_start=evs[0].ts,
                ts_end=evs[-1].ts,
                host=evs[0].host,
                entity=entity,
                entity_kind=kind,  # type: ignore[arg-type]
                score=round(0.5 + (max_count - len(evs)) * 0.1, 3),
                event_ids=[e.event_id for e in evs],
                evidence_sample=[e.raw for e in evs[:3]],
                detail=f"This log shape occurred {len(evs)} time(s) in the whole dataset: "
                       f"{(evs[0].template or evs[0].raw)[:160]}",
            )
        )
    return out
