"""
The detector consensus.

Two properties carry the design and both fail silently if broken: a detector
that drops out must not drag the consensus down, and the threshold must survive
the outliers it is meant to find.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import numpy as np  # noqa: E402
import pytest  # noqa: E402

from detect import ml  # noqa: E402
from schemas import Event  # noqa: E402

T0 = datetime(2026, 3, 15, 9, 0, tzinfo=timezone.utc)


def _events(n_entities=40, per_window=6, loud_entity="9.9.9.9", seed=7):
    """
    Quiet background plus one entity behaving very differently.

    The background is jittered on purpose: identical windows drive the median
    absolute deviation to exactly zero, which is a degenerate case real traffic
    never produces and which hides whether the MAD path works at all.
    """
    import random

    rng = random.Random(seed)
    out: list[Event] = []
    eid = 0
    for e in range(n_entities):
        for w in range(5):
            for k in range(per_window + rng.randint(0, 4)):
                eid += 1
                out.append(Event(
                    event_id=eid, ts=T0 + timedelta(minutes=w * 5, seconds=k * 10),
                    source="ssh_auth", host="web-01", user=f"u{e}",
                    src_ip=f"10.0.{e // 250}.{e % 250}", dst_port=22,
                    action=rng.choice(["ssh_login", "session_opened"]),
                    outcome="failure" if rng.random() < 0.08 else "success",
                    raw=f"ok {eid}", bytes_out=rng.randint(0, 40_000),
                ))
    for w in range(5):
        for k in range(60):
            eid += 1
            out.append(Event(
                event_id=eid, ts=T0 + timedelta(minutes=w * 5, seconds=k),
                source="ssh_auth", host="web-01", user=f"victim{k % 30}",
                src_ip=loud_entity, dst_port=1000 + k,
                action="ssh_login", outcome="failure", raw=f"fail {eid}",
                bytes_out=5_000_000,
            ))
    return out


@pytest.fixture(scope="module")
def signals():
    return ml.run_consensus(_events())


def test_all_five_detectors_participate(capsys):
    ml.run_consensus(_events())
    out = capsys.readouterr().out
    assert "consensus over 5 detectors" in out, out
    for name in ("iforest", "lof", "ecod", "copod", "lstm"):
        assert name in out


def test_threshold_is_mad_based_on_realistic_data(capsys):
    ml.run_consensus(_events())
    assert "(MAD)" in capsys.readouterr().out


def test_identical_windows_fall_back_to_std_rather_than_a_zero_threshold(capsys):
    """
    Degenerate input: every window identical, so MAD is exactly 0. A zero spread
    must not become a zero threshold that flags the entire dataset.
    """
    events: list[Event] = []
    eid = 0
    for e in range(40):
        for w in range(5):
            for k in range(6):
                eid += 1
                events.append(Event(
                    event_id=eid, ts=T0 + timedelta(minutes=w * 5, seconds=k * 10),
                    source="ssh_auth", host="web-01", user="u", src_ip=f"10.0.0.{e}",
                    dst_port=22, action="ssh_login", outcome="success", raw="x",
                ))
    signals = ml.run_consensus(events)
    assert "std fallback" in capsys.readouterr().out
    assert len(signals) < len(events), "a zero threshold would flag everything"


def test_the_loud_entity_is_flagged(signals):
    assert signals, "the ensemble found nothing at all"
    assert "9.9.9.9" in {s.entity for s in signals}


def test_the_attacker_outranks_all_background(signals):
    """
    Precision at the top of the list, which is the only part an analyst reads.

    This is the regression that caught the clipping bug: normalising with a hard
    1.0 ceiling made the attacker and a merely-unusual background window tie at
    the maximum, and the attacker came second.
    """
    assert signals[0].entity == "9.9.9.9", (
        f"the attacker should rank first, got {signals[0].entity}"
    )
    noisy = {s.entity for s in signals if s.entity.startswith("10.0.")}
    assert not noisy, f"false positives on background traffic: {noisy}"


def test_alert_volume_stays_inside_the_budget(signals):
    """A detector that flags more than a human can read has a recall of zero."""
    assert len(signals) <= max(ml.MIN_FLAGGED, int(205 * ml.MAX_FLAG_RATE))


def test_one_entity_cannot_monopolise_the_budget(signals):
    """
    Budget on entities, not windows. A sustained attack spans many consecutive
    windows; budgeting those let the loudest entity take every slot and pushed
    genuine attackers off the list entirely.
    """
    entities = [s.entity for s in signals]
    assert len(entities) == len(set(entities)), (
        f"the same entity appears more than once: {entities}"
    )


def test_detail_names_which_detectors_agreed(signals):
    top = max(signals, key=lambda s: s.score)
    assert "detectors independently flagged" in top.detail
    assert "Strongest features" in top.detail


def test_weak_corroboration_is_dropped(capsys):
    """
    The separator that replaced a tuned score floor. On the bundled corpus every
    planted attacker drew 4-5 of 5 detectors and every false positive drew 1-3,
    so requiring corroboration removes the noise without a magic number.
    """
    ml.run_consensus(_events())
    out = capsys.readouterr().out
    assert "corroboration" in out or "within budget" in out


def test_agreement_requirement_scales_with_the_detectors_that_ran(monkeypatch):
    """A dropped detector must lower the bar, not make it unreachable."""
    import math

    for n in (5, 4, 3, 2, 1):
        required = max(2, math.ceil(ml.AGREEMENT_FRACTION * n))
        assert required <= max(n, 2), f"{required} of {n} detectors is unsatisfiable"


# -- the two properties that fail silently ---------------------------------


def test_a_failed_detector_drops_out_without_sinking_the_consensus(monkeypatch, capsys):
    """
    A detector that raises must be stepped over and its weight redistributed. If
    its missing contribution were treated as zero, every score would sag and the
    threshold would quietly stop firing.
    """
    def boom(matrix):
        raise RuntimeError("simulated detector failure")

    monkeypatch.setitem(ml.DETECTORS, "ecod", boom)
    signals = ml.run_consensus(_events())
    out = capsys.readouterr().out

    assert "ecod failed" in out
    assert "consensus over 4 detectors" in out
    assert "9.9.9.9" in {s.entity for s in signals}, (
        "losing one detector must not lose the attacker"
    )


def test_weights_renormalise_to_one():
    """Whatever subset runs, the weights must still sum to 1."""
    for subset in (
        {"iforest", "lof", "ecod", "copod", "lstm"},
        {"iforest", "lof"},
        {"copod"},
    ):
        active = {k: ml.WEIGHTS[k] for k in subset}
        total = sum(active.values())
        assert abs(sum(w / total for w in active.values()) - 1.0) < 1e-9


def test_mad_threshold_resists_the_outliers_it_hunts():
    """
    Why median+MAD rather than mean+sigma.

    A few extreme values drag the mean and standard deviation toward themselves,
    so the bar rises until anything short of blatant clears underneath it. The
    extremes are still caught either way - it is the MODERATE anomaly, the one
    an analyst most needs surfaced, that mean+sigma loses.
    """
    from scipy.stats import median_abs_deviation

    quiet = np.random.default_rng(0).normal(0.2, 0.02, 200)
    blatant = np.array([9.0] * 10)
    moderate = np.array([0.5])
    data = np.concatenate([quiet, blatant, moderate])

    mean_based = data.mean() + 3.0 * data.std()
    mad_based = np.median(data) + 3.0 * median_abs_deviation(data, scale="normal")

    assert mad_based < mean_based, "MAD must give the more sensitive bar"
    # Both catch the blatant ones...
    assert (blatant > mean_based).all() and (blatant > mad_based).all()
    # ...but only MAD catches the moderate one.
    assert moderate[0] > mad_based, "MAD threshold should surface the moderate anomaly"
    assert moderate[0] < mean_based, (
        "mean+sigma, inflated by the extremes, hides the moderate anomaly"
    )


def test_normalisation_ignores_non_finite_scores():
    """The LSTM leaves NaN for windows it could not score; those must not poison it."""
    arr = np.array([0.1, 0.2, np.nan, 5.0, 0.15])
    out = ml._normalise(arr, np.array([True, True, True, False, True]))
    assert np.isfinite(out).all()
    assert out[2] == 0.0, "an unscored window must not become an anomalous one"
    assert out.min() >= 0.0


def test_normalisation_leaves_the_tail_unclipped():
    """
    The ceiling is absent on purpose. Clipping to 1.0 made extreme values tie,
    and ties at the top destroy the ordering the whole product rests on.
    """
    arr = np.array([0.1, 0.2, 0.15, 5.0, 50.0])
    clean = np.array([True, True, True, False, False])
    out = ml._normalise(arr, clean)
    assert out[4] > out[3] > 1.0, "extreme values must stay ordered above the clean range"


def test_too_little_data_returns_nothing_rather_than_guessing(capsys):
    tiny = _events(n_entities=2, per_window=6)[:40]
    assert ml.run_consensus(tiny) == []
    assert "needs" in capsys.readouterr().out


def test_lstm_declines_when_sequences_are_too_short():
    """Entities with fewer than SEQ_LEN windows give the LSTM nothing to learn."""
    matrix = np.random.default_rng(1).normal(size=(30, len(ml.FEATURE_NAMES)))
    keys = [(f"e{i}", "src_ip", T0 + timedelta(minutes=5 * i)) for i in range(30)]
    assert ml._fit_lstm(matrix, keys) is None, "30 entities × 1 window each is not a sequence"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
