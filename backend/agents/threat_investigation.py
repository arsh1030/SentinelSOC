"""
Agent 2 - Threat Investigation Agent.

Receives Agent 1's analysis for EVERY open signal at once and decides which of
them belong to the same attack. This is the agent that matters: correlation is
the thing a human analyst is worst at under load, and it is the requirement both
source repositories left unbuilt.

It gets exactly one tool - fetch_log_window - backed by read-only SQLite. Giving
it the ability to pull evidence it was not handed is what makes this an agent
rather than a long prompt, and watching it decide to do so is the moment in the
demo that lands.
"""

from __future__ import annotations

from typing import Any

import causal
import mitre
import store
from llm_client import LLMClient
from redaction import Redactor
from schemas import (
    EvidenceRef,
    Incident,
    InvestigationResult,
    LogAnalysis,
    MitreTechnique,
    Signal,
)

SYSTEM = f"""You are the Threat Investigation Agent in a security operations pipeline.

You receive the full set of open detection signals, each already normalised by the
Log Analysis Agent. Your job is to decide which signals are FACETS OF THE SAME
ATTACK and merge them into a small number of incidents.

Correlate on: shared source addresses, shared accounts, shared hosts, and above
all temporal adjacency combined with a plausible attacker progression. Three
signals from one address inside ten minutes are almost always one incident, not
three. Be aggressive about merging - an analyst drowning in twelve alerts needs
three incidents, not twelve restatements.

For every incident you must:
  - write a narrative an analyst can act on, in plain English
  - assign the kill-chain stage the attack REACHED (the furthest point, not the first)
  - map to MITRE ATT&CK using ONLY the catalogue below - never invent a technique ID
  - assign a risk score 0-100, and justify the number
  - cite evidence: every claim you make must carry the event IDs that support it

Risk scoring. Weigh the damage already done above the noise generated:
  90-100  confirmed compromise with data loss or root access achieved
  70-89   confirmed compromise, contained or in progress
  40-69   attempted compromise, no evidence it succeeded
  10-39   reconnaissance or scanning only
  0-9     benign or a false positive

You may call fetch_log_window to pull additional log lines you were not given.
Use it when correlation hinges on evidence outside the signal windows - for
instance to check whether a scan was followed by a successful request, or what an
account did after a suspicious login. Do not call it more than four times.

If a signal is genuinely benign, put it in dismissed_signal_ids rather than
inventing an incident for it.

MITRE ATT&CK CATALOGUE - use only these IDs:
{mitre.catalogue_for_prompt()}"""


FETCH_TOOL: dict[str, Any] = {
    "name": "fetch_log_window",
    "description": (
        "Fetch raw log events from the session, filtered and time-bounded. Use this "
        "to confirm or rule out a correlation when the signal evidence is not enough - "
        "for example to see what happened on a host immediately after a suspicious "
        "login, or whether a scanned port was later successfully reached. "
        "Returns at most 200 events, oldest first."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Exact hostname, e.g. web-01."},
            "src_ip": {"type": "string", "description": "Exact source IP address."},
            "user": {"type": "string", "description": "Exact account name."},
            "start": {
                "type": "string",
                "description": "ISO-8601 lower bound, e.g. 2026-03-15T02:00:00+00:00.",
            },
            "end": {"type": "string", "description": "ISO-8601 upper bound."},
            "contains": {
                "type": "string",
                "description": "Substring that must appear in the raw log line.",
            },
            "limit": {"type": "integer", "description": "Max events, 1-200. Default 50."},
        },
        "required": [],
    },
}


def make_fetch_tool(session_id: str, redactor: Redactor | None = None):
    """
    Bind the tool to one session. Read-only by construction.

    Tool output is raw log text going straight to the provider, so it goes
    through the same redactor as the prompt - otherwise redaction would be
    trivially bypassed by the agent simply asking for the logs.
    """

    def fetch_log_window(
        host: str | None = None,
        src_ip: str | None = None,
        user: str | None = None,
        start: str | None = None,
        end: str | None = None,
        contains: str | None = None,
        limit: int = 50,
    ) -> str:
        rows = store.query_events(
            session_id=session_id,
            host=host or None,
            src_ip=src_ip or None,
            user=user or None,
            start=start or None,
            end=end or None,
            contains=contains or None,
            limit=max(1, min(int(limit or 50), 200)),
        )
        if not rows:
            return "No events matched that filter. Widen the time range or drop a filter."
        if redactor and redactor.enabled:
            rows = [redactor.redact_event(r) for r in rows]
        head = f"{len(rows)} events:\n"
        return head + "\n".join(
            f"[event {r['event_id']}] {r['ts']} {r['host']} {r['action']}/{r['outcome']} :: {r['raw'][:220]}"
            for r in rows
        )

    return fetch_log_window


def _prompt(signals: list[Signal], analyses: dict[int, LogAnalysis]) -> str:
    blocks = []
    for s in signals:
        a = analyses.get(s.signal_id)
        iocs = ", ".join(f"{i.kind}:{i.value}" for i in a.iocs[:10]) if a else "-"
        blocks.append(
            f"""SIGNAL {s.signal_id} [{s.severity}] {s.rule_id} score={s.score}
  title    : {s.title}
  window   : {s.ts_start:%Y-%m-%d %H:%M:%S} -> {s.ts_end:%H:%M:%S} UTC
  host     : {s.host}   entity: {s.entity} ({s.entity_kind})
  detector : {s.detail}
  analysis : {a.summary if a else '(none)'}
  pattern  : {a.activity_pattern if a else '-'}
  iocs     : {iocs}
  events   : {len(s.event_ids)} total, notable: {a.notable_event_ids[:6] if a else s.event_ids[:6]}"""
        )
    return (
        f"{len(signals)} open signals from one ingestion session.\n\n"
        + "\n\n".join(blocks)
        + "\n\nCorrelate these into incidents."
    )


# ---------------------------------------------------------------------------
# Deterministic fallback: union-find over shared entities and time proximity
# ---------------------------------------------------------------------------

_STAGE_BY_RULE = {
    "R001": "credential_access",
    "R002": "reconnaissance",
    "R003": "initial_access",
    "R004": "initial_access",
    "R005": "exfiltration",
    "R006": "privilege_escalation",
    "R007": "collection",
    "R008": "lateral_movement",
    "R009": "credential_access",
    "ML001": "discovery",
    "TR001": "discovery",
}
_TECH_BY_RULE = {
    "R001": "T1110.001",
    "R002": "T1046",
    "R003": "T1190",
    "R004": "T1078",
    "R005": "T1048",
    "R006": "T1548.003",
    "R007": "T1005",
    "R008": "T1021",        # Remote Services - pivoting with valid credentials
    "R009": "T1110.003",    # Password Spraying, not generic Brute Force
    "ML001": "T1046",
    "TR001": "T1057",
}
# Ordered by DAMAGE DONE, not by ATT&CK column order. In the official matrix
# Discovery sits after Privilege Escalation, which would let a stray process-
# discovery signal outrank "the attacker got root" when picking the furthest
# stage an incident reached. For triage, what matters is how bad it got.
_STAGE_RANK = [
    "reconnaissance", "discovery", "initial_access", "execution",
    "credential_access", "lateral_movement", "persistence",
    "privilege_escalation", "defense_evasion", "collection",
    "exfiltration", "impact",
]


def _causal_model(session_id: str):
    """
    Learn the feature DAG for this session, once.

    Returns an unfitted model when there is too little data or torch is absent;
    scoring falls back to the non-causal formula rather than trusting a graph
    learned from nothing.
    """
    from collections import defaultdict
    from datetime import datetime

    try:
        import numpy as np
        from detect import ml
    except ImportError:
        return causal.CausalModel(features=[])

    rows = store.all_events(session_id)
    if not rows:
        return causal.CausalModel(features=[])

    from schemas import Event

    parsed: list[Event] = []
    for r in rows:
        try:
            parsed.append(Event(
                event_id=r["event_id"], ts=datetime.fromisoformat(r["ts"]),
                source=r["source"], host=r["host"], user=r["user"],
                src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=r["dst_port"],
                action=r["action"], outcome=r["outcome"], raw=r["raw"],
                bytes_out=r["bytes_out"] or 0,
            ))
        except Exception:
            continue

    buckets: dict[tuple, list[Event]] = defaultdict(list)
    for e in parsed:
        entity = e.src_ip or e.user or e.host
        if entity:
            buckets[(entity, ml._floor(e.ts))].append(e)

    windows = [v for v in buckets.values() if len(v) >= ml.MIN_EVENTS_PER_WINDOW]
    if len(windows) < causal.MIN_ROWS:
        return causal.CausalModel(features=list(ml.FEATURE_NAMES))

    matrix = np.array([ml._features(w) for w in windows], dtype=float)
    return causal.learn_dag(matrix, list(ml.FEATURE_NAMES))


def _observation(session_id: str, event_ids: list[int]) -> list[float] | None:
    """Feature vector for the events an incident actually covers."""
    from datetime import datetime

    from detect import ml
    from schemas import Event

    rows = store.get_events(session_id, event_ids[:400])
    if not rows:
        return None
    parsed = []
    for r in rows:
        try:
            parsed.append(Event(
                event_id=r["event_id"], ts=datetime.fromisoformat(r["ts"]),
                source=r["source"], host=r["host"], user=r["user"],
                src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=r["dst_port"],
                action=r["action"], outcome=r["outcome"], raw=r["raw"],
                bytes_out=r["bytes_out"] or 0,
            ))
        except Exception:
            continue
    return ml._features(parsed) if parsed else None


def _fallback(
    signals: list[Signal],
    analyses: dict[int, LogAnalysis],
    session_id: str | None = None,
) -> InvestigationResult:
    """Correlate by shared entity and overlapping time. Good enough to demo on."""
    model = _causal_model(session_id) if session_id else None
    parent = {s.signal_id: s.signal_id for s in signals}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    def tokens(s: Signal) -> set[str]:
        out = {s.entity, s.host}
        a = analyses.get(s.signal_id)
        if a:
            out |= {i.value for i in a.iocs if i.kind in ("ip", "user")}
            out |= set(a.entities_involved)
        return {t for t in out if t}

    for i, a in enumerate(signals):
        for b in signals[i + 1 :]:
            shared = tokens(a) & tokens(b)
            close = (
                min(a.ts_end, b.ts_end) - max(a.ts_start, b.ts_start)
            ).total_seconds() > -3600
            if shared and close:
                union(a.signal_id, b.signal_id)

    groups: dict[int, list[Signal]] = {}
    for s in signals:
        groups.setdefault(find(s.signal_id), []).append(s)

    incidents: list[Incident] = []
    for n, (_, members) in enumerate(
        sorted(groups.items(), key=lambda kv: -max(m.score for m in kv[1])), start=1
    ):
        members.sort(key=lambda s: s.ts_start)
        stages = [_STAGE_BY_RULE.get(m.rule_id, "discovery") for m in members]
        furthest = max(stages, key=lambda st: _STAGE_RANK.index(st))
        techs = []
        for tid in dict.fromkeys(_TECH_BY_RULE.get(m.rule_id, "T1057") for m in members):
            rec = mitre.coerce(tid)
            techs.append(MitreTechnique(**rec))

        peak = max(m.score for m in members)
        sev_bonus = 25 if any(m.severity == "critical" for m in members) else 0
        stage_bonus = int(_STAGE_RANK.index(furthest) / len(_STAGE_RANK) * 30)
        heuristic = max(5, min(int(peak * 45) + sev_bonus + stage_bonus, 100))

        # Causal risk when a DAG was learned: an incident's weight is its own
        # deviation plus the deviation of everything it causally reaches. A
        # spike leading nowhere is noise; the same spike followed downstream by
        # privilege change and egress is a breach, and correlation alone cannot
        # tell those apart.
        risk, blast = heuristic, None
        if model is not None and model.fitted and session_id:
            observation = _observation(
                session_id, [i for m in members for i in m.event_ids]
            )
            if observation:
                blast = causal.blast_radius(model, observation)
                if blast["fitted"] and blast["contributors"]:
                    # Blast radius measures how ANOMALOUS an incident is, not how
                    # much harm it did, and the two come apart. The credential
                    # spray is statistically extreme - 10 sigma on distinct_users -
                    # yet it never authenticated once, so scoring on deviation
                    # alone ranked it above two confirmed exfiltrations. Scale by
                    # how far along the kill chain the attack actually got.
                    reach = _STAGE_RANK.index(furthest) / (len(_STAGE_RANK) - 1)
                    stage_weight = 0.6 + 0.4 * reach
                    risk = max(
                        5,
                        min(int(causal.to_risk_score(blast["total"]) * stage_weight), 100),
                    )

        hosts = sorted({m.host for m in members})
        users = sorted(
            {u for m in members for u in (analyses[m.signal_id].entities_involved if m.signal_id in analyses else []) if u.isidentifier()}
        )[:6]

        incidents.append(
            Incident(
                incident_id=f"INC-{n:03d}",
                title=members[0].title if len(members) == 1
                      else f"Multi-stage activity involving {members[0].entity}",
                narrative=(
                    f"{len(members)} correlated signals between "
                    f"{members[0].ts_start:%H:%M:%S} and {members[-1].ts_end:%H:%M:%S} UTC "
                    f"on {', '.join(hosts)}. Progression: "
                    + " -> ".join(dict.fromkeys(stages))
                    + ". " + " ".join(m.detail for m in members[:3])
                ),
                signal_ids=[m.signal_id for m in members],
                kill_chain_stage=furthest,  # type: ignore[arg-type]
                mitre_techniques=techs,
                risk_score=risk,
                risk_rationale=_rationale(peak, furthest, members, blast),
                severity="critical" if risk >= 85 else "high" if risk >= 60 else "medium" if risk >= 35 else "low",
                affected_hosts=hosts,
                affected_users=users,
                evidence=[
                    EvidenceRef(claim=m.detail or m.title, event_ids=m.event_ids[:10])
                    for m in members
                ],
                confidence=0.6,
            )
        )
    return InvestigationResult(incidents=incidents)


def _sanitise(result: InvestigationResult) -> InvestigationResult:
    """Snap model-supplied MITRE IDs onto the real catalogue before storing."""
    for inc in result.incidents:
        fixed = []
        for t in inc.mitre_techniques:
            rec = mitre.coerce(t.technique_id, t.name, t.tactic)
            fixed.append(MitreTechnique(**rec))
        # de-duplicate while preserving the model's ordering
        seen: set[str] = set()
        inc.mitre_techniques = [
            t for t in fixed if not (t.technique_id in seen or seen.add(t.technique_id))
        ]
        inc.risk_score = max(0, min(inc.risk_score, 100))
    return result


def investigate(
    client: LLMClient,
    session_id: str,
    signals: list[Signal],
    analyses: dict[int, LogAnalysis],
    redactor: Redactor | None = None,
) -> tuple[InvestigationResult, list[dict], bool]:
    """Returns (result, tool_calls, used_model)."""
    if not signals:
        return InvestigationResult(incidents=[]), [], False

    prompt = _prompt(signals, analyses)
    if redactor and redactor.enabled:
        prompt = redactor.redact(prompt)

    result, calls = client.converse_with_tools(
        tag=f"investigation:{session_id}",
        messages=[{"role": "user", "content": prompt}],
        tools=[FETCH_TOOL],
        tool_impls={"fetch_log_window": make_fetch_tool(session_id, redactor)},
        schema=InvestigationResult,
        system=SYSTEM,
        max_turns=6,
        effort="high",
    )
    if result is None:
        return _fallback(signals, analyses, session_id), calls, False
    if redactor and redactor.enabled:
        result = redactor.restore_model(result)
        calls = redactor.restore_obj(calls)
    return _sanitise(result), calls, True


def _rationale(peak, furthest, members, blast) -> str:
    """Explain the number. A risk score nobody can interrogate is a guess."""
    criticals = sum(1 for m in members if m.severity == "critical")
    base = (
        f"Peak detector score {peak:.2f}; furthest kill-chain stage reached is "
        f"{furthest}; {criticals} critical-severity signals in the group."
    )
    if not blast or not blast.get("contributors"):
        return base

    # Report the feature with real downstream reach, not merely the largest
    # deviation - the biggest number is usually a terminal node in the DAG, so
    # leading with it made every rationale read "no downstream features" and
    # hid the causal chain the score was built from.
    propagating = [c for c in blast["contributors"] if c["reaches"]]
    top = max(propagating, key=lambda c: c["downstream"]) if propagating \
        else blast["contributors"][0]

    causal_part = (
        f" Causal blast radius {blast['total']:.1f}; strongest causal driver is "
        f"{top['feature']} at {top['own_deviation']:.1f} sigma"
    )
    if top["reaches"]:
        causal_part += (
            f", which the learned DAG shows propagating into "
            f"{', '.join(top['reaches'])} (+{top['downstream']:.1f})."
        )
    else:
        causal_part += ", with no deviating downstream features."
    return base + causal_part
