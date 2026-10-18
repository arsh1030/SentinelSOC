"""
Agent 1 - Log Analysis Agent.

Normalises one signal's evidence, extracts indicators of compromise, and states
in one sentence what the logs actually show. High volume, low difficulty, so it
runs at low effort.

Every agent in this package has a deterministic fallback that produces a
schema-valid result with no model at all. That is not a stub - it is what runs
when the venue wifi dies mid-demo, and it is why DEMO_MODE=cached works.
"""

from __future__ import annotations

import re
from typing import Optional

from llm_client import LLMClient
from redaction import Redactor
from schemas import IOC, Deviation, LogAnalysis, Signal

# Above this many standard deviations a feature is worth an analyst's attention;
# above the second, it is the reason the signal fired.
Z_ELEVATED = 2.0
Z_EXTREME = 4.0

SYSTEM = """You are the Log Analysis Agent in a security operations pipeline.

You receive ONE detection signal and the raw log lines that triggered it. Your job
is narrow and factual:
  - state what the logs show, in one sentence, without speculating about intent
  - extract every concrete indicator of compromise
  - name the entities involved
  - describe the shape of the behaviour

You do NOT assign risk, name attack techniques, or recommend actions. A later
agent does that with the full picture. Report only what these specific log lines
support. If the evidence is thin, say so through a low confidence score."""

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PORT = re.compile(r"\bport (\d{1,5})\b", re.I)
_RE_PATH = re.compile(r'"(?:GET|POST|PUT|DELETE) (\S+)')
_RE_PROC = re.compile(r"NewProcessName=([^,]+)")
_RE_USER = re.compile(r"(?:for|user|SubjectUserName=)\s*([A-Za-z_][\w.-]{1,31})\b")


def compute_baseline(session_id: str) -> dict[str, tuple[float, float]]:
    """
    Per-feature mean and standard deviation across every window in the session.

    This is what "anomalous" is measured against, so it is computed over the
    whole corpus rather than the signal's own events - measuring a window against
    itself would put every z-score at zero.
    """
    from collections import defaultdict
    from datetime import datetime

    import store
    from detect import ml
    from schemas import Event

    rows = store.all_events(session_id)
    if not rows:
        return {}

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
    if len(windows) < 5:
        return {}

    columns: dict[str, list[float]] = defaultdict(list)
    for w in windows:
        for name, value in zip(ml.FEATURE_NAMES, ml._features(w), strict=True):
            columns[name].append(value)

    baseline: dict[str, tuple[float, float]] = {}
    for name, values in columns.items():
        n = len(values)
        mean = sum(values) / n
        var = sum((v - mean) ** 2 for v in values) / n
        baseline[name] = (mean, var ** 0.5)
    return baseline


def compute_deviations(
    evidence: list[dict], baseline: dict[str, tuple[float, float]]
) -> list[Deviation]:
    """
    Z-score each feature of this signal's events against the session baseline.

    Arithmetic, deliberately. Asking the model for a z-score would produce the
    most authoritative-looking wrong number on the screen.
    """
    if not baseline or not evidence:
        return []

    from datetime import datetime

    from detect import ml
    from schemas import Event

    parsed: list[Event] = []
    for r in evidence:
        try:
            parsed.append(Event(
                event_id=r["event_id"], ts=datetime.fromisoformat(str(r["ts"])),
                source=r.get("source", "ssh_auth"), host=r.get("host", "unknown"),
                user=r.get("user"), src_ip=r.get("src_ip"), dst_ip=r.get("dst_ip"),
                dst_port=r.get("dst_port"), action=r.get("action", "unknown"),
                outcome=r.get("outcome", "info"), raw=r.get("raw", ""),
                bytes_out=r.get("bytes_out") or 0,
            ))
        except Exception:
            continue
    if not parsed:
        return []

    out: list[Deviation] = []
    for name, value in zip(ml.FEATURE_NAMES, ml._features(parsed), strict=True):
        mean, std = baseline.get(name, (0.0, 0.0))
        if std <= 0:
            continue                      # a constant feature cannot deviate
        z = (value - mean) / std
        magnitude = abs(z)
        out.append(Deviation(
            feature=name,
            value=round(value, 3),
            baseline_mean=round(mean, 3),
            z_score=round(z, 2),
            flag=("extreme" if magnitude >= Z_EXTREME
                  else "elevated" if magnitude >= Z_ELEVATED
                  else "normal"),
        ))

    out.sort(key=lambda d: -abs(d.z_score))
    return out


def threat_score(signal: Signal, deviations: list[Deviation]) -> int:
    """
    Raw 0-100 triage score: detector confidence, lifted by how far out the
    window actually sits.

    Distinct from the incident risk score that Agent 2 assigns. This one says
    "how unusual is this", not "how much harm was done" - a scan can be wildly
    unusual and nearly harmless, and collapsing the two loses that.
    """
    base = signal.score * 70
    sharpest = max((abs(d.z_score) for d in deviations), default=0.0)
    lift = min(sharpest / Z_EXTREME, 1.0) * 30
    return max(1, min(int(round(base + lift)), 100))


def _prompt(signal: Signal, evidence: list[dict]) -> str:
    lines = "\n".join(
        f"  [event {e['event_id']}] {e['ts']} {e['raw']}" for e in evidence[:40]
    )
    return f"""SIGNAL {signal.signal_id}
  detector : {signal.detector} / {signal.rule_id}
  title    : {signal.title}
  severity : {signal.severity} (detector score {signal.score})
  window   : {signal.ts_start:%Y-%m-%d %H:%M:%S} to {signal.ts_end:%H:%M:%S} UTC
  host     : {signal.host}
  entity   : {signal.entity} ({signal.entity_kind})
  detector notes: {signal.detail}

EVIDENCE - {len(evidence)} events, first {min(len(evidence), 40)} shown:
{lines}

Analyse this signal. Use the event IDs above when citing notable events."""


def _fallback(signal: Signal, evidence: list[dict]) -> LogAnalysis:
    """Deterministic analysis from the evidence itself. No model required."""
    blob = "\n".join(e["raw"] for e in evidence[:200])
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, context: str) -> None:
        key = (kind, value)
        if value and key not in seen and len(iocs) < 20:
            seen.add(key)
            iocs.append(IOC(kind=kind, value=value, context=context))  # type: ignore[arg-type]

    for ip in _RE_IP.findall(blob)[:60]:
        add("ip", ip, "address observed in the triggering events")
    for port in _RE_PORT.findall(blob)[:20]:
        add("port", port, "destination port in the triggering events")
    for path in _RE_PATH.findall(blob)[:20]:
        add("path", path[:120], "HTTP path requested")
    for proc in _RE_PROC.findall(blob)[:10]:
        add("process", proc.strip()[:120], "process created on the host")
    for user in {e.get("user") for e in evidence if e.get("user")}:
        add("user", str(user), "account named in the triggering events")
    # The parser fills `user` only where the format exposes it; sudo lines,
    # process arguments and Windows messages carry accounts in free text.
    for user in _RE_USER.findall(blob)[:20]:
        add("user", user, "account referenced in the log text")

    users = sorted({str(e["user"]) for e in evidence if e.get("user")})
    hosts = sorted({str(e["host"]) for e in evidence})
    entities = [signal.entity] + [u for u in users if u != signal.entity] + hosts

    span = max(int((signal.ts_end - signal.ts_start).total_seconds()), 1)
    return LogAnalysis(
        signal_id=signal.signal_id,
        summary=f"{signal.title}: {len(evidence)} events over {span}s on {signal.host}. "
                f"{signal.detail}",
        iocs=iocs,
        entities_involved=list(dict.fromkeys(entities))[:12],
        activity_pattern=f"{signal.detector}/{signal.rule_id} matched {len(evidence)} events "
                         f"attributed to {signal.entity}",
        notable_event_ids=[e["event_id"] for e in evidence[:6]],
        confidence=round(min(0.45 + signal.score * 0.3, 0.75), 2),
    )


def analyse_signal(
    client: LLMClient,
    signal: Signal,
    evidence: list[dict],
    redactor: Redactor | None = None,
    baseline: dict[str, tuple[float, float]] | None = None,
) -> tuple[LogAnalysis, bool]:
    """
    Returns (analysis, used_model).

    The fallback runs on the ORIGINAL evidence - it never leaves the machine, so
    there is nothing to redact and nothing to restore.

    Deviations and the threat score are attached AFTER the model returns, and
    overwrite anything it put there. They are arithmetic over the corpus, and a
    model-invented z-score would be the most convincing wrong number on screen.
    """
    outbound = (
        [redactor.redact_event(e) for e in evidence]
        if redactor and redactor.enabled
        else evidence
    )
    result: Optional[LogAnalysis] = client.structured(
        tag=f"log_analysis:{signal.rule_id}:{signal.entity}",
        messages=[{"role": "user", "content": _prompt(signal, outbound)}],
        schema=LogAnalysis,
        system=SYSTEM,
        effort="low",
        max_tokens=4000,
    )
    used_model = result is not None
    if result is None:
        result = _fallback(signal, evidence)
    elif redactor and redactor.enabled:
        result = redactor.restore_model(result)

    result.signal_id = signal.signal_id
    result.deviations = compute_deviations(evidence, baseline or {})
    result.threat_score = threat_score(signal, result.deviations)
    return result, used_model
