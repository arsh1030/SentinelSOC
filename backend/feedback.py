"""
SentinelSOC - analyst feedback and threshold adaptation.

Taken from DataSentinel's active_learning.py: an analyst marking a detection as a
false positive should change what the platform does next, not just get logged.

Kept deliberately simple and bounded. The nudge is capped so a handful of clicks
cannot blind the detector - DataSentinel hard-capped its own threshold nudge at
1.5x for the same reason.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FEEDBACK_LOG = Path(__file__).resolve().parent.parent / "data" / "feedback.jsonl"

MAX_NUDGE = 0.25          # a rule's score can be damped by at most 25%
MIN_VOTES_TO_ACT = 2      # one analyst mis-click must not move anything


def record(session_id: str, signal_id: int, rule_id: str, verdict: str, note: str = "") -> dict:
    """verdict is 'true_positive' or 'false_positive'."""
    if verdict not in ("true_positive", "false_positive"):
        raise ValueError("verdict must be true_positive or false_positive")

    entry = {
        "session_id": session_id,
        "signal_id": signal_id,
        "rule_id": rule_id,
        "verdict": verdict,
        "note": note[:500],
        "at": datetime.now(timezone.utc).isoformat(),
    }
    FEEDBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with FEEDBACK_LOG.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def _all() -> list[dict]:
    if not FEEDBACK_LOG.exists():
        return []
    out = []
    for line in FEEDBACK_LOG.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def adjustments() -> dict[str, float]:
    """
    Per-rule score multipliers derived from analyst verdicts.

    A rule the team keeps dismissing gets damped; a rule they keep confirming is
    left alone. Confirmation never boosts a score above its detector's own
    judgement - the point is to reduce noise, not to manufacture confidence.
    """
    votes: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
    for entry in _all():
        key = "fp" if entry["verdict"] == "false_positive" else "tp"
        votes[entry["rule_id"]][key] += 1

    out: dict[str, float] = {}
    for rule_id, tally in votes.items():
        total = tally["tp"] + tally["fp"]
        if total < MIN_VOTES_TO_ACT:
            continue
        fp_rate = tally["fp"] / total
        out[rule_id] = round(1.0 - min(fp_rate * MAX_NUDGE / 0.5, MAX_NUDGE), 3)
    return out


def apply(signals: list[dict]) -> list[dict]:
    """Damp scores for rules the team has repeatedly dismissed."""
    adj = adjustments()
    if not adj:
        return signals
    for s in signals:
        factor = adj.get(s["rule_id"])
        if factor and factor < 1.0:
            s["score_original"] = s["score"]
            s["score"] = round(s["score"] * factor, 3)
            s["feedback_adjusted"] = True
    return signals


def summary() -> dict:
    entries = _all()
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
    for e in entries:
        per_rule[e["rule_id"]]["fp" if e["verdict"] == "false_positive" else "tp"] += 1
    return {
        "total_verdicts": len(entries),
        "per_rule": dict(per_rule),
        "active_adjustments": adjustments(),
    }
