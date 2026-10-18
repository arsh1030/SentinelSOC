"""
SentinelSOC - the detection gate.

Runs every deterministic detector, merges near-duplicate signals, and hands the
survivors to the agent layer. Nothing here calls a model.
"""

from __future__ import annotations

from schemas import Event, Signal

from .logic_gate import run_logic_gate
from .ml import rare_template_signals, run_isolation_forest
from .rules import run_rules

_SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _dedupe(signals: list[Signal]) -> list[Signal]:
    """
    Collapse signals that describe the same entity with the same rule.

    Detectors overlap by design - a brute force fires R001 and usually R004 and
    often an Isolation Forest window too. Keeping all three is correct (they are
    independent evidence); keeping three copies of R001 for one address is not.
    """
    best: dict[tuple[str, str], Signal] = {}
    for s in signals:
        key = (s.rule_id, s.entity)
        current = best.get(key)
        if current is None or (s.score, _SEV[s.severity]) > (current.score, _SEV[current.severity]):
            best[key] = s
    return list(best.values())


def detect_all(
    events: list[Event], use_ml: bool = True, client=None
) -> tuple[list[Signal], list[dict]]:
    """
    Returns (signals, logic_gate_audit).

    Order matters: hand-written rules first (free and certain), then the model,
    then the AI-proposed rules. Nothing here needs the agent layer.
    """
    signals = run_rules(events)
    if use_ml:
        signals.extend(run_isolation_forest(events))
    signals.extend(rare_template_signals(events))

    audit: list[dict] = []
    if client is not None:
        try:
            gate_signals, audit = run_logic_gate(events, client)
            signals.extend(gate_signals)
        except Exception as exc:
            print(f"[detect] logic gate failed: {type(exc).__name__}: {exc}")

    signals = _dedupe(signals)
    signals.sort(key=lambda s: (-_SEV[s.severity], -s.score))
    return signals, audit
