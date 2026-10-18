"""
Agent behaviour that must hold regardless of provider.

These are the deterministic paths - what runs when every provider is down, which
on demo day is the difference between degraded and dead.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

from llm_client import LLMClient  # noqa: E402
from schemas import (  # noqa: E402
    EvidenceRef, Incident, InvestigationResult, LogAnalysis, MitreTechnique, Signal,
)

NOW = datetime(2026, 3, 15, 2, 14, tzinfo=timezone.utc)


def _offline() -> LLMClient:
    c = LLMClient()
    c.chain = []
    return c


def _signal(**kw) -> Signal:
    base = dict(
        signal_id=1, detector="rule", rule_id="R001", title="Brute force",
        severity="high", ts_start=NOW, ts_end=NOW + timedelta(minutes=5),
        host="web-01", entity="203.0.113.45", entity_kind="src_ip", score=0.9,
        event_ids=[1, 2, 3], evidence_sample=["line a"], detail="58 failures",
    )
    base.update(kw)
    return Signal(**base)


def _analysis(sid=1) -> LogAnalysis:
    return LogAnalysis(
        signal_id=sid, summary="s", iocs=[], entities_involved=["203.0.113.45"],
        activity_pattern="p", notable_event_ids=[1], confidence=0.8,
    )


def test_agent1_extracts_iocs_without_a_model():
    from agents.log_analysis import analyse_signal

    evidence = [{
        "event_id": 1, "ts": NOW.isoformat(), "host": "web-01", "user": "root",
        "raw": "Failed password for root from 203.0.113.45 port 45000 ssh2",
    }]
    analysis, used = analyse_signal(_offline(), _signal(), evidence)
    assert used is False and analysis.signal_id == 1
    assert any(i.kind == "ip" and i.value == "203.0.113.45" for i in analysis.iocs)
    assert any(i.kind == "user" and i.value == "root" for i in analysis.iocs)


def test_agent2_fallback_correlates_on_shared_entity():
    from agents.threat_investigation import _fallback

    s1 = _signal(signal_id=1, rule_id="R001", entity="203.0.113.45")
    s2 = _signal(signal_id=2, rule_id="R004", entity="203.0.113.45", severity="critical",
                 ts_start=NOW + timedelta(minutes=5), ts_end=NOW + timedelta(minutes=6))
    s3 = _signal(signal_id=3, rule_id="R007", entity="mreddy", entity_kind="user",
                 host="fs-01", ts_start=NOW + timedelta(hours=20),
                 ts_end=NOW + timedelta(hours=20, minutes=5))

    res = _fallback([s1, s2, s3], {i: _analysis(i) for i in (1, 2, 3)})
    groups = {tuple(sorted(i.signal_ids)) for i in res.incidents}
    assert (1, 2) in groups          # same address, minutes apart -> one incident
    assert (3,) in groups            # different entity, 20h later -> its own


def test_agent2_snaps_invented_mitre_ids_onto_the_catalogue():
    from agents.threat_investigation import _sanitise

    inc = Incident(
        incident_id="INC-001", title="t", narrative="n", signal_ids=[1],
        kill_chain_stage="exfiltration",
        mitre_techniques=[
            MitreTechnique(technique_id="T1110.999", name="Made up", tactic="nonsense"),
            MitreTechnique(technique_id="T1048", name="x", tactic="y"),
            MitreTechnique(technique_id="T1048", name="dupe", tactic="y"),
        ],
        risk_score=95, risk_rationale="r", severity="critical",
        affected_hosts=["web-01"], affected_users=[],
        evidence=[EvidenceRef(claim="c", event_ids=[1])], confidence=0.9,
    )
    # ge=0/le=100 means a validated model can never exceed the range; bypass
    # validation to prove the clamp still guards the fallback's arithmetic.
    object.__setattr__(inc, "risk_score", 150)

    out = _sanitise(InvestigationResult.model_construct(incidents=[inc])).incidents[0]
    assert [t.technique_id for t in out.mitre_techniques] == ["T1110", "T1048"]
    assert out.mitre_techniques[0].tactic == "credential_access"
    assert out.risk_score == 100


def test_agent3_fallback_leads_with_containment():
    from agents.response import _fallback

    inc = Incident(
        incident_id="INC-001", title="t", narrative="n", signal_ids=[1],
        kill_chain_stage="exfiltration", mitre_techniques=[],
        risk_score=95, risk_rationale="r", severity="critical",
        affected_hosts=["fs-01"], affected_users=["mreddy"],
        evidence=[EvidenceRef(claim="transfer from 10.0.4.31", event_ids=[1])],
        confidence=0.9,
    )
    plan = _fallback(inc)
    assert plan.actions[0].phase == "containment"
    assert plan.actions[0].urgency == "immediate"
    assert plan.escalate_to == "ciso"
    assert plan.containment_deadline_minutes == 15
    assert "mreddy" in (plan.actions[1].command or "")


def test_offline_client_returns_none_not_an_exception():
    c = _offline()
    assert c.structured("t", [{"role": "user", "content": "x"}], LogAnalysis) is None
    obj, calls = c.converse_with_tools(
        "t", [{"role": "user", "content": "x"}], [], {}, InvestigationResult
    )
    assert obj is None and calls == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
