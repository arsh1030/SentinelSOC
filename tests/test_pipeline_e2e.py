"""
End-to-end: raw log files in, correlated incidents out.

Guards the properties the demo depends on. If one of these fails, the demo is
broken - not degraded.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

import store  # noqa: E402
from agents import run_investigation  # noqa: E402
from ingest import parse_directory  # noqa: E402
from llm_client import LLMClient  # noqa: E402
from service import ingest_directory  # noqa: E402

SAMPLES = ROOT / "data" / "samples"


@pytest.fixture(scope="module")
def session():
    """One full run, shared across the assertions below."""
    store.reset_db()                      # conftest points this at a test graph

    summary = ingest_directory(SAMPLES, label="e2e")
    offline = LLMClient()
    offline.chain = []                    # exercise the demo-safe path
    ctx = run_investigation(summary["session_id"], offline)
    return summary, ctx


def test_samples_exist():
    assert SAMPLES.exists(), "run scripts/generate_logs.py first"
    assert (SAMPLES / "auth.log").exists()


def test_every_line_parses():
    """A silent parse failure quietly deletes evidence. Nothing may be dropped."""
    events, per_file = parse_directory(SAMPLES)
    for name, count in per_file.items():
        raw = len([ln for ln in (SAMPLES / name).read_text().splitlines() if ln.strip()])
        assert count == raw, f"{name}: parsed {count} of {raw} lines"
    assert len(events) == sum(per_file.values())


def test_events_are_chronological():
    events, _ = parse_directory(SAMPLES)
    assert all(a.ts <= b.ts for a, b in zip(events, events[1:], strict=False))


def test_ingest_produces_signals(session):
    summary, _ = session
    assert summary["events"] > 14_000
    assert 5 <= summary["signals"] <= 30, (
        f"{summary['signals']} signals - too few misses chains, too many is noise"
    )


def test_all_five_planted_chains_are_detected(session):
    summary, _ = session
    signals = store.get_signals(summary["session_id"])
    rules = {s["rule_id"] for s in signals}
    entities = {s["entity"] for s in signals}

    assert "R004" in rules, "SSH brute force -> success chain not detected"
    assert "R003" in rules, "SQL injection chain not detected"
    assert "R005" in rules, "exfiltration chain not detected"
    assert "R008" in rules, "lateral movement chain not detected"
    assert "R009" in rules, "credential spray chain not detected"
    assert {"203.0.113.45", "198.51.100.77", "mreddy",
            "svc_deploy", "198.51.100.203"} <= entities


def test_lateral_movement_does_not_flag_ordinary_admins(session):
    """
    The regression that matters most on this rule.

    Routine operators log into several hosts a day from many workstations. An
    earlier version of R008 counted only hosts and flagged five innocent
    accounts; bounding source addresses is what separates a pivot from a busy
    admin.
    """
    summary, _ = session
    lateral = [s for s in store.get_signals(summary["session_id"]) if s["rule_id"] == "R008"]
    flagged = {s["entity"] for s in lateral}
    assert flagged == {"svc_deploy"}, f"false positives on {flagged - {'svc_deploy'}}"


def test_spray_and_brute_force_are_not_double_reported(session):
    """One attack described twice as two different attacks is noise."""
    signals = store.get_signals(session[0]["session_id"])
    brute = {s["entity"] for s in signals if s["rule_id"] == "R001"}
    spray = {s["entity"] for s in signals if s["rule_id"] == "R009"}
    assert not (brute & spray), "the same source is being called both shapes"
    assert "203.0.113.45" in brute and "198.51.100.203" in spray


def test_ml_ensemble_corroborates_every_attacker_and_nothing_else(session):
    """
    The consensus should agree with the rules, not invent its own suspects.

    Each of the four attacking entities should be independently flagged by the
    unsupervised ensemble, and no ordinary internal host should be.
    """
    summary, _ = session
    ml_entities = {
        s["entity"] for s in store.get_signals(summary["session_id"])
        if s["rule_id"] == "ML001"
    }
    assert {"198.51.100.77", "203.0.113.45", "10.0.4.31", "198.51.100.203"} <= ml_entities
    innocent = ml_entities - {"198.51.100.77", "203.0.113.45", "10.0.4.31", "198.51.100.203"}
    assert not innocent, f"ensemble flagged ordinary hosts: {innocent}"


def test_signals_collapse_into_four_incidents(session):
    """
    Five chains, four incidents: the lateral movement is correctly absorbed into
    the brute-force chain it continues, since the same account did both.
    """
    summary, ctx = session
    incidents = store.get_incidents(summary["session_id"])
    assert len(incidents) == 4, (
        f"expected four correlated incidents, got {len(incidents)}"
    )
    assert len(incidents) < summary["signals"], "correlation must reduce the count"


def test_lateral_movement_is_merged_into_the_chain_it_continues(session):
    """svc_deploy's pivot belongs to the incident where it was compromised."""
    summary, _ = session
    signals = {s["signal_id"]: s for s in store.get_signals(summary["session_id"])}
    lateral_id = next(i for i, s in signals.items() if s["rule_id"] == "R008")
    brute_id = next(i for i, s in signals.items()
                    if s["rule_id"] == "R001" and s["entity"] == "203.0.113.45")

    owning = [inc for inc in store.get_incidents(summary["session_id"])
              if lateral_id in inc["signal_ids"]]
    assert len(owning) == 1
    assert brute_id in owning[0]["signal_ids"], (
        "the pivot should be correlated with the intrusion that enabled it"
    )


def test_every_incident_is_evidence_backed(session):
    summary, _ = session
    all_ids = {e["event_id"] for e in store.all_events(summary["session_id"])}
    for inc in store.get_incidents(summary["session_id"]):
        assert inc["evidence"], f"{inc['incident_id']} has no evidence"
        assert inc["mitre_techniques"], f"{inc['incident_id']} has no MITRE mapping"
        assert 0 <= inc["risk_score"] <= 100
        assert inc["risk_rationale"].strip()
        for ev in inc["evidence"]:
            assert ev["event_ids"], "an evidence claim cites no events"
            # every cited id must be a real event, or the citation is theatre
            assert set(ev["event_ids"]) <= all_ids


def test_mitre_ids_are_all_real(session):
    import mitre

    summary, _ = session
    for inc in store.get_incidents(summary["session_id"]):
        for t in inc["mitre_techniques"]:
            assert mitre.validate(t["technique_id"]), f"invented ID {t['technique_id']}"


def test_risk_ranks_confirmed_breach_above_a_blocked_attempt(session):
    """
    The correction the causal score needed. Blast radius measures how ANOMALOUS
    an incident is, and the credential spray is statistically extreme - 10 sigma
    on distinct_users - despite never authenticating once. Scoring on deviation
    alone put it above two confirmed exfiltrations; scaling by kill-chain reach
    is what restores the ordering an analyst would expect.
    """
    summary, _ = session
    incidents = {i["kill_chain_stage"]: i for i in store.get_incidents(summary["session_id"])}
    if "credential_access" in incidents and "exfiltration" in incidents:
        assert incidents["exfiltration"]["risk_score"] > incidents["credential_access"]["risk_score"]


def test_risk_rationale_explains_the_number(session):
    """A risk score nobody can interrogate is a guess with a decimal point."""
    summary, _ = session
    for inc in store.get_incidents(summary["session_id"]):
        why = inc["risk_rationale"]
        assert "Peak detector score" in why
        if "blast radius" in why:
            assert "sigma" in why, "a causal claim must show the deviation it rests on"


def test_every_incident_has_an_actionable_plan(session):
    summary, _ = session
    for inc in store.get_incidents(summary["session_id"]):
        plan = store.get_plan(inc["incident_id"])
        assert plan, f"{inc['incident_id']} has no response plan"
        assert plan["actions"], "plan has no actions"
        assert plan["actions"][0]["phase"] == "containment", "plan must lead with containment"
        assert all(a["execution"] in ("manual", "automated") for a in plan["actions"])


def test_agent_trace_records_all_three_agents(session):
    summary, _ = session
    runs = store.get_runs(summary["session_id"])
    agents = {r["agent"] for r in runs}
    assert agents == {"log_analysis", "threat_investigation", "response"}
    assert [r["stage_index"] for r in runs] == sorted(r["stage_index"] for r in runs)


def test_report_contains_the_findings(session):
    import report

    summary, _ = session
    md = report.build_markdown(summary["session_id"])
    assert "# Security Incident Report" in md
    assert "## Executive summary" in md
    for inc in store.get_incidents(summary["session_id"]):
        assert inc["incident_id"] in md
    html = report.build_html(summary["session_id"])
    assert html.count("<table>") == html.count("</table>")
    assert "<script" not in html.lower(), "report must not carry executable content"


def test_pipeline_survives_with_no_model(session):
    """The whole point of the fallbacks: a dead API key must not stop the demo."""
    _, ctx = session
    assert ctx.used_model == {
        "log_analysis": False,
        "threat_investigation": False,
        "response": False,
    }
    assert ctx.investigation and ctx.investigation.incidents
    assert ctx.plans


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
