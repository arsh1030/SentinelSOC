"""
The logic gate is the hallucination guard. If it stops rejecting bad rules, the
platform starts executing whatever the model imagined, so these are the tests
that matter most for the "is this just prompting?" question.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

from detect.logic_gate import ProposedRule, execute, run_logic_gate, validate  # noqa: E402
from schemas import Event  # noqa: E402

NOW = datetime(2026, 3, 15, 2, 0, tzinfo=timezone.utc)


def _rule(**kw) -> ProposedRule:
    base = dict(
        statement="s", aggregate="count", group_by="src_ip",
        filter_field="outcome", filter_value="failure", window_seconds=600,
        operator="greater_than", value=10, severity="high",
        mitre_technique="T1110", rationale="r",
    )
    base.update(kw)
    return ProposedRule(**base)


def _events(n: int, ip="203.0.113.45", outcome="failure", step=5, bytes_out=0) -> list[Event]:
    return [
        Event(event_id=i + 1, ts=NOW + timedelta(seconds=i * step), source="ssh_auth",
              host="web-01", user="root", src_ip=ip, dst_port=22 + i,
              action="ssh_login", outcome=outcome, raw=f"line {i}", bytes_out=bytes_out)
        for i in range(n)
    ]


# -- validation -------------------------------------------------------------


@pytest.mark.parametrize("kw,expect", [
    ({}, True),
    ({"group_by": "attacker_score"}, False),          # field does not exist
    ({"aggregate": "average"}, False),                # not in the grammar
    ({"operator": "regex_match"}, False),             # not in the grammar
    ({"filter_field": "threat_level"}, False),        # field does not exist
    ({"window_seconds": 5}, False),                   # below the floor
    ({"window_seconds": 999_999}, False),             # above the ceiling
    ({"value": 0}, False),                            # non-positive threshold
    ({"value": -3}, False),
    ({"severity": "catastrophic"}, False),            # not a severity
    ({"aggregate": "distinct", "count_field": None}, False),
    ({"aggregate": "distinct", "count_field": "dst_port"}, True),
    ({"aggregate": "distinct", "count_field": "password"}, False),
    ({"filter_field": "outcome", "filter_value": None}, False),
    ({"filter_field": None, "filter_value": None}, True),
])
def test_validation(kw, expect):
    ok, reason = validate(_rule(**kw))
    assert ok is expect, f"{kw} -> {reason}"
    if not ok:
        assert reason and reason != "ok", "a rejection must say what was wrong"


# -- execution --------------------------------------------------------------


def test_count_rule_fires_above_threshold_only():
    assert execute(_rule(value=10), _events(20), 1), "20 failures should trip a >10 rule"
    assert not execute(_rule(value=50), _events(20), 1), "20 failures must not trip >50"


def test_filter_is_actually_applied():
    """A rule filtering on failures must ignore successes entirely."""
    evs = _events(20, outcome="success")
    assert not execute(_rule(value=5, filter_field="outcome", filter_value="failure"), evs, 1)


def test_window_is_respected():
    spread = _events(20, step=3600)          # one per hour
    assert not execute(_rule(value=5, window_seconds=600), spread, 1)
    assert execute(_rule(value=5, window_seconds=86_400), spread, 1)


def test_distinct_counts_unique_values_not_rows():
    evs = _events(20)                         # 20 rows, 20 distinct ports
    r = _rule(aggregate="distinct", count_field="dst_port", value=15, filter_field=None,
              filter_value=None)
    assert execute(r, evs, 1)
    r2 = _rule(aggregate="distinct", count_field="host", value=2, filter_field=None,
               filter_value=None)
    assert not execute(r2, evs, 1), "all events share one host; distinct(host) is 1"


def test_sum_bytes_aggregates_volume():
    evs = _events(10, bytes_out=2_000_000, outcome="allowed")
    r = _rule(aggregate="sum_bytes", value=15_000_000, filter_field=None, filter_value=None)
    assert execute(r, evs, 1)


def test_signals_are_grouped_per_entity():
    evs = _events(20, ip="1.1.1.1") + _events(20, ip="2.2.2.2")
    sigs = execute(_rule(value=10), evs, 1)
    assert {s.entity for s in sigs} == {"1.1.1.1", "2.2.2.2"}


def test_signal_carries_real_event_ids_and_provenance():
    sigs = execute(_rule(value=10), _events(20), 1)
    s = sigs[0]
    assert s.detector == "logic_gate" and s.rule_id == "LG001"
    assert s.event_ids and all(isinstance(i, int) for i in s.event_ids)
    assert "schema-validated before execution" in s.detail


def test_offline_gate_is_a_no_op():
    """No model configured must mean no rules - never silent invented ones."""
    from llm_client import LLMClient

    c = LLMClient()
    c.chain = []
    signals, audit = run_logic_gate(_events(20), c)
    assert signals == [] and audit == []


def test_rejected_rules_are_audited_not_executed(monkeypatch, tmp_path):
    """A bad rule must appear in the audit and produce no signals."""
    import detect.logic_gate as lg
    from llm_client import LLMClient
    from detect.logic_gate import RuleSet

    monkeypatch.setattr(lg, "CACHE_PATH", tmp_path / "cache.json")

    good = _rule(statement="good rule", value=10)
    bad = _rule(statement="bad rule", group_by="vibes")

    class FakeProvider:
        name, model = "fake", "fake-model"

        def structured(self, *a, **kw):
            return RuleSet(rules=[good, bad])

    class FakeClient(LLMClient):
        def __init__(self):
            self.replay = False
            self.record = False
            self.last_provider = ""
            self.chain = [FakeProvider()]

    signals, audit = run_logic_gate(_events(20), FakeClient())

    assert len(audit) == 2
    accepted = [a for a in audit if a["accepted"]]
    rejected = [a for a in audit if not a["accepted"]]
    assert len(accepted) == 1 and accepted[0]["statement"] == "good rule"
    assert len(rejected) == 1 and "vibes" in rejected[0]["reason"]
    assert signals and all(s.rule_id == "LG001" for s in signals)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
