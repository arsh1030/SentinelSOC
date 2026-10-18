"""
Statistical deviation metrics on the Agent 1 payload.

The property worth guarding: these are arithmetic, not model output. A z-score a
language model invented would be the most authoritative-looking wrong number on
the screen, and nothing downstream would question it.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

from agents.log_analysis import (  # noqa: E402
    Z_ELEVATED, Z_EXTREME, analyse_signal, compute_deviations, threat_score,
)
from llm_client import LLMClient  # noqa: E402
from schemas import Deviation, LogAnalysis, Signal  # noqa: E402

T0 = datetime(2026, 3, 15, 2, 0, tzinfo=timezone.utc)


def _signal(score=0.9, **kw) -> Signal:
    base = dict(
        signal_id=1, detector="rule", rule_id="R001", title="t", severity="high",
        ts_start=T0, ts_end=T0 + timedelta(minutes=5), host="web-01",
        entity="203.0.113.45", entity_kind="src_ip", score=score,
        event_ids=[1, 2, 3], evidence_sample=[], detail="d",
    )
    base.update(kw)
    return Signal(**base)


def _evidence(n=20, ports=1, users=1, outcome="failure"):
    return [
        {"event_id": i, "ts": (T0 + timedelta(seconds=i)).isoformat(),
         "source": "ssh_auth", "host": "web-01", "user": f"u{i % users}",
         "src_ip": "203.0.113.45", "dst_ip": "10.0.0.1",
         "dst_port": 22 + (i % ports), "action": "ssh_login",
         "outcome": outcome, "raw": f"line {i}", "bytes_out": 0}
        for i in range(1, n + 1)
    ]


BASELINE = {
    "event_count":      (7.0, 3.0),
    "failure_ratio":    (0.05, 0.05),
    "distinct_ports":   (2.0, 1.5),
    "distinct_users":   (2.0, 1.0),
    "distinct_hosts":   (3.0, 1.2),
    "log_mbytes_out":   (0.1, 0.2),
    "distinct_actions": (2.5, 0.8),
    "blocked_ratio":    (0.01, 0.06),
    "off_hours":        (0.08, 0.27),
}


# -- the arithmetic --------------------------------------------------------


def test_z_scores_match_the_definition():
    """(value - mean) / std. Nothing cleverer, and nothing model-supplied."""
    devs = compute_deviations(_evidence(n=25), BASELINE)
    by = {d.feature: d for d in devs}
    ec = by["event_count"]
    assert ec.value == 25.0
    assert ec.baseline_mean == 7.0
    assert ec.z_score == pytest.approx((25.0 - 7.0) / 3.0, abs=0.01)


def test_flags_follow_the_thresholds():
    devs = compute_deviations(_evidence(n=25, users=12), BASELINE)
    for d in devs:
        expected = ("extreme" if abs(d.z_score) >= Z_EXTREME
                    else "elevated" if abs(d.z_score) >= Z_ELEVATED
                    else "normal")
        assert d.flag == expected, f"{d.feature} z={d.z_score} flagged {d.flag}"


def test_sorted_by_magnitude_so_the_reason_is_first():
    devs = compute_deviations(_evidence(n=40, ports=30, users=15), BASELINE)
    magnitudes = [abs(d.z_score) for d in devs]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_negative_deviation_is_kept_signed():
    """Unusually few of something is also a deviation; sign carries meaning."""
    devs = compute_deviations(_evidence(n=6, outcome="success"), BASELINE)
    by = {d.feature: d for d in devs}
    assert by["failure_ratio"].z_score < 0


def test_constant_feature_is_skipped_not_divided_by_zero():
    flat = dict(BASELINE, event_count=(7.0, 0.0))
    devs = compute_deviations(_evidence(), flat)
    assert "event_count" not in {d.feature for d in devs}
    assert devs, "the other features should still be scored"


def test_no_baseline_yields_no_deviations():
    assert compute_deviations(_evidence(), {}) == []


def test_no_evidence_yields_no_deviations():
    assert compute_deviations([], BASELINE) == []


def test_unparseable_evidence_is_skipped_not_fatal():
    junk = [{"event_id": 1, "ts": "not-a-timestamp"}]
    assert compute_deviations(junk, BASELINE) == []


# -- threat score ----------------------------------------------------------


def test_threat_score_rises_with_detector_confidence():
    devs = compute_deviations(_evidence(), BASELINE)
    low = threat_score(_signal(score=0.2), devs)
    high = threat_score(_signal(score=0.95), devs)
    assert 1 <= low < high <= 100


def test_threat_score_rises_with_deviation():
    quiet = [Deviation(feature="event_count", value=8, baseline_mean=7,
                       z_score=0.3, flag="normal")]
    loud = [Deviation(feature="event_count", value=99, baseline_mean=7,
                      z_score=12.0, flag="extreme")]
    assert threat_score(_signal(), loud) > threat_score(_signal(), quiet)


def test_threat_score_stays_in_range():
    extreme = [Deviation(feature="x", value=1e9, baseline_mean=1,
                         z_score=9999.0, flag="extreme")]
    assert threat_score(_signal(score=1.0), extreme) == 100
    assert 1 <= threat_score(_signal(score=0.0), []) <= 100


# -- the guarantee that matters -------------------------------------------


class _Liar(LLMClient):
    """A model that returns fabricated deviations and an absurd threat score."""

    def __init__(self):
        self.chain = [object()]
        self.replay = False
        self.record = False
        self.last_provider = ""

    def structured(self, tag, messages, schema, system=None, effort="high",
                   max_tokens=16000):
        return LogAnalysis(
            signal_id=999, summary="s", iocs=[], entities_involved=[],
            activity_pattern="p", notable_event_ids=[], confidence=0.9,
            deviations=[Deviation(feature="invented", value=1.0,
                                  baseline_mean=0.0, z_score=42.0, flag="extreme")],
            threat_score=100,
        )


def test_model_supplied_deviations_are_overwritten():
    """
    The model may fill these fields; the pipeline must ignore whatever it said.
    A fabricated z-score is more dangerous than a missing one because nothing
    downstream would question it.
    """
    analysis, used = analyse_signal(
        _Liar(), _signal(score=0.5), _evidence(), None, BASELINE
    )
    assert used is True
    features = {d.feature for d in analysis.deviations}
    assert "invented" not in features, "model-supplied deviations survived"
    assert features, "real deviations should have replaced them"
    assert analysis.threat_score != 100, "model-supplied threat score survived"


def test_fallback_path_also_gets_deviations():
    offline = LLMClient()
    offline.chain = []
    analysis, used = analyse_signal(
        offline, _signal(), _evidence(), None, BASELINE
    )
    assert used is False
    assert analysis.deviations and analysis.threat_score > 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
