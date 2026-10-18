"""Analyst feedback must move the needle, but only a little and only with quorum."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

import feedback  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_log(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback, "FEEDBACK_LOG", tmp_path / "feedback.jsonl")


def test_single_vote_changes_nothing():
    feedback.record("s1", 1, "R002", "false_positive")
    assert feedback.adjustments() == {}, "one click must not move a threshold"


def test_repeated_dismissals_damp_the_rule():
    for i in range(4):
        feedback.record("s1", i, "R002", "false_positive")
    adj = feedback.adjustments()
    assert "R002" in adj and adj["R002"] < 1.0


def test_damping_is_capped():
    for i in range(50):
        feedback.record("s1", i, "R002", "false_positive")
    assert feedback.adjustments()["R002"] >= 1.0 - feedback.MAX_NUDGE - 1e-9


def test_confirmations_do_not_inflate_scores():
    for i in range(10):
        feedback.record("s1", i, "R004", "true_positive")
    assert feedback.adjustments().get("R004", 1.0) <= 1.0


def test_apply_marks_what_it_changed():
    for i in range(4):
        feedback.record("s1", i, "R002", "false_positive")
    signals = [{"rule_id": "R002", "score": 0.80}, {"rule_id": "R004", "score": 0.95}]
    out = feedback.apply(signals)
    damped = next(s for s in out if s["rule_id"] == "R002")
    assert damped["score"] < 0.80 and damped["feedback_adjusted"] is True
    assert damped["score_original"] == 0.80
    untouched = next(s for s in out if s["rule_id"] == "R004")
    assert untouched["score"] == 0.95 and "feedback_adjusted" not in untouched


def test_bad_verdict_is_rejected():
    with pytest.raises(ValueError):
        feedback.record("s1", 1, "R002", "maybe")


def test_corrupt_log_lines_are_skipped():
    feedback.record("s1", 1, "R002", "false_positive")
    with feedback.FEEDBACK_LOG.open("a") as fh:
        fh.write("not json\n")
    feedback.record("s1", 2, "R002", "false_positive")
    assert feedback.summary()["total_verdicts"] == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
