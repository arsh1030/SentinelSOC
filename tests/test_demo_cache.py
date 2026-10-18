"""
DEMO_MODE=cached is the difference between a dead wifi being an inconvenience and
being the end of the pitch. It has to actually round-trip.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

import llm_client as lc  # noqa: E402
from llm_client import LLMClient  # noqa: E402
from schemas import InvestigationResult, LogAnalysis  # noqa: E402


ANALYSIS = LogAnalysis(
    signal_id=7, summary="brute force observed", iocs=[],
    entities_involved=["203.0.113.45"], activity_pattern="repeated failures",
    notable_event_ids=[1, 2], confidence=0.9,
)
MESSAGES = [{"role": "user", "content": "analyse signal 7"}]


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    path = tmp_path / "demo_run.json"
    monkeypatch.setattr(lc, "_CACHE_PATH", path)
    return path


class _ScriptedProvider:
    """Returns queued objects; stands in for a live provider."""

    name = "scripted"
    model = "scripted-model"

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def structured(self, messages, schema, system, max_tokens):
        self.calls += 1
        return self.script.pop(0)

    def tools(self, messages, tools, tool_impls, schema, system, max_turns,
              run_tool, calls):
        self.calls += 1
        return self.script.pop(0)


class _CountingProvider(_ScriptedProvider):
    """Fails loudly if reached - used to prove a cache hit short-circuits."""

    def __init__(self):
        super().__init__([])


def _recorder(script):
    c = LLMClient(record=True)
    c.chain = [_ScriptedProvider(script)]
    return c


def test_record_then_replay_returns_the_same_object(cache_file):
    rec = _recorder([ANALYSIS])
    first = rec.structured("log_analysis:R001", MESSAGES, LogAnalysis, effort="low")
    assert first == ANALYSIS
    rec.save_cache()
    assert cache_file.exists(), "recording must write the cache file"

    replay = LLMClient(replay=True)
    replay.chain = []                    # no key, no network
    replay._client = None
    got = replay.structured("log_analysis:R001", MESSAGES, LogAnalysis, effort="low")

    assert got is not None, "replay must not fall through to offline"
    assert got.model_dump() == ANALYSIS.model_dump()


def test_replay_makes_no_provider_calls(cache_file):
    rec = _recorder([ANALYSIS])
    rec.structured("t", MESSAGES, LogAnalysis)
    rec.save_cache()

    replay = LLMClient(replay=True)
    exploding = _CountingProvider()
    replay.chain = [exploding]
    replay.structured("t", MESSAGES, LogAnalysis)
    assert exploding.calls == 0, "a cache hit must never reach the provider"


def test_cache_miss_falls_through_rather_than_failing(cache_file):
    rec = _recorder([ANALYSIS])
    rec.structured("known", MESSAGES, LogAnalysis)
    rec.save_cache()

    replay = LLMClient(replay=True)
    replay.chain = []
    assert replay.structured("never-recorded", MESSAGES, LogAnalysis) is None


def test_corrupt_cache_does_not_crash_startup(cache_file):
    cache_file.write_text("{ this is not json")
    c = LLMClient(replay=True)
    assert c.replay is False, "an unreadable cache must fall back to live, not raise"


def test_stale_cache_entry_is_rejected_not_returned(cache_file):
    import json

    rec = _recorder([ANALYSIS])
    rec.structured("t", MESSAGES, LogAnalysis)
    rec.save_cache()

    data = json.loads(cache_file.read_text())
    key = next(iter(data))
    data[key] = {"totally": "wrong shape"}      # schema drifted since recording
    cache_file.write_text(json.dumps(data))

    replay = LLMClient(replay=True)
    replay.chain = []
    assert replay.structured("t", MESSAGES, LogAnalysis) is None


def test_tool_run_round_trips_with_its_calls(cache_file):
    result = InvestigationResult(incidents=[])
    rec = _recorder([result])
    got, calls = rec.converse_with_tools(
        "investigation:s1", MESSAGES, tools=[], tool_impls={},
        schema=InvestigationResult,
    )
    assert got is not None
    rec.save_cache()

    replay = LLMClient(replay=True)
    replay.chain = []
    got2, calls2 = replay.converse_with_tools(
        "investigation:s1", MESSAGES, tools=[], tool_impls={},
        schema=InvestigationResult,
    )
    assert got2 is not None and got2.model_dump() == result.model_dump()
    assert calls2 == calls


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
