"""
The provider chain, exercised without a network.

Two wire formats and one promise: if OpenRouter cannot answer, Gemini is asked
the same question before anything gives up, and if neither can, the caller gets
None rather than an exception.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

import llm_client as lc  # noqa: E402
from llm_client import (  # noqa: E402
    GeminiProvider, LLMClient, OpenRouterProvider, _gemini_safe_params,
)
from schemas import InvestigationResult, LogAnalysis  # noqa: E402

ANALYSIS = {
    "signal_id": 7, "summary": "brute force", "iocs": [],
    "entities_involved": ["203.0.113.45"], "activity_pattern": "failures",
    "notable_event_ids": [1], "confidence": 0.9,
}
MESSAGES = [{"role": "user", "content": "analyse"}]
FETCH_TOOL = {
    "name": "fetch_log_window", "description": "d",
    "input_schema": {"type": "object",
                     "properties": {"host": {"type": "string"}},
                     "additionalProperties": False, "$defs": {}},
}


def _stub_http(monkeypatch, responses):
    """Queue responses; record every request. A callable entry is invoked to raise."""
    sent: list[dict] = []
    queue = list(responses)

    def fake_post(url, payload, headers, timeout=lc.HTTP_TIMEOUT):
        # deep-copy: providers mutate their conversation list after posting,
        # so a stored reference would show the final state, not what was sent
        sent.append({"url": url, "payload": copy.deepcopy(payload), "headers": headers})
        item = queue.pop(0)
        if callable(item):
            return item()
        return item

    monkeypatch.setattr(lc, "_post_json", fake_post)
    return sent


def _or_reply(content, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {"choices": [{"message": msg, "finish_reason": "stop"}]}


def _gem_reply(text=None, function_calls=None):
    parts = []
    if text is not None:
        parts.append({"text": text})
    for fc in function_calls or []:
        parts.append({"functionCall": fc})
    return {"candidates": [{"content": {"parts": parts, "role": "model"},
                            "finishReason": "STOP"}]}


def _client(openrouter=True, gemini=True) -> LLMClient:
    c = LLMClient()
    c.chain = []
    if openrouter:
        c.chain.append(OpenRouterProvider("or-key", "anthropic/claude-sonnet-5"))
    if gemini:
        c.chain.append(GeminiProvider("gem-key", "gemini-2.5-flash"))
    return c


# ===========================================================================
# OpenRouter
# ===========================================================================


def test_openrouter_structured(monkeypatch):
    sent = _stub_http(monkeypatch, [_or_reply(json.dumps(ANALYSIS))])
    got = _client(gemini=False).structured("t", MESSAGES, LogAnalysis, system="sys")

    assert isinstance(got, LogAnalysis) and got.signal_id == 7
    p = sent[0]["payload"]
    assert sent[0]["url"] == lc.OPENROUTER_URL
    assert p["model"] == "anthropic/claude-sonnet-5"
    assert p["response_format"] == {"type": "json_object"}
    assert "JSON Schema" in p["messages"][0]["content"]
    h = sent[0]["headers"]
    assert h["Authorization"] == "Bearer or-key"
    assert "HTTP-Referer" in h and "X-Title" in h


def test_openrouter_unwraps_markdown_fences(monkeypatch):
    _stub_http(monkeypatch, [_or_reply("```json\n" + json.dumps(ANALYSIS) + "\n```")])
    assert _client(gemini=False).structured("t", MESSAGES, LogAnalysis) is not None


def test_openrouter_retries_with_the_validation_error(monkeypatch):
    sent = _stub_http(monkeypatch, [
        _or_reply(json.dumps({"signal_id": "not-an-int"})),
        _or_reply(json.dumps(ANALYSIS)),
    ])
    assert _client(gemini=False).structured("t", MESSAGES, LogAnalysis) is not None
    retry = sent[1]["payload"]["messages"]
    assert any("did not validate" in m["content"] for m in retry if m["role"] == "user")
    assert sent[1]["payload"]["temperature"] > sent[0]["payload"]["temperature"]


def test_openrouter_tool_loop(monkeypatch):
    call = {"id": "call_1", "type": "function",
            "function": {"name": "fetch_log_window",
                         "arguments": json.dumps({"host": "web-01"})}}
    sent = _stub_http(monkeypatch, [
        _or_reply(None, tool_calls=[call]),
        _or_reply("done"),
        _or_reply(json.dumps({"incidents": []})),
    ])
    seen = []
    got, calls = _client(gemini=False).converse_with_tools(
        "inv", MESSAGES, [FETCH_TOOL],
        {"fetch_log_window": lambda **kw: seen.append(kw) or "3 events"},
        InvestigationResult,
    )
    assert isinstance(got, InvestigationResult)
    assert seen == [{"host": "web-01"}] and calls[0]["error"] is False
    convo = sent[1]["payload"]["messages"]
    assert [m for m in convo if m["role"] == "assistant"][0]["tool_calls"] == [call]
    tool_msgs = [m for m in convo if m["role"] == "tool"]
    assert tool_msgs[0]["tool_call_id"] == "call_1" and tool_msgs[0]["content"] == "3 events"


# ===========================================================================
# Gemini
# ===========================================================================


def test_gemini_structured_uses_google_wire_format(monkeypatch):
    sent = _stub_http(monkeypatch, [_gem_reply(json.dumps(ANALYSIS))])
    got = _client(openrouter=False).structured("t", MESSAGES, LogAnalysis, system="sys")

    assert isinstance(got, LogAnalysis) and got.signal_id == 7
    p = sent[0]["payload"]
    assert "gemini-2.5-flash:generateContent" in sent[0]["url"]
    assert sent[0]["headers"]["x-goog-api-key"] == "gem-key"
    assert p["contents"][0]["role"] == "user"
    assert p["contents"][0]["parts"][0]["text"] == "analyse"
    assert "JSON Schema" in p["systemInstruction"]["parts"][0]["text"]
    assert p["generationConfig"]["responseMimeType"] == "application/json"
    assert "responseSchema" not in p["generationConfig"], "Pydantic $refs would 400"


def test_gemini_maps_assistant_role_to_model(monkeypatch):
    sent = _stub_http(monkeypatch, [_gem_reply(json.dumps(ANALYSIS))])
    _client(openrouter=False).structured(
        "t", [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}],
        LogAnalysis,
    )
    assert [c["role"] for c in sent[0]["payload"]["contents"]] == ["user", "model"]


def test_gemini_retries_on_schema_miss(monkeypatch):
    sent = _stub_http(monkeypatch, [
        _gem_reply(json.dumps({"signal_id": "nope"})),
        _gem_reply(json.dumps(ANALYSIS)),
    ])
    assert _client(openrouter=False).structured("t", MESSAGES, LogAnalysis) is not None
    assert len(sent) == 2
    last = sent[1]["payload"]["contents"][-1]
    assert last["role"] == "user" and "did not validate" in last["parts"][0]["text"]


def test_gemini_blocked_prompt_is_reported(monkeypatch):
    _stub_http(monkeypatch, [{"candidates": [], "promptFeedback": {"blockReason": "SAFETY"}}])
    assert _client(openrouter=False).structured("t", MESSAGES, LogAnalysis) is None


def test_gemini_tool_loop(monkeypatch):
    sent = _stub_http(monkeypatch, [
        _gem_reply(function_calls=[{"name": "fetch_log_window", "args": {"host": "web-01"}}]),
        _gem_reply("no more tools needed"),
        _gem_reply(json.dumps({"incidents": []})),
    ])
    seen = []
    got, calls = _client(openrouter=False).converse_with_tools(
        "inv", MESSAGES, [FETCH_TOOL],
        {"fetch_log_window": lambda **kw: seen.append(kw) or "3 events"},
        InvestigationResult,
    )
    assert isinstance(got, InvestigationResult)
    assert seen == [{"host": "web-01"}] and calls[0]["tool"] == "fetch_log_window"

    decl = sent[0]["payload"]["tools"][0]["functionDeclarations"][0]
    assert decl["name"] == "fetch_log_window"
    assert "additionalProperties" not in decl["parameters"], "Gemini rejects it"
    assert "$defs" not in decl["parameters"]

    responses = sent[1]["payload"]["contents"][-1]["parts"]
    assert responses[0]["functionResponse"]["name"] == "fetch_log_window"
    assert responses[0]["functionResponse"]["response"]["result"] == "3 events"


def test_gemini_param_sanitiser_strips_unsupported_keys():
    out = _gemini_safe_params({
        "type": "object", "additionalProperties": False, "$defs": {"X": {}},
        "properties": {"host": {"type": "string", "title": "Host", "default": "x"}},
        "required": ["host"],
    })
    assert set(out) == {"type", "properties", "required"}
    assert set(out["properties"]["host"]) == {"type"}


# ===========================================================================
# The fallback chain — the behaviour that was asked for
# ===========================================================================


def test_gemini_takes_over_when_openrouter_errors(monkeypatch):
    def boom():
        raise RuntimeError("HTTP 429: rate limited")

    sent = _stub_http(monkeypatch, [boom, _gem_reply(json.dumps(ANALYSIS))])
    c = _client()
    got = c.structured("t", MESSAGES, LogAnalysis)

    assert isinstance(got, LogAnalysis), "the fallback must answer the same question"
    assert c.last_provider == "gemini"
    assert sent[0]["url"] == lc.OPENROUTER_URL
    assert "generativelanguage" in sent[1]["url"]


def test_gemini_takes_over_when_openrouter_never_validates(monkeypatch):
    bad = _or_reply(json.dumps({"signal_id": "nope"}))
    sent = _stub_http(monkeypatch,
                      [bad] * lc.MAX_JSON_ATTEMPTS + [_gem_reply(json.dumps(ANALYSIS))])
    c = _client()
    assert c.structured("t", MESSAGES, LogAnalysis) is not None
    assert c.last_provider == "gemini"
    assert len(sent) == lc.MAX_JSON_ATTEMPTS + 1


def test_openrouter_success_never_reaches_gemini(monkeypatch):
    sent = _stub_http(monkeypatch, [_or_reply(json.dumps(ANALYSIS))])
    c = _client()
    assert c.structured("t", MESSAGES, LogAnalysis) is not None
    assert c.last_provider == "openrouter"
    assert len(sent) == 1, "the fallback must not be called when the primary works"


def test_both_down_returns_none_not_an_exception(monkeypatch):
    def boom():
        raise RuntimeError("HTTP 500")

    _stub_http(monkeypatch, [boom, boom])
    assert _client().structured("t", MESSAGES, LogAnalysis) is None


def test_tool_loop_falls_back_too(monkeypatch):
    def boom():
        raise RuntimeError("HTTP 502")

    _stub_http(monkeypatch, [
        boom,
        _gem_reply(function_calls=[{"name": "fetch_log_window", "args": {"host": "w"}}]),
        _gem_reply("done"),
        _gem_reply(json.dumps({"incidents": []})),
    ])
    c = _client()
    got, calls = c.converse_with_tools(
        "inv", MESSAGES, [FETCH_TOOL],
        {"fetch_log_window": lambda **kw: "3 events"}, InvestigationResult,
    )
    assert got is not None and c.last_provider == "gemini"
    assert calls and calls[0]["tool"] == "fetch_log_window"


def test_tool_calls_from_a_failed_provider_are_still_surfaced(monkeypatch):
    """Evidence the primary pulled before dying should still show in the trace."""
    call = {"id": "c1", "type": "function",
            "function": {"name": "fetch_log_window", "arguments": "{}"}}

    def boom():
        raise RuntimeError("HTTP 500 mid-loop")

    _stub_http(monkeypatch, [_or_reply(None, tool_calls=[call]), boom, boom])
    c = _client(gemini=False)
    got, calls = c.converse_with_tools(
        "inv", MESSAGES, [FETCH_TOOL],
        {"fetch_log_window": lambda **kw: "3 events"}, InvestigationResult,
    )
    assert got is None
    assert calls and calls[0]["tool"] == "fetch_log_window"


def test_chain_order_is_openrouter_then_gemini(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "a")
    monkeypatch.setenv("GEMINI_API_KEY", "b")
    c = LLMClient()
    assert [p.name for p in c.chain] == ["openrouter", "gemini"]
    assert c.provider == "openrouter" and c.fallback_provider == "gemini"


def test_gemini_alone_is_a_valid_configuration(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "b")
    c = LLMClient()
    assert c.provider == "gemini" and c.fallback_provider == "" and c.available


def test_model_overrides_are_honoured(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "a")
    monkeypatch.setenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")
    monkeypatch.setenv("GEMINI_API_KEY", "b")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-pro")
    c = LLMClient()
    assert c.chain[0].model == "meta-llama/llama-3.3-70b-instruct"
    assert c.chain[1].model == "gemini-2.5-pro"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
