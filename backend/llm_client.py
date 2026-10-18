"""
SentinelSOC - the LLM seam.

Every engine imports from this module and nothing else touches a provider. That
is the whole point of the seam: this file has now been rewritten twice (Groq ->
OpenRouter -> OpenRouter + Gemini) without a single change anywhere else.

Provider chain, tried in order:
  1. Gemini      (primary)   GEMINI_API_KEY
  2. OpenRouter  (fallback)  OPENROUTER_API_KEY
  3. offline                 deterministic fallbacks in the agents themselves

Gemini leads because it is measurably faster here: an OpenRouter free-tier call
was timed at 55s and was intermittently 429-ing on the shared pool, while Gemini
answered in well under a second. OpenRouter stays as fallback for its breadth of
models.

The chain is a RUNTIME fallback, not just config precedence. If the primary is
down, rate-limited, or handed a bad model slug, the same call is retried against
Gemini before anything gives up. Only when every configured provider fails does
a call return None - and the agents handle None with deterministic logic, which
is what keeps a dead network from ending the demo.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

# ---------------------------------------------------------------------------
# Endpoints and defaults
# ---------------------------------------------------------------------------

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
# Free tier by default - a hackathon should not need a credit card. Picked for
# supporting BOTH tool calling and JSON mode, which Agent 2's evidence loop needs;
# `scripts/check_providers.py --free` lists the alternatives. Paid slugs
# (anthropic/*, openai/*, google/gemini-*) work by just setting OPENROUTER_MODEL.
DEFAULT_OPENROUTER_MODEL = "google/gemma-4-26b-a4b-it:free"

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"

# OpenRouter attributes traffic to an app via these; harmless if unset.
OPENROUTER_REFERER = os.getenv("OPENROUTER_REFERER", "https://github.com/sih26-s01")
OPENROUTER_TITLE = os.getenv("OPENROUTER_TITLE", "SentinelSOC")

_CACHE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "demo_run.json"

MAX_JSON_ATTEMPTS = 3
HTTP_TIMEOUT = 90


def _log(msg: str, *args: Any) -> None:
    print(f"[llm] {msg % args if args else msg}", flush=True)


def _post_json(url: str, payload: dict, headers: dict, timeout: int = HTTP_TIMEOUT) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:500]
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc


def _strip_fences(text: str) -> str:
    """Smaller models wrap JSON in markdown no matter how firmly you ask them not to."""
    text = text.strip()
    if not text.startswith("```"):
        return text
    body = text[3:]
    if "```" in body:
        body = body.split("```")[0]
    return body.removeprefix("json").strip()


def _schema_instruction(schema: Type[BaseModel]) -> str:
    return (
        "Respond with a single JSON object and nothing else - no prose, no "
        "markdown fences. It must satisfy this JSON Schema:\n"
        + json.dumps(schema.model_json_schema())
    )


def _gemini_safe_params(js: dict) -> dict:
    """
    Gemini's function-declaration schema is an OpenAPI subset: no $ref, no $defs,
    no additionalProperties. Keep only what it accepts rather than let it 400.
    """
    allowed = {"type", "description", "enum", "properties", "required", "items", "nullable"}
    if not isinstance(js, dict):
        return {}
    out = {k: v for k, v in js.items() if k in allowed}
    if "properties" in out and isinstance(out["properties"], dict):
        out["properties"] = {
            k: _gemini_safe_params(v) for k, v in out["properties"].items()
        }
    if "items" in out and isinstance(out["items"], dict):
        out["items"] = _gemini_safe_params(out["items"])
    return out


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


class ProviderError(RuntimeError):
    """A provider failed in a way the chain should fall through on."""


class BaseProvider:
    name = "base"

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    def structured(self, messages, schema, system, max_tokens):  # pragma: no cover
        raise NotImplementedError

    def tools(self, messages, tools, tool_impls, schema, system, max_turns,
              run_tool, calls):
        raise NotImplementedError  # pragma: no cover


class OpenRouterProvider(BaseProvider):
    """
    Primary. OpenAI-compatible, fronts many vendors behind one endpoint.

    Uses JSON mode with the schema in the system prompt rather than strict
    `json_schema` response_format: support for the latter is uneven across the
    vendors OpenRouter routes to, while `json_object` is near-universal. A schema
    miss is re-prompted with the validation error.
    """

    name = "openrouter"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": OPENROUTER_REFERER,
            "X-Title": OPENROUTER_TITLE,
        }

    def structured(self, messages, schema, system, max_tokens):
        instruction = _schema_instruction(schema)
        sys_prompt = f"{system}\n\n{instruction}" if system else instruction
        convo = [{"role": "system", "content": sys_prompt}] + list(messages)

        last_error = ""
        for attempt in range(MAX_JSON_ATTEMPTS):
            data = _post_json(
                OPENROUTER_URL,
                {
                    "model": self.model,
                    "messages": convo,
                    "temperature": 0.1 if attempt == 0 else 0.35,
                    "max_tokens": max_tokens,
                    "response_format": {"type": "json_object"},
                },
                self._headers(),
            )
            choices = data.get("choices") or []
            if not choices:
                raise ProviderError(f"no choices in response: {str(data)[:300]}")

            text = _strip_fences((choices[0].get("message") or {}).get("content") or "")
            try:
                return schema.model_validate_json(text)
            except ValidationError as exc:
                last_error = str(exc)[:800]
                _log("openrouter attempt %d invalid; retrying", attempt + 1)
                convo = convo + [
                    {"role": "assistant", "content": text[:4000]},
                    {"role": "user", "content":
                        f"That did not validate against the schema:\n{last_error}\n\n"
                        "Return corrected JSON only."},
                ]
        raise ProviderError(f"schema validation failed after {MAX_JSON_ATTEMPTS}: {last_error}")

    def tools(self, messages, tools, tool_impls, schema, system, max_turns,
              run_tool, calls):
        """
        OpenAI-compatible tool calling.

        Two shape rules matter: the assistant turn must be echoed back with its
        tool_calls intact, and each result is its own message keyed by
        tool_call_id.

        `calls` is owned by the caller and appended to as we go, so evidence this
        provider pulled before failing still reaches the trace.
        """
        convo: list[dict] = []
        if system:
            convo.append({"role": "system", "content": system})
        convo += list(messages)

        oai_tools = [
            {"type": "function",
             "function": {"name": t["name"], "description": t.get("description", ""),
                          "parameters": t.get("input_schema", {"type": "object", "properties": {}})}}
            for t in tools
        ]

        for turn in range(max_turns):
            payload: dict[str, Any] = {
                "model": self.model, "messages": convo,
                "max_tokens": 16000, "temperature": 0.2,
            }
            if oai_tools:
                payload["tools"] = oai_tools
                payload["tool_choice"] = "auto"

            data = _post_json(OPENROUTER_URL, payload, self._headers())
            choices = data.get("choices") or []
            if not choices:
                raise ProviderError(f"no choices in response: {str(data)[:300]}")

            message = choices[0].get("message") or {}
            tool_calls = message.get("tool_calls") or []
            convo.append({
                "role": "assistant",
                "content": message.get("content") or "",
                **({"tool_calls": tool_calls} if tool_calls else {}),
            })
            if not tool_calls:
                break

            for call in tool_calls:
                fn = call.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                out, _ = run_tool(fn.get("name", ""), args, tool_impls, turn, calls)
                convo.append({"role": "tool", "tool_call_id": call.get("id", ""),
                              "content": out})

        body = convo[1:] if system else convo
        return self.structured(body, schema, system, 16000)


class GeminiProvider(BaseProvider):
    """
    Fallback. Google Generative Language API.

    Not the OpenAI shape: roles are user/model, content is `parts`, the system
    prompt is `systemInstruction`, and tool results come back as
    `functionResponse` parts. Uses responseMimeType=application/json with the
    schema in the prompt rather than `responseSchema`, because responseSchema
    rejects the $ref/$defs that Pydantic emits for nested models.
    """

    name = "gemini"

    def _url(self, method: str = "generateContent") -> str:
        return f"{GEMINI_BASE}/models/{self.model}:{method}"

    def _headers(self) -> dict:
        return {"Content-Type": "application/json", "x-goog-api-key": self.api_key}

    @staticmethod
    def _to_contents(messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role = "model" if m.get("role") == "assistant" else "user"
            content = m.get("content")
            if isinstance(content, str):
                out.append({"role": role, "parts": [{"text": content}]})
            elif isinstance(content, list):
                out.append({"role": role, "parts": content})
        return out

    @staticmethod
    def _text_of(candidate: dict) -> str:
        parts = (candidate.get("content") or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts)

    def structured(self, messages, schema, system, max_tokens):
        instruction = _schema_instruction(schema)
        sys_prompt = f"{system}\n\n{instruction}" if system else instruction
        contents = self._to_contents(messages)

        last_error = ""
        for attempt in range(MAX_JSON_ATTEMPTS):
            data = _post_json(
                self._url(),
                {
                    "contents": contents,
                    "systemInstruction": {"parts": [{"text": sys_prompt}]},
                    "generationConfig": {
                        "temperature": 0.1 if attempt == 0 else 0.35,
                        "maxOutputTokens": max_tokens,
                        "responseMimeType": "application/json",
                    },
                },
                self._headers(),
            )
            candidates = data.get("candidates") or []
            if not candidates:
                blocked = (data.get("promptFeedback") or {}).get("blockReason")
                raise ProviderError(f"no candidates{f' (blocked: {blocked})' if blocked else ''}")

            text = _strip_fences(self._text_of(candidates[0]))
            try:
                return schema.model_validate_json(text)
            except ValidationError as exc:
                last_error = str(exc)[:800]
                _log("gemini attempt %d invalid; retrying", attempt + 1)
                contents = contents + [
                    {"role": "model", "parts": [{"text": text[:4000]}]},
                    {"role": "user", "parts": [{"text":
                        f"That did not validate against the schema:\n{last_error}\n\n"
                        "Return corrected JSON only."}]},
                ]
        raise ProviderError(f"schema validation failed after {MAX_JSON_ATTEMPTS}: {last_error}")

    def tools(self, messages, tools, tool_impls, schema, system, max_turns,
              run_tool, calls):
        contents = self._to_contents(messages)
        declarations = [
            {"name": t["name"], "description": t.get("description", ""),
             "parameters": _gemini_safe_params(
                 t.get("input_schema", {"type": "object", "properties": {}}))}
            for t in tools
        ]

        for turn in range(max_turns):
            payload: dict[str, Any] = {
                "contents": contents,
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 16000},
            }
            if system:
                payload["systemInstruction"] = {"parts": [{"text": system}]}
            if declarations:
                payload["tools"] = [{"functionDeclarations": declarations}]

            data = _post_json(self._url(), payload, self._headers())
            candidates = data.get("candidates") or []
            if not candidates:
                raise ProviderError("no candidates in tool response")

            parts = (candidates[0].get("content") or {}).get("parts") or []
            fn_calls = [p["functionCall"] for p in parts if "functionCall" in p]

            contents.append({"role": "model", "parts": parts})
            if not fn_calls:
                break

            responses = []
            for fc in fn_calls:
                args = fc.get("args") or {}
                out, _ = run_tool(fc.get("name", ""), args, tool_impls, turn, calls)
                responses.append({
                    "functionResponse": {
                        "name": fc.get("name", ""),
                        "response": {"result": out},
                    }
                })
            contents.append({"role": "user", "parts": responses})

        text_msgs = [
            {"role": "model" if c["role"] == "model" else "user",
             "content": "".join(p.get("text", "") for p in c["parts"])}
            for c in contents
            if any("text" in p for p in c["parts"])
        ]
        return self.structured(text_msgs or messages, schema, system, 16000)


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


class LLMClient:
    """Provider-agnostic front door. Construct once, share it."""

    def __init__(self, record: bool = False, replay: bool = False) -> None:
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY")
        self.gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.replay = replay or os.getenv("DEMO_MODE") == "cached"
        self.record = record and not self.replay
        self._recorded: dict[str, Any] = {}
        self._cache: dict[str, Any] = {}
        self.last_provider: str = ""

        if self.replay and _CACHE_PATH.exists():
            try:
                self._cache = json.loads(_CACHE_PATH.read_text())
                _log("replaying %d cached responses", len(self._cache))
            except (OSError, json.JSONDecodeError) as exc:
                _log("cache unreadable (%s); continuing live", exc)
                self.replay = False

        self.chain: list[BaseProvider] = []
        if self.openrouter_key:
            self.chain.append(OpenRouterProvider(
                self.openrouter_key,
                os.getenv("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL),
            ))
        if self.gemini_key:
            self.chain.append(GeminiProvider(
                self.gemini_key,
                os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
            ))

        if not self.replay:
            if self.chain:
                _log("provider chain: %s", " -> ".join(
                    f"{p.name}({p.model})" for p in self.chain))
            else:
                _log("no provider configured; deterministic fallbacks only")

    # -- introspection used by /api/health and the CLI ---------------------

    @property
    def provider(self) -> str:
        return self.chain[0].name if self.chain else "offline"

    @property
    def model(self) -> str:
        return self.chain[0].model if self.chain else "offline"

    @property
    def fallback_provider(self) -> str:
        return self.chain[1].name if len(self.chain) > 1 else ""

    @property
    def available(self) -> bool:
        return bool(self.chain) or bool(self._cache)

    # -- cache -------------------------------------------------------------

    @staticmethod
    def _key(tag: str, messages: list[dict], schema: Optional[type]) -> str:
        blob = json.dumps(
            {"tag": tag, "messages": messages, "schema": schema.__name__ if schema else None},
            sort_keys=True, default=str,
        )
        return f"{tag}:{hashlib.sha256(blob.encode()).hexdigest()[:16]}"

    def save_cache(self) -> None:
        """Write the recorded run so DEMO_MODE=cached can replay it."""
        if not self._recorded:
            return
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing: dict[str, Any] = {}
        if _CACHE_PATH.exists():
            try:
                existing = json.loads(_CACHE_PATH.read_text())
            except (OSError, json.JSONDecodeError):
                existing = {}
        existing.update(self._recorded)
        _CACHE_PATH.write_text(json.dumps(existing, indent=2, default=str))
        _log("recorded %d responses -> %s", len(self._recorded), _CACHE_PATH.name)

    # -- the chain ---------------------------------------------------------

    def _attempt(self, tag: str, call: Callable[[BaseProvider], Any]) -> Any:
        """
        Walk the provider chain until one succeeds.

        A provider that raises for any reason - network, 401, 429, bad slug,
        unparseable output - is stepped over rather than allowed to end the run.
        """
        for index, provider in enumerate(self.chain):
            started = time.monotonic()
            try:
                result = call(provider)
            except Exception as exc:
                nxt = self.chain[index + 1].name if index + 1 < len(self.chain) else "none"
                _log("%s: %s failed (%s: %s); falling back to %s",
                     tag, provider.name, type(exc).__name__, str(exc)[:160], nxt)
                continue
            if result is None:
                continue
            self.last_provider = provider.name
            _log("%s ok via %s in %dms", tag, provider.name,
                 int((time.monotonic() - started) * 1000))
            return result
        return None

    # -- public API --------------------------------------------------------

    def structured(
        self,
        tag: str,
        messages: list[dict],
        schema: Type[T],
        system: str | None = None,
        effort: str = "high",          # accepted for call-site compatibility
        max_tokens: int = 16000,
    ) -> Optional[T]:
        """
        Ask for one schema-valid object.

        Returns a validated instance, or None when every configured provider
        failed. Never raises - callers fall back to deterministic logic.
        """
        key = self._key(tag, messages, schema)

        if self.replay and key in self._cache:
            try:
                return schema.model_validate(self._cache[key])
            except ValidationError as exc:
                _log("cached payload for %s no longer matches schema: %s", tag, exc)
                return None

        if not self.chain:
            return None

        obj = self._attempt(
            tag, lambda p: p.structured(messages, schema, system, max_tokens)
        )
        if obj is None:
            _log("%s: every provider failed; using deterministic fallback", tag)
            return None

        if self.record:
            self._recorded[key] = obj.model_dump(mode="json")
        return obj

    def _run_tool(
        self, name: str, args: dict, tool_impls: dict[str, Any], turn: int, calls: list[dict]
    ) -> tuple[str, bool]:
        fn = tool_impls.get(name)
        if fn is None:
            out, is_err = f"No such tool: {name}", True
        else:
            try:
                out, is_err = fn(**args), False
            except Exception as exc:
                out, is_err = f"{type(exc).__name__}: {exc}", True
        calls.append({"turn": turn, "tool": name, "input": args,
                      "output": str(out)[:4000], "error": is_err})
        return str(out)[:20000], is_err

    def converse_with_tools(
        self,
        tag: str,
        messages: list[dict],
        tools: list[dict],
        tool_impls: dict[str, Any],
        schema: Type[T],
        system: str | None = None,
        max_turns: int = 6,
        effort: str = "high",
    ) -> tuple[Optional[T], list[dict]]:
        """
        Run a tool-use loop, then structure the outcome.

        The agent decides when it needs more evidence; every call it makes is
        returned alongside the result so the UI can show the trace. Both
        providers support this - the wire shapes differ, the behaviour does not.
        """
        key = self._key(tag, messages, schema)

        if self.replay and key in self._cache:
            entry = self._cache[key]
            try:
                return schema.model_validate(entry["result"]), entry.get("tool_calls", [])
            except (ValidationError, KeyError, TypeError) as exc:
                _log("cached tool run for %s unusable: %s", tag, exc)
                return None, []

        if not self.chain:
            return None, []

        # Owned here, not by the provider: a provider that dies mid-loop has
        # already spent real tool calls, and the trace should still show them.
        captured: list[dict] = []

        obj = self._attempt(
            tag,
            lambda p: p.tools(messages, tools, tool_impls, schema, system,
                              max_turns, self._run_tool, captured),
        )
        if obj is None:
            _log("%s: every provider failed; using deterministic fallback", tag)
            return None, captured

        if self.record:
            self._recorded[key] = {
                "result": obj.model_dump(mode="json"),
                "tool_calls": captured,
            }
        return obj, captured


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def list_openrouter_models(filter_text: str = "", limit: int = 40) -> list[dict]:
    """Fetch the live OpenRouter catalogue. Slugs rot; look them up."""
    key = os.getenv("OPENROUTER_API_KEY")
    req = urllib.request.Request(
        OPENROUTER_MODELS_URL,
        headers={"Authorization": f"Bearer {key}"} if key else {},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    models = data.get("data", [])
    if filter_text:
        needle = filter_text.lower()
        models = [m for m in models if needle in m.get("id", "").lower()]
    models.sort(key=lambda m: m.get("id", ""))
    return models[:limit]


def list_gemini_models(filter_text: str = "", limit: int = 40) -> list[dict]:
    """Fetch the Gemini catalogue. Requires a key - Google does not expose it publicly."""
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set; Google requires a key to list models")
    req = urllib.request.Request(
        f"{GEMINI_BASE}/models", headers={"x-goog-api-key": key}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    models = [
        m for m in data.get("models", [])
        if "generateContent" in (m.get("supportedGenerationMethods") or [])
    ]
    if filter_text:
        needle = filter_text.lower()
        models = [m for m in models if needle in m.get("name", "").lower()]
    models.sort(key=lambda m: m.get("name", ""))
    return models[:limit]


_shared: Optional[LLMClient] = None


def get_client() -> LLMClient:
    global _shared
    if _shared is None:
        _shared = LLMClient(record=os.getenv("RECORD_DEMO") == "1")
    return _shared
