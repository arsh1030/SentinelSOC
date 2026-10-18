"""
Verify provider keys and find valid model slugs.

Slugs change and vendors come and go, so look the catalogue up rather than trust
a hard-coded name. A wrong slug is a 404 you would otherwise debug at hour four.

    python scripts/check_providers.py              # check both configured models
    python scripts/check_providers.py --free      # list usable FREE models
    python scripts/check_providers.py openrouter llama    # browse OpenRouter
    python scripts/check_providers.py gemini              # browse Gemini
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from llm_client import (  # noqa: E402
    DEFAULT_GEMINI_MODEL, DEFAULT_OPENROUTER_MODEL,
    list_gemini_models, list_openrouter_models,
)


def _free_models() -> int:
    """List free OpenRouter models that can actually drive this pipeline."""
    try:
        every = list_openrouter_models("", limit=10_000)
    except Exception as exc:
        print(f"  could not reach OpenRouter: {type(exc).__name__}: {exc}")
        return 1

    free = [
        m for m in every
        if float((m.get("pricing") or {}).get("prompt") or 1) == 0
        and float((m.get("pricing") or {}).get("completion") or 1) == 0
    ]
    usable, partial = [], []
    for m in free:
        sp = set(m.get("supported_parameters") or [])
        has_tools = "tools" in sp
        has_json = "response_format" in sp or "structured_outputs" in sp
        (usable if (has_tools and has_json) else partial).append((m, has_tools, has_json))

    usable.sort(key=lambda t: -(t[0].get("context_length") or 0))
    print(f"  {len(free)} free models; {len(usable)} support both tool calling")
    print("  and JSON mode, which Agent 2's evidence loop needs.\n")
    print(f"  {'slug':48s} {'context':>10s}")
    print("  " + "-" * 60)
    for m, _, _ in usable:
        print(f"  {m['id']:48s} {m.get('context_length') or 0:>9,}")

    if partial:
        print(f"\n  {len(partial)} more are free but miss tools or JSON mode -")
        print("  usable, but Agent 2 falls back to reasoning without evidence pulls.")

    print("\n  Free tiers are rate-limited (commonly ~20 req/min and a daily cap).")
    print("  One full pipeline run is about 17 calls. Record a cached run early:")
    print("      RECORD_DEMO=1 python scripts/run_pipeline.py --reset")
    return 0


def _openrouter(needle: str) -> int:
    configured = os.getenv("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL)
    if not os.getenv("OPENROUTER_API_KEY"):
        print("  OPENROUTER_API_KEY not set (catalogue is public; calls will 401)")
    try:
        every = {m["id"] for m in list_openrouter_models("", limit=10_000)}
    except Exception as exc:
        print(f"  could not reach OpenRouter: {type(exc).__name__}: {exc}")
        return 1

    ok = configured in every
    print(f"  configured : {configured}")
    print(f"  exists     : {'yes' if ok else 'NO'}")
    if not ok:
        stem = configured.split("/")[0]
        near = sorted(i for i in every if i.startswith(stem))[:10]
        if near:
            print("  did you mean:")
            for i in near:
                print(f"    {i}")

    if needle:
        print()
        for m in list_openrouter_models(needle, limit=30):
            ctx = m.get("context_length") or 0
            price = (m.get("pricing") or {}).get("prompt", "?")
            print(f"    {m['id']:56s} ctx={ctx:>9,}  in=${price}/tok")
    return 0 if ok else 1


def _gemini(needle: str) -> int:
    configured = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    print(f"  configured : {configured}")
    if not (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")):
        print("  GEMINI_API_KEY not set - Google requires a key to list models,")
        print("  so the slug cannot be verified from here. Get one at")
        print("  https://aistudio.google.com/apikey")
        return 1
    try:
        models = list_gemini_models("", limit=500)
    except Exception as exc:
        print(f"  could not reach Gemini: {type(exc).__name__}: {exc}")
        return 1

    names = {m["name"].removeprefix("models/") for m in models}
    ok = configured in names
    print(f"  exists     : {'yes' if ok else 'NO'}")
    if not ok:
        print("  available:")
        for n in sorted(names)[:15]:
            print(f"    {n}")
    if needle:
        print()
        for m in list_gemini_models(needle, limit=30):
            print(f"    {m['name'].removeprefix('models/'):44s} "
                  f"in={m.get('inputTokenLimit', '?')}")
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if "--free" in args:
        print("Free OpenRouter models\n")
        return _free_models()
    args = [a for a in args if not a.startswith("--")]
    which = args[0].lower() if args and args[0].lower() in ("openrouter", "gemini") else ""
    needle = args[1] if which and len(args) > 1 else (args[0] if args and not which else "")

    rc = 0
    if which in ("", "openrouter"):
        print("OpenRouter (primary)")
        rc |= _openrouter(needle if which == "openrouter" else "")
        print()
    if which in ("", "gemini"):
        print("Gemini (fallback)")
        rc |= _gemini(needle if which == "gemini" else "")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
