"""
SentinelSOC - agent orchestration.

Plain Python, deliberately. DataSentinel's detection.py threads a PipelineContext
through ordered stages; this is the same shape with three agent stages appended.
No LangGraph, no CrewAI - a framework nobody on the team has debugged before is
not something to introduce with hours on the clock.

Every hop is persisted to agent_runs before the next one starts. That table is
what the trace panel renders, and it is the evidence that two specialised agents
actually collaborated rather than one prompt doing everything.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import store
from llm_client import LLMClient, get_client
from redaction import Redactor
from schemas import (
    AgentRun,
    Incident,
    InvestigationResult,
    LogAnalysis,
    ResponsePlan,
    Signal,
)

from .log_analysis import analyse_signal
from .response import plan_response
from .threat_investigation import investigate

MAX_SIGNALS_TO_ANALYSE = 25


@dataclass
class Context:
    """Threaded through every stage. Mutated in place, never rebuilt."""

    session_id: str
    client: LLMClient
    redactor: Redactor = field(default_factory=Redactor)
    signals: list[Signal] = field(default_factory=list)
    analyses: dict[int, LogAnalysis] = field(default_factory=dict)
    investigation: InvestigationResult | None = None
    plans: list[ResponsePlan] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    used_model: dict[str, bool] = field(default_factory=dict)
    stage_timings: dict[str, int] = field(default_factory=dict)
    on_hop: Callable[[str, int, dict[str, Any]], None] | None = None


def _record(
    ctx: Context,
    agent: str,
    stage_index: int,
    input_summary: str,
    payload,
    latency_ms: int,
    tool_calls: list[dict] | None = None,
    ok: bool = True,
    error: str = "",
) -> None:
    store.insert_run(
        AgentRun(
            session_id=ctx.session_id,
            agent=agent,  # type: ignore[arg-type]
            stage_index=stage_index,
            input_summary=input_summary,
            output_json=payload.model_dump_json() if hasattr(payload, "model_dump_json") else str(payload),
            tool_calls=tool_calls or [],
            model=ctx.client.model,
            latency_ms=latency_ms,
            ok=ok,
            error=error,
            created_at=datetime.now(timezone.utc),
        )
    )
    if ctx.on_hop:
        ctx.on_hop(agent, stage_index, {
            "agent": agent,
            "stage_index": stage_index,
            "input_summary": input_summary,
            "latency_ms": latency_ms,
            "ok": ok,
            "error": error,
        })


# ---------------------------------------------------------------------------
# Stage 1 - Log Analysis Agent, once per signal
# ---------------------------------------------------------------------------


def stage_analyse(ctx: Context) -> Context:
    started = time.monotonic()
    used_any = False

    # One pass over the corpus, not one per signal: this is what every window's
    # deviation is measured against, so it must be the same for all of them.
    from .log_analysis import compute_baseline

    baseline = compute_baseline(ctx.session_id)
    if baseline:
        print(f"[orchestrator] baseline over {len(baseline)} features")

    for signal in ctx.signals[:MAX_SIGNALS_TO_ANALYSE]:
        t0 = time.monotonic()
        evidence = store.get_events(ctx.session_id, signal.event_ids[:60])
        try:
            analysis, used = analyse_signal(
                ctx.client, signal, evidence, ctx.redactor, baseline
            )
            err = ""
        except Exception as exc:
            from .log_analysis import _fallback

            analysis, used, err = _fallback(signal, evidence), False, f"{type(exc).__name__}: {exc}"

        used_any = used_any or used
        ctx.analyses[signal.signal_id] = analysis
        store.attach_analysis(signal.signal_id, analysis.model_dump_json())
        _record(
            ctx,
            "log_analysis",
            1,
            f"signal {signal.signal_id} ({signal.rule_id}) - {len(evidence)} events",
            analysis,
            int((time.monotonic() - t0) * 1000),
            ok=not err,
            error=err,
        )

    ctx.used_model["log_analysis"] = used_any
    ctx.stage_timings["log_analysis"] = int((time.monotonic() - started) * 1000)
    print(f"[orchestrator] stage 1: analysed {len(ctx.analyses)} signals "
          f"({'model' if used_any else 'deterministic fallback'})")
    return ctx


# ---------------------------------------------------------------------------
# Stage 2 - Threat Investigation Agent, once for all signals together
# ---------------------------------------------------------------------------


def stage_investigate(ctx: Context) -> Context:
    t0 = time.monotonic()
    try:
        result, calls, used = investigate(
            ctx.client, ctx.session_id, ctx.signals[:MAX_SIGNALS_TO_ANALYSE],
            ctx.analyses, ctx.redactor,
        )
        err = ""
    except Exception as exc:
        from .threat_investigation import _fallback

        result = _fallback(
            ctx.signals[:MAX_SIGNALS_TO_ANALYSE], ctx.analyses, ctx.session_id
        )
        calls, used, err = [], False, f"{type(exc).__name__}: {exc}"

    latency = int((time.monotonic() - t0) * 1000)
    ctx.investigation = result
    ctx.tool_calls = calls
    ctx.used_model["threat_investigation"] = used

    for inc in result.incidents:
        store.insert_incident(ctx.session_id, inc)
        if ctx.on_hop:
            ctx.on_hop("incident", 2, {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "risk_score": inc.risk_score,
                "severity": inc.severity,
                "signal_ids": inc.signal_ids,
            })

    _record(
        ctx,
        "threat_investigation",
        2,
        f"{len(ctx.signals)} signals, {len(ctx.analyses)} analyses",
        result,
        latency,
        tool_calls=calls,
        ok=not err,
        error=err,
    )
    ctx.stage_timings["threat_investigation"] = latency
    print(f"[orchestrator] stage 2: {len(ctx.signals)} signals -> "
          f"{len(result.incidents)} incidents, {len(calls)} tool call(s) "
          f"({'model' if used else 'deterministic fallback'})")
    return ctx


# ---------------------------------------------------------------------------
# Stage 3 - Response Agent, once per incident
# ---------------------------------------------------------------------------


def stage_respond(ctx: Context) -> Context:
    started = time.monotonic()
    used_any = False
    incidents: list[Incident] = ctx.investigation.incidents if ctx.investigation else []

    for inc in incidents:
        t0 = time.monotonic()
        try:
            plan, used = plan_response(ctx.client, inc, ctx.redactor)
            err = ""
        except Exception as exc:
            from .response import _fallback

            plan, used, err = _fallback(inc), False, f"{type(exc).__name__}: {exc}"

        used_any = used_any or used
        ctx.plans.append(plan)
        store.insert_plan(ctx.session_id, plan)
        _record(
            ctx,
            "response",
            3,
            f"incident {inc.incident_id} (risk {inc.risk_score})",
            plan,
            int((time.monotonic() - t0) * 1000),
            ok=not err,
            error=err,
        )

    ctx.used_model["response"] = used_any
    ctx.stage_timings["response"] = int((time.monotonic() - started) * 1000)
    print(f"[orchestrator] stage 3: {len(ctx.plans)} response plans "
          f"({'model' if used_any else 'deterministic fallback'})")
    return ctx


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_investigation(
    session_id: str, client: LLMClient | None = None,
    on_hop: Callable[[str, int, dict[str, Any]], None] | None = None,
) -> Context:
    """Run all three agents over a session's open signals."""
    signal_rows = store.get_signals(session_id)
    signals = [
        Signal(
            signal_id=r["signal_id"],
            detector=r["detector"],
            rule_id=r["rule_id"],
            title=r["title"],
            severity=r["severity"],
            ts_start=datetime.fromisoformat(r["ts_start"]),
            ts_end=datetime.fromisoformat(r["ts_end"]),
            host=r["host"],
            entity=r["entity"],
            entity_kind=r["entity_kind"],
            score=r["score"],
            event_ids=r["event_ids"],
            evidence_sample=r["evidence_sample"],
            detail=r["detail"],
        )
        for r in signal_rows
    ]

    ctx = Context(
        session_id=session_id,
        client=client or get_client(),
        signals=signals,
        on_hop=on_hop,
    )
    store.update_session(session_id, status="investigating")
    if ctx.redactor.enabled:
        print(f"[orchestrator] redaction mode: {ctx.redactor.mode}")

    ctx = stage_analyse(ctx)
    ctx = stage_investigate(ctx)
    ctx = stage_respond(ctx)

    store.update_session(
        session_id,
        status="complete",
        incident_count=len(ctx.investigation.incidents) if ctx.investigation else 0,
    )
    if ctx.redactor.enabled:
        print(f"[orchestrator] pseudonymised for egress: {ctx.redactor.summary()}")
    if ctx.client.record:
        ctx.client.save_cache()
    return ctx
