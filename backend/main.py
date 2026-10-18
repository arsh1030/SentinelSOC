"""
SentinelSOC - HTTP API.

FastAPI, no database server, no broker. Route layout follows DataSentinel's
session-scoped shape so its frontend maps across with renames rather than a
rewrite.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

import feedback  # noqa: E402
import query as query_engine  # noqa: E402
import report  # noqa: E402
from redaction import Redactor  # noqa: E402
import store  # noqa: E402
from agents import run_investigation  # noqa: E402
from ingest.parsers import PARSERS  # noqa: E402
from llm_client import get_client  # noqa: E402
from service import ingest_directory, ingest_files  # noqa: E402
from detect.pipeline import detect_all  # noqa: E402
from sse import SSEChannel, event_stream  # noqa: E402
import injector  # noqa: E402

SAMPLES = ROOT / "data" / "samples"

# Make scripts importable so we can call generate_logs.main(seed=None)
_scripts = str(ROOT / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

app = FastAPI(
    title="SentinelSOC API",
    version="1.0.0",
    description="Agentic AI cybersecurity assistant - SIH26-S01",
    docs_url="/api/docs",
)

# A hardcoded port list breaks the moment the dev server picks a different one -
# which it does whenever 3000 is already taken. Default to any localhost origin,
# and let CORS_ORIGINS pin it down for a real deployment.
_origins = os.getenv("CORS_ORIGINS")
if _origins:
    _cors = {"allow_origins": [o.strip() for o in _origins.split(",") if o.strip()]}
else:
    _cors = {"allow_origin_regex": r"https?://(localhost|127\.0\.0\.1)(:\d+)?"}

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    **_cors,
)


@app.on_event("startup")
def _startup() -> None:
    store.init_db()
    client = get_client()
    chain = " -> ".join(f"{p.name}({p.model})" for p in client.chain) or "offline"
    print(f"[api] ready - provider chain: {chain}")


def _require_session(session_id: str) -> dict:
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, f"No such session: {session_id}")
    return session


# ---------------------------------------------------------------------------
# Health & metadata
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    client = get_client()
    return {
        "status": "healthy",
        "llm_provider": client.provider,
        "llm_model": client.model,
        "llm_fallback": client.fallback_provider or None,
        "llm_chain": [{"provider": p.name, "model": p.model} for p in client.chain],
        "llm_available": client.available,
        "last_provider_used": client.last_provider or None,
        "replay_mode": client.replay,
        "redaction_mode": Redactor().mode,
        "supported_sources": sorted(PARSERS),
        "samples_present": SAMPLES.exists() and any(SAMPLES.iterdir()),
    }


@app.get("/api/sessions")
def sessions(limit: int = Query(50, ge=1, le=200)) -> list[dict]:
    return store.list_sessions(limit)


@app.get("/api/session/{session_id}")
def session_detail(session_id: str) -> dict:
    session = _require_session(session_id)
    return {
        **session,
        "signals": len(store.get_signals(session_id)),
        "logic_rules": len(store.get_logic_rules(session_id)),
        "incidents": len(store.get_incidents(session_id)),
        "agent_runs": len(store.get_runs(session_id)),
    }


@app.delete("/api/session/{session_id}")
def delete_session(session_id: str) -> dict:
    _require_session(session_id)
    store.delete_session(session_id)
    return {"deleted": session_id}


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


@app.post("/api/ingest/samples")
def ingest_samples() -> dict:
    if not SAMPLES.exists():
        raise HTTPException(
            400,
            "No sample logs found. Run: python scripts/generate_logs.py",
        )
    return ingest_directory(SAMPLES, label="bundled sample logs", client=get_client())


@app.post("/api/upload")
async def upload(files: list[UploadFile] = File(...)) -> dict:
    """
    Accepts one or more raw log files. Known formats get specialised parsing, 
    unknown formats fall back to generic regex parsing.
    """
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-upload-"))
    try:
        paths = []
        for upload_file in files:
            dest = tmp / Path(upload_file.filename).name
            with dest.open("wb") as fh:
                shutil.copyfileobj(upload_file.file, fh)
            paths.append(dest)
        return ingest_files(paths, label=f"upload ({len(paths)} files)", client=get_client())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Streaming endpoints (SSE)
# ---------------------------------------------------------------------------


@app.post("/api/run/stream")
async def run_stream() -> StreamingResponse:
    """
    Full pipeline: ingest bundled samples → detect → investigate, streamed as
    Server-Sent Events.  The pipeline runs in a background thread; each
    milestone pushes an event to the SSE channel.

    Event types: ingest_progress, signal, agent_hop, incident, complete, error.
    """
    if not SAMPLES.exists():
        raise HTTPException(
            400,
            "No sample logs found. Run: python scripts/generate_logs.py",
        )

    loop = asyncio.get_event_loop()
    channel = SSEChannel(loop)

    def _worker() -> None:
        try:
            # Regenerate logs with a random seed into a temp dir so we don't overwrite static samples
            import generate_logs
            print("[live] regenerating sample logs with random seed…")
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                generate_logs.main(seed=None, out_dir=tmp_path)
                client = get_client()
                summary = ingest_directory(
                    tmp_path,
                    label="live stream",
                    client=client,
                    on_progress=channel.send,
                )
            session_id = summary["session_id"]
            channel.send("detect_complete", {
                "session_id": session_id,
                "events": summary["events"],
                "signals": summary["signals"],
            })

            if summary["signals"] > 0:
                run_investigation(
                    session_id,
                    client=client,
                    on_hop=lambda agent, stage, data: channel.send("agent_hop", data),
                )

            channel.send("complete", {
                "session_id": session_id,
                "events": summary["events"],
                "signals": summary["signals"],
                "incidents": len(store.get_incidents(session_id)),
            })
        except Exception as exc:
            channel.send("error", {"message": f"{type(exc).__name__}: {exc}"})
        finally:
            channel.close()

    threading.Thread(target=_worker, daemon=True).start()

    return StreamingResponse(
        event_stream(channel),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/ingest/samples/live")
async def ingest_samples_live() -> StreamingResponse:
    """
    Ingest + detect only (no agents), streamed as SSE.  Useful when you want
    to watch signals appear in the triage view before manually triggering the
    agents.
    """
    if not SAMPLES.exists():
        raise HTTPException(
            400,
            "No sample logs found. Run: python scripts/generate_logs.py",
        )

    loop = asyncio.get_event_loop()
    channel = SSEChannel(loop)

    def _worker() -> None:
        try:
            client = get_client()
            summary = ingest_directory(
                SAMPLES,
                label="live ingest",
                client=client,
                on_progress=channel.send,
            )
            channel.send("complete", {
                "session_id": summary["session_id"],
                "events": summary["events"],
                "signals": summary["signals"],
            })
        except Exception as exc:
            channel.send("error", {"message": f"{type(exc).__name__}: {exc}"})
        finally:
            channel.close()

    threading.Thread(target=_worker, daemon=True).start()

    return StreamingResponse(
        event_stream(channel),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Injection endpoints (Live Simulation)
# ---------------------------------------------------------------------------

def _run_incremental_detection(session_id: str):
    """Run detection on the recent window, inserting only novel signals."""
    from schemas import Event
    from datetime import datetime

    # Fetch recent window (enough for rules to trigger)
    # query_events returns dicts, need to parse back to Event
    raw_events = store.query_events(session_id, limit=5000)
    # The DB stores ts as string, parse it
    events = []
    for r in raw_events:
        r_copy = dict(r)
        if isinstance(r_copy['ts'], str):
            r_copy['ts'] = datetime.fromisoformat(r_copy['ts'])
        events.append(Event(**r_copy))
    
    if not events:
        return

    client = get_client()
    signals, audit = detect_all(events, client=client)

    # Filter out signals we already have
    existing = store.get_signals(session_id)
    existing_keys = {
        (s['detector'], s['rule_id'], s['entity'], s['ts_start'])
        for s in existing
    }
    
    novel = []
    for s in signals:
        key = (s.detector, s.rule_id, s.entity, s.ts_start.isoformat())
        if key not in existing_keys:
            novel.append(s)

    if novel:
        store.insert_signals(session_id, novel)
    if audit:
        store.insert_logic_rules(session_id, audit)
        
    store.update_session(
        session_id,
        event_count=len(store.query_events(session_id, limit=1000000)),
        signal_count=len(existing) + len(novel),
        status="detected",
    )


@app.post("/api/inject/normal/{session_id}")
def inject_normal(session_id: str) -> dict:
    """Inject a single normal event."""
    _require_session(session_id)
    event = injector.random_event()
    inserted_ids = store.insert_events(session_id, [event])
    if not inserted_ids:
        raise HTTPException(500, "Failed to insert event")
    _run_incremental_detection(session_id)
    return {"status": "ok", "event_id": inserted_ids[0], "type": "normal"}


@app.post("/api/inject/anomaly/{session_id}")
def inject_anomaly(session_id: str) -> dict:
    """Inject a single anomalous event."""
    _require_session(session_id)
    event = injector.anomaly_event()
    inserted_ids = store.insert_events(session_id, [event])
    if not inserted_ids:
        raise HTTPException(500, "Failed to insert event")
    _run_incremental_detection(session_id)
    return {"status": "ok", "event_id": inserted_ids[0], "type": "anomaly"}


# ---------------------------------------------------------------------------
# Detection output
# ---------------------------------------------------------------------------


@app.get("/api/signals/{session_id}")
def signals(session_id: str) -> list[dict]:
    _require_session(session_id)
    return feedback.apply(store.get_signals(session_id))


@app.post("/api/feedback/{session_id}")
def submit_feedback(session_id: str, signal_id: int, verdict: str, note: str = "") -> dict:
    """
    An analyst marks a signal true or false positive.

    Repeated dismissals damp that rule's score on the next run, so the platform
    gets quieter where the team says it is wrong.
    """
    _require_session(session_id)
    signal = next(
        (s for s in store.get_signals(session_id) if s["signal_id"] == signal_id), None
    )
    if signal is None:
        raise HTTPException(404, f"No signal {signal_id} in this session")
    try:
        entry = feedback.record(session_id, signal_id, signal["rule_id"], verdict, note)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"recorded": entry, "adjustments": feedback.adjustments()}


@app.get("/api/feedback")
def feedback_summary() -> dict:
    return feedback.summary()


@app.get("/api/logic-rules/{session_id}")
def logic_rules(session_id: str) -> dict:
    """
    The AI-proposed detection rules and the verdict on each.

    This is the answer to "is the detection just the LLM deciding?" - every rule
    the model wrote is here with whether the schema validator accepted it and,
    when it did not, exactly what was wrong.
    """
    _require_session(session_id)
    rules = store.get_logic_rules(session_id)
    return {
        "proposed": len(rules),
        "accepted": sum(1 for r in rules if r["accepted"]),
        "rejected": sum(1 for r in rules if not r["accepted"]),
        "rules": rules,
    }


@app.get("/api/events/{session_id}")
def events(
    session_id: str,
    host: str | None = None,
    src_ip: str | None = None,
    user: str | None = None,
    start: str | None = None,
    end: str | None = None,
    contains: str | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[dict]:
    _require_session(session_id)
    return store.query_events(
        session_id, host=host, src_ip=src_ip, user=user,
        start=start, end=end, contains=contains, limit=limit,
    )


# ---------------------------------------------------------------------------
# The agent layer
# ---------------------------------------------------------------------------


@app.post("/api/investigate/{session_id}")
def investigate(session_id: str) -> dict:
    _require_session(session_id)
    if not store.get_signals(session_id):
        raise HTTPException(400, "No signals to investigate. Ingest logs first.")

    ctx = run_investigation(session_id)
    incidents = store.get_incidents(session_id)
    return {
        "session_id": session_id,
        "signals_in": len(ctx.signals),
        "incidents_out": len(incidents),
        "tool_calls": len(ctx.tool_calls),
        "used_model": ctx.used_model,
        "stage_timings_ms": ctx.stage_timings,
        "redaction": ctx.redactor.summary(),
        "incidents": incidents,
    }


@app.get("/api/incidents/{session_id}")
def incidents(session_id: str) -> list[dict]:
    _require_session(session_id)
    out = store.get_incidents(session_id)
    plans = {p["incident_id"]: p for p in store.get_plans(session_id)}
    for inc in out:
        inc["response_plan"] = plans.get(inc["incident_id"])
    return out


@app.get("/api/incident/{incident_id}")
def incident_detail(incident_id: str) -> dict:
    inc = store.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, f"No such incident: {incident_id}")
    inc["response_plan"] = store.get_plan(incident_id)
    return inc


@app.get("/api/trace/{session_id}")
def trace(session_id: str) -> list[dict]:
    """The agent_runs table. This is what the trace panel renders."""
    _require_session(session_id)
    return store.get_runs(session_id)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class QueryRequest(BaseModel):
    question: str


@app.post("/api/query/{session_id}")
def natural_language_query(session_id: str, payload: QueryRequest) -> dict:
    """
    Ask the logs a question in English.

    Executes model-generated Cypher through GRAPH.RO_QUERY, so FalkorDB itself
    refuses writes; see backend/query.py for the full guard.
    """
    _require_session(session_id)
    question = payload.question.strip()
    if not question:
        raise HTTPException(400, "Ask a question.")
    if len(question) > 500:
        raise HTTPException(400, "Question too long (500 characters max).")
    return query_engine.answer(get_client(), session_id, question)


@app.get("/api/query/{session_id}/examples")
def query_examples(session_id: str) -> list[str]:
    _require_session(session_id)
    return [
        "How many failed logins came from each source address?",
        "Show every successful login after 02:00 on web-01",
        "Which accounts were touched by 203.0.113.45?",
        "What were the ten largest outbound transfers?",
        "Show all firewall blocks against ports above 1000",
        "Which hosts did svc_deploy authenticate to?",
    ]


@app.get("/api/report/{session_id}", response_class=PlainTextResponse)
def report_markdown(session_id: str) -> str:
    _require_session(session_id)
    return report.build_markdown(session_id)


@app.get("/api/report/{session_id}/view", response_class=HTMLResponse)
def report_view(session_id: str) -> str:
    _require_session(session_id)
    return report.build_html(session_id)


@app.get("/api/report/{session_id}/download")
def report_download(session_id: str, fmt: str = Query("html", pattern="^(html|md)$")):
    _require_session(session_id)
    if fmt == "md":
        body, media, ext = report.build_markdown(session_id), "text/markdown", "md"
    else:
        body, media, ext = report.build_html(session_id), "text/html", "html"
    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition":
                f'attachment; filename="incident-report-{session_id}.{ext}"'
        },
    )
