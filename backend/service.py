"""
SentinelSOC - the end-to-end flow.

ingest -> detect -> investigate. One function per phase so the API, the CLI and
the tests all drive the same code path.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Callable

import store
from detect import detect_all
from ingest import parse_directory, parse_file
from ingest.parsers import PARSERS, TemplateMiner
from schemas import Event

# (event_type, payload) – called at each pipeline milestone when streaming.
ProgressCallback = Callable[[str, Any], None] | None


def new_session_id() -> str:
    return f"s-{uuid.uuid4().hex[:10]}"


def ingest_directory(
    directory: Path, session_id: str | None = None, label: str = "",
    client=None, on_progress: ProgressCallback = None,
) -> dict:
    """Parse every known log file in a directory, store events, run detection."""
    store.init_db()
    session_id = session_id or new_session_id()
    store.create_session(session_id, label or directory.name)

    events, per_file = parse_directory(directory)
    return _finish_ingest(session_id, events, per_file, client, on_progress)


def ingest_files(
    paths: list[Path], session_id: str | None = None, label: str = "",
    client=None, on_progress: ProgressCallback = None,
) -> dict:
    """Parse an explicit list of files. Used by the upload endpoint."""
    store.init_db()
    session_id = session_id or new_session_id()
    store.create_session(session_id, label or "upload")

    miner = TemplateMiner()
    events: list[Event] = []
    per_file: dict[str, int] = {}
    for path in paths:
        got = list(parse_file(path, miner))
        per_file[path.name] = len(got)
        events.extend(got)
    events.sort(key=lambda e: e.ts)
    return _finish_ingest(session_id, events, per_file, client, on_progress)


def _finish_ingest(
    session_id: str, events: list[Event], per_file: dict[str, int],
    client=None, on_progress: ProgressCallback = None,
) -> dict:
    _emit = on_progress or (lambda _t, _d: None)

    if not events:
        store.update_session(session_id, status="empty")
        _emit("complete", {"session_id": session_id, "events": 0, "signals": 0})
        return {
            "session_id": session_id,
            "events": 0,
            "signals": 0,
            "per_file": per_file,
            "warning": "No events parsed. Expected one of: " + ", ".join(sorted(PARSERS)),
        }

    ids = store.insert_events(session_id, events)
    if len(ids) != len(events):
        # Silently zipping a short list would leave events at event_id=0, and
        # every evidence citation pointing at them would be wrong. Fail loudly.
        raise RuntimeError(
            f"stored {len(ids)} ids for {len(events)} events - refusing to "
            "attach mismatched event IDs"
        )
    for event, event_id in zip(events, ids, strict=True):
        event.event_id = event_id

    _emit("ingest_progress", {
        "session_id": session_id,
        "events_stored": len(events),
        "per_file": per_file,
    })

    signals, audit = detect_all(events, client=client)
    if signals:
        signal_ids = store.insert_signals(session_id, signals)
        for signal, sid in zip(signals, signal_ids, strict=True):
            signal.signal_id = sid
            _emit("signal", {
                "signal_id": sid,
                "detector": signal.detector,
                "rule_id": signal.rule_id,
                "title": signal.title,
                "severity": signal.severity,
                "entity": signal.entity,
                "score": signal.score,
            })

    store.insert_logic_rules(session_id, audit)
    store.update_session(
        session_id,
        event_count=len(events),
        signal_count=len(signals),
        status="detected",
    )
    return {
        "session_id": session_id,
        "events": len(events),
        "signals": len(signals),
        "per_file": per_file,
        "detectors": sorted({s.detector for s in signals}),
        "ai_rules_proposed": len(audit),
        "ai_rules_accepted": sum(1 for a in audit if a["accepted"]),
    }
