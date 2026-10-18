"""
SentinelSOC - persistence.

One FalkorDB graph. Embedded by default (falkordblite runs the FalkorDB module
inside a private redis-server backed by one file under data/), or any FalkorDB
server when FALKORDB_URL is set. No Kafka, no TimescaleDB, no Elasticsearch.

The function surface is the one the SQLite store had, so no caller changed. What
changed is the shape underneath: events are linked to the entities they mention,
so "everything 203.0.113.45 touched" is a traversal rather than a self-join.

    (:Event)-[:ON_HOST]->(:Host)
    (:Event)-[:BY_USER]->(:User)
    (:Event)-[:FROM_IP]->(:IP)          src_ip
    (:Event)-[:TO_IP]->(:IP)            dst_ip
    (:Signal)-[:CITES]->(:Event)
    (:Incident)-[:CORRELATES]->(:Signal)
    (:Incident)-[:HAS_PLAN]->(:ResponsePlan)

Session, AgentRun and LogicRule stand alone. Every node carries session_id, and
entity nodes are scoped per session so deleting one session never cuts another.

agent_runs is not bookkeeping - it is what the trace panel renders, and it is the
evidence that two specialised agents actually collaborated.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from schemas import AgentRun, Event, Incident, ResponsePlan, Signal

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinel.falkordb"
GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "sentinel")

# UNWIND batch size for bulk writes. One query per batch keeps a 15k-line ingest
# to a handful of round trips without building a single huge parameter blob.
_BATCH = 2000

EVENT_FIELDS = (
    "event_id", "session_id", "ts", "source", "host", "user", "src_ip", "dst_ip",
    "dst_port", "action", "outcome", "raw", "template_id", "template", "bytes_out",
)
SESSION_FIELDS = (
    "session_id", "created_at", "label", "event_count", "signal_count",
    "incident_count", "status",
)
SIGNAL_FIELDS = (
    "signal_id", "session_id", "detector", "rule_id", "title", "severity",
    "ts_start", "ts_end", "host", "entity", "entity_kind", "score", "event_ids",
    "evidence_sample", "detail", "analysis_json",
)
RUN_FIELDS = (
    "run_id", "session_id", "agent", "stage_index", "input_summary", "output_json",
    "tool_calls", "model", "latency_ms", "ok", "error", "created_at",
)
LOGIC_FIELDS = (
    "rule_pk", "session_id", "statement", "accepted", "reason", "mitre",
    "rationale", "created_at",
)

# (label, property) pairs worth an index. session_id everywhere because every
# read is session-scoped; the id columns because lookups and edge wiring use them.
_INDEXES = [
    ("Session", "session_id"),
    ("Event", "session_id"), ("Event", "event_id"), ("Event", "ts"),
    ("Event", "host"), ("Event", "src_ip"), ("Event", "user"),
    ("Host", "session_id"), ("Host", "name"),
    ("User", "session_id"), ("User", "name"),
    ("IP", "session_id"), ("IP", "address"),
    ("Signal", "session_id"), ("Signal", "signal_id"),
    ("Incident", "session_id"), ("Incident", "incident_id"),
    ("ResponsePlan", "session_id"), ("ResponsePlan", "incident_id"),
    ("AgentRun", "session_id"),
    ("LogicRule", "session_id"),
    ("Counter", "name"),
]
_LABELS = ("Event", "Host", "User", "IP", "Signal", "Incident", "ResponsePlan",
           "AgentRun", "LogicRule", "Session")

_db = None
_initialised: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client():
    """One client per process. The embedded server takes ~2s to boot."""
    global _db
    if _db is None:
        url = os.getenv("FALKORDB_URL")
        if url:
            from falkordb import FalkorDB

            _db = FalkorDB.from_url(url)
        else:
            from redislite.falkordb_client import FalkorDB

            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            _db = FalkorDB(str(DB_PATH))
    return _db


def connect():
    """The session graph. Resolved per call so tests can point GRAPH_NAME elsewhere."""
    return _client().select_graph(GRAPH_NAME)


def _rows(cypher: str, params: Optional[dict] = None) -> list[dict]:
    res = connect().query(cypher, params or {})
    names = [h[1] for h in res.header]
    return [dict(zip(names, r)) for r in res.result_set]


def _project(var: str, fields: Iterable[str]) -> str:
    return ", ".join(f"{var}.{f} AS {f}" for f in fields)


def init_db() -> None:
    if GRAPH_NAME in _initialised:
        return
    g = connect()
    for label, prop in _INDEXES:
        try:
            g.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
        except Exception as exc:  # already indexed
            if "already indexed" not in str(exc).lower():
                raise
    _initialised.add(GRAPH_NAME)


def reset_db() -> None:
    try:
        connect().delete()
    except Exception:
        pass  # graph did not exist yet
    _initialised.discard(GRAPH_NAME)
    init_db()


def _next_ids(name: str, n: int) -> list[int]:
    """
    Reserve n contiguous ids. FalkorDB runs write queries on a graph one at a
    time, so read-increment-return inside one query is atomic - the job SQLite's
    AUTOINCREMENT used to do.
    """
    if n <= 0:
        return []
    top = connect().query(
        "MERGE (c:Counter {name:$name}) ON CREATE SET c.value = 0 "
        "SET c.value = c.value + $n RETURN c.value",
        {"name": name, "n": n},
    ).result_set[0][0]
    return list(range(top - n + 1, top + 1))


def bump_counter(name: str, at_least: int) -> None:
    """Move a counter past ids written explicitly (the SQLite migration)."""
    connect().query(
        "MERGE (c:Counter {name:$name}) ON CREATE SET c.value = 0 "
        "SET c.value = CASE WHEN c.value < $v THEN $v ELSE c.value END",
        {"name": name, "v": at_least},
    )


def _chunks(rows: list, size: int = _BATCH):
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


# -- sessions ---------------------------------------------------------------


def create_session(session_id: str, label: str = "") -> None:
    init_db()
    connect().query(
        "MERGE (s:Session {session_id:$sid}) "
        "SET s.created_at=$now, s.label=$label, s.event_count=0, s.signal_count=0, "
        "s.incident_count=0, s.status='ingested'",
        {"sid": session_id, "now": _now(), "label": label},
    )


def update_session(session_id: str, **fields: Any) -> None:
    allowed = {"event_count", "signal_count", "incident_count", "status", "label"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    # Keys come from the allowlist above, never from the caller, so formatting
    # them into the statement is safe; values travel as parameters.
    clause = ", ".join(f"s.{k}=${k}" for k in sets)
    connect().query(
        f"MATCH (s:Session {{session_id:$sid}}) SET {clause}",
        {"sid": session_id, **sets},
    )


def get_session(session_id: str) -> Optional[dict]:
    rows = _rows(
        f"MATCH (s:Session {{session_id:$sid}}) RETURN {_project('s', SESSION_FIELDS)}",
        {"sid": session_id},
    )
    return rows[0] if rows else None


def list_sessions(limit: int = 50) -> list[dict]:
    return _rows(
        f"MATCH (s:Session) RETURN {_project('s', SESSION_FIELDS)} "
        "ORDER BY s.created_at DESC LIMIT $limit",
        {"limit": limit},
    )


def delete_session(session_id: str) -> None:
    g = connect()
    for label in _LABELS:
        g.query(f"MATCH (n:{label} {{session_id:$sid}}) DETACH DELETE n", {"sid": session_id})


# -- events -----------------------------------------------------------------


def insert_events(session_id: str, events: Iterable[Event]) -> list[int]:
    events = list(events)
    if not events:
        return []
    init_db()
    ids = _next_ids("event", len(events))
    rows = [
        {
            "event_id": eid,
            "ts": e.ts.isoformat(),
            "source": e.source,
            "host": e.host,
            "user": e.user,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "dst_port": e.dst_port,
            "action": e.action,
            "outcome": e.outcome,
            "raw": e.raw,
            "template_id": e.template_id,
            "template": e.template,
            "bytes_out": e.bytes_out,
        }
        for eid, e in zip(ids, events, strict=True)
    ]
    write_event_rows(session_id, rows)
    return ids


def write_event_rows(session_id: str, rows: list[dict]) -> None:
    """Event rows with ids already assigned, linked to their entity nodes."""
    g = connect()
    p: dict[str, Any] = {"sid": session_id}
    for batch in _chunks(rows):
        p["rows"] = batch
        g.query(
            "UNWIND $rows AS r CREATE (e:Event) SET e = r, e.session_id = $sid "
            "MERGE (h:Host {session_id:$sid, name:r.host}) CREATE (e)-[:ON_HOST]->(h)",
            p,
        )
        # Optional entities: a NULL MERGE key is an error, so filter first.
        g.query(
            "UNWIND $rows AS r WITH r WHERE r.user IS NOT NULL "
            "MATCH (e:Event {event_id:r.event_id}) "
            "MERGE (u:User {session_id:$sid, name:r.user}) CREATE (e)-[:BY_USER]->(u)",
            p,
        )
        g.query(
            "UNWIND $rows AS r WITH r WHERE r.src_ip IS NOT NULL "
            "MATCH (e:Event {event_id:r.event_id}) "
            "MERGE (i:IP {session_id:$sid, address:r.src_ip}) CREATE (e)-[:FROM_IP]->(i)",
            p,
        )
        g.query(
            "UNWIND $rows AS r WITH r WHERE r.dst_ip IS NOT NULL "
            "MATCH (e:Event {event_id:r.event_id}) "
            "MERGE (i:IP {session_id:$sid, address:r.dst_ip}) CREATE (e)-[:TO_IP]->(i)",
            p,
        )


_EVENT_RETURN = f"RETURN {_project('e', EVENT_FIELDS)}"


def get_events(session_id: str, event_ids: list[int]) -> list[dict]:
    if not event_ids:
        return []
    return _rows(
        "MATCH (e:Event) WHERE e.event_id IN $ids AND e.session_id = $sid "
        f"{_EVENT_RETURN} ORDER BY e.ts, e.event_id",
        {"sid": session_id, "ids": [int(i) for i in event_ids]},
    )


def query_events(
    session_id: str,
    host: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    contains: Optional[str] = None,
    src_ip: Optional[str] = None,
    user: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    """Backs the fetch_log_window tool. Deliberately narrow: read-only, bounded."""
    where = ["e.session_id = $sid"]
    params: dict[str, Any] = {"sid": session_id, "limit": max(1, min(limit, 500))}
    for name, value, clause in [
        ("host", host, "e.host = $host"),
        ("start", start, "e.ts >= $start"),
        ("end", end, "e.ts <= $end"),
        ("src_ip", src_ip, "e.src_ip = $src_ip"),
        ("user", user, "e.user = $user"),
        # SQLite LIKE was case-insensitive for ASCII; keep that.
        ("contains", contains and contains.lower(), "toLower(e.raw) CONTAINS $contains"),
    ]:
        if value:
            where.append(clause)
            params[name] = value
    return _rows(
        f"MATCH (e:Event) WHERE {' AND '.join(where)} "
        f"{_EVENT_RETURN} ORDER BY e.ts, e.event_id LIMIT $limit",
        params,
    )


def all_events(session_id: str) -> list[dict]:
    return _rows(
        f"MATCH (e:Event {{session_id:$sid}}) {_EVENT_RETURN} ORDER BY e.ts, e.event_id",
        {"sid": session_id},
    )


# -- signals ----------------------------------------------------------------


def insert_signals(session_id: str, signals: Iterable[Signal]) -> list[int]:
    signals = list(signals)
    if not signals:
        return []
    init_db()
    ids = _next_ids("signal", len(signals))
    rows = [
        {
            "signal_id": sid_,
            "detector": s.detector,
            "rule_id": s.rule_id,
            "title": s.title,
            "severity": s.severity,
            "ts_start": s.ts_start.isoformat(),
            "ts_end": s.ts_end.isoformat(),
            "host": s.host,
            "entity": s.entity,
            "entity_kind": s.entity_kind,
            "score": float(s.score),
            "event_ids": list(s.event_ids),
            "evidence_sample": list(s.evidence_sample),
            "detail": s.detail,
        }
        for sid_, s in zip(ids, signals, strict=True)
    ]
    write_signal_rows(session_id, rows)
    return ids


def write_signal_rows(session_id: str, rows: list[dict]) -> None:
    """Signal rows with ids already assigned, linked to the events they cite."""
    g = connect()
    g.query(
        "UNWIND $rows AS r CREATE (s:Signal) SET s = r, s.session_id = $sid",
        {"sid": session_id, "rows": rows},
    )
    links = [{"s": r["signal_id"], "e": e} for r in rows for e in r["event_ids"]]
    for batch in _chunks(links):
        g.query(
            "UNWIND $links AS l MATCH (s:Signal {signal_id:l.s}), (e:Event {event_id:l.e}) "
            "WHERE e.session_id = $sid CREATE (s)-[:CITES]->(e)",
            {"sid": session_id, "links": batch},
        )


def get_signals(session_id: str) -> list[dict]:
    out = _rows(
        f"MATCH (s:Signal {{session_id:$sid}}) RETURN {_project('s', SIGNAL_FIELDS)} "
        "ORDER BY s.score DESC, s.signal_id",
        {"sid": session_id},
    )
    for d in out:
        d["event_ids"] = d["event_ids"] or []
        d["evidence_sample"] = d["evidence_sample"] or []
        if d.get("analysis_json"):
            d["analysis"] = json.loads(d["analysis_json"])
    return out


def attach_analysis(signal_id: int, analysis_json: str) -> None:
    connect().query(
        "MATCH (s:Signal {signal_id:$id}) SET s.analysis_json = $a",
        {"id": signal_id, "a": analysis_json},
    )


# -- incidents & plans ------------------------------------------------------


def insert_incident(session_id: str, inc: Incident) -> None:
    init_db()
    write_incident_row(
        session_id, inc.incident_id, inc.model_dump_json(), inc.risk_score,
        inc.severity, _now(), list(inc.signal_ids),
    )


def write_incident_row(
    session_id: str, incident_id: str, payload_json: str, risk_score: int,
    severity: str, created_at: str, signal_ids: list[int],
) -> None:
    g = connect()
    params = {
        "iid": incident_id,
        "sid": session_id,
        "payload": payload_json,
        "risk": risk_score,
        "severity": severity,
        "now": created_at,
        "signals": signal_ids,
    }
    # Replace semantics: drop the old correlation edges before re-linking.
    g.query(
        "MERGE (i:Incident {incident_id:$iid}) "
        "SET i.session_id=$sid, i.payload_json=$payload, i.risk_score=$risk, "
        "i.severity=$severity, i.created_at=$now "
        "WITH i OPTIONAL MATCH (i)-[c:CORRELATES]->() DELETE c",
        params,
    )
    g.query(
        "MATCH (i:Incident {incident_id:$iid}) "
        "UNWIND $signals AS sid_ MATCH (s:Signal {signal_id:sid_}) "
        "WHERE s.session_id = $sid CREATE (i)-[:CORRELATES]->(s)",
        params,
    )


def get_incidents(session_id: str) -> list[dict]:
    rows = _rows(
        "MATCH (i:Incident {session_id:$sid}) RETURN i.payload_json AS p "
        "ORDER BY i.risk_score DESC",
        {"sid": session_id},
    )
    return [json.loads(r["p"]) for r in rows]


def get_incident(incident_id: str) -> Optional[dict]:
    rows = _rows(
        "MATCH (i:Incident {incident_id:$iid}) RETURN i.payload_json AS p",
        {"iid": incident_id},
    )
    return json.loads(rows[0]["p"]) if rows else None


def insert_plan(session_id: str, plan: ResponsePlan) -> None:
    init_db()
    write_plan_row(session_id, plan.incident_id, plan.model_dump_json(), _now())


def write_plan_row(session_id: str, incident_id: str, payload_json: str, created_at: str) -> None:
    connect().query(
        "MERGE (p:ResponsePlan {incident_id:$iid}) "
        "SET p.session_id=$sid, p.payload_json=$payload, p.created_at=$now "
        "WITH p OPTIONAL MATCH (i:Incident {incident_id:$iid}) "
        "FOREACH (_ IN CASE WHEN i IS NULL THEN [] ELSE [1] END | MERGE (i)-[:HAS_PLAN]->(p))",
        {"iid": incident_id, "sid": session_id, "payload": payload_json, "now": created_at},
    )


def get_plan(incident_id: str) -> Optional[dict]:
    rows = _rows(
        "MATCH (p:ResponsePlan {incident_id:$iid}) RETURN p.payload_json AS p",
        {"iid": incident_id},
    )
    return json.loads(rows[0]["p"]) if rows else None


def get_plans(session_id: str) -> list[dict]:
    rows = _rows(
        "MATCH (p:ResponsePlan {session_id:$sid}) RETURN p.payload_json AS p",
        {"sid": session_id},
    )
    return [json.loads(r["p"]) for r in rows]


# -- agent runs -------------------------------------------------------------


def insert_run(run: AgentRun) -> int:
    init_db()
    (run_id,) = _next_ids("run", 1)
    write_rows("AgentRun", [{
        "run_id": run_id,
        "session_id": run.session_id,
        "agent": run.agent,
        "stage_index": run.stage_index,
        "input_summary": run.input_summary,
        "output_json": run.output_json,
        # Properties cannot hold nested maps, so tool calls stay JSON.
        "tool_calls": json.dumps(run.tool_calls),
        "model": run.model,
        "latency_ms": run.latency_ms,
        "ok": bool(run.ok),
        "error": run.error,
        "created_at": run.created_at.isoformat(),
    }])
    return run_id


def write_rows(label: str, rows: list[dict]) -> None:
    """Standalone nodes (AgentRun, LogicRule): one node per row, no edges."""
    assert label in {"AgentRun", "LogicRule"}
    for batch in _chunks(rows):
        connect().query(f"UNWIND $rows AS r CREATE (n:{label}) SET n = r", {"rows": batch})


def get_runs(session_id: str) -> list[dict]:
    out = _rows(
        f"MATCH (r:AgentRun {{session_id:$sid}}) RETURN {_project('r', RUN_FIELDS)} "
        "ORDER BY r.stage_index, r.run_id",
        {"sid": session_id},
    )
    for d in out:
        d["tool_calls"] = json.loads(d["tool_calls"] or "[]")
        d["ok"] = bool(d["ok"])
    return out


# -- AI-proposed rules (the logic gate audit trail) --------------------------


def insert_logic_rules(session_id: str, audit: list[dict]) -> None:
    if not audit:
        return
    init_db()
    ids = _next_ids("logic_rule", len(audit))
    now = _now()
    write_rows("LogicRule", [
        {"rule_pk": pk, "session_id": session_id, "statement": a["statement"],
         "accepted": bool(a["accepted"]), "reason": a["reason"],
         "mitre": a.get("mitre", ""), "rationale": a.get("rationale", ""),
         "created_at": now}
        for pk, a in zip(ids, audit, strict=True)
    ])


def get_logic_rules(session_id: str) -> list[dict]:
    out = _rows(
        f"MATCH (l:LogicRule {{session_id:$sid}}) RETURN {_project('l', LOGIC_FIELDS)} "
        "ORDER BY l.rule_pk",
        {"sid": session_id},
    )
    for d in out:
        d["accepted"] = bool(d["accepted"])
    return out
