"""
Copy an existing SQLite store (data/sentinel.db) into FalkorDB.

    .venv/bin/python scripts/migrate_sqlite_to_falkordb.py            # migrate + verify
    .venv/bin/python scripts/migrate_sqlite_to_falkordb.py --dry-run  # counts only
    .venv/bin/python scripts/migrate_sqlite_to_falkordb.py --sqlite other.db --replace

Original ids are kept (event_id, signal_id, run_id, rule_pk), so incident
payloads that cite them stay valid, and the id counters are moved past the
highest migrated id so new writes never collide.

The SQLite file is only ever opened read-only and is left in place: rolling back
is deleting the FalkorDB graph (or data/sentinel.falkordb) and checking out the
SQLite store again.

Sessions already present in the graph are skipped unless --replace is given.
After writing, every session is verified by reading it back through the store
API and comparing it to the SQLite rows.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import store  # noqa: E402

DEFAULT_SQLITE = ROOT / "data" / "sentinel.db"


def _open(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _all(conn: sqlite3.Connection, sql: str, *args) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def migrate_session(conn: sqlite3.Connection, sess: dict) -> dict:
    sid = sess["session_id"]
    g = store.connect()
    g.query(
        "MERGE (s:Session {session_id:$sid}) SET s.created_at=$created_at, "
        "s.label=$label, s.event_count=$event_count, s.signal_count=$signal_count, "
        "s.incident_count=$incident_count, s.status=$status",
        {**{k: sess[k] for k in store.SESSION_FIELDS if k != "session_id"}, "sid": sid},
    )

    events = _all(conn, "SELECT * FROM events WHERE session_id=? ORDER BY event_id", sid)
    store.write_event_rows(sid, [
        {k: e[k] for k in store.EVENT_FIELDS if k != "session_id"} for e in events
    ])

    signals = _all(conn, "SELECT * FROM signals WHERE session_id=? ORDER BY signal_id", sid)
    rows = []
    for s in signals:
        row = {k: s[k] for k in store.SIGNAL_FIELDS if k not in ("session_id", "analysis_json")}
        row["event_ids"] = json.loads(s["event_ids"])
        row["evidence_sample"] = json.loads(s["evidence_sample"])
        if s.get("analysis_json"):
            row["analysis_json"] = s["analysis_json"]
        rows.append(row)
    store.write_signal_rows(sid, rows)

    incidents = _all(conn, "SELECT * FROM incidents WHERE session_id=?", sid)
    for i in incidents:
        store.write_incident_row(
            sid, i["incident_id"], i["payload_json"], i["risk_score"], i["severity"],
            i["created_at"], json.loads(i["payload_json"]).get("signal_ids", []),
        )

    plans = _all(conn, "SELECT * FROM response_plans WHERE session_id=?", sid)
    for p in plans:
        store.write_plan_row(sid, p["incident_id"], p["payload_json"], p["created_at"])

    runs = _all(conn, "SELECT * FROM agent_runs WHERE session_id=? ORDER BY run_id", sid)
    store.write_rows("AgentRun", [{**r, "ok": bool(r["ok"])} for r in runs])

    rules = []
    if _table_exists(conn, "logic_rules"):
        rules = _all(conn, "SELECT * FROM logic_rules WHERE session_id=? ORDER BY rule_pk", sid)
        store.write_rows("LogicRule", [{**r, "accepted": bool(r["accepted"])} for r in rules])

    return {"events": len(events), "signals": len(signals), "incidents": len(incidents),
            "plans": len(plans), "runs": len(runs), "logic_rules": len(rules)}


def verify_session(conn: sqlite3.Connection, sid: str) -> list[str]:
    """Read back through the store API and compare with what SQLite holds."""
    problems = []

    want = _all(conn, "SELECT * FROM events WHERE session_id=? ORDER BY ts, event_id", sid)
    got = store.all_events(sid)
    if len(want) != len(got):
        problems.append(f"events: sqlite {len(want)} vs graph {len(got)}")
    else:
        for w, g in zip(want, got, strict=True):
            if any(w[k] != g[k] for k in store.EVENT_FIELDS):
                problems.append(f"event {w['event_id']} differs")
                break

    want_sig = {s["signal_id"]: s for s in _all(
        conn, "SELECT * FROM signals WHERE session_id=?", sid)}
    got_sig = {s["signal_id"]: s for s in store.get_signals(sid)}
    if want_sig.keys() != got_sig.keys():
        problems.append(f"signals: ids differ ({len(want_sig)} vs {len(got_sig)})")
    else:
        for k, w in want_sig.items():
            g = got_sig[k]
            if json.loads(w["event_ids"]) != g["event_ids"] or w["score"] != g["score"] \
                    or (w["analysis_json"] or None) != (g["analysis_json"] or None):
                problems.append(f"signal {k} differs")
                break

    want_inc = sorted(json.loads(r["payload_json"])["incident_id"] for r in _all(
        conn, "SELECT payload_json FROM incidents WHERE session_id=?", sid))
    got_inc = sorted(i["incident_id"] for i in store.get_incidents(sid))
    if want_inc != got_inc:
        problems.append(f"incidents: {want_inc} vs {got_inc}")

    n_plans = len(_all(conn, "SELECT 1 FROM response_plans WHERE session_id=?", sid))
    if n_plans != len(store.get_plans(sid)):
        problems.append("response plan count differs")

    want_runs = [r["run_id"] for r in _all(
        conn, "SELECT run_id FROM agent_runs WHERE session_id=? ORDER BY stage_index, run_id", sid)]
    if want_runs != [r["run_id"] for r in store.get_runs(sid)]:
        problems.append("agent runs differ")

    if _table_exists(conn, "logic_rules"):
        n_rules = len(_all(conn, "SELECT 1 FROM logic_rules WHERE session_id=?", sid))
        if n_rules != len(store.get_logic_rules(sid)):
            problems.append("logic rule count differs")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sqlite", type=Path, default=DEFAULT_SQLITE)
    ap.add_argument("--replace", action="store_true",
                    help="overwrite sessions that already exist in the graph")
    ap.add_argument("--dry-run", action="store_true", help="report what would move, write nothing")
    args = ap.parse_args()

    if not args.sqlite.exists():
        print(f"No SQLite store at {args.sqlite} - nothing to migrate.")
        return 0

    conn = _open(args.sqlite)
    sessions = _all(conn, "SELECT * FROM sessions ORDER BY created_at")
    print(f"{len(sessions)} session(s) in {args.sqlite}")

    if args.dry_run:
        for s in sessions:
            n = conn.execute("SELECT count(*) FROM events WHERE session_id=?",
                             (s["session_id"],)).fetchone()[0]
            print(f"  {s['session_id']}  {s['label']!r:30}  {n} events")
        return 0

    store.init_db()
    failed = 0
    for s in sessions:
        sid = s["session_id"]
        if store.get_session(sid):
            if not args.replace:
                print(f"  {sid}  already in graph, skipped (use --replace)")
                continue
            store.delete_session(sid)
        counts = migrate_session(conn, s)
        problems = verify_session(conn, sid)
        status = "ok" if not problems else "MISMATCH: " + "; ".join(problems)
        failed += bool(problems)
        print(f"  {sid}  " + " ".join(f"{k}={v}" for k, v in counts.items()) + f"  {status}")

    # Keep new ids clear of everything migrated.
    for counter, table, col in [("event", "events", "event_id"), ("signal", "signals", "signal_id"),
                                ("run", "agent_runs", "run_id"), ("logic_rule", "logic_rules", "rule_pk")]:
        if _table_exists(conn, table):
            top = conn.execute(f"SELECT COALESCE(MAX({col}), 0) FROM {table}").fetchone()[0]
            store.bump_counter(counter, top)

    conn.close()
    if failed:
        print(f"{failed} session(s) failed verification. The SQLite file is untouched.")
        return 1
    print(f"Done. Graph '{store.GRAPH_NAME}'. The SQLite file is untouched; delete it when satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
