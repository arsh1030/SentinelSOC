"""
SentinelSOC - natural-language log query.

Ported in spirit from DataSentinel's engines/query.py, which turned English into
SQL over DuckDB with a three-strike self-healing loop. Here the target is the
FalkorDB graph the pipeline already writes, so the model writes Cypher, and a
question like "which hosts did this IP reach" is a pattern match over the
entity edges rather than a self-join.

SAFETY. This executes Cypher a language model wrote, against a graph holding
security logs. Three independent layers, in order of how much they are trusted:

  1. Every statement runs through GRAPH.RO_QUERY. This is the guard that
     actually matters: FalkorDB itself refuses any query that would write, so a
     prompt-injected DELETE or SET fails at the engine even if every check
     above it were bypassed.
  2. One statement only, and it must open with MATCH, OPTIONAL MATCH, WITH,
     UNWIND or RETURN.
  3. A denylist of write and procedure keywords.

Layers 2 and 3 exist to return a clear message rather than an opaque engine
error. Layer 1 is what makes the feature safe.
"""

from __future__ import annotations

import re
from typing import Any

from falkordb import Edge, Node, Path
from llm_client import LLMClient
from pydantic import BaseModel, Field
from redaction import Redactor
from redis.exceptions import RedisError

import store

MAX_ATTEMPTS = 3
ROW_LIMIT = 200
QUERY_TIMEOUT_MS = 5000

SCHEMA = """NODE (:Event)
  event_id    int       unique id, cite these when showing evidence
  session_id  string    always filter on this: e.session_id = $sid
  ts          string    ISO-8601 UTC, e.g. '2026-03-15T02:19:47+00:00'
  source      string    ssh_auth | nginx_access | firewall | windows_security
  host        string    web-01, db-01, fs-01, fw-01, win-dc-01, app-01, app-02
  user        string    account name, null where the format carries none
  src_ip      string
  dst_ip      string
  dst_port    int
  action      string    ssh_login | http_get | fw_tcp | windows_logon |
                        file_access | process_create | account_created |
                        sudo:root | session_opened
  outcome     string    success | failure | blocked | allowed | info
  raw         string    the original log line
  template_id string
  bytes_out   int

NODE (:Host {session_id, name})
NODE (:User {session_id, name})
NODE (:IP   {session_id, address})

NODE (:Signal)
  signal_id, session_id, detector, rule_id, title, severity, ts_start, ts_end,
  host, entity, entity_kind, score, detail, event_ids (list of int)

NODE (:Incident)
  incident_id, session_id, risk_score, severity, created_at

EDGES
  (:Event)-[:ON_HOST]->(:Host)
  (:Event)-[:BY_USER]->(:User)
  (:Event)-[:FROM_IP]->(:IP)        the event's src_ip
  (:Event)-[:TO_IP]->(:IP)          the event's dst_ip
  (:Signal)-[:CITES]->(:Event)
  (:Incident)-[:CORRELATES]->(:Signal)"""

SYSTEM = f"""You translate a security analyst's question into one read-only
openCypher query for FalkorDB.

GRAPH
{SCHEMA}

RULES
  - Emit exactly one statement. It must begin with MATCH, OPTIONAL MATCH, WITH,
    UNWIND or RETURN.
  - Always constrain to the session with the parameter $sid, e.g.
    MATCH (e:Event) WHERE e.session_id = $sid. Never inline the session id.
  - ts is an ISO-8601 string, so lexical comparison works:
    e.ts >= '2026-03-15T02:00:00'.
  - Return scalar columns with aliases (e.event_id AS event_id), not whole
    nodes, and prefer including event_id so findings stay citable.
  - Never write. No CREATE, MERGE, SET, DELETE, REMOVE, DROP, CALL, LOAD CSV.
  - Aggregate when the question asks "how many" or "which is most"; return rows
    otherwise.
  - If the question cannot be answered from this graph, say so in `note` and
    return the closest useful query rather than inventing a property."""

_WRITE = re.compile(
    r"\b(create|merge|set|delete|detach|remove|drop|call|load|foreach)\b",
    re.I,
)
_STARTS_OK = re.compile(r"^\s*(match|optional\s+match|with|unwind|return)\b", re.I)
_HAS_LIMIT = re.compile(r"\blimit\s+\d+\s*$", re.I)


class GeneratedQuery(BaseModel):
    cypher: str = Field(description="One read-only Cypher query using $sid for the session.")
    explanation: str = Field(description="One sentence: what this query returns.")
    note: str = Field(default="", description="Caveats, or why the question is unanswerable.")


class QueryError(RuntimeError):
    pass


def validate_cypher(cypher: str) -> str:
    """Reject anything that is not a single read. Returns the cleaned statement."""
    cleaned = cypher.strip().rstrip(";").strip()
    if not cleaned:
        raise QueryError("Empty query.")
    if ";" in cleaned:
        raise QueryError("Only one statement is allowed.")
    if not _STARTS_OK.match(cleaned):
        raise QueryError("Only MATCH, WITH, UNWIND or RETURN queries are allowed.")
    hit = _WRITE.search(cleaned)
    if hit:
        raise QueryError(f"Write operation '{hit.group(0)}' is not permitted.")
    return cleaned


def _plain(value: Any) -> Any:
    """Make graph values JSON-safe for the API: nodes and edges become property maps."""
    if isinstance(value, Node):
        return {"_labels": value.labels, **value.properties}
    if isinstance(value, Edge):
        return {"_type": value.relation, **value.properties}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def execute(cypher: str, session_id: str) -> tuple[list[str], list[list[Any]]]:
    statement = validate_cypher(cypher)
    if not _HAS_LIMIT.search(statement):
        statement = f"{statement} LIMIT {ROW_LIMIT}"

    # RO_QUERY: the engine refuses writes. The timeout kills a runaway traversal
    # rather than hold the request open.
    res = store.connect().ro_query(
        statement, {"sid": session_id}, timeout=QUERY_TIMEOUT_MS
    )
    columns = [h[1] for h in res.header]
    rows = [[_plain(v) for v in r] for r in res.result_set[:ROW_LIMIT]]
    return columns, rows


def _fallback_cypher(question: str) -> GeneratedQuery:
    """
    No model reachable. Keyword-match the question onto a few known shapes so the
    feature degrades rather than disappears - same principle as the agents.
    """
    q = question.lower()
    where = ["e.session_id = $sid"]
    described = []

    for token, clause, label in [
        ("fail", "e.outcome = 'failure'", "failed events"),
        ("block", "e.outcome = 'blocked'", "blocked events"),
        ("success", "e.outcome = 'success'", "successful events"),
        ("ssh", "e.action = 'ssh_login'", "SSH logins"),
        ("firewall", "e.source = 'firewall'", "firewall events"),
        ("web", "e.source = 'nginx_access'", "web requests"),
        ("windows", "e.source = 'windows_security'", "Windows events"),
    ]:
        if token in q:
            where.append(clause)
            described.append(label)

    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question):
        where.append(f"e.src_ip = '{ip}'")
        described.append(f"from {ip}")

    cypher = (
        "MATCH (e:Event)\nWHERE " + "\n  AND ".join(where) + "\n"
        "RETURN e.event_id AS event_id, e.ts AS ts, e.host AS host, e.user AS user,\n"
        "       e.src_ip AS src_ip, e.action AS action, e.outcome AS outcome, e.raw AS raw\n"
        "ORDER BY ts LIMIT 200"
    )
    return GeneratedQuery(
        cypher=cypher,
        explanation="Keyword-matched " + (", ".join(described) or "recent events") + ".",
        note="No model was reachable, so this query was built by keyword matching "
             "rather than language understanding.",
    )


def answer(
    client: LLMClient,
    session_id: str,
    question: str,
    redactor: Redactor | None = None,
) -> dict:
    """
    English in, rows out.

    Three strikes: a query that fails validation or execution goes back to the
    model with the exact error, which is DataSentinel's self-healing loop and is
    what makes a mid-tier model usable for this.
    """
    attempts: list[dict] = []
    messages = [{
        "role": "user",
        "content": f"The session is bound to $sid.\n\nQuestion: {question}",
    }]
    used_model = False

    for attempt in range(MAX_ATTEMPTS):
        generated = client.structured(
            tag=f"query:{session_id}:{attempt}",
            messages=messages,
            schema=GeneratedQuery,
            system=SYSTEM,
            effort="low",
            max_tokens=2000,
        )
        if generated is None:
            break
        used_model = True

        try:
            columns, rows = execute(generated.cypher, session_id)
        except (QueryError, RedisError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            attempts.append({"cypher": generated.cypher, "error": error})
            messages = messages + [
                {"role": "assistant", "content": generated.cypher},
                {"role": "user", "content":
                    f"That query failed: {error}\nReturn a corrected query."},
            ]
            continue

        return {
            "question": question,
            "cypher": generated.cypher,
            "explanation": generated.explanation,
            "note": generated.note,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "attempts": attempts,
            "used_model": True,
        }

    # Every model attempt failed, or none was possible.
    generated = _fallback_cypher(question)
    try:
        columns, rows = execute(generated.cypher, session_id)
    except (QueryError, RedisError) as exc:
        return {
            "question": question, "cypher": generated.cypher, "explanation": "",
            "note": f"Query failed: {exc}", "columns": [], "rows": [],
            "row_count": 0, "attempts": attempts, "used_model": used_model,
        }
    return {
        "question": question,
        "cypher": generated.cypher,
        "explanation": generated.explanation,
        "note": generated.note,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "attempts": attempts,
        "used_model": False,
    }
