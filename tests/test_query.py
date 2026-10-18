"""
Natural-language log query.

This executes Cypher a language model wrote, against security logs. The guard
tests are not box-ticking: a prompt-injected write reaching the graph would be
the worst defect in the project.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402
from redis.exceptions import ResponseError  # noqa: E402

import query  # noqa: E402
import store  # noqa: E402
from llm_client import LLMClient  # noqa: E402
from query import GeneratedQuery, QueryError, validate_cypher  # noqa: E402
from schemas import Event  # noqa: E402

# -- the guard -------------------------------------------------------------


@pytest.mark.parametrize("cypher", [
    "MATCH (e:Event) DELETE e",
    "MATCH (e:Event) DETACH DELETE e",
    "MATCH (e:Event) SET e.raw = 'x'",
    "MATCH (e:Event) REMOVE e.raw",
    "CREATE (e:Event {raw: 'x'})",
    "MERGE (e:Event {raw: 'x'})",
    "CALL db.idx.fulltext.drop('Event')",
    "LOAD CSV FROM 'file:///etc/passwd' AS row RETURN row",
    "MATCH (e:Event) FOREACH (x IN [1] | SET e.raw = 'x')",
    "DROP INDEX ON :Event(session_id)",
    "MATCH (e) RETURN e; MATCH (e) DELETE e",
    "RETURN 1;MATCH (e) DELETE e",
    "",
    "   ",
])
def test_write_and_multi_statement_are_refused(cypher):
    with pytest.raises(QueryError):
        validate_cypher(cypher)


@pytest.mark.parametrize("cypher", [
    "MATCH (e:Event) WHERE e.session_id = $sid RETURN e.event_id",
    "OPTIONAL MATCH (e:Event) RETURN count(e)",
    "WITH 1 AS n RETURN n",
    "UNWIND [1, 2] AS n RETURN n",
    "  match (e:Event) return e.event_id  ",
    "MATCH (e:Event) RETURN count(e);",
])
def test_reads_are_allowed(cypher):
    assert validate_cypher(cypher)


def test_trailing_semicolon_is_stripped_not_treated_as_two_statements():
    assert validate_cypher("RETURN 1;") == "RETURN 1"


# -- execution -------------------------------------------------------------


@pytest.fixture
def seeded():
    store.reset_db()
    store.create_session("s1")
    store.insert_events("s1", [
        Event(
            ts=datetime.fromisoformat(f"2026-03-15T0{i % 10}:00:00+00:00"),
            source="ssh_auth", host="web-01", user=f"u{i % 5}",
            src_ip="203.0.113.45" if i % 2 else "10.0.0.1", dst_ip="10.0.0.9",
            dst_port=22, action="ssh_login",
            outcome="failure" if i % 2 else "success", raw=f"line {i}",
            template_id="t1",
        )
        for i in range(1, 401)
    ])
    store.create_session("s2")
    store.insert_events("s2", [
        Event(ts=datetime.fromisoformat("2026-03-15T00:00:00+00:00"),
              source="firewall", host="fw-01", action="fw_tcp",
              outcome="blocked", raw="other session"),
    ])
    return "s1"


def test_the_engine_itself_refuses_writes(seeded):
    """
    The layer that actually matters. String checks can be argued with; FalkorDB
    refusing a write under RO_QUERY cannot. If this ever passes a write, the
    other tests are decoration.
    """
    g = store.connect()
    with pytest.raises(ResponseError, match="read-only"):
        g.ro_query("MATCH (e:Event) DETACH DELETE e")
    with pytest.raises(ResponseError, match="read-only"):
        g.ro_query("CREATE (:Event {raw: 'x'})")
    assert g.ro_query("MATCH (e:Event {session_id:'s1'}) RETURN count(e)").result_set[0][0] == 400


def test_execute_returns_columns_and_rows(seeded):
    cols, rows = query.execute(
        "MATCH (e:Event) WHERE e.session_id = $sid "
        "RETURN e.event_id AS event_id, e.src_ip AS src_ip", seeded
    )
    assert cols == ["event_id", "src_ip"]
    assert rows


def test_sid_is_bound_to_the_session(seeded):
    _, rows = query.execute(
        "MATCH (e:Event) WHERE e.session_id = $sid RETURN DISTINCT e.session_id", "s2"
    )
    assert rows == [["s2"]]


def test_limit_is_injected_when_absent(seeded):
    _, rows = query.execute("MATCH (e:Event) WHERE e.session_id = $sid RETURN e.event_id", seeded)
    assert len(rows) == query.ROW_LIMIT


def test_an_explicit_smaller_limit_is_respected(seeded):
    _, rows = query.execute(
        "MATCH (e:Event) WHERE e.session_id = $sid RETURN e.event_id LIMIT 7", seeded
    )
    assert len(rows) == 7


def test_whole_nodes_come_back_json_safe(seeded):
    _, rows = query.execute(
        "MATCH (e:Event)-[:FROM_IP]->(i:IP) WHERE e.session_id = $sid RETURN i LIMIT 1", seeded
    )
    assert rows[0][0]["_labels"] == ["IP"]
    assert rows[0][0]["address"] in {"203.0.113.45", "10.0.0.1"}


# -- the self-healing loop -------------------------------------------------


class _Scripted(LLMClient):
    """Returns queued GeneratedQuery objects; records the prompts it received."""

    def __init__(self, script):
        self.script = list(script)
        self.seen: list[list[dict]] = []
        self.chain = [object()]
        self.replay = False
        self.record = False
        self.last_provider = ""

    def structured(self, tag, messages, schema, system=None, effort="high",
                   max_tokens=16000):
        self.seen.append(list(messages))
        return self.script.pop(0) if self.script else None


def test_a_bad_query_is_retried_with_the_exact_error(seeded):
    bad = GeneratedQuery(cypher="MATCH (e:Event) DETACH DELETE e", explanation="x")
    good = GeneratedQuery(
        cypher="MATCH (e:Event) WHERE e.session_id = $sid RETURN e.event_id",
        explanation="ok",
    )
    client = _Scripted([bad, good])

    out = query.answer(client, seeded, "show me events")

    assert out["used_model"] is True
    assert out["row_count"] > 0
    assert len(out["attempts"]) == 1, "the rejected query should be reported, not hidden"
    assert "not permitted" in out["attempts"][0]["error"] or \
           "allowed" in out["attempts"][0]["error"]
    # the retry must carry the failure back to the model
    retry = client.seen[1]
    assert any("failed" in m["content"] for m in retry if m["role"] == "user")


def test_an_engine_error_is_retried_too(seeded):
    broken = GeneratedQuery(cypher="MATCH (e:Event RETURN e", explanation="x")
    good = GeneratedQuery(
        cypher="MATCH (e:Event) WHERE e.session_id = $sid RETURN count(e) AS n",
        explanation="ok",
    )
    out = query.answer(_Scripted([broken, good]), seeded, "how many events")
    assert out["rows"] == [[400]]
    assert len(out["attempts"]) == 1


def test_gives_up_after_max_attempts_and_falls_back(seeded):
    bad = GeneratedQuery(cypher="MATCH (e:Event) DELETE e", explanation="x")
    client = _Scripted([bad] * query.MAX_ATTEMPTS)

    out = query.answer(client, seeded, "show failed events")

    assert out["used_model"] is False, "should fall back rather than return nothing"
    assert len(out["attempts"]) == query.MAX_ATTEMPTS
    assert out["row_count"] > 0, "the keyword fallback should still answer"


def test_offline_uses_the_keyword_fallback(seeded):
    client = LLMClient()
    client.chain = []
    out = query.answer(client, seeded, "show failed events from 203.0.113.45")
    assert out["used_model"] is False
    assert out["row_count"] > 0
    assert "203.0.113.45" in out["cypher"]
    assert out["note"], "a keyword-matched answer must say so"


def test_fallback_scopes_to_the_session(seeded):
    client = LLMClient()
    client.chain = []
    out = query.answer(client, "s2", "everything")
    assert "$sid" in out["cypher"]
    assert out["row_count"] == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
