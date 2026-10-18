"""
Redaction has to hold two properties at once: nothing sensitive leaves, and the
analysis still works. Deleting identifiers would satisfy the first and destroy
the second, which is why this pseudonymises consistently instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

from redaction import Redactor  # noqa: E402
from schemas import EvidenceRef, Incident, MitreTechnique  # noqa: E402

LINE = ("Failed password for mreddy from 10.0.4.31 port 45000 ssh2 "
        "contact=m.reddy@corp.co.in")


# -- what must never leave --------------------------------------------------


@pytest.mark.parametrize("secret,label", [
    ("m.reddy@corp.co.in", "EMAIL"),
    ("4123 5678 9012", "AADHAAR"),
    ("ABCDE1234F", "PAN"),
    ("+91 9876543210", "PHONE"),
])
def test_personal_data_never_appears_in_output(secret, label):
    out = Redactor("pii").redact(f"user record: {secret} end")
    assert secret not in out
    assert label in out


@pytest.mark.parametrize("mode", ["pii", "strict"])
def test_credentials_are_destroyed_not_tokenised(mode):
    """A password has no analytical value, so it is not worth a reversible token."""
    r = Redactor(mode)
    out = r.redact("login password=hunter2 token: abc123xyz")
    assert "hunter2" not in out and "abc123xyz" not in out
    assert "<REDACTED>" in out
    assert "hunter2" not in r.restore(out), "a secret must not come back"


# -- what must survive, because the analysis needs it -----------------------


def test_pii_mode_keeps_operational_identifiers():
    """Strip the addresses and accounts and there is nothing left to correlate."""
    out = Redactor("pii").redact(LINE)
    assert "10.0.4.31" in out and "mreddy" in out
    assert "m.reddy@corp.co.in" not in out


def test_strict_mode_pseudonymises_addresses_but_stays_correlatable():
    r = Redactor("strict")
    a = r.redact("SRC=10.0.4.31 DST=185.220.101.34")
    b = r.redact("connection from 10.0.4.31 again")

    assert "10.0.4.31" not in a and "10.0.4.31" not in b
    token = a.split("SRC=")[1].split(" ")[0]
    assert token in b, "the same address must map to the same token, or correlation breaks"
    assert token.startswith("INT_IP")
    assert "EXT_IP" in a, "public and private addresses stay distinguishable"


def test_tokens_are_stable_across_calls_and_unique_per_value():
    r = Redactor("strict")
    first = r.redact("10.0.4.31 and 10.0.4.99")
    second = r.redact("10.0.4.31")
    t1, t2 = first.split(" and ")
    assert t1 != t2, "different addresses must not collide"
    assert second == t1


# -- reversibility ----------------------------------------------------------


def test_round_trip_restores_the_original():
    r = Redactor("strict")
    out = r.redact(LINE)
    assert r.restore(out) == LINE


def test_restore_walks_nested_agent_output():
    r = Redactor("strict")
    r.redact("10.0.4.31 talked to web-01")
    payload = {
        "narrative": "INT_IP_01 reached HOST_01",
        "evidence": [{"claim": "INT_IP_01 was the source", "ids": [1]}],
    }
    out = r.restore_obj(payload)
    assert out["narrative"] == "10.0.4.31 reached web-01"
    assert out["evidence"][0]["claim"] == "10.0.4.31 was the source"
    assert out["evidence"][0]["ids"] == [1], "non-strings pass through untouched"


def test_restore_model_returns_a_validated_instance():
    r = Redactor("strict")
    r.redact("host web-01 here")
    inc = Incident(
        incident_id="INC-001", title="HOST_01 compromised",
        narrative="HOST_01 was reached", signal_ids=[1],
        kill_chain_stage="initial_access",
        mitre_techniques=[MitreTechnique(technique_id="T1078", name="Valid Accounts",
                                         tactic="initial_access")],
        risk_score=80, risk_rationale="r", severity="high",
        affected_hosts=["HOST_01"], affected_users=[],
        evidence=[EvidenceRef(claim="HOST_01 seen", event_ids=[1])], confidence=0.8,
    )
    out = r.restore_model(inc)
    assert isinstance(out, Incident)
    assert out.title == "web-01 compromised"
    assert out.affected_hosts == ["web-01"]
    assert out.evidence[0].claim == "web-01 seen"
    assert out.risk_score == 80


def test_longer_tokens_restore_before_shorter_prefixes():
    """INT_IP_1 must not eat the prefix of INT_IP_11."""
    r = Redactor("strict")
    text = " ".join(f"10.0.4.{i}" for i in range(1, 15))
    out = r.redact(text)
    assert r.restore(out) == text


# -- modes and safety -------------------------------------------------------


def test_off_mode_is_a_pass_through():
    assert Redactor("off").redact(LINE) == LINE
    assert Redactor("off").enabled is False


def test_unknown_mode_falls_back_to_pii_not_off():
    """A typo in REDACT_MODE must fail safe, never silently disable redaction."""
    r = Redactor("nonsense")
    assert r.mode == "pii" and r.enabled


def test_env_var_selects_the_mode(monkeypatch):
    monkeypatch.setenv("REDACT_MODE", "strict")
    assert Redactor().mode == "strict"


def test_default_is_pii():
    assert Redactor(None).mode == "pii"


def test_empty_and_none_are_safe():
    r = Redactor("strict")
    assert r.redact("") == ""
    assert r.restore("") == ""


def test_event_redaction_covers_raw_and_identifiers():
    r = Redactor("strict")
    event = {"event_id": 1, "raw": LINE, "host": "web-01", "src_ip": "10.0.4.31",
             "user": "mreddy", "action": "ssh_login"}
    out = r.redact_event(event)
    assert "10.0.4.31" not in out["raw"]
    assert out["src_ip"].startswith("INT_IP")
    assert out["host"].startswith("HOST")
    assert out["event_id"] == 1 and out["action"] == "ssh_login"
    assert event["raw"] == LINE, "the original event must not be mutated"


def test_summary_reports_what_was_pseudonymised():
    r = Redactor("strict")
    r.redact("10.0.4.31 and 185.220.101.34 and a@b.co")
    s = r.summary()
    assert s["mode"] == "strict" and s["values_pseudonymised"] == 3
    assert s["by_category"] == {"INT_IP": 1, "EXT_IP": 1, "EMAIL": 1}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
