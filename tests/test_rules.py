"""
Rule-level tests, isolated from the sample data.

The end-to-end tests prove the rules fire on the planted chains. These prove
they DON'T fire on the shapes that look similar but are benign - which is the
harder half, and the half that decides whether an analyst trusts the tool.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

from detect.rules import (  # noqa: E402
    rule_credential_spray, rule_failed_login_burst, rule_lateral_movement,
    rule_web_injection,
)
from schemas import Event  # noqa: E402

T0 = datetime(2026, 3, 15, 3, 0, tzinfo=timezone.utc)
_n = 0


def ev(**kw) -> Event:
    global _n
    _n += 1
    base = dict(
        event_id=_n, ts=T0, source="ssh_auth", host="web-01", user="alice",
        src_ip="10.0.4.11", action="ssh_login", outcome="success", raw="line",
    )
    base.update(kw)
    return Event(**base)


# -- R008 lateral movement --------------------------------------------------


def test_lateral_fires_on_many_hosts_from_one_origin():
    evs = [ev(host=h, user="svc_deploy", src_ip="10.0.4.11",
              ts=T0 + timedelta(minutes=i * 4))
           for i, h in enumerate(["db-01", "app-01", "app-02", "fs-01", "win-dc-01"])]
    sigs = rule_lateral_movement(evs)
    assert len(sigs) == 1
    assert sigs[0].entity == "svc_deploy" and sigs[0].severity == "critical"
    assert "5 distinct" in sigs[0].detail


def test_lateral_ignores_an_admin_working_from_many_workstations():
    """Same host count, many origins - routine work, not a pivot."""
    evs = [ev(host=h, user="alice", src_ip=f"10.0.4.{20 + i}",
              ts=T0 + timedelta(minutes=i * 4))
           for i, h in enumerate(["db-01", "app-01", "app-02", "fs-01", "win-dc-01"])]
    assert rule_lateral_movement(evs) == []


def test_lateral_ignores_repeated_logins_to_one_host():
    evs = [ev(host="db-01", user="svc_deploy", ts=T0 + timedelta(minutes=i))
           for i in range(20)]
    assert rule_lateral_movement(evs) == []


def test_lateral_ignores_failed_logins():
    """Failures are R001's business; a pivot is defined by success."""
    evs = [ev(host=h, user="svc_deploy", outcome="failure",
              ts=T0 + timedelta(minutes=i * 4))
           for i, h in enumerate(["db-01", "app-01", "app-02", "fs-01", "win-dc-01"])]
    assert rule_lateral_movement(evs) == []


def test_lateral_ignores_hosts_touched_slowly_over_a_day():
    evs = [ev(host=h, user="svc_deploy", ts=T0 + timedelta(hours=i * 3))
           for i, h in enumerate(["db-01", "app-01", "app-02", "fs-01", "win-dc-01"])]
    assert rule_lateral_movement(evs) == []


# -- R009 credential spraying ----------------------------------------------


def _spray(users: int, per_user: int, ip="198.51.100.203", gap=30):
    out, t = [], T0
    for u in range(users):
        for _ in range(per_user):
            out.append(ev(user=f"user{u:02d}", src_ip=ip, outcome="failure", ts=t))
            t += timedelta(seconds=gap)
    return out


def test_spray_fires_on_thin_cover_across_many_accounts():
    sigs = rule_credential_spray(_spray(users=20, per_user=2))
    assert len(sigs) == 1
    assert sigs[0].entity == "198.51.100.203"
    assert "not" in sigs[0].detail and "brute force" in sigs[0].detail


def test_spray_ignores_a_burst_against_one_account():
    """Deep on one account is brute force, and R001 names it correctly."""
    assert rule_credential_spray(_spray(users=1, per_user=40)) == []


def test_spray_ignores_deep_attempts_even_across_several_accounts():
    assert rule_credential_spray(_spray(users=20, per_user=8)) == []


def test_spray_needs_enough_accounts_to_be_a_spray():
    assert rule_credential_spray(_spray(users=4, per_user=2)) == []


def test_brute_force_defers_to_spray_on_the_spray_shape():
    """The two rules must not both claim the same traffic."""
    evs = _spray(users=20, per_user=2, gap=5)     # dense enough for R001's window
    assert rule_failed_login_burst(evs) == []
    assert rule_credential_spray(evs)


def test_brute_force_still_fires_on_a_real_burst():
    evs = [ev(user=f"u{i % 3}", src_ip="203.0.113.45", outcome="failure",
              ts=T0 + timedelta(seconds=i * 5)) for i in range(40)]
    sigs = rule_failed_login_burst(evs)
    assert len(sigs) == 1 and sigs[0].entity == "203.0.113.45"


# -- R003 injection ---------------------------------------------------------


def test_injection_sees_through_percent_encoding():
    """
    The bug this guards: attackers encode payloads, and matching the raw line
    missed an entire attack chain until the decode was added.
    """
    encoded = ev(
        source="nginx_access", src_ip="198.51.100.77", action="http_get",
        raw='198.51.100.77 - - [15/Mar/2026:11:12:09 +0000] '
            '"GET /api?id=1%20UNION%20SELECT%20pw%20FROM%20users HTTP/1.1" 200 400 "-" "x"',
    )
    sigs = rule_web_injection([encoded])
    assert len(sigs) == 1 and "UNION" in sigs[0].detail.upper()


def test_injection_ignores_ordinary_traffic():
    normal = ev(source="nginx_access", src_ip="10.0.4.20", action="http_get",
                raw='10.0.4.20 - - [15/Mar/2026:09:00:00 +0000] '
                    '"GET /api/products?id=42 HTTP/1.1" 200 900 "-" "Mozilla/5.0"')
    assert rule_web_injection([normal]) == []


def test_injection_escalates_when_the_payload_succeeded():
    blocked = ev(source="nginx_access", src_ip="1.2.3.4", outcome="blocked",
                 raw="GET /x?q=%27%20OR%20%271%27=%271 403")
    served = ev(source="nginx_access", src_ip="5.6.7.8", outcome="success",
                raw="GET /x?q=%27%20OR%20%271%27=%271 200")
    assert rule_web_injection([blocked])[0].severity == "high"
    assert rule_web_injection([served])[0].severity == "critical"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
