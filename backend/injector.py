"""
SentinelSOC - live log injector.

Generates individual normalised events on demand — either benign (background
noise) or anomalous (attack indicators).  Used by the inject API endpoints to
simulate a live log feed.

Each call to `random_event()` or `anomaly_event()` returns a single Event
ready to be stored via `store.insert_events()`.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Literal

from schemas import Event

HOSTS = ["web-01", "web-02", "app-01", "app-02", "db-01", "fs-01", "win-dc-01"]
USERS = ["alice", "bob", "carol", "dinesh", "mreddy", "svc_deploy", "svc_backup", "priya"]
INTERNAL = [f"10.0.4.{i}" for i in range(10, 60)]

_rng = random.Random()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Normal (benign) events
# ---------------------------------------------------------------------------

def _ssh_login() -> Event:
    host = _rng.choice(HOSTS[:5])
    user = _rng.choice(USERS[:5])
    ip = _rng.choice(INTERNAL)
    outcome: Literal["success", "failure"] = _rng.choices(
        ["success", "failure"], weights=[93, 7]
    )[0]
    action = "login_accepted" if outcome == "success" else "login_failed"
    pid = _rng.randint(1000, 9999)
    verb = "Accepted publickey" if outcome == "success" else "Failed password"
    raw = (
        f"{_now().isoformat()} {host} sshd[{pid}]: {verb} for {user} "
        f"from {ip} port {_rng.randint(40000, 60000)} ssh2"
    )
    return Event(
        ts=_now(), source="ssh_auth", host=host, user=user, src_ip=ip,
        action=action, outcome=outcome, raw=raw,
    )


def _web_request() -> Event:
    ip = _rng.choice(INTERNAL + ["203.0.113.9", "198.51.100.5"])
    urls = ["/", "/login", "/dashboard", "/api/orders", "/api/users/me",
            "/health", "/api/products", "/checkout"]
    url = _rng.choice(urls)
    code = _rng.choices([200, 200, 200, 304, 404, 500], k=1)[0]
    outcome: Literal["success", "failure"] = "success" if code < 400 else "failure"
    host = _rng.choice(HOSTS[:2])
    raw = (
        f'{ip} - - [{_now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"GET {url} HTTP/1.1" {code} {_rng.randint(180, 9000)} '
        f'"-" "Mozilla/5.0 (X11; Linux x86_64)"'
    )
    return Event(
        ts=_now(), source="nginx_access", host=host, src_ip=ip,
        action=f"GET {url}", outcome=outcome, raw=raw, bytes_out=_rng.randint(180, 9000),
    )


def _fw_allow() -> Event:
    ip = _rng.choice(INTERNAL)
    port = _rng.choice([80, 443, 22, 5432])
    raw = (
        f"{_now().isoformat()} fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= "
        f"SRC={ip} DST=10.0.4.10 PROTO=TCP "
        f"SPT={_rng.randint(40000, 60000)} DPT={port} LEN={_rng.randint(60, 1500)}"
    )
    return Event(
        ts=_now(), source="firewall", host="fw-01", src_ip=ip,
        dst_ip="10.0.4.10", dst_port=port,
        action="allow", outcome="allowed", raw=raw,
    )


def _win_login() -> Event:
    user = _rng.choice(USERS[:5])
    ip = _rng.choice(INTERNAL)
    raw = (
        f"{_now().isoformat()},4624,win-dc-01,An account was successfully logged on,"
        f"SubjectUserName={user},IpAddress={ip},LogonType=3"
    )
    return Event(
        ts=_now(), source="windows_security", host="win-dc-01",
        user=user, src_ip=ip, action="logon", outcome="success", raw=raw,
    )


_NORMAL_GENERATORS = [_ssh_login, _web_request, _fw_allow, _win_login]


def random_event() -> Event:
    """Generate one random benign event."""
    gen = _rng.choices(_NORMAL_GENERATORS, weights=[30, 45, 20, 5])[0]
    return gen()


# ---------------------------------------------------------------------------
# Anomaly events — attack indicators
# ---------------------------------------------------------------------------

def _ssh_brute_force() -> Event:
    """Failed SSH login from a suspicious external IP — classic brute force."""
    attacker = f"{_rng.randint(100, 220)}.{_rng.randint(0, 255)}.{_rng.randint(0, 255)}.{_rng.randint(1, 254)}"
    user = _rng.choice(["root", "admin", "test", "oracle", "postgres", "ubuntu"])
    host = _rng.choice(HOSTS[:2])
    pid = _rng.randint(20000, 29999)
    raw = (
        f"{_now().isoformat()} {host} sshd[{pid}]: Failed password for "
        f"{'invalid user ' if user in ('test', 'oracle') else ''}{user} "
        f"from {attacker} port {_rng.randint(45000, 55000)} ssh2"
    )
    return Event(
        ts=_now(), source="ssh_auth", host=host, user=user, src_ip=attacker,
        action="login_failed", outcome="failure", raw=raw,
    )


def _sqli_attempt() -> Event:
    """SQL injection probe in a web request."""
    attacker = f"{_rng.randint(100, 220)}.{_rng.randint(0, 255)}.{_rng.randint(0, 255)}.{_rng.randint(1, 254)}"
    paths = [
        "/api/products?id=1' OR '1'='1",
        "/api/products?id=1 UNION SELECT username,password FROM users",
        "/login?next=' UNION SELECT NULL,version()--",
        "/api/search?q=' OR 1=1--",
        "/api/users?id=1; DROP TABLE sessions--",
    ]
    path = _rng.choice(paths)
    host = _rng.choice(HOSTS[:2])
    raw = (
        f'{attacker} - - [{_now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"GET {path} HTTP/1.1" {_rng.choice([200, 403, 500])} '
        f'{_rng.randint(200, 800)} "-" "sqlmap/1.8.2"'
    )
    return Event(
        ts=_now(), source="nginx_access", host=host, src_ip=attacker,
        action=f"GET {path}", outcome="failure", raw=raw,
    )


def _port_scan() -> Event:
    """Firewall block from a port scan."""
    attacker = f"{_rng.randint(100, 220)}.{_rng.randint(0, 255)}.{_rng.randint(0, 255)}.{_rng.randint(1, 254)}"
    port = _rng.choice([21, 23, 25, 135, 139, 445, 1433, 3389, 5900, 8080, 27017])
    raw = (
        f"{_now().isoformat()} fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= "
        f"SRC={attacker} DST=10.0.4.12 PROTO=TCP "
        f"SPT={_rng.randint(50000, 60000)} DPT={port} LEN=44"
    )
    return Event(
        ts=_now(), source="firewall", host="fw-01", src_ip=attacker,
        dst_ip="10.0.4.12", dst_port=port,
        action="block", outcome="blocked", raw=raw,
    )


def _priv_escalation() -> Event:
    """Suspicious sudo to root."""
    user = _rng.choice(["svc_deploy", "svc_backup"])
    raw = (
        f"{_now().isoformat()} web-01 sudo:  {user} : TTY=pts/1 ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
    )
    return Event(
        ts=_now(), source="ssh_auth", host="web-01", user=user,
        action="sudo_root", outcome="success", raw=raw,
    )


def _data_exfil() -> Event:
    """Large outbound transfer to an external IP — possible exfiltration."""
    exfil_ip = f"{_rng.randint(100, 220)}.{_rng.randint(0, 255)}.{_rng.randint(0, 255)}.{_rng.randint(1, 254)}"
    size = _rng.randint(1_400_000, 3_000_000)
    raw = (
        f"{_now().isoformat()} fw-01 kernel: [UFW ALLOW] IN= OUT=eth0 "
        f"SRC=10.0.4.31 DST={exfil_ip} PROTO=TCP "
        f"SPT={_rng.randint(50000, 60000)} DPT=443 LEN={size}"
    )
    return Event(
        ts=_now(), source="firewall", host="fw-01", src_ip="10.0.4.31",
        dst_ip=exfil_ip, dst_port=443,
        action="allow", outcome="allowed", raw=raw, bytes_out=size,
    )


_ANOMALY_GENERATORS = [
    _ssh_brute_force,
    _sqli_attempt,
    _port_scan,
    _priv_escalation,
    _data_exfil,
]


def anomaly_event() -> Event:
    """Generate one random anomalous event (attack indicator)."""
    gen = _rng.choice(_ANOMALY_GENERATORS)
    return gen()
