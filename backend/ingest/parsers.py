"""
SentinelSOC - ingestion and normalisation.

Four native log formats in, one nine-field event schema out. This is the layer
LogGuard had and DataSentinel did not; the Drain3 template miner is lifted from
LogGuard's flink_jobs/parsers/drain3_parser.py, with Flink and its mandatory
drain3.ini dropped - the library's defaults are fine and one less file can go
missing on demo day.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from schemas import Event

try:
    from drain3 import TemplateMiner as _Drain
    from drain3.template_miner_config import TemplateMinerConfig

    _DRAIN_OK = True
except ImportError:  # template mining is an enhancement, never a hard dependency
    _DRAIN_OK = False


class TemplateMiner:
    """Thin wrapper so the rest of the codebase never imports drain3 directly."""

    def __init__(self) -> None:
        self._miner = _Drain(config=TemplateMinerConfig()) if _DRAIN_OK else None

    def mine(self, message: str) -> tuple[Optional[str], Optional[str]]:
        if self._miner is None:
            return None, None
        try:
            res = self._miner.add_log_message(message)
        except Exception:
            return None, None
        if not res:
            return None, None
        return str(res.get("cluster_id")), res.get("template_mined")


# ---------------------------------------------------------------------------
# Regexes  (compiled once)
# ---------------------------------------------------------------------------

_ISO = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)"

RE_AUTH_HEAD = re.compile(rf"^{_ISO}\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
RE_SSH_FAIL = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SSH_OK = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SUDO = re.compile(r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")
RE_USERADD = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
RE_SESSION = re.compile(r"session opened for user (?P<user>\S+)")

RE_NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) "[^"]*" "(?P<agent>[^"]*)"'
)

RE_FW = re.compile(
    rf"^{_ISO}\s+(?P<host>\S+)\s+kernel:\s+\[UFW (?P<verdict>ALLOW|BLOCK)\]\s+(?P<kv>.*)$"
)

RE_WIN = re.compile(rf"^{_ISO},(?P<eid>\d+),(?P<host>[^,]+),(?P<desc>[^,]+),(?P<kv>.*)$")


def _parse_ts(raw: str) -> datetime:
    txt = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(txt)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _kv(blob: str, sep: str = " ") -> dict[str, str]:
    out: dict[str, str] = {}
    for part in blob.split(sep):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------------------
# Per-source parsers
# ---------------------------------------------------------------------------


def parse_ssh_auth(line: str) -> Optional[Event]:
    head = RE_AUTH_HEAD.match(line)
    if not head:
        return None
    ts, host, proc, msg = (
        _parse_ts(head["ts"]),
        head["host"],
        head["proc"],
        head["msg"],
    )
    base = dict(ts=ts, source="ssh_auth", host=host, raw=line)

    if m := RE_SSH_FAIL.search(msg):
        return Event(**base, user=m["user"], src_ip=m["ip"], dst_port=22,
                     action="ssh_login", outcome="failure")
    if m := RE_SSH_OK.search(msg):
        return Event(**base, user=m["user"], src_ip=m["ip"], dst_port=22,
                     action="ssh_login", outcome="success")
    if proc == "sudo":
        if m := RE_SUDO.search(msg):
            return Event(**base, user=m["user"], action=f"sudo:{m['target']}",
                         outcome="success")
        if m := RE_SESSION.search(msg):
            return Event(**base, user=m["user"], action="sudo_session", outcome="success")
    if proc == "useradd":
        if m := RE_USERADD.search(msg):
            return Event(**base, user=m["user"], action="account_created",
                         outcome="success")
    if m := RE_SESSION.search(msg):
        return Event(**base, user=m["user"], action="session_opened", outcome="success")

    return Event(**base, action=proc, outcome="info")


def parse_nginx(line: str) -> Optional[Event]:
    m = RE_NGINX.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    status = int(m["status"])
    outcome = "success" if status < 400 else ("blocked" if status in (401, 403) else "failure")
    return Event(
        ts=ts, source="nginx_access", host="web-01", src_ip=m["ip"], dst_port=443,
        action=f"http_{m['method'].lower()}", outcome=outcome, raw=line,
        bytes_out=int(m["bytes"]),
    )


def parse_firewall(line: str) -> Optional[Event]:
    m = RE_FW.match(line)
    if not m:
        return None
    kv = _kv(m["kv"])
    port = kv.get("DPT")
    return Event(
        ts=_parse_ts(m["ts"]), source="firewall", host=m["host"],
        src_ip=kv.get("SRC"), dst_ip=kv.get("DST"),
        dst_port=int(port) if port and port.isdigit() else None,
        action=f"fw_{kv.get('PROTO', 'ip').lower()}",
        outcome="blocked" if m["verdict"] == "BLOCK" else "allowed",
        raw=line, bytes_out=int(kv.get("LEN", 0) or 0),
    )


_WIN_ACTIONS = {
    "4624": ("windows_logon", "success"),
    "4625": ("windows_logon", "failure"),
    "4663": ("file_access", "success"),
    "4688": ("process_create", "success"),
    "4720": ("account_created", "success"),
}


def parse_windows(line: str) -> Optional[Event]:
    m = RE_WIN.match(line)
    if not m:
        return None
    kv = _kv(m["kv"], sep=",")
    action, outcome = _WIN_ACTIONS.get(m["eid"], (f"win_{m['eid']}", "info"))
    return Event(
        ts=_parse_ts(m["ts"]), source="windows_security", host=m["host"],
        user=kv.get("SubjectUserName"), src_ip=kv.get("IpAddress"),
        action=action, outcome=outcome, raw=line,
    )


PARSERS = {
    "auth.log": parse_ssh_auth,
    "nginx_access.log": parse_nginx,
    "firewall.log": parse_firewall,
    "windows_security.log": parse_windows,
}

def parse_generic(line: str) -> Optional[Event]:
    # Try to find a timestamp
    m = re.search(_ISO, line)
    ts = _parse_ts(m.group("ts")) if m else datetime.now(timezone.utc)
    return Event(
        ts=ts, source="generic", host="unknown", action="generic_log",
        outcome="info", raw=line,
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


_RE_STRIP_TS = re.compile(rf"^{_ISO}[,\s]+")
_RE_STRIP_PID = re.compile(r"\[\d+\]")
_RE_STRIP_NUM = re.compile(r"\b\d+\b")


def _mine_key(ev: Event) -> str:
    """
    Template mining works on the message, not the envelope.

    Feeding Drain3 the raw line makes every entry near-unique because the
    timestamp and PID never repeat, which is why LogGuard's templates were so
    sparse. Strip the envelope first and cluster quality jumps.
    """
    text = _RE_STRIP_TS.sub("", ev.raw)
    text = _RE_STRIP_PID.sub("[]", text)
    return f"{ev.source}:{text}"


def parse_file(path: Path, miner: Optional[TemplateMiner] = None) -> Iterator[Event]:
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        
        ev = None
        # Try all specialized parsers first
        for parser in PARSERS.values():
            try:
                ev = parser(line)
                if ev is not None:
                    break
            except (ValueError, KeyError):
                pass
                
        # Fallback to generic parser if no specialized parser worked
        if ev is None:
            try:
                ev = parse_generic(line)
            except (ValueError, KeyError):
                pass
                
        if ev is None:
            continue
            
        if miner is not None:
            tid, tmpl = miner.mine(_mine_key(ev))
            ev.template_id, ev.template = tid, tmpl
        yield ev


def parse_directory(directory: Path) -> tuple[list[Event], dict[str, int]]:
    """Parse every known log file in a directory. Returns events sorted by time."""
    miner = TemplateMiner()
    events: list[Event] = []
    stats: dict[str, int] = {}
    for path in directory.iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        got = list(parse_file(path, miner))
        stats[path.name] = len(got)
        events.extend(got)
    events.sort(key=lambda e: e.ts)
    return events, stats
