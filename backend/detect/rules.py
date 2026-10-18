"""
SentinelSOC - deterministic detection rules.

Cheap, fast, explainable. These run before any model is loaded and before any
token is spent, and they produce *signals* - candidates - never verdicts. The
agent layer only ever sees what survived this gate, which is what bounds cost
and what lets you answer "is this just prompting?" with a no.

Modelled on Sigma correlation rules, kept deliberately readable.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote_plus
from datetime import timedelta
from typing import Callable

from schemas import Event, Severity, Signal

# ---------------------------------------------------------------------------
# Tunables. Every threshold here is one a SOC analyst would recognise.
# ---------------------------------------------------------------------------

FAILED_LOGIN_COUNT = 10
FAILED_LOGIN_WINDOW = timedelta(minutes=10)
PORT_SWEEP_DISTINCT = 15
PORT_SWEEP_WINDOW = timedelta(minutes=10)
SUCCESS_AFTER_FAIL_WINDOW = timedelta(minutes=10)
EGRESS_SIGMA = 3.0
EGRESS_MIN_BYTES = 1_000_000
OFF_HOURS = range(22, 24)

INJECTION_PATTERNS = [
    (r"union\s+select", "SQL UNION injection"),
    (r"'\s*or\s*'?1'?\s*=\s*'?1", "SQL tautology injection"),
    (r";\s*drop\s+table", "SQL DROP statement"),
    (r"--\s*$", "SQL comment terminator"),
    (r"\.\./\.\./", "Path traversal"),
    (r"<script[^>]*>", "Cross-site scripting"),
    (r"/etc/passwd", "Sensitive file access attempt"),
]
_INJECTION = [(re.compile(p, re.I), label) for p, label in INJECTION_PATTERNS]

_SEV_ORDER: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _sample(events: list[Event], n: int = 5) -> list[str]:
    return [e.raw for e in events[:n]]


def _mk(
    rule_id: str,
    title: str,
    severity: Severity,
    events: list[Event],
    entity: str,
    entity_kind: str,
    score: float,
    detail: str,
) -> Signal:
    ordered = sorted(events, key=lambda e: e.ts)
    return Signal(
        detector="rule",
        rule_id=rule_id,
        title=title,
        severity=severity,
        ts_start=ordered[0].ts,
        ts_end=ordered[-1].ts,
        host=ordered[0].host,
        entity=entity,
        entity_kind=entity_kind,
        score=round(min(score, 1.0), 3),
        event_ids=[e.event_id for e in ordered],
        evidence_sample=_sample(ordered),
        detail=detail,
    )


# ---------------------------------------------------------------------------
# R001 - authentication brute force
# ---------------------------------------------------------------------------


def rule_failed_login_burst(events: list[Event]) -> list[Signal]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.action in ("ssh_login", "windows_logon") and e.outcome == "failure" and e.src_ip:
            by_ip[e.src_ip].append(e)

    out: list[Signal] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        i = 0
        for j in range(len(evs)):
            while evs[j].ts - evs[i].ts > FAILED_LOGIN_WINDOW:
                i += 1
            window = evs[i : j + 1]
            if len(window) >= FAILED_LOGIN_COUNT and (
                j == len(evs) - 1 or evs[j + 1].ts - evs[i].ts > FAILED_LOGIN_WINDOW
            ):
                users = sorted({e.user for e in window if e.user})
                per_user: dict[str, int] = defaultdict(int)
                for ev in window:
                    if ev.user:
                        per_user[ev.user] += 1
                # Thin cover across many accounts is a spray, and R009 says so
                # precisely. Two rules describing one thing as different attacks
                # is noise an analyst has to reconcile.
                #
                # The bound is 6, not R009's 12: this window is 10 minutes while
                # R009 looks over an hour, so a spray pacing itself shows only a
                # slice of its accounts here. A real brute force still lands
                # many attempts per account and is untouched by this.
                if len(per_user) >= 6 and per_user and max(per_user.values()) <= 3:
                    break
                out.append(
                    _mk(
                        "R001",
                        f"Authentication brute force from {ip}",
                        "high",
                        window,
                        ip,
                        "src_ip",
                        min(0.55 + len(window) / 100, 0.95),
                        f"{len(window)} failed authentications in "
                        f"{(window[-1].ts - window[0].ts).seconds // 60} minutes "
                        f"against {len(users)} distinct accounts: {', '.join(users[:8])}",
                    )
                )
                break
    return out


# ---------------------------------------------------------------------------
# R002 - port sweep
# ---------------------------------------------------------------------------


def rule_port_sweep(events: list[Event]) -> list[Signal]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "firewall" and e.src_ip and e.dst_port:
            by_ip[e.src_ip].append(e)

    out: list[Signal] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        i = 0
        for j in range(len(evs)):
            while evs[j].ts - evs[i].ts > PORT_SWEEP_WINDOW:
                i += 1
            window = evs[i : j + 1]
            ports = {e.dst_port for e in window}
            if len(ports) >= PORT_SWEEP_DISTINCT:
                blocked = sum(1 for e in window if e.outcome == "blocked")
                out.append(
                    _mk(
                        "R002",
                        f"Port sweep from {ip}",
                        "medium",
                        window,
                        ip,
                        "src_ip",
                        min(0.5 + len(ports) / 80, 0.9),
                        f"{len(ports)} distinct destination ports probed in "
                        f"{max((window[-1].ts - window[0].ts).seconds // 60, 1)} minutes "
                        f"({blocked} blocked by firewall)",
                    )
                )
                break
    return out


# ---------------------------------------------------------------------------
# R003 - web injection attempt
# ---------------------------------------------------------------------------


def rule_web_injection(events: list[Event]) -> list[Signal]:
    hits: dict[str, list[tuple[Event, str]]] = defaultdict(list)
    for e in events:
        if e.source != "nginx_access" or not e.src_ip:
            continue
        # Attackers percent-encode payloads precisely so naive matching misses
        # them. Decode twice: single encoding is the norm, double is common.
        decoded = unquote_plus(unquote_plus(e.raw))
        for pattern, label in _INJECTION:
            if pattern.search(decoded):
                hits[e.src_ip].append((e, label))
                break

    out: list[Signal] = []
    for ip, pairs in hits.items():
        evs = [e for e, _ in pairs]
        labels = sorted({lbl for _, lbl in pairs})
        succeeded = sum(1 for e in evs if e.outcome == "success")
        out.append(
            _mk(
                "R003",
                f"Web application injection attempts from {ip}",
                "critical" if succeeded else "high",
                evs,
                ip,
                "src_ip",
                min(0.6 + 0.08 * len(evs) + (0.2 if succeeded else 0), 0.97),
                f"{len(evs)} injection attempts ({'; '.join(labels)}). "
                f"{succeeded} returned a success status - "
                f"{'the payload was likely served' if succeeded else 'all were rejected'}.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# R004 - successful login straight after a failed burst
# ---------------------------------------------------------------------------


def rule_success_after_failures(events: list[Event]) -> list[Signal]:
    fails: dict[str, list[Event]] = defaultdict(list)
    succs: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.action not in ("ssh_login", "windows_logon") or not e.src_ip:
            continue
        (fails if e.outcome == "failure" else succs)[e.src_ip].append(e)

    out: list[Signal] = []
    for ip, ok_events in succs.items():
        prior = fails.get(ip)
        if not prior:
            continue
        prior.sort(key=lambda e: e.ts)
        for ok in sorted(ok_events, key=lambda e: e.ts):
            recent = [f for f in prior if timedelta(0) < ok.ts - f.ts <= SUCCESS_AFTER_FAIL_WINDOW]
            if len(recent) >= FAILED_LOGIN_COUNT:
                out.append(
                    _mk(
                        "R004",
                        f"Successful login after {len(recent)} failures from {ip}",
                        "critical",
                        recent + [ok],
                        ip,
                        "src_ip",
                        0.95,
                        f"Account '{ok.user}' authenticated successfully at "
                        f"{ok.ts:%H:%M:%S} after {len(recent)} failed attempts from the "
                        f"same address. This is the signature of a successful "
                        f"credential-guessing attack.",
                    )
                )
                break
    return out


# ---------------------------------------------------------------------------
# R005 - anomalous egress volume
# ---------------------------------------------------------------------------


def rule_egress_volume(events: list[Event]) -> list[Signal]:
    outbound = [
        e for e in events
        if e.bytes_out >= EGRESS_MIN_BYTES and (e.dst_ip or e.source == "nginx_access")
    ]
    if not outbound:
        return []

    all_bytes = [e.bytes_out for e in events if e.bytes_out > 0]
    if len(all_bytes) < 20:
        return []
    mean = sum(all_bytes) / len(all_bytes)
    var = sum((b - mean) ** 2 for b in all_bytes) / len(all_bytes)
    sd = var ** 0.5
    threshold = max(mean + EGRESS_SIGMA * sd, EGRESS_MIN_BYTES)

    by_entity: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in outbound:
        if e.bytes_out < threshold:
            continue
        key = (e.dst_ip or "external", e.src_ip or e.host)
        by_entity[key].append(e)

    out: list[Signal] = []
    for (dst, src), evs in by_entity.items():
        total = sum(e.bytes_out for e in evs)
        off_hours = any(e.ts.hour in OFF_HOURS for e in evs)
        out.append(
            _mk(
                "R005",
                f"Large outbound transfer {src} -> {dst}",
                "critical" if off_hours else "high",
                evs,
                src,
                "src_ip",
                min(0.6 + (0.2 if off_hours else 0) + len(evs) / 60, 0.95),
                f"{total / 1_048_576:.1f} MB across {len(evs)} transfers to {dst}, "
                f"each above the {threshold / 1_048_576:.1f} MB "
                f"({EGRESS_SIGMA}-sigma) baseline"
                + (". Activity occurred outside business hours." if off_hours else "."),
            )
        )
    return out


# ---------------------------------------------------------------------------
# R006 - privilege escalation and persistence
# ---------------------------------------------------------------------------


def rule_privilege_escalation(events: list[Event]) -> list[Signal]:
    interesting = [
        e for e in events
        if e.action.startswith("sudo:root")
        or e.action == "account_created"
        or (e.action == "process_create" and re.search(r"rclone|7z\.exe|psexec|mimikatz", e.raw, re.I))
    ]
    if not interesting:
        return []

    by_host: dict[str, list[Event]] = defaultdict(list)
    for e in interesting:
        by_host[e.host].append(e)

    out: list[Signal] = []
    for host, evs in by_host.items():
        users = sorted({e.user for e in evs if e.user})
        kinds = sorted({e.action for e in evs})
        out.append(
            _mk(
                "R006",
                f"Privilege escalation or persistence activity on {host}",
                "high",
                evs,
                users[0] if users else host,
                "user" if users else "host",
                min(0.6 + 0.1 * len(evs), 0.92),
                f"{len(evs)} elevation/persistence events by {', '.join(users) or 'unknown'}: "
                f"{', '.join(kinds)}",
            )
        )
    return out


# ---------------------------------------------------------------------------
# R007 - off-hours bulk file access
# ---------------------------------------------------------------------------


def rule_offhours_file_access(events: list[Event]) -> list[Signal]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.action == "file_access" and e.user and e.ts.hour in OFF_HOURS:
            by_user[e.user].append(e)

    out: list[Signal] = []
    for user, evs in by_user.items():
        if len(evs) < 20:
            continue
        span = max((evs[-1].ts - evs[0].ts).seconds // 60, 1)
        out.append(
            _mk(
                "R007",
                f"Off-hours bulk file access by {user}",
                "high",
                evs,
                user,
                "user",
                min(0.55 + len(evs) / 120, 0.9),
                f"{len(evs)} file access events in {span} minutes between 22:00 and "
                f"midnight - well outside this account's normal working pattern.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# R008 - lateral movement
# ---------------------------------------------------------------------------

LATERAL_DISTINCT_HOSTS = 4
LATERAL_WINDOW = timedelta(minutes=45)
# The discriminator. An attacker pivots FROM a foothold, so many hosts are
# reached from one or two addresses. A real admin's logins come from all over
# the estate - in the sample data, one account touched 5 hosts from 50 distinct
# sources, which is routine work, not an intrusion. Without this bound the rule
# flags every busy operator in the company.
LATERAL_MAX_SOURCES = 2


def rule_lateral_movement(events: list[Event]) -> list[Signal]:
    """
    One account authenticating to many hosts in quick succession.

    Distinct from brute force: these succeed. A service account that normally
    touches one host reaching five in half an hour is an attacker walking the
    network with credentials that already work.
    """
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.action in ("ssh_login", "windows_logon") and e.outcome == "success" and e.user:
            by_user[e.user].append(e)

    out: list[Signal] = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e.ts)
        i = 0
        best: list[Event] | None = None
        for j in range(len(evs)):
            while evs[j].ts - evs[i].ts > LATERAL_WINDOW:
                i += 1
            window = evs[i : j + 1]
            hosts = {e.host for e in window}
            sources = {e.src_ip for e in window if e.src_ip}
            if len(hosts) < LATERAL_DISTINCT_HOSTS:
                continue
            if len(sources) > LATERAL_MAX_SOURCES:
                continue
            if best is None or len(hosts) > len({e.host for e in best}):
                best = window
        if best is None:
            continue
        hosts = sorted({e.host for e in best})
        sources = sorted({e.src_ip for e in best if e.src_ip})
        out.append(
            _mk(
                "R008",
                f"Lateral movement by {user} across {len(hosts)} hosts",
                "critical",
                best,
                user,
                "user",
                min(0.6 + len(hosts) / 15, 0.95),
                f"Account '{user}' authenticated successfully to {len(hosts)} distinct "
                f"hosts ({', '.join(hosts)}) within "
                f"{max((best[-1].ts - best[0].ts).seconds // 60, 1)} minutes, "
                f"all from {' and '.join(sources) or 'an unknown source'}. "
                f"Many hosts reached from a single origin is an attacker pivoting "
                f"with credentials that already work, not an operator at their desk.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# R009 - credential spraying
# ---------------------------------------------------------------------------

SPRAY_DISTINCT_USERS = 12
SPRAY_MAX_PER_USER = 3
SPRAY_WINDOW = timedelta(hours=1)


def rule_credential_spray(events: list[Event]) -> list[Signal]:
    """
    Few attempts against many accounts - the inverse shape of brute force.

    Sprays stay deliberately under per-account lockout thresholds, so a rule
    counting failures per account never fires. Counting distinct ACCOUNTS per
    source is what catches it.
    """
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.action in ("ssh_login", "windows_logon") and e.outcome == "failure"                 and e.src_ip and e.user:
            by_ip[e.src_ip].append(e)

    out: list[Signal] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        i = 0
        for j in range(len(evs)):
            while evs[j].ts - evs[i].ts > SPRAY_WINDOW:
                i += 1
            window = evs[i : j + 1]
            per_user: dict[str, int] = defaultdict(int)
            for e in window:
                per_user[e.user] += 1
            if len(per_user) < SPRAY_DISTINCT_USERS:
                continue
            # A burst against one account is R001's job, not this rule's.
            if max(per_user.values()) > SPRAY_MAX_PER_USER:
                continue
            out.append(
                _mk(
                    "R009",
                    f"Credential spraying from {ip}",
                    "high",
                    window,
                    ip,
                    "src_ip",
                    min(0.6 + len(per_user) / 60, 0.92),
                    f"{len(window)} failed authentications spread across "
                    f"{len(per_user)} distinct accounts, at most "
                    f"{max(per_user.values())} per account - low enough to stay under "
                    f"per-account lockout thresholds. This is a password spray, not "
                    f"a brute force.",
                )
            )
            break
    return out


RULES: list[Callable[[list[Event]], list[Signal]]] = [
    rule_failed_login_burst,
    rule_port_sweep,
    rule_web_injection,
    rule_success_after_failures,
    rule_egress_volume,
    rule_privilege_escalation,
    rule_offhours_file_access,
    rule_lateral_movement,
    rule_credential_spray,
]


def run_rules(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for rule in RULES:
        try:
            signals.extend(rule(events))
        except Exception as exc:
            print(f"[detect] rule {rule.__name__} failed: {type(exc).__name__}: {exc}")
    signals.sort(key=lambda s: (-_SEV_ORDER[s.severity], -s.score))
    return signals
