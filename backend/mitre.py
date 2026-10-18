"""
SentinelSOC - MITRE ATT&CK reference.

A deliberately small, curated slice. The investigation agent is given this
catalogue in its prompt and must pick from it, which stops it inventing
technique IDs that look plausible and are not real - the same hallucination
guard DataSentinel's logic gate applies to column names.
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
    "T1110": {"name": "Brute Force", "tactic": "credential_access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential_access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential_access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation"},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "privilege_escalation"},
    "T1136": {"name": "Create Account", "tactic": "persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence"},
    "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "discovery"},
    "T1021": {"name": "Remote Services", "tactic": "lateral_movement"},
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "impact"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
}

VALID_TACTICS = sorted({t["tactic"] for t in TECHNIQUES.values()})


def catalogue_for_prompt() -> str:
    """Render the catalogue for injection into the investigation prompt."""
    return "\n".join(
        f"  {tid} | {info['name']} | tactic: {info['tactic']}"
        for tid, info in TECHNIQUES.items()
    )


def validate(technique_id: str) -> dict[str, str] | None:
    """Return the canonical record, or None when the ID is not in the catalogue."""
    return TECHNIQUES.get(technique_id.strip().upper())


def coerce(technique_id: str, name: str = "", tactic: str = "") -> dict[str, str]:
    """
    Snap a model-supplied technique onto the catalogue.

    Exact hit wins. A sub-technique falls back to its parent. Anything else is
    reported as unmapped rather than silently accepted.
    """
    tid = technique_id.strip().upper()
    hit = TECHNIQUES.get(tid)
    if hit:
        return {"technique_id": tid, **hit}
    if "." in tid:
        parent = tid.split(".", 1)[0]
        hit = TECHNIQUES.get(parent)
        if hit:
            return {"technique_id": parent, **hit}
    return {
        "technique_id": tid,
        "name": name or "Unmapped technique",
        "tactic": tactic if tactic in VALID_TACTICS else "discovery",
    }
