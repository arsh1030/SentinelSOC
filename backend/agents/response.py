"""
Agent 3 - Response Agent.

Turns one incident into a playbook an analyst can execute, ordered by urgency and
split into containment, eradication, recovery and hardening. Every action is
tagged manual or automated, because "recommended response" that a human cannot
tell how to run is not a recommendation.
"""

from __future__ import annotations

from typing import Optional

from llm_client import LLMClient
from redaction import Redactor
from schemas import Incident, ResponseAction, ResponsePlan

SYSTEM = """You are the Response Agent in a security operations pipeline.

You receive ONE correlated incident and produce the playbook a SOC analyst will
work through. Rules:

  - Order actions by urgency, containment first. The first action must be the one
    that stops ongoing damage.
  - Every action names a concrete, specific step. "Investigate further" is not an
    action. "Disable the svc_deploy account and revoke its active SSH sessions" is.
  - Give a real command or console path where one exists, matched to the platform
    the evidence implies. Leave it null when the step is a human decision.
  - Tag execution honestly: automated only if it can safely run without a human
    reading the output first.
  - Set containment_deadline_minutes from real damage potential: minutes for
    active exfiltration or root access, hours for contained attempts.
  - Escalate to ciso only for confirmed data loss or a breach with regulatory
    reporting duties.

Do not recommend actions the evidence does not support. If the incident shows a
failed attack, say so and keep the plan proportionate."""


def _prompt(inc: Incident) -> str:
    techs = ", ".join(f"{t.technique_id} ({t.name})" for t in inc.mitre_techniques) or "none mapped"
    ev = "\n".join(f"  - {e.claim} [events {e.event_ids[:6]}]" for e in inc.evidence[:12])
    return f"""INCIDENT {inc.incident_id}
  title      : {inc.title}
  risk       : {inc.risk_score}/100 ({inc.severity})
  rationale  : {inc.risk_rationale}
  kill chain : {inc.kill_chain_stage}
  MITRE      : {techs}
  hosts      : {', '.join(inc.affected_hosts) or 'unknown'}
  accounts   : {', '.join(inc.affected_users) or 'unknown'}

NARRATIVE
{inc.narrative}

EVIDENCE
{ev}

Produce the response playbook."""


_PLAYBOOKS: dict[str, list[tuple[str, str, str, str, str, Optional[str]]]] = {
    "exfiltration": [
        ("containment", "Block the destination address at the perimeter firewall",
         "Stops any transfer still in flight.", "automated", "immediate",
         "iptables -I OUTPUT -d {dest} -j DROP"),
        ("containment", "Suspend the account and revoke its active sessions",
         "Removes the actor's ability to continue.", "manual", "immediate",
         "usermod -L {user} && pkill -KILL -u {user}"),
        ("eradication", "Identify exactly what left the network",
         "Scope determines the breach-notification duty.", "manual", "hours", None),
        ("recovery", "Rotate every credential the account could reach",
         "Assume anything it touched is compromised.", "manual", "hours", None),
        ("hardening", "Add a DLP egress rule for this data class",
         "Prevents a repeat by the same route.", "manual", "days", None),
    ],
    "privilege_escalation": [
        ("containment", "Revoke the elevated session and lock the account",
         "Cuts off root-level access now.", "manual", "immediate",
         "usermod -L {user} && pkill -KILL -u {user}"),
        ("eradication", "Remove any accounts or keys the actor created",
         "Persistence outlives the original access.", "manual", "immediate", None),
        ("eradication", "Audit sudoers and authorized_keys on the host",
         "Finds backdoors left behind.", "manual", "hours",
         "cat /etc/sudoers.d/* && cat /home/*/.ssh/authorized_keys"),
        ("recovery", "Rebuild the host from a known-good image",
         "Root compromise cannot be reliably cleaned in place.", "manual", "days", None),
    ],
    "initial_access": [
        ("containment", "Block the source address at the perimeter",
         "Stops continued access attempts.", "automated", "immediate",
         "iptables -I INPUT -s {source} -j DROP"),
        ("containment", "Force a password reset on the affected account",
         "The credential is known to the attacker.", "manual", "immediate", None),
        ("eradication", "Review everything the account did after authenticating",
         "Establishes whether access was used.", "manual", "hours", None),
        ("hardening", "Require MFA for this account class",
         "Password-only auth is what allowed this.", "manual", "days", None),
    ],
    "credential_access": [
        ("containment", "Rate-limit or block the source address",
         "Stops the guessing.", "automated", "immediate",
         "iptables -I INPUT -s {source} -j DROP"),
        ("eradication", "Confirm no attempt succeeded",
         "A single success changes the severity entirely.", "manual", "immediate", None),
        ("hardening", "Enforce lockout after repeated failures",
         "Removes brute force as a viable route.", "manual", "days", None),
    ],
    "persistence": [
        ("containment", "Disable any account created during the incident window",
         "A new account is the attacker's way back in.", "manual", "immediate",
         "usermod -L {user}"),
        ("eradication", "Audit all accounts, SSH keys and scheduled tasks on the host",
         "Persistence is rarely planted in only one place.", "manual", "immediate",
         "getent passwd && crontab -l -u {user} && ls -la /home/*/.ssh/"),
        ("recovery", "Rebuild the host from a known-good image",
         "Persistence you did not find is persistence that survives.", "manual", "days", None),
    ],
    "collection": [
        ("containment", "Suspend the account and revoke its file-share access",
         "Stops further staging of data.", "manual", "immediate",
         "usermod -L {user} && pkill -KILL -u {user}"),
        ("eradication", "Enumerate exactly which files were accessed",
         "Scope determines the notification duty.", "manual", "immediate", None),
        ("recovery", "Interview the account owner and preserve the endpoint",
         "Insider cases become HR and legal matters.", "manual", "hours", None),
    ],
    "reconnaissance": [
        ("containment", "Block the scanning address",
         "Scanning usually precedes an attempt.", "automated", "hours",
         "iptables -I INPUT -s {source} -j DROP"),
        ("hardening", "Confirm every probed port that answered should be exposed",
         "Reduces the attack surface the scan revealed.", "manual", "days", None),
    ],
}
_DEFAULT_PLAYBOOK = _PLAYBOOKS["credential_access"]


def _fallback(inc: Incident) -> ResponsePlan:
    """Template playbook keyed on kill-chain stage. Always schema-valid."""
    steps = _PLAYBOOKS.get(inc.kill_chain_stage, _DEFAULT_PLAYBOOK)
    user = inc.affected_users[0] if inc.affected_users else "the affected account"
    source = next(
        (e.claim.split()[-1] for e in inc.evidence if "from" in e.claim), "the source address"
    )

    actions = [
        ResponseAction(
            order=i,
            phase=phase,  # type: ignore[arg-type]
            action=action,
            rationale=rationale,
            execution=execution,  # type: ignore[arg-type]
            urgency=urgency,  # type: ignore[arg-type]
            command=(cmd.replace("{user}", user)
                        .replace("{source}", source)
                        .replace("{dest}", source)) if cmd else None,
        )
        for i, (phase, action, rationale, execution, urgency, cmd) in enumerate(steps, start=1)
    ]

    return ResponsePlan(
        incident_id=inc.incident_id,
        executive_summary=(
            f"{inc.title}. Risk {inc.risk_score}/100, reached the {inc.kill_chain_stage} "
            f"stage on {', '.join(inc.affected_hosts) or 'unknown hosts'}. "
            f"{len(actions)} actions, containment first."
        ),
        actions=actions,
        containment_deadline_minutes=15 if inc.risk_score >= 85 else 60 if inc.risk_score >= 60 else 240,
        escalate_to="ciso" if inc.risk_score >= 85 else "soc_lead" if inc.risk_score >= 60 else "soc_analyst",
    )


def plan_response(
    client: LLMClient, inc: Incident, redactor: Redactor | None = None
) -> tuple[ResponsePlan, bool]:
    """Returns (plan, used_model)."""
    prompt = _prompt(inc)
    if redactor and redactor.enabled:
        prompt = redactor.redact(prompt)
    result: Optional[ResponsePlan] = client.structured(
        tag=f"response:{inc.incident_id}",
        messages=[{"role": "user", "content": prompt}],
        schema=ResponsePlan,
        system=SYSTEM,
        effort="medium",
        max_tokens=8000,
    )
    if result is None:
        return _fallback(inc), False
    if redactor and redactor.enabled:
        result = redactor.restore_model(result)
    result.incident_id = inc.incident_id
    result.actions.sort(key=lambda a: a.order)
    return result, True
