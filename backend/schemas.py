"""
SentinelSOC - shared contracts.

Every agent output and every stored record is defined here. These models are the
contract between ingestion, detection, the agent layer and the frontend; write
them before the prompts, not after.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Normalised event  (the nine-field schema everything keys off)
# ---------------------------------------------------------------------------

LogSource = Literal["ssh_auth", "nginx_access", "firewall", "windows_security", "generic"]
Outcome = Literal["success", "failure", "blocked", "allowed", "info"]


class Event(BaseModel):
    """One normalised log line. Source-agnostic."""

    event_id: int = 0
    ts: datetime
    source: LogSource
    host: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    action: str
    outcome: Outcome
    raw: str
    template_id: Optional[str] = None
    template: Optional[str] = None
    bytes_out: int = 0


# ---------------------------------------------------------------------------
# Detection output
# ---------------------------------------------------------------------------

Detector = Literal["rule", "isolation_forest", "logic_gate", "template_rarity"]
Severity = Literal["low", "medium", "high", "critical"]


class Signal(BaseModel):
    """A detector firing on a window of events. A candidate, never a verdict."""

    signal_id: int = 0
    detector: Detector
    rule_id: str
    title: str
    severity: Severity
    ts_start: datetime
    ts_end: datetime
    host: str
    entity: str = Field(description="The subject: a user, a source IP, or a host.")
    entity_kind: Literal["user", "src_ip", "host"]
    score: float = Field(ge=0.0, le=1.0)
    event_ids: list[int]
    evidence_sample: list[str] = Field(default_factory=list)
    detail: str = ""


# ---------------------------------------------------------------------------
# Agent 1 - Log Analysis Agent
# ---------------------------------------------------------------------------


class IOC(BaseModel):
    kind: Literal["ip", "user", "port", "path", "process", "hash", "domain"]
    value: str
    context: str


class Deviation(BaseModel):
    """
    How far one feature of this signal's window sits from the session baseline.

    Computed arithmetic, never asked of the model: a z-score a language model
    invented would be the most confident-looking wrong number on the screen.
    """

    feature: str
    value: float
    baseline_mean: float
    z_score: float = Field(description="Signed standard deviations from the baseline.")
    flag: Literal["normal", "elevated", "extreme"]


class LogAnalysis(BaseModel):
    """Agent 1 output. One per signal."""

    signal_id: int
    summary: str = Field(description="One sentence: what the logs actually show.")
    iocs: list[IOC]
    entities_involved: list[str]
    activity_pattern: str = Field(description="The shape of the behaviour observed.")
    notable_event_ids: list[int] = Field(
        description="Event IDs a human should read first."
    )
    confidence: float = Field(ge=0.0, le=1.0)
    deviations: list[Deviation] = Field(
        default_factory=list,
        description="Statistical deviation metrics. Filled by the pipeline, "
                    "not by the model.",
    )
    threat_score: int = Field(
        default=0, ge=0, le=100,
        description="Raw 0-100 triage score from detector confidence and deviation.",
    )


# ---------------------------------------------------------------------------
# Agent 2 - Threat Investigation Agent
# ---------------------------------------------------------------------------


class EvidenceRef(BaseModel):
    """A claim tied to the log lines that support it. No orphan assertions."""

    claim: str
    event_ids: list[int]


class MitreTechnique(BaseModel):
    technique_id: str = Field(description="e.g. T1110.001")
    name: str
    tactic: str


class Incident(BaseModel):
    """Agent 2 output. Correlates many signals into one attack narrative."""

    incident_id: str
    title: str
    narrative: str = Field(description="What happened, in analyst English.")
    signal_ids: list[int]
    kill_chain_stage: Literal[
        "reconnaissance",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "exfiltration",
        "impact",
    ]
    mitre_techniques: list[MitreTechnique]
    risk_score: int = Field(ge=0, le=100)
    risk_rationale: str = Field(description="Why this number and not a lower one.")
    severity: Severity
    affected_hosts: list[str]
    affected_users: list[str]
    evidence: list[EvidenceRef]
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationResult(BaseModel):
    """Agent 2's full return: many signals in, few incidents out."""

    incidents: list[Incident]
    dismissed_signal_ids: list[int] = Field(
        default_factory=list,
        description="Signals judged benign, with the reason in dismissal_notes.",
    )
    dismissal_notes: str = ""


# ---------------------------------------------------------------------------
# Agent 3 - Response Agent
# ---------------------------------------------------------------------------


class ResponseAction(BaseModel):
    order: int
    phase: Literal["containment", "eradication", "recovery", "hardening"]
    action: str
    rationale: str
    execution: Literal["manual", "automated"]
    urgency: Literal["immediate", "hours", "days"]
    command: Optional[str] = Field(
        default=None, description="Concrete command or console step, when one applies."
    )


class ResponsePlan(BaseModel):
    """Agent 3 output. One per incident."""

    incident_id: str
    executive_summary: str
    actions: list[ResponseAction]
    containment_deadline_minutes: int
    escalate_to: Literal["soc_analyst", "soc_lead", "ciso", "no_escalation"]


# ---------------------------------------------------------------------------
# Orchestration bookkeeping
# ---------------------------------------------------------------------------


class AgentRun(BaseModel):
    """One agent hop. This table is what powers the trace panel in the UI."""

    run_id: int = 0
    session_id: str
    agent: Literal["log_analysis", "threat_investigation", "response"]
    stage_index: int
    input_summary: str
    output_json: str
    tool_calls: list[dict] = Field(default_factory=list)
    model: str = ""
    latency_ms: int = 0
    ok: bool = True
    error: str = ""
    created_at: datetime
