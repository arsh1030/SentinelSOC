/**
 * Mirrors backend/schemas.py.
 *
 * The Pydantic models are the contract between the agents and this UI; these
 * types are that contract restated, not a reinterpretation of it.
 */

import type { Severity } from "@/constants/config";

export type Detector =
  | "rule"
  | "isolation_forest"
  | "logic_gate"
  | "template_rarity";

export interface Signal {
  signal_id: number;
  detector: Detector;
  rule_id: string;
  title: string;
  severity: Severity;
  ts_start: string;
  ts_end: string;
  host: string;
  entity: string;
  entity_kind: "user" | "src_ip" | "host";
  score: number;
  event_ids: number[];
  evidence_sample: string[];
  detail: string;
  analysis?: LogAnalysis;
  score_original?: number;
  feedback_adjusted?: boolean;
}

export interface IOC {
  kind: "ip" | "user" | "port" | "path" | "process" | "hash" | "domain";
  value: string;
  context: string;
}

export interface Deviation {
  feature: string;
  value: number;
  baseline_mean: number;
  z_score: number;
  flag: "normal" | "elevated" | "extreme";
}

export interface LogAnalysis {
  signal_id: number;
  summary: string;
  iocs: IOC[];
  entities_involved: string[];
  activity_pattern: string;
  notable_event_ids: number[];
  confidence: number;
  deviations: Deviation[];
  threat_score: number;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface EvidenceRef {
  claim: string;
  event_ids: number[];
}

export interface ResponseAction {
  order: number;
  phase: "containment" | "eradication" | "recovery" | "hardening";
  action: string;
  rationale: string;
  execution: "manual" | "automated";
  urgency: "immediate" | "hours" | "days";
  command?: string | null;
}

export interface ResponsePlan {
  incident_id: string;
  executive_summary: string;
  actions: ResponseAction[];
  containment_deadline_minutes: number;
  escalate_to: "soc_analyst" | "soc_lead" | "ciso" | "no_escalation";
}

export interface Incident {
  incident_id: string;
  title: string;
  narrative: string;
  signal_ids: number[];
  kill_chain_stage: string;
  mitre_techniques: MitreTechnique[];
  risk_score: number;
  risk_rationale: string;
  severity: Severity;
  affected_hosts: string[];
  affected_users: string[];
  evidence: EvidenceRef[];
  confidence: number;
  response_plan?: ResponsePlan | null;
}

export interface ToolCall {
  turn: number;
  tool: string;
  input: Record<string, unknown>;
  output: string;
  error: boolean;
}

export interface AgentRun {
  run_id: number;
  session_id: string;
  agent: "log_analysis" | "threat_investigation" | "response";
  stage_index: number;
  input_summary: string;
  output_json: string;
  tool_calls: ToolCall[];
  model: string;
  latency_ms: number;
  ok: boolean;
  error: string;
  created_at: string;
}

export interface LogicRule {
  rule_pk: number;
  statement: string;
  accepted: boolean;
  reason: string;
  mitre: string;
  rationale: string;
}

export interface SessionSummary {
  session_id: string;
  created_at: string;
  label: string;
  event_count: number;
  signal_count: number;
  incident_count: number;
  status: string;
  signals?: number;
  incidents?: number;
  agent_runs?: number;
  logic_rules?: number;
}

export interface IngestResult {
  session_id: string;
  events: number;
  signals: number;
  per_file: Record<string, number>;
  detectors?: string[];
  ai_rules_proposed?: number;
  ai_rules_accepted?: number;
  warning?: string;
}

export interface InvestigateResult {
  session_id: string;
  signals_in: number;
  incidents_out: number;
  tool_calls: number;
  used_model: Record<string, boolean>;
  stage_timings_ms: Record<string, number>;
  redaction: { mode: string; values_pseudonymised: number; by_category: Record<string, number> };
  incidents: Incident[];
}

export interface Health {
  status: string;
  llm_provider: string;
  llm_model: string;
  llm_fallback: string | null;
  llm_chain: { provider: string; model: string }[];
  llm_available: boolean;
  last_provider_used: string | null;
  replay_mode: boolean;
  redaction_mode: string;
  supported_sources: string[];
  samples_present: boolean;
}

export interface EventRow {
  event_id: number;
  ts: string;
  source: string;
  host: string;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  action: string;
  outcome: string;
  raw: string;
}
