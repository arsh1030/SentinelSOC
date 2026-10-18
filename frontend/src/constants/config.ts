/** Base URL for the SentinelSOC backend. */
export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Severity → the one saturated colour on an otherwise monochrome console. */
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#ff3333",
  high: "#ff6600",
  medium: "#ffff33",
  low: "#33ff33",
};

export const AGENT_LABEL: Record<string, string> = {
  log_analysis: "Log Analysis Agent",
  threat_investigation: "Threat Investigation Agent",
  response: "Response Agent",
};

export default { API_BASE };
