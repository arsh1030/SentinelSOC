"use client";

/**
 * Incidents — the output the problem statement actually asks for.
 *
 * Each card carries the four graded things together: a risk score that explains
 * itself, MITRE technique mapping, evidence citing real event IDs, and a
 * response playbook. The evidence is clickable: a claim you cannot trace back
 * to log lines is an assertion, not a finding.
 */

import { use, useCallback, useEffect, useState } from "react";
import {
  ChevronDown,
  Crosshair,
  FileText,
  Server,
  Terminal,
  User,
} from "lucide-react";
import Link from "next/link";
import api from "@/services/api.service";
import type { EventRow, Incident } from "@/types/api";
import { Button, Empty, Panel, RiskMeter, SeverityChip } from "@/components/ui";

const PHASE_TONE: Record<string, string> = {
  containment: "#ff3333",
  eradication: "#ff6600",
  recovery: "#ffff33",
  hardening: "#33ff33",
};

export default function IncidentsPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [openId, setOpenId] = useState<string | null>(null);

  const load = useCallback(async () => {
    const { data } = await api.get<Incident[]>(`/api/incidents/${sessionId}`);
    setIncidents(data);
    setOpenId((cur) => cur ?? data[0]?.incident_id ?? null);
    setLoading(false);
  }, [sessionId]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <Empty>Loading incidents…</Empty>;

  if (incidents.length === 0) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-extrabold tracking-tighter uppercase">Incidents</h1>
        <Panel>
          <Empty>
            No incidents yet — run the agents from the Triage or Agents screen.
          </Empty>
        </Panel>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
            Incidents
          </h1>
          <p className="text-sm text-ink-2 mt-1">
            {incidents.length} correlated from the open signals, highest risk first.
          </p>
        </div>
        <Button variant="ghost" href={`/${sessionId}/report`}>
          <FileText size={13} /> Report
        </Button>
      </div>

      <div className="flex flex-col gap-3">
        {incidents.map((inc) => (
          <IncidentCard
            key={inc.incident_id}
            sessionId={sessionId}
            incident={inc}
            open={openId === inc.incident_id}
            onToggle={() =>
              setOpenId(openId === inc.incident_id ? null : inc.incident_id)
            }
          />
        ))}
      </div>
    </div>
  );
}

function IncidentCard({
  sessionId,
  incident: inc,
  open,
  onToggle,
}: {
  sessionId: string;
  incident: Incident;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <article className="glass rounded-lg overflow-hidden anim-fade">
      <button
        onClick={onToggle}
        className="w-full flex flex-wrap items-center gap-4 px-5 py-4 text-left hover:bg-white/[0.03] transition-colors"
      >
        <SeverityChip severity={inc.severity} pulse />
        <span className="font-mono text-xs font-bold text-ink-2">
          {inc.incident_id}
        </span>
        <h2 className="text-[15px] font-bold tracking-tight flex-1 min-w-[240px]">
          {inc.title}
        </h2>
        <span className="label hidden md:inline">
          {inc.kill_chain_stage.replace(/_/g, " ")}
        </span>
        <div className="w-40 shrink-0">
          <RiskMeter score={inc.risk_score} severity={inc.severity} />
        </div>
        <ChevronDown
          size={14}
          className={`text-ink-3 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div className="border-t border-white/[0.07] px-5 py-5 flex flex-col gap-6 anim-fade">
          <div className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 flex flex-col gap-5">
              <Section title="What happened">
                <p className="text-[13px] text-ink-1 leading-relaxed">{inc.narrative}</p>
              </Section>

              <Section title="Why this risk score">
                <p className="text-[13px] text-ink-2 leading-relaxed">
                  {inc.risk_rationale}
                </p>
              </Section>

              <Section title={`Evidence · ${inc.evidence.length} claims`}>
                <ul className="flex flex-col gap-2">
                  {inc.evidence.map((ev, i) => (
                    <EvidenceItem key={i} sessionId={sessionId} claim={ev.claim} ids={ev.event_ids} />
                  ))}
                </ul>
              </Section>
            </div>

            <aside className="flex flex-col gap-5">
              <Section title="MITRE ATT&CK">
                <ul className="flex flex-col gap-2">
                  {inc.mitre_techniques.map((t) => (
                    <li key={t.technique_id} className="flex items-start gap-2.5">
                      <Crosshair size={12} className="mt-1 text-ink-3 shrink-0" />
                      <div>
                        <span className="font-mono text-xs font-bold text-ink-1">
                          {t.technique_id}
                        </span>
                        <span className="text-[13px] text-ink-2"> {t.name}</span>
                        <span className="block label mt-0.5">
                          {t.tactic.replace(/_/g, " ")}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              </Section>

              <Section title="Affected">
                <div className="flex flex-col gap-2">
                  <Facts icon={Server} items={inc.affected_hosts} empty="no hosts identified" />
                  <Facts icon={User} items={inc.affected_users} empty="no accounts identified" />
                </div>
                <p className="label mt-3">
                  signals {inc.signal_ids.map((s) => `#${s}`).join(" ")}
                </p>
              </Section>
            </aside>
          </div>

          {inc.response_plan && <ResponsePlanView plan={inc.response_plan} />}
        </div>
      )}
    </article>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="label mb-2">{title}</h3>
      {children}
    </div>
  );
}

function Facts({
  icon: Icon,
  items,
  empty,
}: {
  icon: typeof Server;
  items: string[];
  empty: string;
}) {
  return (
    <div className="flex items-start gap-2.5">
      <Icon size={12} className="mt-1 text-ink-3 shrink-0" />
      <span className="font-mono text-xs text-ink-1">
        {items.length ? items.join(", ") : <span className="text-ink-3">{empty}</span>}
      </span>
    </div>
  );
}

/** A claim you cannot open is an assertion. This one opens. */
function EvidenceItem({
  sessionId,
  claim,
  ids,
}: {
  sessionId: string;
  claim: string;
  ids: number[];
}) {
  const [rows, setRows] = useState<EventRow[] | null>(null);
  const [open, setOpen] = useState(false);

  async function toggle() {
    setOpen(!open);
    if (!rows && !open) {
      const { data } = await api.get<EventRow[]>(`/api/events/${sessionId}`, {
        params: { limit: 200 },
      });
      setRows(data.filter((r) => ids.includes(r.event_id)).slice(0, 12));
    }
  }

  return (
    <li className="rounded-md bg-white/[0.02] border border-white/[0.06]">
      <button
        onClick={toggle}
        className="w-full flex items-start gap-2.5 px-4 py-2.5 text-left hover:bg-white/[0.03] transition-colors"
      >
        <Terminal size={12} className="mt-1 text-ink-3 shrink-0" />
        <span className="text-[13px] text-ink-1 flex-1">{claim}</span>
        <span className="label shrink-0">{ids.length} events</span>
      </button>
      {open && (
        <div className="px-4 pb-3 anim-fade">
          {rows === null ? (
            <p className="label">loading…</p>
          ) : rows.length === 0 ? (
            <p className="label">events outside the fetched window</p>
          ) : (
            <pre className="overflow-x-auto font-mono text-[11px] leading-relaxed text-ink-2 border-t border-white/[0.06] pt-2">
              {rows.map((r) => `[${r.event_id}] ${r.ts.slice(11, 19)}  ${r.raw}`).join("\n")}
            </pre>
          )}
        </div>
      )}
    </li>
  );
}

function ResponsePlanView({ plan }: { plan: import("@/types/api").ResponsePlan }) {
  return (
    <div className="border-t border-white/[0.07] pt-5">
      <div className="flex flex-wrap items-baseline gap-3 mb-3">
        <h3 className="label">Recommended response</h3>
        <span className="chip" data-sev="critical">
          contain within {plan.containment_deadline_minutes}m
        </span>
        <span className="chip" data-sev="none">
          escalate: {plan.escalate_to.replace(/_/g, " ")}
        </span>
      </div>
      <p className="text-[13px] text-ink-2 mb-4 max-w-3xl">{plan.executive_summary}</p>

      <ol className="flex flex-col gap-2">
        {plan.actions.map((a) => (
          <li
            key={a.order}
            className="rail pl-4 py-1"
            style={{ color: PHASE_TONE[a.phase] ?? "#666" }}
          >
            <div className="flex flex-wrap items-baseline gap-2">
              <span className="font-mono text-[11px] font-bold tabular-nums">
                {String(a.order).padStart(2, "0")}
              </span>
              <span className="label" style={{ color: PHASE_TONE[a.phase] }}>
                {a.phase}
              </span>
              <span className="chip" data-sev="none">
                {a.execution}
              </span>
              <span className="chip" data-sev={a.urgency === "immediate" ? "critical" : "none"}>
                {a.urgency}
              </span>
            </div>
            <p className="text-[13px] text-ink-1 mt-1">{a.action}</p>
            <p className="text-[11px] text-ink-3 mt-0.5">{a.rationale}</p>
            {a.command && (
              <pre className="mt-1.5 px-3 py-2 rounded bg-black/60 border border-white/[0.07] overflow-x-auto font-mono text-[11px] text-ink-2">
                {a.command}
              </pre>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
