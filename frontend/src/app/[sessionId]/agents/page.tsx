"use client";

/**
 * The agent trace.
 *
 * The problem statement asks for at least two specialised agents that
 * collaborate. This screen is the evidence: every hop was recorded to the
 * agent_runs table as it ran, in order, with the handoff between stages and the
 * evidence Agent 2 chose to pull for itself.
 *
 * Nothing here is reconstructed for display - it is the stored trace.
 */

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowDown,
  Bot,
  ChevronRight,
  Search,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import api from "@/services/api.service";
import type { AgentRun } from "@/types/api";
import { AGENT_LABEL } from "@/constants/config";
import { Button, Empty, Panel } from "@/components/ui";
import { useSession } from "../SessionProvider";

const STAGE_ICON = {
  log_analysis: Search,
  threat_investigation: ShieldAlert,
  response: Wrench,
} as const;

const STAGE_ROLE: Record<string, string> = {
  log_analysis:
    "Normalises one signal at a time, extracts indicators, and says what the logs show — without speculating about intent.",
  threat_investigation:
    "Receives every analysis at once and decides which signals are facets of the same attack. Holds the only tool.",
  response:
    "Turns one correlated incident into an ordered playbook, containment first.",
};

export default function AgentsPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const { refresh, busy, setBusy, streaming, subscribe } = useSession();
  const [runs, setRuns] = useState<AgentRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<number | null>(null);

  const load = useCallback(async () => {
    const { data } = await api.get<AgentRun[]>(`/api/trace/${sessionId}`);
    setRuns(data);
    setLoading(false);
  }, [sessionId]);

  useEffect(() => {
    load();
  }, [load]);

  // Subscribe to live agent hop events from SSE stream
  useEffect(() => {
    const unsub = subscribe({
      onAgentHop: () => {
        // Refetch the trace to get the latest runs
        api.get<AgentRun[]>(`/api/trace/${sessionId}`).then((r) => {
          setRuns(r.data);
          setLoading(false);
        });
      },
    });
    return unsub;
  }, [subscribe, sessionId]);

  async function run() {
    setBusy("investigate");
    try {
      await api.post(`/api/investigate/${sessionId}`);
      await Promise.all([load(), refresh()]);
    } finally {
      setBusy(null);
    }
  }

  const stages = [1, 2, 3].map((i) => runs.filter((r) => r.stage_index === i));
  const toolCalls = runs.flatMap((r) => r.tool_calls);
  const totalMs = runs.reduce((a, r) => a + r.latency_ms, 0);

  if (loading) return <Empty>Loading trace…</Empty>;

  if (runs.length === 0) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
          Agent trace
        </h1>
        <Panel>
          <div className="py-12 flex flex-col items-center gap-4 text-center">
            <Bot size={28} className="text-ink-3" />
            <p className="text-sm text-ink-2 max-w-md">
              The agents have not run for this session yet. Each hop is recorded
              as it happens and appears here in order.
            </p>
            <Button onClick={run} busy={busy === "investigate"}>
              <Bot size={13} />
              {busy === "investigate" ? "Running" : "Run the agents"}
            </Button>
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
            Agent trace
            {streaming && (
              <span
                className="inline-block w-2 h-2 rounded-full ml-3 align-middle"
                style={{
                  background: "#33ff33",
                  boxShadow: "0 0 6px #33ff33",
                  animation: "pulse 1.5s ease-in-out infinite",
                }}
                title="Agents running live"
              />
            )}
          </h1>
          <p className="text-sm text-ink-2 mt-1 max-w-2xl">
            {streaming
              ? `${runs.length} hops recorded — agents working…`
              : (<>
            {runs.length} recorded hops across three specialised agents
            {toolCalls.length > 0 && (
              <>
                {" · "}
                <span className="text-ink-1">
                  {toolCalls.length} evidence {toolCalls.length === 1 ? "pull" : "pulls"}
                </span>{" "}
                requested by the investigation agent
              </>
            )}
            {" · "}
            {totalMs.toLocaleString()} ms total
            </>)}
          </p>
        </div>
        <Button variant="ghost" onClick={run} busy={busy === "investigate"}>
          Re-run
        </Button>
      </div>

      <div className="flex flex-col">
        {stages.map((hops, idx) => {
          if (hops.length === 0) return null;
          const agent = hops[0].agent;
          const Icon = STAGE_ICON[agent];
          const stageMs = hops.reduce((a, r) => a + r.latency_ms, 0);
          const stageTools = hops.flatMap((h) => h.tool_calls);

          return (
            <div key={idx}>
              <Panel className="anim-slide">
                <div className="flex flex-wrap items-start gap-4">
                  <div className="w-9 h-9 rounded-md border border-white/10 bg-white/5 grid place-items-center shrink-0">
                    <Icon size={16} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <span className="label">Stage {idx + 1}</span>
                      <h2 className="text-base font-bold tracking-tight">
                        {AGENT_LABEL[agent]}
                      </h2>
                      <span className="font-mono text-[11px] text-ink-3 tabular-nums">
                        {hops.length} {hops.length === 1 ? "hop" : "hops"} ·{" "}
                        {stageMs.toLocaleString()} ms
                      </span>
                    </div>
                    <p className="text-[13px] text-ink-2 mt-1 max-w-3xl">
                      {STAGE_ROLE[agent]}
                    </p>
                  </div>
                </div>

                {/* The tool loop, given its own weight - it is the difference
                    between an agent and a long prompt. */}
                {stageTools.length > 0 && (
                  <div className="mt-4 rail text-[#ff6600] pl-4">
                    <span className="label" style={{ color: "#ff6600" }}>
                      Tool calls · fetch_log_window
                    </span>
                    <ul className="mt-2 flex flex-col gap-2">
                      {stageTools.map((c, i) => (
                        <li
                          key={i}
                          className="rounded-md bg-white/[0.02] border border-white/[0.06] px-4 py-2.5"
                        >
                          <p className="font-mono text-[11px] text-ink-1">
                            {c.tool}(
                            {Object.entries(c.input)
                              .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
                              .join(", ")}
                            )
                          </p>
                          <p className="font-mono text-[11px] text-ink-3 mt-1 line-clamp-2">
                            {c.error ? "error: " : "→ "}
                            {c.output.slice(0, 220)}
                          </p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <ul className="mt-4 flex flex-col gap-1">
                  {hops.map((hop) => (
                    <li key={hop.run_id}>
                      <button
                        onClick={() => setOpen(open === hop.run_id ? null : hop.run_id)}
                        className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-left
                          hover:bg-white/[0.04] transition-colors"
                      >
                        <ChevronRight
                          size={12}
                          className={`text-ink-3 shrink-0 transition-transform ${
                            open === hop.run_id ? "rotate-90" : ""
                          }`}
                        />
                        <span className="text-[13px] text-ink-1 truncate flex-1">
                          {hop.input_summary}
                        </span>
                        {!hop.ok && (
                          <span className="chip" data-sev="critical">
                            failed
                          </span>
                        )}
                        <span className="font-mono text-[11px] text-ink-3 tabular-nums shrink-0">
                          {hop.latency_ms} ms
                        </span>
                      </button>
                      {open === hop.run_id && (
                        <pre
                          className="mx-3 mb-2 mt-1 p-4 rounded-md bg-black/60 border border-white/[0.07]
                            overflow-x-auto font-mono text-[11px] leading-relaxed text-ink-2 anim-fade"
                        >
                          {safeFormat(hop.output_json)}
                        </pre>
                      )}
                    </li>
                  ))}
                </ul>
              </Panel>

              {idx < 2 && stages[idx + 1]?.length > 0 && (
                <div className="flex items-center gap-3 py-3 pl-5">
                  <ArrowDown size={13} className="text-ink-3" />
                  <span className="label">handoff</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex justify-end">
        <Link
          href={`/${sessionId}/incidents`}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-white text-black
            text-xs font-bold uppercase tracking-widest hover:bg-ink-1 transition-colors"
        >
          See the incidents <ChevronRight size={13} />
        </Link>
      </div>
    </div>
  );
}

function safeFormat(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}
