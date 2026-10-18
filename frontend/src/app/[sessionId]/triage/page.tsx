"use client";

/**
 * Triage — what the deterministic detectors found, before any model ran.
 *
 * This screen exists to make one point on stage: everything below was produced
 * by cheap, explainable detectors. The agents only ever see what survived here,
 * which is what bounds cost and answers "is this just prompting?".
 */

import { use, useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bot, Check, Cpu, Ruler, Sparkles, ThumbsDown, X } from "lucide-react";
import api from "@/services/api.service";
import type { LogAnalysis, LogicRule, Signal } from "@/types/api";
import { Button, Empty, Panel, ScoreBar, SeverityChip, Stat } from "@/components/ui";
import { useSession } from "../SessionProvider";
import { LiveInjector } from "@/components/LiveInjector";

const FLAG_TONE: Record<string, string> = {
  extreme: "#ff3333",
  elevated: "#ff6600",
  normal: "#a0a0a0",
};

/**
 * The deviation metrics behind a signal.
 *
 * Only the features that actually deviate are shown — listing all nine would
 * bury the two that matter. Computed arithmetic, never model output.
 */
function Deviations({ analysis }: { analysis?: LogAnalysis }) {
  const notable = (analysis?.deviations ?? []).filter((d) => d.flag !== "normal");
  if (notable.length === 0) return null;

  return (
    <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
      {analysis?.threat_score ? (
        <span className="label" title="Raw triage score: detector confidence lifted by deviation">
          threat {analysis.threat_score}
        </span>
      ) : null}
      {notable.slice(0, 4).map((d) => (
        <span
          key={d.feature}
          className="font-mono text-[10px] px-1.5 py-0.5 rounded-sm border"
          style={{
            color: FLAG_TONE[d.flag],
            borderColor: `${FLAG_TONE[d.flag]}4d`,
            background: `${FLAG_TONE[d.flag]}1a`,
          }}
          title={`${d.feature} = ${d.value} against a baseline mean of ${d.baseline_mean}`}
        >
          {d.feature} {d.z_score > 0 ? "+" : ""}
          {d.z_score.toFixed(1)}σ
        </span>
      ))}
    </div>
  );
}

const DETECTOR_META: Record<string, { icon: typeof Ruler; label: string }> = {
  rule: { icon: Ruler, label: "Rule" },
  isolation_forest: { icon: Cpu, label: "Isolation Forest" },
  template_rarity: { icon: Sparkles, label: "Template rarity" },
  logic_gate: { icon: Bot, label: "AI-proposed rule" },
};

export default function TriagePage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const router = useRouter();
  const { refresh, busy, setBusy, summary, setSummary } = useSession();

  const [allSignals, setAllSignals] = useState<Signal[]>([]);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [rules, setRules] = useState<LogicRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [isInjecting, setIsInjecting] = useState(false);
  const newIdsRef = useRef<Set<number>>(new Set());
  const targetEventCount = useRef<number>(0);

  const load = useCallback(async () => {
    const [s, r] = await Promise.all([
      api.get<Signal[]>(`/api/signals/${sessionId}`),
      api.get<{ rules: LogicRule[] }>(`/api/logic-rules/${sessionId}`).catch(() => ({
        data: { rules: [] },
      })),
    ]);
    setAllSignals(s.data);
    setRules(r.data.rules ?? []);
    setLoading(false);
  }, [sessionId]);

  useEffect(() => {
    load();
  }, [load]);

  // Initialize fake count targets
  useEffect(() => {
    if (summary && summary.event_count > 0 && targetEventCount.current === 0) {
      targetEventCount.current = summary.event_count;
      setSummary((prev) => (prev ? { ...prev, event_count: 0, signal_count: 0 } : null));
    }
  }, [summary, setSummary]);

  // Fast rolling counter for event_count when injecting
  useEffect(() => {
    if (!isInjecting || targetEventCount.current === 0) return;
    
    const interval = setInterval(() => {
      setSummary((prev) => {
        if (!prev) return prev;
        if (prev.event_count >= targetEventCount.current) {
          clearInterval(interval);
          return prev;
        }
        // Increment by a random chunk
        const nextCount = Math.min(
          prev.event_count + Math.floor(Math.random() * 25) + 5, 
          targetEventCount.current
        );
        return { ...prev, event_count: nextCount };
      });
    }, 50);
    
    return () => clearInterval(interval);
  }, [isInjecting, setSummary]);

  // Sync signal count with the rendered signals array
  useEffect(() => {
    setSummary((prev) => (prev ? { ...prev, signal_count: signals.length } : null));
  }, [signals.length, setSummary]);

  // Incrementally display signals to simulate live data with random delay
  useEffect(() => {
    if (!isInjecting || signals.length >= allSignals.length) return;
    
    const delay = Math.floor(Math.random() * 1500) + 500; // Random delay between 500ms - 2000ms
    const timeout = setTimeout(() => {
      setSignals((prev) => {
        if (prev.length >= allSignals.length) return prev;
        const next = allSignals[prev.length];
        newIdsRef.current.add(next.signal_id);
        return [...prev, next];
      });
    }, delay);

    return () => clearTimeout(timeout);
  }, [allSignals, signals.length, isInjecting]);

  // Poll for signals while the session is still being processed.
  // This catches the case where we navigate here before detection finishes.
  useEffect(() => {
    if (signals.length > 0 || loading) return;

    const interval = setInterval(async () => {
      try {
        const [s, r] = await Promise.all([
          api.get<Signal[]>(`/api/signals/${sessionId}`),
          api.get<{ rules: LogicRule[] }>(`/api/logic-rules/${sessionId}`).catch(() => ({
            data: { rules: [] },
          })),
        ]);
        if (s.data.length > 0) {
          setAllSignals(s.data);
          setRules(r.data.rules ?? []);
          clearInterval(interval);
        }
      } catch {
        // backend may not be ready yet
      }
    }, 2000);

    // Stop polling after 60 seconds no matter what
    const timeout = setTimeout(() => clearInterval(interval), 60_000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [signals.length, loading, sessionId]);

  async function investigate() {
    setBusy("investigate");
    try {
      await api.post(`/api/investigate/${sessionId}`);
      await refresh();
      router.push(`/${sessionId}/agents`);
    } finally {
      setBusy(null);
    }
  }

  async function dismiss(signal: Signal) {
    await api.post(`/api/feedback/${sessionId}`, null, {
      params: { signal_id: signal.signal_id, verdict: "false_positive" },
    });
    load();
  }

  const counts = signals.reduce<Record<string, number>>((acc, s) => {
    acc[s.severity] = (acc[s.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
            Detection triage
          </h1>
          <p className="text-sm text-ink-2 mt-1 max-w-2xl">
            {signals.length} signals from deterministic detectors. No model has
            run yet — these are candidates, not verdicts.
          </p>
        </div>
        <Button onClick={investigate} busy={busy === "investigate"}>
          <Bot size={13} />
          {busy === "investigate" ? "Agents running" : "Run the agents"}
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Critical" value={counts.critical ?? 0} tone="critical" />
        <Stat label="High" value={counts.high ?? 0} tone="high" />
        <Stat label="Medium" value={counts.medium ?? 0} tone="medium" />
        <Stat label="Low" value={counts.low ?? 0} tone="low" />
      </div>

      <LiveInjector injecting={isInjecting} onToggle={() => setIsInjecting(p => !p)} />

      <Panel title={`Signals · ${signals.length}`}>
        {loading ? (
          <Empty>Loading…</Empty>
        ) : signals.length === 0 ? (
          <Empty>No signals in this session.</Empty>
        ) : (
          <div className="overflow-x-auto -mx-5">
            <table className="w-full min-w-[880px] text-sm">
              <thead>
                <tr className="border-b border-white/[0.07]">
                  {["", "Rule", "Detector", "Entity", "Window", "Confidence", "Finding", ""].map(
                    (h, i) => (
                      <th key={i} className="label text-left px-4 py-2 font-medium">
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05]">
                {signals.map((s) => {
                  const meta = DETECTOR_META[s.detector] ?? DETECTOR_META.rule;
                  const Icon = meta.icon;
                  return (
                    <tr
                      key={s.signal_id}
                      className={`hover:bg-white/[0.03] transition-colors ${
                        newIdsRef.current.has(s.signal_id) ? "anim-slide" : ""
                      }`}
                    >
                      <td className="px-4 py-3">
                        <SeverityChip severity={s.severity} pulse />
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs font-bold">{s.rule_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1.5 text-[11px] text-ink-3"
                          title={meta.label}
                        >
                          <Icon size={12} /> {meta.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-ink-1">{s.entity}</span>
                        <span className="block text-[10px] text-ink-3">{s.host}</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="font-mono text-[11px] text-ink-2">
                          {s.ts_start.slice(11, 19)}
                        </span>
                        <span className="text-ink-3 text-[11px]"> → </span>
                        <span className="font-mono text-[11px] text-ink-2">
                          {s.ts_end.slice(11, 19)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <ScoreBar score={s.score} />
                        {s.feedback_adjusted && (
                          <span className="text-[10px] text-ink-3">
                            damped from {Math.round((s.score_original ?? 0) * 100)}%
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 max-w-[420px]">
                        <p className="text-[13px] text-ink-1 leading-snug">{s.title}</p>
                        <p className="text-[11px] text-ink-3 leading-snug mt-0.5 line-clamp-2">
                          {s.detail}
                        </p>
                        <Deviations analysis={s.analysis} />
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => dismiss(s)}
                          title="Mark false positive — repeated dismissals damp this rule"
                          className="text-ink-3 hover:text-ink transition-colors p-1"
                        >
                          <ThumbsDown size={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {rules.length > 0 && (
        <Panel
          title={`AI-proposed rules · ${rules.filter((r) => r.accepted).length}/${rules.length} accepted`}
          right={<span className="label">schema-validated before execution</span>}
        >
          <p className="text-[13px] text-ink-2 mb-4 max-w-3xl">
            The model writes rules in a constrained grammar; every field,
            operator and bound is checked against the real log schema before a
            single event is read. A hallucinated field is rejected here, not
            executed.
          </p>
          <ul className="flex flex-col gap-2">
            {rules.map((r) => (
              <li
                key={r.rule_pk}
                className="flex items-start gap-3 px-4 py-3 rounded-md bg-white/[0.02] border border-white/[0.06]"
              >
                {r.accepted ? (
                  <Check size={14} className="mt-0.5 shrink-0" color="#33ff33" />
                ) : (
                  <X size={14} className="mt-0.5 shrink-0" color="#ff3333" />
                )}
                <div className="min-w-0">
                  <p className="text-[13px] text-ink-1">{r.statement}</p>
                  <p className="text-[11px] text-ink-3 mt-0.5">
                    {r.accepted ? r.rationale : `rejected — ${r.reason}`}
                  </p>
                </div>
                {r.mitre && (
                  <span className="chip ml-auto shrink-0" data-sev="none">
                    {r.mitre}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
