"use client";

/**
 * The session shell.
 *
 * Structure is DataSentinel's - a sticky step nav over an App Router session
 * route. The skin is LogGuard's: glass over black, uppercase wide-tracked
 * labels, and severity as the only colour that carries meaning.
 *
 * The steps are the pipeline, in order, so the nav doubles as the story a judge
 * is being walked through.
 */

import { use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bot,
  FileText,
  Search,
  ShieldAlert,
  Radio,
} from "lucide-react";
import { SessionProvider, useSession } from "./SessionProvider";

const STEPS = [
  { id: "triage", icon: Activity, label: "Triage", key: "signals" },
  { id: "agents", icon: Bot, label: "Agents", key: "agent_runs" },
  { id: "incidents", icon: ShieldAlert, label: "Incidents", key: "incidents" },
  { id: "query", icon: Search, label: "Ask", key: null },
  { id: "report", icon: FileText, label: "Report", key: null },
] as const;

function Chrome({ children }: { children: React.ReactNode }) {
  const { sessionId, summary, health } = useSession();
  const pathname = usePathname();

  return (
    <div className="min-h-screen flex flex-col">
      {/* Masthead */}
      <header className="glass sticky top-0 z-50 border-x-0 border-t-0">
        <div className="max-w-[1500px] mx-auto px-6 h-16 flex items-center gap-6">
          <Link href="/" className="flex items-baseline gap-2 shrink-0">
            <span className="text-xl font-extrabold tracking-tighter uppercase">
              Sentinel<span className="text-ink-3">SOC</span>
            </span>
          </Link>

          <span className="label hidden md:inline truncate">
            {summary?.label ?? "session"} · {sessionId}
          </span>

          <div className="ml-auto flex items-center gap-5 shrink-0">
            {summary && (
              <div className="hidden lg:flex items-center gap-5">
                <Metric label="Events" value={summary.event_count} />
                <Metric label="Signals" value={summary.signal_count} />
                <Metric label="Incidents" value={summary.incident_count} />
              </div>
            )}
            <ProviderPill health={health} />
          </div>
        </div>

        {/* Step nav */}
        <nav className="max-w-[1500px] mx-auto px-6 pb-3 flex gap-2 overflow-x-auto">
          {STEPS.map((step) => {
            const active = pathname.includes(`/${step.id}`);
            const Icon = step.icon;
            return (
              <Link
                key={step.id}
                href={`/${sessionId}/${step.id}`}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-bold
                  uppercase tracking-widest whitespace-nowrap transition-colors ${
                    active
                      ? "bg-white text-black"
                      : "text-ink-3 hover:text-ink hover:bg-white/5"
                  }`}
              >
                <Icon size={14} />
                {step.label}
              </Link>
            );
          })}
        </nav>
      </header>

      <main className="flex-1 w-full max-w-[1500px] mx-auto px-6 py-8">
        {children}
      </main>

      <footer className="border-t border-white/[0.07] mt-8">
        <div className="max-w-[1500px] mx-auto px-6 py-4 flex flex-wrap gap-x-6 gap-y-1">
          <span className="label">SIH26-S01 · Agentic AI Cybersecurity Assistant</span>
          {health && (
            <span className="label ml-auto">
              redaction {health.redaction_mode}
              {health.replay_mode && " · replay"}
            </span>
          )}
        </div>
      </footer>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col leading-none gap-1">
      <span className="label">{label}</span>
      <span className="font-mono text-sm font-bold tabular-nums">
        {value.toLocaleString()}
      </span>
    </div>
  );
}

function ProviderPill({ health }: { health: import("@/types/api").Health | null }) {
  if (!health) {
    return (
      <span className="chip" data-sev="none">
        <Radio size={10} /> offline
      </span>
    );
  }
  const live = health.llm_available;
  return (
    <span
      className="chip"
      data-sev={live ? "low" : "none"}
      title={
        health.llm_chain.map((c) => `${c.provider}: ${c.model}`).join("  →  ") ||
        "no provider configured; deterministic fallbacks only"
      }
    >
      <Radio size={10} />
      {live ? health.llm_provider : "fallbacks"}
    </span>
  );
}

export default function SessionLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  return (
    <SessionProvider sessionId={sessionId}>
      <Chrome>{children}</Chrome>
    </SessionProvider>
  );
}
