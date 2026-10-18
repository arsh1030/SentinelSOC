"use client";

/**
 * Console primitives, in LogGuard's language.
 *
 * The rule the whole palette follows: the console is monochrome and severity is
 * the only saturated colour on it. Nothing decorative is allowed to compete
 * with a critical row.
 */

import type { Severity } from "@/constants/config";
import { SEVERITY_HEX } from "@/constants/config";

export function SeverityChip({
  severity,
  children,
  pulse = false,
}: {
  severity: Severity | "none";
  children?: React.ReactNode;
  pulse?: boolean;
}) {
  return (
    <span className="chip" data-sev={severity}>
      {pulse && severity !== "none" && (
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            severity === "critical" ? "animate-pulse" : ""
          }`}
          style={{ background: SEVERITY_HEX[severity as Severity] }}
        />
      )}
      {children ?? severity}
    </span>
  );
}

export function Panel({
  title,
  right,
  children,
  className = "",
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`glass rounded-lg ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-4 px-5 py-3 border-b border-white/[0.07]">
          <h2 className="label">{title}</h2>
          {right}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: Severity;
}) {
  return (
    <div className="glass rounded-lg px-5 py-4 flex flex-col gap-1">
      <span className="label">{label}</span>
      <span
        className="font-mono text-3xl font-bold tabular-nums leading-none"
        style={tone ? { color: SEVERITY_HEX[tone] } : undefined}
      >
        {value}
      </span>
      {hint && <span className="text-[11px] text-ink-3 mt-0.5">{hint}</span>}
    </div>
  );
}

/** A 0-100 risk score. The bar is the read; the number confirms it. */
export function RiskMeter({
  score,
  severity,
  compact = false,
}: {
  score: number;
  severity: Severity;
  compact?: boolean;
}) {
  const hex = SEVERITY_HEX[severity];
  return (
    <div className={`flex items-center gap-2 ${compact ? "" : "w-full"}`}>
      <div
        className={`${compact ? "w-16" : "flex-1"} h-1.5 rounded-full bg-white/10 overflow-hidden`}
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${score}%`, background: hex }}
        />
      </div>
      <span
        className="font-mono text-xs font-bold tabular-nums"
        style={{ color: hex }}
      >
        {score}
      </span>
    </div>
  );
}

export function ScoreBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1.5 rounded-full bg-white/10">
        <div className="h-full rounded-full bg-white" style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-[10px] font-bold text-ink-2 tabular-nums">
        {pct}%
      </span>
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled,
  busy,
  href,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost";
  disabled?: boolean;
  busy?: boolean;
  href?: string;
}) {
  const base =
    "relative overflow-hidden inline-flex items-center gap-2 px-4 py-2 rounded-md " +
    "text-xs font-bold uppercase tracking-widest transition-colors " +
    "disabled:opacity-40 disabled:cursor-not-allowed";
  const skin =
    variant === "primary"
      ? "bg-white text-black hover:bg-ink-1"
      : "border border-white/15 text-ink-2 hover:text-ink hover:bg-white/5";
  const cls = `${base} ${skin} ${busy ? "anim-sweep" : ""}`;

  if (href) {
    return (
      <a href={href} className={cls}>
        {children}
      </a>
    );
  }
  return (
    <button className={cls} onClick={onClick} disabled={disabled || busy}>
      {children}
    </button>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="py-16 text-center">
      <p className="text-sm text-ink-3">{children}</p>
    </div>
  );
}

export function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-ink-2">{children}</span>;
}
