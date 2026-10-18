"use client";

/**
 * Entry point. One button starts the whole demo.
 *
 * Deliberately spare: the pipeline is the product, so the landing page's only
 * job is to get you into a session and out of its own way.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight, Play, Radio, Upload, Zap } from "lucide-react";
import api from "@/services/api.service";
import { API_BASE } from "@/constants/config";
import type { Health, IngestResult, SessionSummary } from "@/types/api";
import { Button } from "@/components/ui";

export default function Landing() {
  const router = useRouter();
  const [health, setHealth] = useState<Health | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [liveActive, setLiveActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([
        api.get<Health>("/api/health"),
        api.get<SessionSummary[]>("/api/sessions", { params: { limit: 8 } }),
      ]);
      setHealth(h.data);
      setSessions(s.data);
      setError(null);
    } catch {
      setError(
        "Backend unreachable. Start it with:  uvicorn main:app --app-dir backend --port 8000",
      );
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function ingestSamples() {
    setBusy(true);
    setError(null);
    try {
      const { data } = await api.post<IngestResult>("/api/ingest/samples");
      router.push(`/${data.session_id}/triage`);
    } catch (e) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Ingestion failed.";
      setError(msg);
      setBusy(false);
    }
  }

  /** Live mode: starts SSE stream and navigates to triage immediately. */
  async function ingestLive() {
    setLiveActive(true);
    setError(null);
    try {
      const controller = new AbortController();
      abortRef.current = controller;
      const resp = await fetch(`${API_BASE}/api/run/stream`, {
        method: "POST",
        signal: controller.signal,
      });
      if (!resp.ok || !resp.body) {
        setError(`Stream failed: HTTP ${resp.status}`);
        setLiveActive(false);
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let sessionId: string | null = null;
      let navigated = false;

      // Process the stream — navigate as soon as we know the session ID
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const messages = buffer.split("\n\n");
        buffer = messages.pop() ?? "";

        for (const msg of messages) {
          if (!msg.trim()) continue;
          let eventType = "";
          let data = "";
          for (const line of msg.split("\n")) {
            if (line.startsWith("event: ")) eventType = line.slice(7).trim();
            if (line.startsWith("data: ")) data = line.slice(6);
          }
          if (!data) continue;
          try {
            const parsed = JSON.parse(data);
            // Track session ID from any event
            if (parsed.session_id && !sessionId) {
              sessionId = parsed.session_id;
            }
            // Navigate only after detection is done — signals are in the DB
            if (sessionId && !navigated && (
              eventType === "detect_complete" ||
              eventType === "complete"
            )) {
              navigated = true;
              router.push(`/${sessionId}/triage`);
            }
          } catch {
            // skip
          }
        }
      }
      setLiveActive(false);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError((err as Error).message ?? "Live stream failed.");
      }
      setLiveActive(false);
    }
  }

  async function upload(files: FileList) {
    setBusy(true);
    setError(null);
    const form = new FormData();
    Array.from(files).forEach((f) => form.append("files", f));
    try {
      const { data } = await api.post<IngestResult>("/api/upload", form);
      router.push(`/${data.session_id}/triage`);
    } catch (e) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Upload failed.";
      setError(msg);
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 max-w-[1100px] w-full mx-auto px-6 py-20 flex flex-col gap-12">
        {/* Thesis */}
        <header className="flex flex-col gap-5 anim-fade">
          <span className="label">SIH26-S01 · Agentic AI Cybersecurity Assistant</span>
          <h1 className="text-5xl md:text-6xl font-extrabold tracking-tighter uppercase leading-[0.95]">
            Sentinel<span className="text-ink-3">SOC</span>
          </h1>
          <p className="text-ink-2 max-w-2xl leading-relaxed">
            Raw security logs in. Correlated incidents out — each one carrying
            its MITRE mapping, a risk score that explains itself, evidence
            citing the exact log lines, and a response playbook. Three
            specialised agents do the work an analyst would otherwise do by
            hand.
          </p>
        </header>

        {/* Actions */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="glass rounded-lg p-6 flex flex-col gap-3">
            <span className="label">Bundled corpus</span>
            <p className="text-sm text-ink-2 flex-1">
              Four log sources with five attack chains planted in them: SSH
              brute force into privilege escalation, a port scan into SQL
              injection and bulk theft, after-hours insider exfiltration,
              lateral movement on stolen credentials, and a password spray.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button onClick={ingestSamples} busy={busy} disabled={!!error || liveActive}>
                <Play size={13} /> {busy ? "Ingesting" : "Run the pipeline"}
              </Button>
            </div>
          </div>

          <div className="glass rounded-lg p-6 flex flex-col gap-3">
            <span className="label">Your own logs</span>
            <p className="text-sm text-ink-2 flex-1">
              The filename selects the parser, so name files{" "}
              {(health?.supported_sources ?? []).map((s, i) => (
                <span key={s}>
                  {i > 0 && ", "}
                  <code className="font-mono text-ink-1">{s}</code>
                </span>
              ))}
              .
            </p>
            <label className="inline-flex">
              <input
                type="file"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && upload(e.target.files)}
              />
              <span
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-white/15
                  text-xs font-bold uppercase tracking-widest text-ink-2
                  hover:text-ink hover:bg-white/5 cursor-pointer transition-colors"
              >
                <Upload size={13} /> Upload logs
              </span>
            </label>
          </div>
        </div>

        {error && (
          <div
            className="glass rounded-lg p-4 flex items-start gap-3"
            style={{ borderColor: "rgb(255 51 51 / .3)" }}
          >
            <AlertTriangle size={16} className="mt-0.5 shrink-0" color="#ff3333" />
            <p className="font-mono text-xs text-ink-1 leading-relaxed">{error}</p>
          </div>
        )}

        {/* Provider chain */}
        {health && (
          <div className="flex flex-wrap items-center gap-3">
            <span className="label">Provider chain</span>
            {health.llm_chain.length ? (
              health.llm_chain.map((c, i) => (
                <span key={c.provider} className="flex items-center gap-3">
                  {i > 0 && <span className="text-ink-3 text-xs">fallback &rarr;</span>}
                  <span className="chip" data-sev={i === 0 ? "low" : "none"}>
                    <Radio size={10} /> {c.provider} · {c.model}
                  </span>
                </span>
              ))
            ) : (
              <span className="chip" data-sev="none">
                no key set — deterministic fallbacks
              </span>
            )}
          </div>
        )}

        {/* Prior sessions */}
        {sessions.length > 0 && (
          <div className="flex flex-col gap-2">
            <span className="label">Recent sessions</span>
            <div className="glass rounded-lg divide-y divide-white/[0.07]">
              {sessions.map((s) => (
                <button
                  key={s.session_id}
                  onClick={() => router.push(`/${s.session_id}/triage`)}
                  className="w-full flex items-center gap-4 px-5 py-3 text-left hover:bg-white/5 transition-colors"
                >
                  <span className="font-mono text-xs text-ink-2 shrink-0">
                    {s.session_id}
                  </span>
                  <span className="text-sm text-ink-1 truncate flex-1">{s.label}</span>
                  <span className="font-mono text-[11px] text-ink-3 tabular-nums hidden sm:block">
                    {s.event_count.toLocaleString()} ev · {s.signal_count} sig ·{" "}
                    {s.incident_count} inc
                  </span>
                  <ArrowRight size={14} className="text-ink-3 shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
