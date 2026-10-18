"use client";

/**
 * Session context, following DataSentinel's provider pattern.
 *
 * Holds the session id and the counts every screen shows in its header, so the
 * nav can render progress without each page refetching the same summary.
 *
 * Extended with SSE streaming state: when a live pipeline run is active,
 * stream events are distributed to all subscribed pages via context.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import api from "@/services/api.service";
import type { Health, SessionSummary } from "@/types/api";

// --------------------------------------------------------------------------
// Stream event types — what each page can subscribe to
// --------------------------------------------------------------------------

export interface StreamCallbacks {
  onSignal?: (data: Record<string, unknown>) => void;
  onAgentHop?: (data: Record<string, unknown>) => void;
  onIncident?: (data: Record<string, unknown>) => void;
}

interface SessionCtx {
  sessionId: string;
  summary: SessionSummary | null;
  health: Health | null;
  refresh: () => Promise<void>;
  busy: string | null;
  setBusy: (v: string | null) => void;
  /** True when an SSE stream is actively pushing events */
  streaming: boolean;
  setStreaming: (v: boolean) => void;
  /** Subscribe a page to live events. Returns an unsubscribe function. */
  subscribe: (callbacks: StreamCallbacks) => () => void;
  /** Dispatch a stream event to all subscribers */
  dispatch: (eventType: string, data: Record<string, unknown>) => void;
  setSummary: React.Dispatch<React.SetStateAction<SessionSummary | null>>;
}

const Ctx = createContext<SessionCtx | null>(null);

export function useSession() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSession must be used inside SessionProvider");
  return ctx;
}

export function SessionProvider({
  children,
  sessionId,
}: {
  children: React.ReactNode;
  sessionId: string;
}) {
  const [summary, setSummary] = useState<SessionSummary | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);

  // Subscribers — pages register callbacks for live events
  const subscribersRef = useRef<Set<StreamCallbacks>>(new Set());

  const subscribe = useCallback((callbacks: StreamCallbacks) => {
    subscribersRef.current.add(callbacks);
    return () => {
      subscribersRef.current.delete(callbacks);
    };
  }, []);

  const dispatch = useCallback(
    (eventType: string, data: Record<string, unknown>) => {
      for (const sub of subscribersRef.current) {
        if (eventType === "signal" && sub.onSignal) sub.onSignal(data);
        if (eventType === "agent_hop" && sub.onAgentHop) sub.onAgentHop(data);
        if (eventType === "incident" && sub.onIncident) sub.onIncident(data);
      }
    },
    [],
  );

  const refresh = useCallback(async () => {
    try {
      const { data } = await api.get<SessionSummary>(`/api/session/${sessionId}`);
      setSummary(data);
    } catch {
      setSummary(null);
    }
  }, [sessionId]);

  useEffect(() => {
    refresh();
    api
      .get<Health>("/api/health")
      .then((r) => setHealth(r.data))
      .catch(() => setHealth(null));
  }, [refresh]);

  return (
    <Ctx.Provider
      value={{
        sessionId,
        summary,
        health,
        refresh,
        busy,
        setBusy,
        streaming,
        setStreaming,
        subscribe,
        dispatch,
        setSummary,
      }}
    >
      {children}
    </Ctx.Provider>
  );
}
