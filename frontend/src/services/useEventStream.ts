/**
 * React hook for consuming Server-Sent Events from the SentinelSOC backend.
 *
 * Opens an EventSource (via fetch + ReadableStream, since SSE endpoints are
 * POST not GET) and dispatches typed callbacks as events arrive.  Returns
 * connection state and a close function.
 *
 * Usage:
 *   const stream = useEventStream(url, {
 *     onSignal: (d) => setSignals(prev => [...prev, d]),
 *     onAgentHop: (d) => setRuns(prev => [...prev, d]),
 *     onIncident: (d) => setIncidents(prev => [...prev, d]),
 *     onComplete: (d) => setDone(true),
 *   });
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE } from "@/constants/config";

export interface SSECallbacks {
  onIngestProgress?: (data: Record<string, unknown>) => void;
  onSignal?: (data: Record<string, unknown>) => void;
  onDetectComplete?: (data: Record<string, unknown>) => void;
  onAgentHop?: (data: Record<string, unknown>) => void;
  onIncident?: (data: Record<string, unknown>) => void;
  onComplete?: (data: Record<string, unknown>) => void;
  onError?: (data: Record<string, unknown>) => void;
}

const EVENT_MAP: Record<string, keyof SSECallbacks> = {
  ingest_progress: "onIngestProgress",
  signal: "onSignal",
  detect_complete: "onDetectComplete",
  agent_hop: "onAgentHop",
  incident: "onIncident",
  complete: "onComplete",
  error: "onError",
};

export interface UseEventStreamReturn {
  connected: boolean;
  done: boolean;
  lastEvent: string | null;
  start: () => void;
  close: () => void;
}

/**
 * Opens a POST-based SSE stream and dispatches typed events.
 *
 * We use fetch + ReadableStream instead of EventSource because the SSE
 * endpoints are POST (EventSource only supports GET).
 */
export function useEventStream(
  path: string,
  callbacks: SSECallbacks,
): UseEventStreamReturn {
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [lastEvent, setLastEvent] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const cbRef = useRef(callbacks);
  cbRef.current = callbacks;

  const close = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setConnected(false);
  }, []);

  const start = useCallback(() => {
    // Prevent double-start
    if (abortRef.current) return;

    const controller = new AbortController();
    abortRef.current = controller;
    setDone(false);
    setConnected(true);
    setLastEvent(null);

    (async () => {
      try {
        const resp = await fetch(`${API_BASE}${path}`, {
          method: "POST",
          signal: controller.signal,
        });

        if (!resp.ok || !resp.body) {
          setConnected(false);
          cbRef.current.onError?.({ message: `HTTP ${resp.status}` });
          return;
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done: streamDone, value } = await reader.read();
          if (streamDone) break;

          buffer += decoder.decode(value, { stream: true });

          // SSE messages are separated by double newlines
          const messages = buffer.split("\n\n");
          // Keep the last (possibly incomplete) chunk in the buffer
          buffer = messages.pop() ?? "";

          for (const msg of messages) {
            if (!msg.trim()) continue;

            let eventType = "message";
            let data = "";

            for (const line of msg.split("\n")) {
              if (line.startsWith("event: ")) {
                eventType = line.slice(7).trim();
              } else if (line.startsWith("data: ")) {
                data = line.slice(6);
              }
            }

            if (!data) continue;

            try {
              const parsed = JSON.parse(data);
              setLastEvent(eventType);

              const cbKey = EVENT_MAP[eventType];
              if (cbKey && cbRef.current[cbKey]) {
                cbRef.current[cbKey]!(parsed);
              }

              if (eventType === "complete") {
                setDone(true);
                setConnected(false);
              }
              if (eventType === "error") {
                setConnected(false);
              }
            } catch {
              // Malformed JSON — skip
            }
          }
        }

        setConnected(false);
        setDone(true);
      } catch (err) {
        if ((err as Error).name !== "AbortError") {
          setConnected(false);
          cbRef.current.onError?.({
            message: (err as Error).message ?? "Stream failed",
          });
        }
      }
    })();
  }, [path]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  return { connected, done, lastEvent, start, close };
}
