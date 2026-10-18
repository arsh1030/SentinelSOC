"use client";

/**
 * Ask the logs a question in English.
 *
 * The Cypher the model wrote is shown, always. An analyst who cannot see the query
 * cannot check the answer, and an answer nobody can check is not evidence. Failed
 * attempts are shown too — the self-healing retry is the interesting part, not
 * something to hide.
 */

import { use, useEffect, useState } from "react";
import { AlertTriangle, CornerDownLeft, Database, Search } from "lucide-react";
import api from "@/services/api.service";
import { Button, Empty, Panel } from "@/components/ui";

interface QueryResult {
  question: string;
  cypher: string;
  explanation: string;
  note: string;
  columns: string[];
  // Scalars mostly; a query returning whole nodes or lists yields objects.
  rows: Cell[][];
  row_count: number;
  attempts: { cypher: string; error: string }[];
  used_model: boolean;
}

type Cell = string | number | boolean | null | Cell[] | { [key: string]: Cell };

const show = (cell: Cell) =>
  typeof cell === "object" && cell !== null ? JSON.stringify(cell) : String(cell);

export default function QueryPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const [question, setQuestion] = useState("");
  const [examples, setExamples] = useState<string[]>([]);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<string[]>(`/api/query/${sessionId}/examples`)
      .then((r) => setExamples(r.data))
      .catch(() => setExamples([]));
  }, [sessionId]);

  async function ask(q: string) {
    const text = q.trim();
    if (!text) return;
    setQuestion(text);
    setBusy(true);
    setError(null);
    try {
      const { data } = await api.post<QueryResult>(`/api/query/${sessionId}`, {
        question: text,
      });
      setResult(data);
    } catch (e) {
      const detail =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(detail ?? "Query failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
          Ask the logs
        </h1>
        <p className="text-sm text-ink-2 mt-1 max-w-2xl">
          Plain English, translated to Cypher and run read-only against the event
          graph. The generated query is always shown, so any answer can be
          checked rather than taken on trust.
        </p>
      </div>

      <Panel>
        <div className="flex gap-2">
          <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-md bg-white/[0.03] border border-white/10 focus-within:border-white/25 transition-colors">
            <Search size={14} className="text-ink-3 shrink-0" />
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !busy && ask(question)}
              placeholder="Which accounts did 203.0.113.45 try?"
              className="flex-1 bg-transparent outline-none text-sm text-ink placeholder:text-ink-3"
            />
            <CornerDownLeft size={12} className="text-ink-3 shrink-0" />
          </div>
          <Button onClick={() => ask(question)} busy={busy} disabled={!question.trim()}>
            {busy ? "Asking" : "Ask"}
          </Button>
        </div>

        {examples.length > 0 && !result && (
          <div className="mt-4 flex flex-col gap-1.5">
            <span className="label">Try</span>
            {examples.map((ex) => (
              <button
                key={ex}
                onClick={() => ask(ex)}
                className="text-left text-[13px] text-ink-2 hover:text-ink transition-colors"
              >
                {ex}
              </button>
            ))}
          </div>
        )}
      </Panel>

      {error && (
        <div
          className="glass rounded-lg p-4 flex items-start gap-3"
          style={{ borderColor: "rgb(255 51 51 / .3)" }}
        >
          <AlertTriangle size={15} className="mt-0.5 shrink-0" color="#ff3333" />
          <p className="text-[13px] text-ink-1">{error}</p>
        </div>
      )}

      {result && (
        <>
          <Panel
            title="Generated query"
            right={
              <span className="chip" data-sev={result.used_model ? "low" : "none"}>
                {result.used_model ? "model" : "keyword fallback"}
              </span>
            }
          >
            {result.explanation && (
              <p className="text-[13px] text-ink-2 mb-3">{result.explanation}</p>
            )}
            <pre className="p-4 rounded-md bg-black/60 border border-white/[0.07] overflow-x-auto font-mono text-[11px] leading-relaxed text-ink-1">
              {result.cypher}
            </pre>
            {result.note && (
              <p className="text-[11px] text-ink-3 mt-2">{result.note}</p>
            )}

            {result.attempts.length > 0 && (
              <div className="mt-4">
                <span className="label">
                  Self-healing · {result.attempts.length} rejected before this one
                </span>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {result.attempts.map((a, i) => (
                    <li
                      key={i}
                      className="rounded-md bg-white/[0.02] border border-white/[0.06] px-3 py-2"
                    >
                      <pre className="font-mono text-[10px] text-ink-3 overflow-x-auto">
                        {a.cypher}
                      </pre>
                      <p
                        className="font-mono text-[10px] mt-1"
                        style={{ color: "#ff6600" }}
                      >
                        {a.error}
                      </p>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>

          <Panel
            title={`Result · ${result.row_count} row${result.row_count === 1 ? "" : "s"}`}
            right={
              result.row_count >= 200 ? (
                <span className="label">capped at 200</span>
              ) : null
            }
          >
            {result.rows.length === 0 ? (
              <Empty>
                <Database size={18} className="mx-auto mb-2 text-ink-3" />
                No rows matched.
              </Empty>
            ) : (
              <div className="overflow-x-auto -mx-5 max-h-[55vh] overflow-y-auto">
                <table className="w-full text-[13px]">
                  <thead className="sticky top-0 bg-surface">
                    <tr className="border-b border-white/[0.07]">
                      {result.columns.map((c) => (
                        <th key={c} className="label text-left px-4 py-2 font-medium">
                          {c}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.05]">
                    {result.rows.map((row, i) => (
                      <tr key={i} className="hover:bg-white/[0.03]">
                        {row.map((cell, j) => (
                          <td
                            key={j}
                            className="px-4 py-2 text-ink-2 font-mono text-[11px] align-top max-w-[420px] truncate"
                            title={cell === null ? "" : show(cell)}
                          >
                            {cell === null ? (
                              <span className="text-ink-3">null</span>
                            ) : (
                              show(cell)
                            )}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
