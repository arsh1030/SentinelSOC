"use client";

/**
 * The downloadable incident report — the last item in the problem statement's
 * expected output. Rendered from the same Markdown the backend serves, so the
 * screen and the file can never drift apart.
 */

import { use, useEffect, useState } from "react";
import { Download, FileText } from "lucide-react";
import api from "@/services/api.service";
import { API_BASE } from "@/constants/config";
import { Button, Empty, Panel } from "@/components/ui";

export default function ReportPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const [markdown, setMarkdown] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<string>(`/api/report/${sessionId}`, { responseType: "text" })
      .then((r) => setMarkdown(r.data))
      .catch(() => setMarkdown(""));
  }, [sessionId]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tighter uppercase">
            Incident report
          </h1>
          <p className="text-sm text-ink-2 mt-1">
            Every incident, its evidence and its playbook, in one analyst-facing
            document.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="ghost"
            href={`${API_BASE}/api/report/${sessionId}/download?fmt=md`}
          >
            <Download size={13} /> Markdown
          </Button>
          <Button href={`${API_BASE}/api/report/${sessionId}/download?fmt=html`}>
            <Download size={13} /> HTML
          </Button>
        </div>
      </div>

      <Panel
        title="Preview"
        right={
          <a
            href={`${API_BASE}/api/report/${sessionId}/view`}
            target="_blank"
            rel="noreferrer"
            className="label hover:text-ink transition-colors"
          >
            open printable ↗
          </a>
        }
      >
        {markdown === null ? (
          <Empty>Loading report…</Empty>
        ) : markdown === "" ? (
          <Empty>
            <FileText size={20} className="mx-auto mb-2 text-ink-3" />
            No report yet — run the agents first.
          </Empty>
        ) : (
          <div className="max-h-[70vh] overflow-y-auto -mx-1 px-1">
            <Markdown source={markdown} />
          </div>
        )}
      </Panel>
    </div>
  );
}

/**
 * Small renderer for exactly the Markdown subset the backend emits: headings,
 * tables, lists, fenced code, bold and inline code. A dependency would be more
 * general and none of that generality is needed here.
 */
function Markdown({ source }: { source: string }) {
  const blocks: React.ReactNode[] = [];
  const lines = source.split("\n");
  let i = 0;
  let key = 0;

  const inline = (text: string): React.ReactNode[] =>
    text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean).map((part, n) => {
      if (part.startsWith("`") && part.endsWith("`"))
        return (
          <code key={n} className="font-mono text-[12px] text-ink-1 bg-white/[0.06] px-1 py-0.5 rounded">
            {part.slice(1, -1)}
          </code>
        );
      if (part.startsWith("**") && part.endsWith("**"))
        return (
          <strong key={n} className="text-ink font-bold">
            {part.slice(2, -2)}
          </strong>
        );
      return <span key={n}>{part}</span>;
    });

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) body.push(lines[i++]);
      i++;
      blocks.push(
        <pre
          key={key++}
          className="my-3 p-4 rounded-md bg-black/60 border border-white/[0.07] overflow-x-auto font-mono text-[11px] leading-relaxed text-ink-2"
        >
          {body.join("\n")}
        </pre>,
      );
      continue;
    }

    if (line.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        const cells = lines[i].replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        if (!cells.every((c) => /^[-: ]*$/.test(c) && c.length)) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      blocks.push(
        <div key={key++} className="my-3 overflow-x-auto">
          <table className="w-full text-[13px] border border-white/[0.07] rounded-md">
            <thead>
              <tr className="border-b border-white/[0.07]">
                {head.map((h, n) => (
                  <th key={n} className="label text-left px-3 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.05]">
              {body.map((r, n) => (
                <tr key={n}>
                  {r.map((c, m) => (
                    <td key={m} className="px-3 py-2 text-ink-2 align-top">
                      {inline(c)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (line.startsWith("### "))
      blocks.push(<h3 key={key++} className="label mt-5 mb-1">{line.slice(4)}</h3>);
    else if (line.startsWith("## "))
      blocks.push(
        <h2 key={key++} className="text-lg font-bold tracking-tight mt-7 mb-2 pb-1 border-b border-white/[0.07]">
          {line.slice(3)}
        </h2>,
      );
    else if (line.startsWith("# "))
      blocks.push(
        <h1 key={key++} className="text-xl font-extrabold tracking-tighter uppercase mb-2">
          {line.slice(2)}
        </h1>,
      );
    else if (line.startsWith("- "))
      blocks.push(
        <p key={key++} className="text-[13px] text-ink-2 pl-4 relative leading-relaxed">
          <span className="absolute left-0 text-ink-3">·</span>
          {inline(line.slice(2))}
        </p>,
      );
    else if (line.startsWith("---")) blocks.push(<hr key={key++} className="my-5 border-white/[0.07]" />);
    else if (line.trim())
      blocks.push(
        <p key={key++} className="text-[13px] text-ink-2 leading-relaxed my-1">
          {inline(line)}
        </p>,
      );
    i++;
  }

  return <div>{blocks}</div>;
}
