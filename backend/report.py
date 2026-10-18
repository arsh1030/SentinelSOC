"""
SentinelSOC - incident report generation.

DataSentinel's report endpoint streamed a reportlab canvas of drawString calls -
functional, but a debug print with a .pdf extension. This produces a real analyst
document in Markdown, and an HTML rendering with a print stylesheet so the
browser's own Print-to-PDF gives a clean file with no extra dependency.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

import store

_SEV_COLOR = {
    "critical": "#B3261E",
    "high": "#B3541E",
    "medium": "#8A6D1F",
    "low": "#3A6B4F",
}


def _fmt_ts(raw: str) -> str:
    try:
        return datetime.fromisoformat(raw).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return raw or "-"


def build_markdown(session_id: str) -> str:
    session = store.get_session(session_id) or {}
    incidents = store.get_incidents(session_id)
    signals = {s["signal_id"]: s for s in store.get_signals(session_id)}
    runs = store.get_runs(session_id)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    tool_calls = sum(len(r["tool_calls"]) for r in runs)

    out: list[str] = [
        "# Security Incident Report",
        "",
        f"**Session** `{session_id}`  ",
        f"**Generated** {generated}  ",
        f"**Source data** {session.get('event_count', 0):,} events "
        f"across {len(signals)} detection signals  ",
        f"**Incidents** {len(incidents)}",
        "",
        "---",
        "",
        "## Executive summary",
        "",
    ]

    if not incidents:
        out += ["No incidents were raised for this session.", ""]
        return "\n".join(out)

    top = max(incidents, key=lambda i: i["risk_score"])
    crit = sum(1 for i in incidents if i["severity"] == "critical")
    out += [
        f"Automated triage reduced **{len(signals)} detection signals** to "
        f"**{len(incidents)} correlated incidents**, of which **{crit}** "
        f"{'is' if crit == 1 else 'are'} critical. The highest-risk incident is "
        f"**{top['incident_id']}** at **{top['risk_score']}/100** — {top['title']}.",
        "",
        f"Three specialised agents ran across {len(runs)} recorded hops"
        + (f", including {tool_calls} evidence retrieval{'s' if tool_calls != 1 else ''} "
           f"requested by the Threat Investigation Agent." if tool_calls else "."),
        "",
        "| Incident | Risk | Severity | Stage reached | Hosts |",
        "|---|---|---|---|---|",
    ]
    for inc in sorted(incidents, key=lambda i: -i["risk_score"]):
        out.append(
            f"| {inc['incident_id']} | {inc['risk_score']}/100 | {inc['severity']} | "
            f"{inc['kill_chain_stage'].replace('_', ' ')} | "
            f"{', '.join(inc['affected_hosts']) or '-'} |"
        )
    out += ["", "---", ""]

    for inc in sorted(incidents, key=lambda i: -i["risk_score"]):
        plan = store.get_plan(inc["incident_id"])
        out += [
            f"## {inc['incident_id']} — {inc['title']}",
            "",
            f"**Risk {inc['risk_score']}/100** · severity {inc['severity']} · "
            f"kill-chain stage reached: {inc['kill_chain_stage'].replace('_', ' ')} · "
            f"confidence {inc.get('confidence', 0):.0%}",
            "",
            "### What happened",
            "",
            inc["narrative"],
            "",
            "### Why this risk score",
            "",
            inc["risk_rationale"],
            "",
        ]

        if inc["mitre_techniques"]:
            out += ["### MITRE ATT&CK", "", "| Technique | Name | Tactic |", "|---|---|---|"]
            for t in inc["mitre_techniques"]:
                out.append(f"| `{t['technique_id']}` | {t['name']} | {t['tactic'].replace('_',' ')} |")
            out.append("")

        out += ["### Affected", "",
                f"- **Hosts**: {', '.join(inc['affected_hosts']) or 'none identified'}",
                f"- **Accounts**: {', '.join(inc['affected_users']) or 'none identified'}",
                f"- **Contributing signals**: {', '.join(f'#{s}' for s in inc['signal_ids'])}",
                ""]

        if inc["evidence"]:
            out += ["### Evidence", ""]
            for ev in inc["evidence"]:
                ids = ", ".join(str(i) for i in ev["event_ids"][:10])
                out.append(f"- {ev['claim']}  \n  *supporting events: {ids}*")
            out.append("")

        out += ["### Contributing signals", "",
                "| # | Rule | Severity | Score | Window | Detail |", "|---|---|---|---|---|---|"]
        for sid in inc["signal_ids"]:
            s = signals.get(sid)
            if not s:
                continue
            out.append(
                f"| {sid} | `{s['rule_id']}` | {s['severity']} | {s['score']:.2f} | "
                f"{_fmt_ts(s['ts_start'])} | {s['detail'][:150]} |"
            )
        out.append("")

        if plan:
            out += ["### Recommended response", "",
                    plan["executive_summary"], "",
                    f"**Contain within {plan['containment_deadline_minutes']} minutes.** "
                    f"Escalate to: {plan['escalate_to'].replace('_', ' ')}.", "",
                    "| # | Phase | Action | Execution | Urgency |", "|---|---|---|---|---|"]
            for a in plan["actions"]:
                out.append(
                    f"| {a['order']} | {a['phase']} | {a['action']} | "
                    f"{a['execution']} | {a['urgency']} |"
                )
            out.append("")
            cmds = [a for a in plan["actions"] if a.get("command")]
            if cmds:
                out += ["**Commands**", "", "```bash"]
                out += [f"# {a['action']}\n{a['command']}" for a in cmds]
                out += ["```", ""]
        out += ["---", ""]

    out += [
        "## Agent trace",
        "",
        "Every hop below was recorded as it ran. This is the provenance of the "
        "findings above.",
        "",
        "| Stage | Agent | Input | Latency | Tool calls |",
        "|---|---|---|---|---|",
    ]
    for r in runs:
        out.append(
            f"| {r['stage_index']} | {r['agent'].replace('_',' ')} | "
            f"{r['input_summary']} | {r['latency_ms']} ms | {len(r['tool_calls'])} |"
        )
    out += ["", f"*Generated by SentinelSOC on {generated}.*", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML rendering  (self-contained; print stylesheet gives a clean PDF)
# ---------------------------------------------------------------------------

_CSS = """
:root { --ink:#16191d; --mid:#4d565e; --soft:#78838b; --rule:#dde3e6;
        --bg:#ffffff; --sunk:#f4f6f8; --accent:#0f6e78; }
* { box-sizing:border-box; }
body { margin:0; padding:48px 32px 96px; background:var(--bg); color:var(--ink);
       font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
main { max-width:860px; margin:0 auto; }
h1 { font-size:2rem; margin:0 0 .4em; letter-spacing:-.02em; }
h2 { font-size:1.4rem; margin:2.2em 0 .5em; padding-bottom:.3em;
     border-bottom:2px solid var(--rule); letter-spacing:-.01em; }
h3 { font-size:1.05rem; margin:1.6em 0 .4em; color:var(--mid);
     text-transform:uppercase; letter-spacing:.06em; }
p, li { color:var(--mid); }
table { border-collapse:collapse; width:100%; margin:.8em 0 1.2em; font-size:.9rem; }
th { text-align:left; background:var(--sunk); color:var(--soft); font-weight:600;
     font-size:.72rem; text-transform:uppercase; letter-spacing:.08em;
     padding:9px 11px; border-bottom:2px solid var(--rule); }
td { padding:9px 11px; border-bottom:1px solid var(--rule); vertical-align:top; }
code { background:var(--sunk); border:1px solid var(--rule); border-radius:3px;
       padding:.08em .35em; font-size:.86em;
       font-family:ui-monospace,"SF Mono",Menlo,monospace; }
pre { background:var(--sunk); border:1px solid var(--rule); border-radius:5px;
      padding:14px 16px; overflow-x:auto; font-size:.84rem; }
pre code { background:none; border:none; padding:0; }
hr { border:none; border-top:1px solid var(--rule); margin:2.4em 0; }
em { color:var(--soft); font-size:.9em; }
blockquote { margin:0; padding-left:14px; border-left:3px solid var(--accent); }
@media print {
  body { padding:0; font-size:11pt; }
  h2 { page-break-after:avoid; } table { page-break-inside:avoid; }
  a[href]:after { content:""; }
}
"""


def _md_to_html(md: str) -> str:
    """
    Minimal, dependency-free Markdown rendering for exactly the subset this
    report emits: headings, tables, lists, fenced code, bold, inline code, rules.
    """
    lines = md.split("\n")
    out: list[str] = []
    in_table = in_code = False

    def inline(text: str) -> str:
        text = html.escape(text)
        # order matters: code spans first so bold markers inside them survive
        parts = text.split("`")
        for i in range(1, len(parts), 2):
            parts[i] = f"\x00code\x01{parts[i]}\x00/code\x01"
        text = "".join(parts)
        while "**" in text:
            text = text.replace("**", "\x00b\x01", 1)
            if "**" in text:
                text = text.replace("**", "\x00/b\x01", 1)
            else:
                text = text.replace("\x00b\x01", "**", 1)
                break
        text = text.replace("\x00code\x01", "<code>").replace("\x00/code\x01", "</code>")
        text = text.replace("\x00b\x01", "<strong>").replace("\x00/b\x01", "</strong>")
        # *emphasis* after bold, so it never eats bold markers
        while text.count("*") >= 2:
            text = text.replace("*", "<em>", 1).replace("*", "</em>", 1)
        return text

    def close_table() -> None:
        nonlocal in_table
        if in_table:
            out.append("</tbody></table>")
            in_table = False

    for raw in lines:
        line = raw.rstrip()

        if line.startswith("```"):
            close_table()
            out.append("</code></pre>" if in_code else '<pre><code>')
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(raw))
            continue

        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-: ") and c for c in cells):
                continue  # separator row
            if not in_table:
                out.append('<table><thead><tr>')
                out += [f"<th>{inline(c)}</th>" for c in cells]
                out.append("</tr></thead><tbody>")
                in_table = True
            else:
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        close_table()

        if not line.strip():
            continue
        if line.startswith("### "):
            out.append(f"<h3>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("---"):
            out.append("<hr>")
        elif line.startswith("- "):
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line.startswith("  *") and line.endswith("*"):
            out.append(f"<div><em>{inline(line.strip().strip('*'))}</em></div>")
        else:
            out.append(f"<p>{inline(line)}</p>")

    close_table()
    if in_code:
        out.append("</code></pre>")

    body = "\n".join(out)
    # wrap stray <li> runs
    body = body.replace("<li>", "<ul><li>", 1) if "<li>" in body else body
    if "<li>" in body:
        body = body[::-1].replace(">il/<", ">lu/<>il/<", 1)[::-1]

    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Security Incident Report</title>"
        f"<style>{_CSS}</style></head><body><main>{body}</main></body></html>"
    )


def build_html(session_id: str) -> str:
    return _md_to_html(build_markdown(session_id))
