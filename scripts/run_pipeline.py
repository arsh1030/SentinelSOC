"""
SentinelSOC - CLI driver.

    python scripts/run_pipeline.py                  # ingest samples + investigate
    python scripts/run_pipeline.py --ingest-only
    RECORD_DEMO=1 python scripts/run_pipeline.py    # save responses for cached mode
    DEMO_MODE=cached python scripts/run_pipeline.py # replay them, no network
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import store  # noqa: E402
from agents import run_investigation  # noqa: E402
from llm_client import get_client  # noqa: E402
from service import ingest_directory  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", default=str(ROOT / "data" / "samples"))
    ap.add_argument("--ingest-only", action="store_true")
    ap.add_argument("--reset", action="store_true", help="drop the database first")
    args = ap.parse_args()

    if args.reset:
        store.reset_db()
        print("database reset")

    print("\n=== INGEST + DETECT " + "=" * 44)
    client = get_client()
    chain = " -> ".join(f"{p.name}({p.model})" for p in client.chain) or "offline"
    print(f"  providers : {chain}")
    summary = ingest_directory(Path(args.samples), label="sample security logs", client=client)
    sid = summary["session_id"]
    print(f"  session   : {sid}")
    print(f"  events    : {summary['events']:,}")
    print(f"  per file  : {summary['per_file']}")
    print(f"  signals   : {summary['signals']}  via {summary.get('detectors')}")

    for s in store.get_signals(sid):
        print(f"    [{s['severity']:8s}] {s['rule_id']:6s} {s['score']:.2f}  {s['title'][:78]}")

    audit = store.get_logic_rules(sid)
    if audit:
        ok = sum(1 for a in audit if a["accepted"])
        print(f"\n  AI-proposed rules: {ok}/{len(audit)} passed schema validation")
        for a in audit:
            mark = "accept" if a["accepted"] else "REJECT"
            print(f"    [{mark}] {a['statement'][:74]}")
            if not a["accepted"]:
                print(f"             reason: {a['reason']}")

    if args.ingest_only:
        return 0

    print("\n=== AGENTS " + "=" * 53)
    ctx = run_investigation(sid, client)

    print("\n=== INCIDENTS " + "=" * 50)
    for inc in store.get_incidents(sid):
        techs = ", ".join(t["technique_id"] for t in inc["mitre_techniques"])
        print(f"\n  {inc['incident_id']}  risk {inc['risk_score']}/100  [{inc['severity']}]")
        print(f"    {inc['title']}")
        print(f"    stage    : {inc['kill_chain_stage']}   MITRE: {techs}")
        print(f"    signals  : {inc['signal_ids']}")
        print(f"    hosts    : {', '.join(inc['affected_hosts'])}")
        print(f"    narrative: {inc['narrative'][:200]}")
        plan = store.get_plan(inc["incident_id"])
        if plan:
            print(f"    response : {len(plan['actions'])} actions, "
                  f"contain within {plan['containment_deadline_minutes']}m, "
                  f"escalate to {plan['escalate_to']}")
            for a in plan["actions"][:3]:
                print(f"       {a['order']}. [{a['phase']}/{a['urgency']}] {a['action']}")

    runs = store.get_runs(sid)
    print(f"\n=== AGENT TRACE ({len(runs)} hops) " + "=" * 38)
    for r in runs:
        tc = f", {len(r['tool_calls'])} tool call(s)" if r["tool_calls"] else ""
        print(f"  stage {r['stage_index']} {r['agent']:22s} {r['latency_ms']:6d}ms  "
              f"{r['input_summary'][:60]}{tc}")

    print(f"\n  used model: {ctx.used_model}")
    if client.last_provider:
        print(f"  served by : {client.last_provider}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
