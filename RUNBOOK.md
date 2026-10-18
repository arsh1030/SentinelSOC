# SentinelSOC — Runbook

## First run (about 2 minutes)

```bash
cd sentinel
uv venv --python 3.12 .venv          # or: python3.12 -m venv .venv
uv pip install -r requirements.txt   # or: .venv/bin/pip install -r requirements.txt

cp .env.example .env                 # add ANTHROPIC_API_KEY (optional — see below)

.venv/bin/python scripts/generate_logs.py     # writes ~14,700 sample log lines
.venv/bin/python scripts/run_pipeline.py --reset
```

That last command runs everything: ingest → detect → three agents → incidents.
It prints the signals, the incidents, the response plans and the agent trace.

## The store: FalkorDB

Everything persists in a FalkorDB graph. By default it is **embedded**:
`falkordblite` (installed by `requirements.txt`) runs FalkorDB from
`data/sentinel.falkordb`, so no server and no Docker. The first connection in a
process takes ~2 s while the embedded server boots.

To use a FalkorDB server instead:

```bash
docker run -p 6379:6379 -it --rm falkordb/falkordb
echo 'FALKORDB_URL=redis://localhost:6379' >> .env
```

`FALKORDB_GRAPH` picks the graph name (default `sentinel`).

### Migrating an old SQLite store

Sessions in an existing `data/sentinel.db` are copied with their original ids
and verified by reading them back:

```bash
.venv/bin/python scripts/migrate_sqlite_to_falkordb.py --dry-run   # what would move
.venv/bin/python scripts/migrate_sqlite_to_falkordb.py             # migrate + verify
```

The SQLite file is opened read-only and left alone. Re-running skips sessions
already in the graph (`--replace` overwrites them). To roll back, delete
`data/sentinel.falkordb` (or the graph on your server).

## Choosing a provider

OpenRouter is primary; Gemini is the automatic fallback. Set either or both:

```bash
OPENROUTER_API_KEY=sk-or-...     # openrouter.ai/keys
GEMINI_API_KEY=...               # aistudio.google.com/apikey
```

Both defaults are free models, so neither key needs billing set up.

Verify the slugs before you rely on them — a wrong one is a 404 at the worst
possible moment:

```bash
.venv/bin/python scripts/check_providers.py          # verify configured models
.venv/bin/python scripts/check_providers.py --free   # list usable free models
```

**Free tiers are rate-limited** (commonly ~20 req/min plus a daily cap) and one
run is ~17 calls. Record a cached run as soon as the pipeline works, then demo
from the cache — it costs nothing and survives a dead network.

`/api/health` reports the whole chain and which provider served the last call.

## No API key?

Everything still runs. Each agent falls back to a deterministic implementation
and the pipeline completes with all three incidents. `used_model` in the output
tells you which stages reached a model:

```
used model: {'log_analysis': False, 'threat_investigation': False, 'response': False}
```

This is the safety net, not a degraded mode you have to avoid.

## The dashboard

```bash
cd frontend && npm install     # once
./start.sh                     # backend :8000 + dashboard :3000
```

`start.sh` refuses to start on a busy port rather than half-starting — port 3000
is often already taken, so use `PORT=3100 ./start.sh` in that case. It also
generates the sample logs if they are missing.

Four screens, in pipeline order:

| Screen | Shows |
|---|---|
| **Triage** | Signals from the deterministic detectors, before any model ran. Also lists AI-proposed rules with the accept/reject verdict on each. Thumbs-down damps a noisy rule. |
| **Agents** | The recorded trace: three stages, every hop, the handoff, and the evidence Agent 2 pulled for itself. Click any hop for its raw output. |
| **Incidents** | Risk score, MITRE mapping, evidence, response playbook. Evidence claims expand into the actual log lines they cite. |
| **Report** | The full report, with Markdown and HTML download. |

The frontend needs the backend URL only at build/run time via
`NEXT_PUBLIC_API_URL` (`start.sh` sets it). CORS accepts any localhost port by
default; set `CORS_ORIGINS` for a real deployment.

## The API

```bash
.venv/bin/python -m uvicorn main:app --app-dir backend --port 8000 --reload
```

Docs at `http://localhost:8000/api/docs`.

```bash
SID=$(curl -s -X POST localhost:8000/api/ingest/samples | jq -r .session_id)
curl -s -X POST localhost:8000/api/investigate/$SID | jq '.incidents_out'
curl -s localhost:8000/api/incidents/$SID | jq '.[0]'
curl -s localhost:8000/api/trace/$SID | jq 'length'
curl -sO -J "localhost:8000/api/report/$SID/download?fmt=html"
```

## Before the demo — record the cached run

Do this while the network is good, not at 4:50.

```bash
RECORD_DEMO=1 .venv/bin/python scripts/run_pipeline.py --reset
```

Every model response lands in `fixtures/demo_run.json`. Then, if the venue wifi
dies mid-pitch:

```bash
DEMO_MODE=cached .venv/bin/python scripts/run_pipeline.py --reset
```

Zero network calls, identical output. Verify it with the cable unplugged before
you present.

## Redaction

Evidence reaches a third-party API. `REDACT_MODE` controls what it sees:

| Mode | Behaviour |
|---|---|
| `off` | send as-is |
| `pii` | **default** — emails, phones, Aadhaar, PAN, cards pseudonymised; credentials destroyed. Addresses and accounts stay readable. |
| `strict` | also pseudonymises IPs, hostnames and account names |

Tokens are consistent within a session and reversed before you see them, so
correlation still works: the model sees `INT_IP_03 reached HOST_02`, you read
`10.0.4.31 reached db-01`. `/api/investigate` returns a `redaction` summary of
exactly what was swapped.

```bash
REDACT_MODE=strict .venv/bin/python scripts/run_pipeline.py --reset
```

## Tests

```bash
.venv/bin/python -m pytest tests/ -q      # 110 tests, ~1.5s
```

`tests/test_pipeline_e2e.py` guards the demo itself: all five planted attack
chains must be detected, they must collapse to exactly four incidents, every
incident must cite real event IDs, and every MITRE ID must exist in the
catalogue. If those fail, the demo is broken — not degraded.

## Ingesting your own logs

Filenames select the parser, so name files one of `auth.log`, `nginx_access.log`,
`firewall.log`, `windows_security.log`:

```bash
curl -X POST localhost:8000/api/upload -F "files=@/var/log/auth.log"
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No sample logs found` | run `scripts/generate_logs.py` |
| 0 signals | logs parsed but nothing matched; check `/api/session/{id}` event count |
| `Unrecognised file name(s)` | rename the upload to a supported source name |
| Agents return templated text | no API key set — check `/api/health` |
| OpenRouter 404 on the model | bad slug — run `scripts/check_providers.py` |
| OpenRouter 401 | key not set, or set after the shell started |
| Falls through to Gemini every call | check the OpenRouter line in the log — usually a bad slug or a daily cap |
| OpenRouter 429 | free-tier rate limit; the Gemini fallback covers it, or demo from the cache |
| Gemini slug unverifiable | Google needs a key to list models; get one at aistudio.google.com/apikey |
| `provider=offline` with a key set | key is in `.env` but the shell was started before it; restart |
| `Redis socket file ... is not present` | the embedded FalkorDB could not start; check `data/` is writable, or set `FALKORDB_URL` |
| `Connection refused` on 6379 | `FALKORDB_URL` is set but no server is running |
