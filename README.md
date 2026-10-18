# SentinelSOC

**Agentic AI Cybersecurity Assistant for Automated Threat Investigation and Incident Response**
SIH26-S01

Ingests raw security logs, detects suspicious activity with deterministic
detectors, then hands the survivors to three specialised AI agents that
correlate them into incidents, explain the evidence, score the risk, and produce
a downloadable incident report.

## What it does

```
14,803 raw log lines  ->  16 detection signals  ->  4 correlated incidents  ->  1 report
```

## Pipeline

```
  auth.log · nginx_access.log · firewall.log · windows_security.log
        │
        ▼
  INGEST          four native formats -> one nine-field event schema
                  Drain3 template mining (from LogGuard)
        │
        ▼
  DETECT          runs before any token is spent; produces candidates, not verdicts
                  ├─ 9 hand-written rules (brute force, port sweep, injection,
                  │  success-after-failure, egress volume, privesc, off-hours
                  │  access, lateral movement, credential spraying)
                  ├─ 5-detector consensus over entity-centric 5-minute windows
                  │  (Isolation Forest · LOF · ECOD · COPOD · LSTM autoencoder)
                  │  weighted, MAD-thresholded, corroboration-gated
                  ├─ Drain3 template rarity
                  └─ Logic gate: the model PROPOSES rules, an AST validator CHECKS
                     them against the real schema, a deterministic engine EXECUTES
                     them. A hallucinated field is rejected, not run.
        │
        ▼  signals
  REDACT          pseudonymise before anything leaves the machine
        │
        ▼
  AGENTS          plain-Python orchestrator, staged, every hop persisted
                  ├─ 1. Log Analysis Agent       normalise · extract IOCs · summarise
                  ├─ 2. Threat Investigation     correlate · MITRE · risk · evidence
                  │     tool: fetch_log_window() — it decides when it needs more
                  └─ 3. Response Agent           containment · eradication · recovery
        │
        ▼
  STORE           one FalkorDB graph: events linked to host · user · IP,
                  signals cite events, incidents correlate signals
        │
        ▼
  REPORT          Markdown + HTML with a print stylesheet, served as a download
```

## Where it came from

Merged from two repositories, per `../IMPLEMENTATION_PLAN.md`.

**From DataSentinel (the base)** — the staged pipeline-context pattern, the
neuro-symbolic logic gate (retargeted from business rules to security
detection), the LLM-as-a-single-seam design, analyst feedback damping
thresholds, and the report-download endpoint.

**From LogGuard** — Drain3 template mining (lifted out of Flink, and out of its
mandatory `drain3.ini`), the log-event vocabulary, and the attack scenarios that
seeded the sample generator.

**Built new** — everything security-specific: the ingestion and normalisation
layer, all seven detection rules, entity-centric ML features, the MITRE
catalogue and its validator, all three agents, the tool loop, incident
correlation, risk scoring, response playbooks, and the incident report.

Neither source repository carries an open licence. Both were used as reference;
this is a fresh implementation. See §10 of the implementation plan.

## Design decisions worth defending

**Five detectors, because each is blind differently.** Isolation Forest
partitions on feature splits and misses dense clusters; LOF is local and misses
global shifts; ECOD and COPOD are training-free tail methods; only the LSTM
autoencoder sees *sequence*, which separates "this window is odd" from "this
entity's behaviour changed". Scores are normalised against the clean subset,
combined by weight, and cut with a **median + 3·MAD** threshold — robust because
the distribution being thresholded contains, by construction, the outliers being
hunted.

Three gates then decide what an analyst actually sees, and each catches a
failure the others miss: **corroboration** (most detectors must agree),
**margin** (barely clearing the bar is not a finding), and an **alert budget**
per entity (a detector nobody reads has a recall of zero). On the bundled corpus
this surfaces all four attacking entities and no ordinary host.

**Risk is causal, not just severity.** `causal.py` fits a feature DAG with
NOTEARS (Zheng et al. 2018): a weighted adjacency matrix learned by gradient
descent under the constraint `trace(exp(W∘W)) - d = 0`, which is exactly zero
iff the graph is acyclic — turning a discrete graph search into an ordinary
optimisation. An incident's weight is its own deviation plus the deviation of
everything it causally reaches, so a spike leading nowhere ranks below the same
spike followed downstream by privilege change and egress.

Two things this needed in practice. Dual ascent, because a fixed acyclicity
penalty converged to h=0.073 and kept both `a→b` and `b→a`. And a kill-chain
weighting, because blast radius measures how *anomalous* an incident is, not how
much *harm* it did — the credential spray is 10σ on `distinct_users` yet never
authenticated once, and scoring on deviation alone ranked it above two confirmed
exfiltrations.

Limits worth stating: the DAG is over features, not incidents; it is linear and
observational, so "causal" means recovered structure, not proof of mechanism.
It runs only on the deterministic fallback — with a model reachable, the
investigation agent scores and explains risk itself.

**The detectors gate the model.** Nothing reaches an agent that a cheap,
explainable detector did not first flag. This bounds token cost and it is the
answer to "is this just prompting?"

**The store is a graph.** Events are linked to the hosts, accounts and
addresses they mention, signals cite their events, and incidents correlate
signals. "What else did 203.0.113.45 touch" is one traversal, not a self-join.
FalkorDB runs embedded from one file by default, so the demo still needs no
server; set `FALKORDB_URL` to point at one. The English query screen writes
Cypher, and every query runs through `GRAPH.RO_QUERY`, so the engine itself
refuses a prompt-injected write.

**The model proposes, it never decides.** In the logic gate the model writes a
rule in a constrained grammar; every field name, operator, aggregate, window and
threshold is validated against the real schema before a single event is read.
`/api/logic-rules/{session}` shows every proposed rule and why each was accepted
or rejected.

**MITRE IDs are snapped to a catalogue.** The investigation agent picks from a
curated list. An invented sub-technique falls back to its parent; anything
unrecognised is flagged unmapped rather than silently trusted.

**Every claim cites its events.** Incident evidence carries the event IDs that
support it, and the end-to-end test asserts those IDs are real rows.

**Nothing sensitive leaves the machine.** Evidence goes to a third-party API,
which for a security tool is a real objection. `redaction.py` pseudonymises
before egress and reverses on the way back, so the model reasons over
`INT_IP_03 contacted EXT_IP_01` and the analyst reads real addresses.
Consistent tokens rather than deletion, because in a security investigation the
identifiers *are* the signal. Three modes: `off`, `pii` (default — emails,
phones, Aadhaar, PAN, cards; credentials destroyed outright), `strict` (also
addresses, hosts, accounts). The tool output is redacted too, or the agent could
bypass it by simply asking for the logs.

**Every stage has a deterministic fallback.** With no API key the whole pipeline
still completes. That is what makes `DEMO_MODE=cached` possible and what keeps a
dead network from ending the demo.

## Providers

`backend/llm_client.py` is the only file that knows a provider exists. It has
been rewritten three times (Groq → OpenRouter → OpenRouter + Gemini) without a
single change anywhere else in the codebase.

| Order | Provider | Key | Default model |
|---|---|---|---|
| 1 | OpenRouter | `OPENROUTER_API_KEY` | `z-ai/glm-5.2:free` |
| 2 | Gemini | `GEMINI_API_KEY` | `gemini-2.5-flash` |
| — | offline | none | deterministic fallbacks |

The chain is a **runtime** fallback, not config precedence. If an OpenRouter
call fails — network, 401, 429, a bad slug, or output that never validates —
the same call is retried against Gemini before anything gives up. Only when
every configured provider fails does a call return `None`, and the agents
handle `None` with deterministic logic. `last_provider_used` on `/api/health`
reports which one actually served the last call.

Both providers support the full agentic tool loop, so Agent 2 pulls its own
evidence either way. The wire formats differ and both are tested: OpenRouter
echoes the assistant turn with `tool_calls` intact and answers each with a
`tool` message keyed by `tool_call_id`; Gemini uses `functionCall` /
`functionResponse` parts with `user`/`model` roles.

Both use JSON mode with the schema in the system prompt, and re-prompt with the
validation error on a miss. Neither uses native schema enforcement: OpenRouter
fronts dozens of vendors with uneven `json_schema` support, and Gemini's
`responseSchema` rejects the `$ref`/`$defs` that Pydantic emits for nested
models.

### Cost

Both defaults are free. `z-ai/glm-5.2:free` is one of nine free OpenRouter
models supporting both tool calling and JSON mode — Agent 2's evidence loop
needs both, and most free models have only one. Gemini's API key from
[AI Studio](https://aistudio.google.com/apikey) also has a free tier, so the
fallback costs nothing either.

Free tiers are **rate-limited** — commonly ~20 requests/minute plus a daily cap.
One full pipeline run is about 17 calls (13 for Agent 1, one per signal; 1 for
Agent 2; 3 for Agent 3). Three mitigations, in order of usefulness:

1. **Record a cached run early** — `RECORD_DEMO=1 python scripts/run_pipeline.py`.
   Replays cost nothing and make the demo network-independent.
2. **The Gemini fallback absorbs rate limits automatically.** A 429 from
   OpenRouter is just another failure the chain steps over.
3. **The deterministic fallbacks mean it never hard-fails**, only degrades.

Paid models work by setting `OPENROUTER_MODEL` — `anthropic/*`, `openai/*`,
`google/gemini-*`. Claude remains reachable that way; it is simply not the
default, because a hackathon should not need a credit card.

Model slugs change. Check before relying on one:

```bash
python scripts/check_providers.py          # verify both configured models
python scripts/check_providers.py --free   # list usable free models
```

## Quick start

See [RUNBOOK.md](RUNBOOK.md).

```bash
./start.sh          # backend :8000 + dashboard :3000
```

Or headless:

```bash
.venv/bin/python scripts/generate_logs.py
.venv/bin/python scripts/run_pipeline.py --reset
```

## The dashboard

DataSentinel's App Router shell wearing LogGuard's visual language: a monochrome
console where severity is the only saturated colour, Manrope over Iosevka
Charon, glass panels on black. Both typefaces ship with the app rather than
loading from a CDN, so the dashboard renders identically with the network
unplugged — the same promise as the cached demo run.

Dropped from DataSentinel's frontend: Three.js, GSAP, Lenis, Framer Motion and
ag-grid. They are demo-fragile on a projector, and its scripts needed a 4 GB
heap flag to build with them present.

Four screens in pipeline order — Triage, Agents, Incidents, Report — so the nav
doubles as the story a judge is walked through.

## Layout

```
backend/
  schemas.py        every agent contract, written before the prompts
  llm_client.py     the provider seam — OpenRouter, Gemini, offline, replay
  store.py          FalkorDB graph: events · entities · signals · incidents · agent_runs
  mitre.py          ATT&CK catalogue + validator
  causal.py         NOTEARS causal DAG, blast-radius risk scoring
  service.py        ingest -> detect
  report.py         incident report, Markdown and HTML
  feedback.py       analyst verdicts damp noisy rules
  redaction.py      reversible pseudonymisation before egress
  main.py           FastAPI
  ingest/parsers.py four log formats -> one schema
  detect/
    rules.py        7 deterministic rules
    ml.py           Isolation Forest + template rarity
    logic_gate.py   AI-proposed rules with AST validation
    pipeline.py     the detection gate
  agents/
    log_analysis.py          Agent 1
    threat_investigation.py  Agent 2 + fetch_log_window
    response.py              Agent 3
    orchestrator.py          staged, persisted
scripts/
  generate_logs.py  sample data with three planted attack chains
  run_pipeline.py   CLI driver
  check_providers.py  verify keys and find valid model slugs
frontend/
  src/app/          Next.js App Router - landing + [sessionId]/{triage,agents,incidents,report}
  src/components/   console primitives in LogGuard's language
  public/fonts/     Manrope + Iosevka Charon, shipped not fetched
tests/              110 tests
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | provider, model, replay state |
| POST | `/api/ingest/samples` | ingest the bundled logs |
| POST | `/api/upload` | ingest uploaded log files |
| GET | `/api/signals/{sid}` | detection signals (feedback-adjusted) |
| GET | `/api/logic-rules/{sid}` | AI-proposed rules + accept/reject verdicts |
| POST | `/api/investigate/{sid}` | run all three agents |
| GET | `/api/incidents/{sid}` | incidents with response plans |
| GET | `/api/incident/{iid}` | one incident |
| GET | `/api/trace/{sid}` | the agent_runs table |
| GET | `/api/events/{sid}` | query raw events |
| POST | `/api/feedback/{sid}` | mark a signal true/false positive |
| GET | `/api/report/{sid}` | report as Markdown |
| GET | `/api/report/{sid}/view` | report as HTML |
| GET | `/api/report/{sid}/download` | report as a download |
