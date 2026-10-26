# AI Control Plane

AI usage monitoring, inventory, and compliance evidence for organizations that handle regulated data (CUI, ITAR, PII). Built by Consultant Works.

**Today (v0.1): monitor mode.** Collectors pull AI usage from systems the customer already has (Microsoft 365 / Copilot, log exports), normalize everything into one audit schema, score it against policy, and generate NIST SP 800-171 evidence.

**Also in v0.1: the inline gateway**, in monitor mode by default. Apps point at it instead of the model provider; it records every request into the same store with `observation_level: enforced` and the policy decision attached. Flip `AICP_GW_MODE=enforce` and the same policy starts blocking and masking.

## What's in the box

```
schemas/audit-event.schema.json   the contract every component reads and writes
api/                              FastAPI service: ingest, inventory, console, evidence export
collectors/                       pull upstream logs -> schema events -> POST /api/v1/events
gateway/                          OpenAI-compatible inline proxy: identify -> ingress -> forward -> egress -> audit
forwarder/                        SIEM forwarder: audit store -> Splunk HEC / Sentinel / syslog CEF / file
policies/                         OPA/Rego rules; advisory today, binding when the gateway ships
evidence/mappings/                 control mappings (800-171 -> narrative templates)
deploy/compose/                   single-box install (Postgres + OPA + API + collectors)
samples/                          demo data so the console isn't empty on first run
tests/                            pytest; policies have their own `opa test` suite
.github/workflows/ci.yml          lint, tests, policy tests, image build, SBOM
```

## Run it locally (5 minutes)

Prereqs: Docker Desktop.

```bash
cd deploy/compose
cp .env.example .env            # defaults are fine for local
docker compose --profile demo up --build
```

Open <http://localhost:8000>. **First login:** username `admin`; the password is printed once in `docker compose logs api` (or set `AICP_ADMIN_PASSWORD` in `.env` first). You'll be asked to change it. The `demo` profile loads `samples/sample-events.jsonl` once. Pages:

- `/` dashboard: coverage by observation level, flagged content, policy "would have acted" count
- `/inventory` every AI system seen, with governed / observed / declared state; click one to set approval, CUI scoping, owner and notes (every change is audited); "Declare a system" registers tools no log can see
- `/events` the audit log, filterable, raw JSON per event
- `/evidence` 800-171 control narratives generated from live data; download as Markdown or JSON
- `/docs` the API

Without Docker (dev loop):

```bash
pip install -r requirements-dev.txt
cd api && uvicorn app.main:app --reload          # SQLite, OPA off
cd collectors && python -m aicp_collectors.run file --path ../samples/sample-events.jsonl
pytest -q                                        # from repo root
```

## The gateway

```
  app ──(base_url = http://gateway:8080/v1, api_key = gateway key)──► gateway ──(provider key)──► OpenAI / Azure OpenAI / Bedrock / vLLM
                                                                         │
                                                                         ├──► OPA   (what does policy say?)
                                                                         └──► API   (audit event, observation_level=enforced)
```

Every request goes through four stages, one module each in `gateway/gw/`:

| Stage | Module | What it does |
|---|---|---|
| Identify | `identity.py` | Maps the app's gateway key to a user/agent identity. The provider key never leaves the gateway. |
| Ingress | `main.py` + `policy.py` | Extracts prompt text, runs the DLP scanner, asks OPA. **monitor**: record and pass through. **enforce**: `block` → 403 with policy ID; `mask` → replace flagged values with placeholders; `route_local` → send to the on-prem model instead. |
| Forward | `main.py` | Proxies to the upstream, streaming or not. |
| Egress | `main.py` + `audit.py` | Scans the response, restores masked values, emits the audit event. Audit is non-blocking and spills to a local file if the control plane is down. |

Try it (the demo profile includes a fake model that echoes your prompt):

```bash
docker compose --profile demo up --build
```

```python
from openai import OpenAI
c = OpenAI(base_url="http://localhost:8080/v1", api_key="gw-dev-key-alice")
c.chat.completions.create(model="mock-1", messages=[{"role": "user", "content": "Rewrite: CUI//SP-CTI bracket load 400 lbf"}])
```

In monitor mode that returns normally and the dashboard shows `AICP-001 block` under "policy would have acted". Set `AICP_GW_MODE=enforce` in `.env`, restart, and the same call returns `403 {"policy_id": "AICP-001", ...}`.

Gateway keys live in `gateway/gateway_keys.json` (copy from the `.example`; the real file is git-ignored). Each key maps to an identity and, for agents, the human sponsor, so audit records carry both.

What the gateway does **not** do yet, by design: streaming responses are scanned but not held (0.5); `require_approval` is a block with a distinct reason until the human-in-the-loop queue exists (0.4); tool/MCP calls that happen outside the chat completion payload are not seen (0.4); DLP is regex only (0.5 adds Presidio and a classifier). Masking replaces identifiers (keys, SSNs, CAGE codes); CUI-marked content is blocked or routed locally rather than masked, because stripping a banner doesn't make the content safe.

## How a customer deployment works

1. **Discovery.** List the AI tools in use. Register ones no log can see: `POST /api/v1/systems`.
2. **Entra app registration** in the customer tenant (one time): application permissions `AuditLog.Read.All`, `Directory.Read.All`, `SecurityAlert.Read.All`, `AiEnterpriseInteraction.Read.All`; grant admin consent; put tenant/client/secret in `.env`.
3. **Install** the compose stack on a VM inside their network (or in their Azure subscription). `docker compose --profile m365 up -d`.
4. **Let it run 30 days** in monitor mode. Review the inventory with the customer: mark systems approved / not approved and CUI in scope / not (`PATCH /api/v1/systems/{key}`). Tune the policy's `cui_approved_systems` list.
5. **Hand over the evidence report.** `/evidence/report.md` → their SSP, their POA&M, their assessor.
6. **Repoint applications** to the gateway, still in monitor mode. Internal apps, scripts, and agent frameworks change one setting (base URL + a gateway key). Watch the "policy would have acted" count for a couple of weeks.
7. **Flip to enforce.** `AICP_GW_MODE=enforce`. Blocks and masks begin; the evidence report's 3.1.3 and 3.13.1 narratives move from *partial* to *full*.

## Console access and audit of the tool itself

Local accounts (bcrypt, signed session cookie, lockout after 10 failures, 12-char minimum). Two roles: `admin` (edit inventory) and `viewer`. Every login, failed login, logout, password change and inventory edit is written to the audit store as an `ai.admin.change` event, so the control plane's own access is part of the evidence package (3.3.1, 3.3.2, CM-3). Collectors, the gateway and the forwarder authenticate with the machine token, not a session. Entra/Okta OIDC login is additive in 0.3; local accounts stay for air-gapped sites.

## SIEM forwarding

The forwarder reads the audit store in sequence order through `/api/v1/events/stream`, checkpoints after every batch *all* outputs accept, and retries otherwise, so a SIEM outage delays delivery but never drops records (AU-5). Outputs, selectable in `.env` (`AICP_FWD_OUTPUTS=splunk_hec,syslog_cef`):

| Output | Format | Notes |
|---|---|---|
| `splunk_hec` | HEC JSON, sourcetype `aicp:audit` | set index, token; `SPLUNK_VERIFY_TLS=false` for self-signed |
| `sentinel` | Logs Ingestion API → custom table `AICPAudit_CL` | needs DCE, DCR, and an Entra app with Monitoring Metrics Publisher on the DCR |
| `syslog_cef` | CEF over TCP/TLS/UDP | QRadar, ArcSight, Elastic, Graylog, rsyslog; severity from policy action |
| `file` | JSONL | air-gapped hand-off; also the default in the demo |

Detection content (prompt-injection-then-tool-call, agent runaway, unapproved model, repeated CUI attempts) ships as SPL/KQL in a later release once a customer SIEM is in hand.

## The three design rules that make the gateway a drop-in later

1. **One schema.** `observation_level` (`metadata_only` | `content_visible` | `enforced`) and `decision.mode` (`monitor` | `enforce`) are first-class fields. The evidence engine will never claim "full" strength for a control unless an `enforced` event backs it.
2. **Policy exists from day one.** OPA runs in advisory mode and stamps every event with what it *would* do. Customers see enforcement before it's turned on; you get tuning data before anyone is blocked.
3. **Append-only, hash-chained audit store.** `GET /api/v1/events/integrity` walks the chain. This is the 3.3.8 / AU-9 story and it's cheap.

## Adding a collector

Subclass `Collector` in `collectors/aicp_collectors/`, implement `fetch(since)` and `normalize(record)`, register it in `run.py`. Use `base_event()` for the envelope and `dlp.scan()` on any text you can see. Raw prompt text never leaves the collector; only hashes and finding categories are emitted. Next collectors, in priority order: Azure OpenAI diagnostic logs, Zscaler/Netskope web logs (shadow-AI discovery), ChatGPT Enterprise compliance API, AWS Bedrock CloudTrail.

## Pushing to GitHub

```bash
git init -b main
git add .
git commit -m "AI Control Plane v0.1: monitor mode"
gh repo create consultantworks-ai/ai-control-plane --private --source . --push
```

Then in the repo settings: protect `main` (require PR + passing CI), enable Dependabot and CodeQL.

## Before the first paying customer

- Add OIDC (customer's Entra) on top of local accounts; mTLS or per-collector tokens for ingest; TLS in front of the console (`AICP_COOKIE_SECURE=true`).
- Switch base images to a FIPS/STIG-able base (Iron Bank Python or Chainguard); sign images with cosign.
- Retention policy and encrypted Postgres backups.
- Write the one-page network requirements sheet (ports 443 out to `login.microsoftonline.com` and `graph.microsoft.com`; nothing inbound).

## Roadmap

| Milestone | Adds |
|---|---|
| 0.2 (done) | Console login + audit of the tool itself, inventory editing, SIEM forwarder |
| 0.2.x | Azure OpenAI + web gateway collectors, M365 collector validated against a live tenant |
| 0.3 | Anthropic Messages API + Azure OpenAI URL handling in the gateway, OIDC/JWT gateway keys, per-rule mode overrides |
| 0.4 | MCP proxy for agent tool calls, human-in-the-loop approvals |
| 0.5 | Presidio + local classifier DLP, streaming egress scanning |
| 1.0 | Helm chart, Iron Bank hardening, air-gap mode, AI RMF + 800-53 evidence packs |
