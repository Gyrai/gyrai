# How Gyrai works: code map

This page shows how a request moves through the code. Each box names the file or function you can open to follow along. GitHub draws the diagrams automatically.

Gyrai has four programs. They share one event format (`schemas/audit-event.schema.json`) and meet at the API.

| Program | Folder | Job |
|---|---|---|
| Gateway | `gateway/gw/` | Sits between an app and the AI model. Scans each request, applies policy, forwards it and audits it. |
| Collectors | `collectors/aicp_collectors/` | Read logs from tools Gyrai cannot sit in front of (Microsoft 365, log files) and turn them into events. |
| API and console | `api/app/` | Validates and stores events, keeps the AI inventory, builds evidence reports and serves the web console. |
| Forwarder | `forwarder/fwd/` | Copies stored events to a SIEM. |

Policy decisions come from OPA, which runs the rules in `policies/advisory.rego`.

## 1. The whole system

```mermaid
flowchart LR
    app["Your app or agent"] -->|"OpenAI-style request<br/>+ gateway key"| gw
    subgraph GW["Gateway (gateway/gw)"]
        gw["main.py<br/>chat_completions()"]
    end
    gw -->|"identify()"| ident["identity.py"]
    gw -->|"scan()"| dlp["collectors/.../dlp.py"]
    gw -->|"evaluate()"| pol["policy.py"]
    pol -->|"POST /v1/data/aicp/advisory"| opa[("OPA<br/>advisory.rego")]
    gw -->|"_forward()"| model["AI model<br/>(public, tenant or local)"]
    gw -->|"sink().emit()"| aud["audit.py<br/>queue + background thread"]

    m365["Microsoft 365<br/>(Graph API)"] --> col
    files["JSONL log files"] --> col
    subgraph COL["Collectors (collectors/aicp_collectors)"]
        col["base.py run_once()<br/>m365.py, file_collector.py"]
    end

    aud -->|"POST /api/v1/events"| api
    col -->|"POST /api/v1/events"| api
    subgraph API["API (api/app)"]
        api["routers/events.py<br/>post_events()"] --> ing["ingest.py<br/>ingest_event()"]
        ing --> db[("database<br/>db.py")]
        console["routers/console.py<br/>web console"] --> db
        console --> ev["evidence.py<br/>build_report()"]
        ev --> db
    end
    ing -.->|"only if the sender gave no decision"| opa

    subgraph FWD["Forwarder (forwarder/fwd)"]
        f["main.py<br/>Forwarder.run_once()"]
    end
    f -->|"GET /api/v1/events/stream"| api
    f --> siem["SIEM<br/>outputs.py"]

    admin["Person using the console"] --> console
```

## 2. One chat request through the gateway

The path in `gateway/gw/main.py`, `chat_completions()`. Everything the gateway does happens here, in this order.

```mermaid
sequenceDiagram
    autonumber
    participant App as App or agent
    participant GW as main.py chat_completions()
    participant Id as identity.py identify()
    participant Dlp as dlp.py scan() / redact()
    participant Pol as policy.py evaluate()
    participant OPA as OPA (advisory.rego)
    participant Up as AI model
    participant Aud as audit.py sink().emit()
    participant API as API /api/v1/events

    App->>GW: POST /v1/chat/completions
    GW->>Id: Who is calling?
    Id-->>GW: actor (type, id, on_behalf_of)
    GW->>Dlp: scan(prompt text)
    Dlp-->>GW: findings (counts only)
    GW->>Pol: evaluate(event)
    Pol->>OPA: POST /v1/data/aicp/advisory
    OPA-->>Pol: action, policy_id, reason
    Pol-->>GW: decision
    Note over GW: effective_action() decides what really happens.<br/>Monitor mode always allows.
    alt block or require_approval (enforce mode)
        GW->>Aud: emit ai.policy.violation
        GW-->>App: 403 blocked by policy
    else mask
        GW->>Dlp: redact() swaps values for [AICP:...] placeholders
        GW->>Aud: emit prompt event
        GW->>Up: forward masked prompt
    else route_local
        GW->>Aud: emit prompt event
        GW->>Up: forward to the local model instead
    else allow
        GW->>Aud: emit prompt event
        GW->>Up: forward prompt
    end
    Up-->>GW: reply (whole, or streamed chunks)
    GW->>Dlp: scan(reply) and unredact()
    GW->>Aud: emit response event
    GW-->>App: reply (original values restored)
    Aud--)API: batch POST in the background
```

If the API is down, `audit.py` writes the events to a local fallback file instead of losing them.

## 3. How an event is stored

Every event from every source goes through `ingest_event()` in `api/app/ingest.py`.

```mermaid
flowchart TD
    start(["Event arrives<br/>post_events() in routers/events.py"]) --> token{"Valid ingest token?"}
    token -- no --> r401["401 rejected"]
    token -- yes --> val["validate()<br/>check the JSON Schema"]
    val -- invalid --> rej["Listed as rejected in the response"]
    val -- valid --> dup{"event_id already stored?"}
    dup -- yes --> same["Return the existing row<br/>(re-collecting is harmless)"]
    dup -- no --> stamp["Stamp received_at"]
    stamp --> dec{"Sender included a decision?"}
    dec -- no --> adv["advisory_decision()<br/>ask OPA what it would do"]
    dec -- yes --> chain
    adv --> chain["Hash chain<br/>hash = SHA-256(previous hash + this event)"]
    chain --> row["Copy searchable fields into an AuditEvent row"]
    row --> inv["_upsert_system()<br/>update the AI inventory"]
    inv --> commit[("Commit to the database")]
```

`verify_chain()` in the same file re-computes the chain from the start. If anyone changed or removed a stored event, the check reports the first record that no longer matches.

## 4. How a collector works

```mermaid
sequenceDiagram
    autonumber
    participant CLI as run.py main()
    participant C as Collector.run_once() in base.py
    participant S as Source (Graph API or file)
    participant API as API /api/v1/events
    participant St as State file (~/.aicp)

    CLI->>C: run once, or every N seconds
    C->>St: load_since() (where the last run stopped)
    loop each new record
        C->>S: fetch(since)
        S-->>C: raw record
        C->>C: normalize() builds a schema event<br/>base_event() gives a repeatable event_id
    end
    C->>API: post() in batches of 200 (retries if the API is not up yet)
    API-->>C: accepted / rejected
    C->>St: save_since() (only after posting succeeds)
```

Adding a new source means writing one class that implements `fetch()` and `normalize()`. See the top of `collectors/aicp_collectors/base.py`.

## 5. How events reach the SIEM

```mermaid
flowchart TD
    tick(["Every few seconds<br/>forwarder/fwd/main.py main()"]) --> run["Forwarder.run_once()"]
    run --> get["fetch()<br/>GET /api/v1/events/stream?after_seq=N"]
    get --> any{"Any new events?"}
    any -- no --> idle(["Wait for the next poll"])
    any -- yes --> send["Send the batch to every output<br/>(outputs.py: file, Splunk, Sentinel, syslog CEF)"]
    send --> ok{"Did every output accept it?"}
    ok -- no --> retry(["Keep the old checkpoint<br/>the same batch is retried later"])
    ok -- yes --> save["Move the checkpoint forward<br/>_save() writes it to disk"]
    save --> more{"Was the batch full?"}
    more -- yes --> get
    more -- no --> idle
```

Because the checkpoint only moves after all outputs accept a batch, a SIEM outage causes a delay and never a gap. Delivery is "at least once", so a SIEM may see an event twice, and `event_id` is the key to remove duplicates.

## 6. Who can do what in the console

```mermaid
flowchart LR
    v["Visitor"] --> login["/login<br/>auth_pages.py"]
    login --> att["attempt_login() in auth.py<br/>checks the password and the lockout"]
    att -- fail --> audit1["Audited as a blocked login"]
    att -- ok --> cookie["Signed session cookie"]
    cookie --> pages["Console pages<br/>routers/console.py"]
    pages --> role{"Role?"}
    role -- viewer --> read["Read-only pages"]
    role -- admin --> edit["Can edit the inventory"]
    edit --> audit2["Each change audited<br/>audit_inventory_change()"]
```

Every login, logout, password change and inventory edit becomes an audit event too, so the tool's own use is part of the record.
