# DLP Gateway — Handoff for Backend / Classifier Engineers

Simple guide to what the gateway already does, how the three services connect, and where to take over.

## Three services

| Service | Role |
| --- | --- |
| `dlp-gateway/` | Mail pipe: SMTP accept, store MIME, relay on command |
| `backend/dlp/` | Orchestration: capture consumer, extraction, policy, APIs, review |
| `dlp-classifier/` | Detectors: return **findings only** (no allow/hold/stop) |

```text
Sender / provider
      │
      ▼
dlp-gateway (SMTP + store + relay)     ← DONE (local MVP)
      │
      │  capture event
      ▼
backend/dlp (extract + policy + APIs)  ← BACKEND WORK
      │
      │  classify request
      ▼
dlp-classifier (PII / NER / …)         ← CLASSIFIER WORK
      │
      │  findings
      ▼
backend/dlp policy
      │
      │  allow / release / stop command
      ▼
dlp-gateway relays (or stops)
```

Gateway does **not** classify. Classifier does **not** send gateway commands.

---

## What the gateway already has

| Piece | Status |
| --- | --- |
| Local Docker stack (gateway + MailHog + Azurite) | Done |
| SMTP accept + durable spool (`250` only after save) | Done |
| Strip untrusted `X-Himaya-*` headers | Done |
| Tenant config from local JSON (no DB on SMTP path) | Done |
| Save immutable MIME to Azurite (Blob) | Done |
| Publish `dlp.message.captured.v1` | Done |
| Local auto-allow (`FORCE_ALLOW=true`) | Done (temporary stub) |
| Relay original MIME to MailHog | Done |
| Health check `:8080/healthz` | Done |

**Still later on gateway:** crash recovery hardening, Service Bus, real Microsoft 365 relay, Google.

**Backend / classifier still needed:** extraction client path, classifier API wiring, policy → commands, review APIs, Enable DLP, turn off `FORCE_ALLOW`.

Design docs:

- `docs/DLP_INGRESS_GATEWAY_PLAN.md`
- `docs/DLP_BACKEND_IMPLEMENTATION_ROADMAP.md`
- `dlp-gateway/ARCHITECTURE.md`
- `dlp-gateway/DEVELOPMENT.md`

---

## How to run the gateway locally

```bash
cd dlp-gateway
docker compose up --build -d
```

| Service | URL / port | Use |
| --- | --- | --- |
| Gateway SMTP | `localhost:2525` | Send test mail in |
| Gateway health | http://localhost:8080/healthz | Is it up? |
| MailHog UI | http://localhost:8025 | See relayed mail |
| Azurite Blob | `localhost:10000` | Stored MIME |

```bash
python scripts/send_test_mail.py
```

Allowed sender domains (`conf/tenants/local-tenant.json`): `example.test`, `himaya.test`.

---

## How backend connects to the gateway

Talk through **events and commands**, not SMTP or the spool disk.

### 1. Consume: capture event

**Event type:** `dlp.message.captured.v1`

| Field | Meaning |
| --- | --- |
| `message_id` | ID for later commands |
| `org_id` | Tenant |
| `envelope_from` / `envelope_to` | SMTP envelope (includes BCC) |
| `mime_sha256` / `mime_size` | Integrity / size |
| `blob_uri` | Original MIME in Blob |
| `received_at` | Accept time |

Model: `dlp-gateway/app/domain/models.py` → `CaptureEvent`  
Local queue: Docker volume `dlp_queues` → `captures/ready/`

### 2. Publish: gateway commands

| Command | Gateway does |
| --- | --- |
| `allow` | Relay original MIME |
| `release` | Same as allow after review |
| `stop` | Do not relay |
| `retry` | Try relay again |

```json
{
  "schema_version": 1,
  "command_type": "allow",
  "message_id": "<uuid from capture event>",
  "org_id": "<same org>",
  "reason": "optional"
}
```

### 3. Turn off the stub when ready

Today: `FORCE_ALLOW=true` (gateway auto-allows after capture).

When backend + classifier + policy work:

1. Set `FORCE_ALLOW=false`
2. Backend consumes capture events
3. Backend calls `dlp-classifier` for findings
4. Policy publishes real `allow` / `stop` (hold/release later)
5. Gateway command consumer already handles those commands

---

## How backend connects to the classifier

Classifier owns detectors. Backend owns orchestration and decisions.

Suggested flow:

1. Backend downloads MIME from `blob_uri` and extracts text/parts  
2. Backend calls `dlp-classifier` with message id + text parts  
3. Classifier returns findings / limitations / escalate flags  
4. Backend policy decides allow / hold / stop  
5. Backend publishes the gateway command  

Classifier must **not** publish `allow`/`stop` to the gateway.

Share a versioned findings schema from `backend/dlp/contracts/` (or equivalent) so both sides stay compatible.

---

## Suggested takeover split

### Backend engineer

1. Mirror contracts: capture events, gateway commands, findings  
2. `capture_consumer` + extraction worker  
3. Thin client to `dlp-classifier`  
4. Policy worker → allow/stop commands  
5. Disable `FORCE_ALLOW` in joint local runs  
6. Review queue / Enable DLP APIs next  

### Classifier engineer

1. Finish detector pack in `dlp-classifier/` (PII/NER started; credentials/LLM later)  
2. Expose a stable classify API or worker interface  
3. Return findings only; set `escalate` when LLM/follow-up is needed  
4. Version detectors so backend can cache safely  

---

## Rules

1. Gateway = SMTP + spool + relay. Backend = extract + policy + APIs. Classifier = findings.  
2. Original MIME in Blob is the source of truth for release.  
3. No Postgres on the SMTP hot path.  
4. Deterministic detectors first; LLM only for hard cases.  
5. Incomplete inspection → limitations; policy decides hold/allow.  
6. Version every event, command, and findings schema.

---

## TL;DR

Gateway local MVP: mail in → Blob + capture event → (stub allow) → MailHog.

**Backend takes over at the capture event.**  
**Classifier takes over when backend asks for findings.**  
Policy in backend publishes `allow` / `stop`, then turn `FORCE_ALLOW` off.
