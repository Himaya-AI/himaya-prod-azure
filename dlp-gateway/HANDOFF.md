# DLP Gateway — Handoff for Classification / Backend Engineer

Simple guide to what is already built, how to plug in, and where you take over.

## What this service is

`dlp-gateway/` is the **mail pipe**.

It:

1. Accepts outbound email over SMTP  
2. Saves the original message safely  
3. Publishes a **capture event**  
4. Waits for a **command** (`allow` / `hold` is your side; gateway acts on `allow` / `release` / `stop`)  
5. Sends allowed/released mail to the provider return path (MailHog locally)

It does **not** classify content. That is your job in `backend/dlp/`.

```text
Sender / provider
      │
      ▼
dlp-gateway (SMTP + store + relay)     ← DONE (local MVP)
      │
      │  capture event
      ▼
backend/dlp (extract → classify → policy)  ← YOUR WORK
      │
      │  allow / release / stop command
      ▼
dlp-gateway relays (or stops)
```

---

## What is already done

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

**Not done yet (gateway side, later):** crash recovery hardening, Service Bus, real Microsoft 365 relay, Google.

**Not started (your side):** extraction, detectors, policy engine, review APIs, Enable DLP.

Design docs (more detail):

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

Send a test message:

```bash
python scripts/send_test_mail.py
```

Allowed test sender domains (see `conf/tenants/local-tenant.json`):

- `example.test`
- `himaya.test`

Example: `alice@example.test` → works. `eve@evil.test` → rejected.

---

## How you connect (the contract)

You talk to the gateway through **events and commands**, not by calling SMTP or reading the spool directly.

### 1. You consume: capture event

After mail is stored in Blob, gateway publishes:

**Event type:** `dlp.message.captured.v1`

Important fields:

| Field | Meaning |
| --- | --- |
| `message_id` | ID you must use in commands |
| `org_id` | Tenant |
| `envelope_from` / `envelope_to` | SMTP envelope (includes BCC recipients) |
| `mime_sha256` / `mime_size` | Integrity / size |
| `blob_uri` | Where to download the original MIME |
| `received_at` | When gateway accepted it |

Model code today: `dlp-gateway/app/domain/models.py` → `CaptureEvent`  
Local queue files: under the `dlp_queues` Docker volume (`captures/ready/…`)

**Your first job:** read MIME from `blob_uri`, extract text, classify, evaluate policy.

### 2. You publish: commands

| Command | Gateway does |
| --- | --- |
| `allow` | Relay original MIME to return path |
| `release` | Same as allow (after a human review hold) |
| `stop` | Do not relay; mark stopped |
| `retry` | Try relay again |

Model: `GatewayCommand` in the same file.

Minimum command payload:

```json
{
  "schema_version": 1,
  "command_type": "allow",
  "message_id": "<same uuid from capture event>",
  "org_id": "<same org>",
  "reason": "optional"
}
```

### 3. Turn off the stub when you are ready

Today local mode has:

```text
FORCE_ALLOW=true
```

That means gateway auto-sends `allow` after every capture so we could test without classification.

When your worker is ready:

1. Set `FORCE_ALLOW=false` on the gateway  
2. Your worker consumes capture events and publishes real `allow` / `stop` (and later hold/release via API)  
3. Gateway command consumer already knows how to act on those commands  

Do **not** classify inside the gateway process.

---

## Suggested takeover steps (your side)

1. **Copy / share contracts**  
   Move or mirror `CaptureEvent` + `GatewayCommand` into `backend/dlp/contracts/` so both services use the same schema.

2. **Build a capture consumer**  
   `backend/dlp/workers/capture_consumer.py`  
   - read event  
   - download MIME from Blob (`blob_uri`)  
   - never rebuild the email from subject/body fields for release  

3. **Extraction + classification**  
   Produce findings only (what was found, confidence, what could not be read).  
   Do not decide delivery inside the classifier.

4. **Policy worker**  
   Input: findings + recipients + org mode  
   Output: publish `allow` or `stop` command (hold later with review API).

5. **Disable `FORCE_ALLOW`** and run both services together locally.

6. **Hold / release (next)**  
   Hold = your backend stores review item; gateway does nothing until `release` or `stop` command.

---

## Rules that keep things maintainable

1. Gateway owns SMTP + spool + relay. You own classify + policy + APIs.  
2. Original MIME in Blob is the source of truth for release.  
3. Do not call Postgres from the SMTP path (gateway already follows this).  
4. Prefer deterministic detectors first; LLM only for hard cases.  
5. If inspection is incomplete (encrypted attachment, etc.), return a limitation — policy decides hold/allow.  
6. Keep event/command schemas versioned (`schema_version`).

---

## Local vs production adapters

| Need | Local now | Later |
| --- | --- | --- |
| Queue | Filesystem bus in gateway | Azure Service Bus (both services) |
| MIME store | Azurite | Same Azure Blob account as Himaya |
| Decisions | `FORCE_ALLOW` | Your policy worker |
| Relay target | MailHog | Microsoft 365 return connector |

You can start classification against **local Docker + Azurite** without waiting for Microsoft staging.

---

## Quick ownership split

| You build | Gateway team builds |
| --- | --- |
| Extractors / detectors / findings | SMTP edge, spool, capture |
| Policy allow/hold/stop | Command consumer + relay |
| Review queue APIs | Provider return adapters (M365) |
| Enable DLP / settings APIs | Signed tenant config publishing |
| Capture consumer worker | Service Bus production wiring |

---

## Questions / blockers to ask early

- Exact Service Bus topic/queue names (when leaving filesystem bus)  
- Shared Blob container name / auth (managed identity vs connection string)  
- Who owns hold state in DB (`dlp_review_items`) vs gateway spool folders  
- Monitor vs enforce behavior when classification fails  

---

## TL;DR

Gateway local MVP is ready: mail in → Blob + capture event → (stub allow) → MailHog.

**You take over at the capture event.**  
Read MIME → classify → policy → publish `allow` / `stop`.  
Then turn `FORCE_ALLOW` off.
