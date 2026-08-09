# DLP Gateway development log

Track what was built, why, and how to verify. Update after each step.

## Step 1 — Scaffold ✅

**Goal:** Create `dlp-gateway/` with hexagonal layout, Docker Compose, and docs.

**Delivered:**

- `README.md`, `ARCHITECTURE.md`, this log
- `Dockerfile`, `docker-compose.yml` (gateway + MailHog + Azurite)
- Azurite uses `--skipApiVersionCheck` for current `azure-storage-blob` SDK compatibility
- Settings via pydantic-settings
- Package layout: domain, smtp, spool, capture, relay, commands, events, workers, health

**Verify:**

```bash
cd dlp-gateway
docker compose config
```

---

## Step 2 — SMTP edge + durable spool ✅

**Goal:** Accept SMTP only after spool `fsync`.

**Delivered:**

- `app/smtp/edge.py` (aiosmtpd)
- `app/spool/mta_spool.py` (tmp → accepted rename + fsync)
- Header stripping for untrusted `X-Himaya-*`
- Temporary `451` on spool failure (never fake `250`)

**Verify:** unit test `test_spool_commit_fsync_roundtrip`

---

## Step 3 — Tenant config cache ✅

**Goal:** Authorize senders from local snapshot without DB calls.

**Delivered:**

- `conf/tenants/local-tenant.json`
- `app/config_cache/snapshot.py`
- Domain allow-list for `example.test` / `himaya.test`

**Verify:** `test_tenant_resolves_allowed_domain`

---

## Step 4 — Capture worker ✅

**Goal:** Spool → Azurite blob → `dlp.message.captured.v1`

**Delivered:**

- `app/capture/mime_store.py`
- `app/capture/worker.py`
- Filesystem event bus (`app/events/bus.py`) as local Service Bus stand-in

---

## Step 5 — Auto-allow command loop ✅

**Goal:** Keep event→command→relay contract without classification.

**Delivered:**

- `app/workers/auto_allow.py` (`FORCE_ALLOW=true`)
- `app/commands/processor.py` + `consumer.py`

---

## Step 6 — Relay to MailHog ✅

**Goal:** Local provider-return round trip.

**Delivered:**

- `SmtpSinkRelayAdapter` → MailHog
- `RelayDispatcher` uses original MIME bytes
- `scripts/send_test_mail.py`
- Health endpoint on `:8080/healthz`

**Verify:**

```bash
cd dlp-gateway
docker compose up --build -d
python scripts/send_test_mail.py
# open http://localhost:8025
```

### Review fix (2026-07-13)

Capture order corrected to: blob → annotate accepted metadata → publish event → move to `captured/`. Previously, moving to `captured/` before publish could drop events on crash.

---

## Step 7 — Idempotent commands and queue recovery ✅

**Goal:** Prevent duplicate/stale backend commands from relaying mail twice or
overriding a terminal stop.

**Delivered:**

- Durable `processed_command_ids` in spool metadata
- `expected_state` and tenant ownership checks
- Terminal guards for stopped/provider-accepted messages
- Command dead-lettering for permanent rejection
- Configurable recovery of stale filesystem queue messages
- Tests for duplicate allow, stop-then-allow, stale state, and recovery

**Verify:**

```bash
cd dlp-gateway
python -m pytest -q
```

---

## Step 8 — Microsoft provider-return adapter ✅

**Goal:** Relay allowed/released mail to Exchange Online MX with tenant client certificate (AWS staging), while keeping MailHog for local.

**Delivered:**

- `RelayRequest` / richer `RelayResult` + `SmtpStage` / `PARTIAL`
- Tenant relay config: `adapter`, `mx_host`, client cert paths, EHLO/TLS name
- `FilesystemRelayCertificateProvider` (PEM on disk; KV/Secrets Manager later)
- Phase-aware SMTP transport (`EHLO` → `STARTTLS` + client cert → `MAIL/RCPT/DATA`)
- Real `Microsoft365RelayAdapter`
- `RelayAdapterRegistry` selects local vs microsoft per tenant
- Example config: `conf/tenants/staging-m365.json.example`

**Enable on AWS:**

1. Place return client cert/key at `/opt/dlp-gateway/certs/m365-client-*.pem`
2. Copy `staging-m365.json.example` → active tenant JSON and set cert domain fields
3. Rebuild/restart gateway
4. Send test mail; confirm `relay.finished` with `adapter=microsoft` and inbox delivery

**Verify:**

```bash
cd dlp-gateway
python -m pytest -q
```

---

## Step 9 — Loop-prevention egress headers + re-entry reject ✅

**Goal:** Stamp a return marker on the egress copy and reject any SMTP re-entry that still carries it (`550`), so EXO does not retry-loop into the gateway.

**Delivered:**

- Egress copy stamps `X-Himaya-DLP-Return: 1` (byte-surgical; immutable spool MIME unchanged)
- SMTP intake rejects marker presence with `550` **before** stripping `X-Himaya-*`
- Spoofed first-hop marker is also rejected (intentional for staging)
- Unit tests for marker detect / body false-positive / edge `550`

**Ops (already in place for staging):** M365 mail-flow exception when `X-Himaya-DLP-Return` contains `1`. Connector-scoped bypass remains the stronger production shape later.

**Verify:**

```bash
cd dlp-gateway
python -m pytest -q
```

---

## Upcoming

| Step | Goal |
| --- | --- |
| 10 | Delivery outcome events + uncertain/retry hardening |
| 11 | Broader M365 staging matrix + CI |
| 12 | Production loop hardening (connector-scoped bypass, signed headers) |
