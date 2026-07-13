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

## Upcoming

| Step | Goal |
| --- | --- |
| 7 | Stronger hold/stop/release state tests |
| 8 | Spool recovery on startup |
| 9 | Broader integration tests in CI |
| 10 | Staging M365 adapter (not local) |
