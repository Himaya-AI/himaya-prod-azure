# Helios Sentinel-Mail Integration Guide

This guide explains how `sentinel-mail` uses the reputation microservice today, what was changed, and what remains for follow-up work.

**Reputation service:** `reputation-service/` (standalone repo folder, not inside `sentinel-mail/`)

**Status:** Integrated in `email_processor.py` via `reputation_client.py` (commit on `feature/reputation-service`).

---

## Integration status

| Area | Status |
|------|--------|
| `reputation_client.py` — HTTP client, entity builder, result mappers | Done |
| `email_processor.py` — single batch lookup per email | Done |
| Inline VT / DNS / WHOIS / IOC in processor | Removed |
| `link_score` + `reputation_score` rollup in processor | Unchanged |
| LLM, graph, reply-to BEC, quarantine, detonation | Unchanged (still in processor) |
| Attachment `sha256` at ingestion (`delta_sync`) | **Not done** — file TI needs this |
| Policy engine / auto-triage direct IOC checks | Unchanged — still use Redis |

---

## Architecture after integration

```text
email_processor.process_email()
  │
  ├─ _classify_content()              LLM / heuristics (unchanged)
  │
  ├─ analyze_email_reputation()       ONE call → reputation-service
  │     ├─ build_entities()             sender + ip + urls + files
  │     ├─ POST /api/v1/reputation/lookup
  │     ├─ map_link_result()            → link_result dict
  │     └─ map_sender_result()          → reputation_result dict
  │
  ├─ content_score += link_score // 2   (unchanged blend)
  ├─ reply-to BEC logic                 (unchanged)
  ├─ graph_service.analyze_sender...    (unchanged)
  ├─ _calculate_risk_score()            40/30/30 blend (unchanged)
  └─ quarantine, alerts, DB             (unchanged)
```

```text
sentinel-mail                              reputation-service
────────────────                           ──────────────────
reputation_client.py                       POST /api/v1/reputation/lookup
  extract URLs from body                     VT + OTX + urlscan + MB + IOC + DNS + WHOIS
  read auth_results from email_data          Cache TI in Redis (rep:v1:*)
  optional file sha256 from attachments      Return score + verdict per entity
  map to link_result / reputation_result
email_processor.py (orchestration only)
```

---

## Files changed in sentinel-mail

| File | Role |
|------|------|
| `backend/services/reputation_client.py` | **New.** Builds entity batch, calls microservice, maps results, handles fallback |
| `backend/services/email_processor.py` | Calls `analyze_email_reputation()` once; removed `_check_sender_reputation()` and `_analyze_links_and_attachments()` inline TI |
| `backend/tests/test_reputation_client.py` | Unit tests for client builders and mappers |
| `.env.example` | Documents `REPUTATION_SERVICE_URL` and timeout |

### What was removed from `email_processor.py`

The following logic now lives in the reputation microservice (not duplicated in sentinel-mail):

- Per-URL VirusTotal HTTP calls
- Per-domain VirusTotal + WHOIS in `_check_sender_reputation`
- Inline DNS (MX / SPF / DMARC record checks)
- Direct Redis IOC lookups via `check_url_in_feeds` / `check_ip_in_feeds`
- Local URL heuristics (digit-prefix, suspicious TLD, etc.)

---

## How `email_processor` calls the client

In `process_email()`, after `auth_results` is set and before reply-to / graph scoring:

```python
from backend.services.reputation_client import analyze_email_reputation

link_result, reputation_result = await analyze_email_reputation(email_data, auth_results)
```

**`link_result`** shape (unchanged for downstream code):

```python
{
    "link_score": int,           # 0–100
    "indicators": list[str],
    "urls_found": int,
    "suspicious_urls": list[str],   # max 5
    "malicious_urls": list[str],    # max 5
    "suspicious_attachments": list[str],
    "all_attachments": list[str],   # max 10 filenames
}
```

**`reputation_result`** shape (unchanged):

```python
{
    "reputation_score": int,     # 0–100
    "indicators": list[str],
    "spf_pass": bool,
    "dkim_pass": bool,
    "dmarc_pass": bool,
}
```

`reputation_result["reputation_score"]` feeds `_calculate_risk_score()` as the 30% reputation weight. `link_result` is blended into `content_score` (`link_score // 2`) and stored in `score_breakdown` for the UI.

---

## What `reputation_client.py` does

### 1. Build entities from `email_data`

| Entity | Source in `email_data` | Notes |
|--------|------------------------|-------|
| `sender` | `email_data["sender"]` | Must contain `@`; uses `auth_results` in context |
| `ip` | `auth_results["sender_ip"]` | Omitted if empty |
| `url` | Regex on `body` + `html_body` | Deduped, max 20 |
| `file` | `attachments[].sha256` (or `.hash`) | Only when hash present on attachment dict |

Batch cap: **25 entities** total. Priority order: sender → ip → urls → files.

**Important:** `email_data` uses key `sender`, not `from`. `delta_sync` already provides `auth_results` with string values `spf` / `dkim` / `dmarc` and optional `sender_ip`.

**Do not send** both `sender` and `domain` for the same address — wastes a batch slot.

### 2. Call the microservice

```http
POST {REPUTATION_SERVICE_URL}/api/v1/reputation/lookup
Content-Type: application/json
```

Skipped when `REPUTATION_SERVICE_URL` is unset.

### 3. Map results → `link_score` rollup

Same weights as the legacy processor (preserves familiar scoring):

| Signal | `link_score` boost |
|--------|-------------------:|
| Any URL with `verdict == "malicious"` | +60 |
| URL indicators contain `ioc_feed` | +20 |
| IP indicators contain `ioc_feed_ip_match` | +30 |
| File indicators contain `malwarebazaar_known_sample` | +40 |
| Suspicious URLs (`verdict == "suspicious"`) | +10 each, max +30 |
| Dangerous attachment extensions | +20 each, max +40 |

### 4. Map sender result → `reputation_score`

Uses the `sender` entity's `score` and `indicators` from the service. `spf_pass` / `dkim_pass` / `dmarc_pass` are derived from parsed `auth_results` (not from the service response).

---

## Fallback when the service is unavailable

Email processing **never blocks** on reputation lookup failure.

| Condition | Sender behavior | Link behavior |
|-----------|-----------------|---------------|
| `REPUTATION_SERVICE_URL` unset | Auth-only scoring (SPF/DKIM/DMARC) | Extension blocklist only |
| HTTP error / timeout | Same auth-only fallback | Extension blocklist only |
| Service returns empty results | Same | Extension blocklist only |

Local extension blocklist (fallback): `.exe`, `.vbs`, `.js`, `.ps1`, `.bat`, `.cmd`, `.msi`, `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`, `.jar`.

---

## Environment variables

### sentinel-mail (processor)

```bash
REPUTATION_SERVICE_URL=http://reputation-service:8080   # no trailing slash
REPUTATION_SERVICE_TIMEOUT_SECONDS=10
REDIS_URL=redis://...                                   # still required for threat_feeds worker + policy engine
```

`VIRUSTOTAL_API_KEY` is **no longer used** by `email_processor`. Move TI keys to the reputation service.

### reputation-service (deploy separately)

```bash
REDIS_URL=redis://...              # MUST match sentinel-mail (IOC feeds read ioc_*:entries)
VIRUSTOTAL_API_KEY=...
ALIENVAULT_OTX_API_KEY=...
URLSCAN_API_KEY=...
ABUSECH_API_KEY=...
REPUTATION_ADMIN_API_KEY=...         # cache admin only
```

### Redis layout (shared instance, different keys)

| Key pattern | Writer | Reader |
|-------------|--------|--------|
| `ioc_urlhaus:entries`, etc. | `threat_feeds_service` (sentinel-mail) | reputation-service `ioc_feeds` adapter |
| `rep:v1:*` | reputation-service | reputation-service only |

---

## Example API request (what the client sends)

```json
{
  "entities": [
    {
      "type": "sender",
      "value": "ceo@fake-bank.com",
      "context": {
        "auth_results": {
          "spf": "fail",
          "dkim": "none",
          "dmarc": "fail",
          "sender_ip": "203.0.113.5"
        }
      }
    },
    { "type": "ip", "value": "203.0.113.5" },
    { "type": "url", "value": "https://evil.example/login" },
    {
      "type": "file",
      "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "hash_type": "sha256",
      "context": { "filename": "invoice.xlsm", "extension": ".xlsm" }
    }
  ]
}
```

See [API.md](./API.md) for full request/response schemas and per-entity examples.

---

## Known gap: attachment hashes

Today `delta_sync` passes attachment **metadata only**:

```python
{"filename": "invoice.xlsm", "mimeType": "...", "size": 12345}
```

Without `sha256` on the attachment dict, the client **cannot** send `file` entities. File TI (VirusTotal, MalwareBazaar, OTX) is skipped; only the local extension fallback runs.

**Follow-up:** In `delta_sync.py` (Gmail + M365 paths), fetch attachment bytes and add:

```python
{"filename": "...", "sha256": "<hex>", "mimeType": "...", "size": N}
```

Once present, `reputation_client.build_file_entities()` picks them up automatically.

---

## What still uses Redis IOC feeds directly

These paths were **not** migrated — they still call `threat_feeds_service` against Redis:

- `policy_engine.py` — policy rule matching
- `auto_triage_service.py` — triage IOC checks
- `email_processor.py` — **no longer** (migrated)

That is intentional: policy/triage can stay on Redis lookups; email reputation TI goes through the microservice.

---

## Deploy checklist

1. Deploy **reputation-service** with TI API keys and shared `REDIS_URL`
2. Ensure **threat feed refresh loop** is running in sentinel-mail (`run_feeds_refresh_loop`)
3. Set `REPUTATION_SERVICE_URL` on sentinel-mail ECS task / `.env`
4. Remove `VIRUSTOTAL_API_KEY` from sentinel-mail if unused elsewhere
5. Verify health: `GET {REPUTATION_SERVICE_URL}/api/v1/reputation/health` → `redis: connected`
6. Run tests: `cd sentinel-mail/backend && python -m pytest tests/test_reputation_client.py -v`

---

## Debugging

| Symptom | Likely cause |
|---------|----------------|
| `reputation_score` only reflects SPF/DKIM/DMARC | Service down or `REPUTATION_SERVICE_URL` unset (auth fallback) |
| IOC URL/IP never matches | Reputation service Redis ≠ feed worker Redis, or feeds not seeded |
| File never hits VT/MalwareBazaar | No `sha256` on attachment dict in `email_data` |
| `link_score` always 0, no URLs flagged | No URLs in body, or service unreachable with no dangerous extensions |
| High latency per email | Cold TI cache; subsequent lookups should hit `rep:v1:*` cache |

Enable debug logs in sentinel-mail: look for `Reputation lookup:` or `Reputation service lookup failed`.

---

## Common mistakes

| Mistake | Fix |
|---------|-----|
| Setting TI API keys only on sentinel-mail | Keys belong on **reputation-service** |
| Different Redis for service vs feed worker | Same `REDIS_URL` in both |
| Expecting `email_data["from"]` | Use `email_data["sender"]` |
| Sending `sender` + `domain` | Send `sender` only |
| Expecting `link_score` from the API | Client rolls up per-entity results in `map_link_result()` |
| Omitting `auth_results` on sender entity | SPF/DKIM/DMARC won't be scored by the service |

---

## Further reading

- [API.md](./API.md) — endpoint reference and response examples
- [SCORING.md](./SCORING.md) — signal impacts inside the microservice
- [WORKFLOW.md](./WORKFLOW.md) — internal reputation-service pipeline
