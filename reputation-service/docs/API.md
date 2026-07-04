# Reputation Service API

Base path: `/api/v1/reputation`

Interactive OpenAPI docs: `/docs`  
ReDoc: `/redoc`

The service accepts a batch of entities (sender, domain, url, file, ip), queries configured threat-intel adapters, applies deterministic scoring, and returns one explainable result per entity.

---

## Lookup

```http
POST /api/v1/reputation/lookup
Content-Type: application/json
```

Batch reputation lookup for **1–25 entities**. Results are returned in the same order as the input `entities` array.

### Entity types

| Type | `value` | Optional fields | Notes |
|------|---------|-----------------|-------|
| `sender` | Email address (`user@domain.com`) | `context.auth_results` | TI runs against the sender **domain**; auth signals are applied fresh every request |
| `domain` | Domain name | `context` | Direct domain TI lookup |
| `url` | Full URL | `context` | URL + embedded domain checked via adapters |
| `file` | Hex digest | `hash_type`, `context.filename`, `context.extension` | `hash_type` defaults to `sha256`; also accepts `md5` (32 chars) and `sha1` (40 chars) |
| `ip` | IPv4 or IPv6 | `context` | Checked against IOC feeds and urlscan |

### Request schema

```json
{
  "entities": [
    {
      "type": "sender | domain | url | file | ip",
      "value": "string",
      "hash_type": "md5 | sha1 | sha256",
      "context": {
        "auth_results": {
          "spf": "pass | fail | softfail | neutral | none | temperror | permerror",
          "dkim": "pass | fail | none",
          "dmarc": "pass | fail | none",
          "sender_ip": "203.0.113.5"
        },
        "filename": "invoice.xlsm",
        "extension": ".xlsm",
        "tenant_id": "tenant-abc",
        "labels": ["campaign-x"]
      }
    }
  ],
  "options": {
    "force_refresh": false,
    "include_raw_signals": false,
    "max_sources": null
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `entities` | array | required | 1–25 lookup items |
| `options.force_refresh` | bool | `false` | Skip TI cache and re-query external adapters |
| `options.include_raw_signals` | bool | `false` | Include per-adapter `raw_signals` in each result |
| `options.max_sources` | int \| null | `null` | Limit how many adapters run per entity (≥ 1) |

### Full request example (email scan)

Typical payload from `email_processor` after parsing a message:

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
    {
      "type": "domain",
      "value": "fake-bank.com"
    },
    {
      "type": "ip",
      "value": "203.0.113.5"
    },
    {
      "type": "url",
      "value": "https://fake-login.com/verify-account"
    },
    {
      "type": "file",
      "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "hash_type": "sha256",
      "context": {
        "filename": "invoice.xlsm",
        "extension": ".xlsm"
      }
    }
  ],
  "options": {
    "force_refresh": false,
    "include_raw_signals": false
  }
}
```

### curl example

```bash
curl -s -X POST "http://localhost:8080/api/v1/reputation/lookup" \
  -H "Content-Type: application/json" \
  -d '{
    "entities": [
      {"type": "url", "value": "https://example.com/login"},
      {"type": "file", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    ]
  }'
```

---

## Lookup response

### Top-level shape

```json
{
  "results": [ /* one ReputationResult per input entity */ ],
  "request_id": "rep_26d2995d9a10",
  "latency_ms": 3065.78
}
```

| Field | Type | Description |
|-------|------|-------------|
| `results` | array | One result per entity, same order as request |
| `request_id` | string | Correlation ID (`rep_` + 12 hex chars) |
| `latency_ms` | float | End-to-end processing time in milliseconds |

### Per-entity result (`ReputationResult`)

```json
{
  "type": "sender",
  "value": "ceo@fake-bank.com",
  "normalized_value": "ceo@fake-bank.com",
  "entity_key": "rep:v1:sender:9f1954d0ebc983287fa40465b1ba02c842c9e1576337b52ab81ecbe29f265f45",
  "verdict": "suspicious",
  "score": 40,
  "confidence": 0.71,
  "cache_hit": false,
  "sources": ["dns", "email_auth", "ioc_feeds"],
  "indicators": ["spf_fail", "dkim_none", "dmarc_fail"],
  "evidence": [
    {
      "source": "email_auth",
      "indicator": "spf_fail",
      "impact": 15,
      "detail": "SPF authentication returned fail"
    },
    {
      "source": "email_auth",
      "indicator": "dkim_none",
      "impact": 5,
      "detail": "DKIM authentication is missing"
    },
    {
      "source": "email_auth",
      "indicator": "dmarc_fail",
      "impact": 20,
      "detail": "DMARC authentication returned fail"
    }
  ],
  "agreement_level": "strong",
  "summary": "Multiple sources agree on suspicious or malicious reputation. Final verdict is suspicious. Sources: email_auth.",
  "raw_signals": null,
  "cached_at": null,
  "expires_at": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Echo of input entity type |
| `value` | string | Echo of input value (normalized for file hashes and IPs) |
| `normalized_value` | string | Canonical form used for lookup |
| `entity_key` | string | Stable cache/admin key (`rep:v1:{type}:{sha256}`) |
| `verdict` | string | `benign` \| `suspicious` \| `malicious` \| `unknown` |
| `score` | int | Risk score **0–100** (higher = worse) |
| `confidence` | float | **0.0–1.0** — agreement/strength, separate from score |
| `cache_hit` | bool | `true` when TI signals were served from cache |
| `sources` | string[] | Adapters or context processors that contributed |
| `indicators` | string[] | Machine-readable signal tags for logging/rules |
| `evidence` | object[] | Per-signal breakdown: `source`, `indicator`, `impact`, `detail` |
| `agreement_level` | string | `strong` \| `partial` \| `conflict` \| `none` |
| `summary` | string | Human-readable explanation |
| `raw_signals` | array \| null | Present when `include_raw_signals: true` |
| `cached_at` | ISO8601 \| null | When TI data was cached (on cache hit) |
| `expires_at` | ISO8601 \| null | TI cache expiry (on cache hit) |

### Score → verdict mapping

| Score | Verdict | Notes |
|-------|---------|-------|
| 0–30 | `benign` | Unless a `suspicious` signal is present |
| 31–60 | `suspicious` | |
| 61–100 | `malicious` | |
| No actionable signals | `unknown` | `score` is 0, `indicators` empty |

See [SCORING.md](./SCORING.md) for per-indicator impacts.

---

## Response examples by entity type

### `sender` — auth failures (no external TI hit)

When SPF/DKIM/DMARC fail, `email_auth` context signals are scored even without a malicious domain:

```json
{
  "type": "sender",
  "value": "ceo@fake-bank.com",
  "normalized_value": "ceo@fake-bank.com",
  "entity_key": "rep:v1:sender:9f1954d0ebc983287fa40465b1ba02c842c9e1576337b52ab81ecbe29f265f45",
  "verdict": "suspicious",
  "score": 40,
  "confidence": 0.71,
  "cache_hit": false,
  "sources": ["email_auth"],
  "indicators": ["spf_fail", "dkim_none", "dmarc_fail"],
  "evidence": [
    {"source": "email_auth", "indicator": "spf_fail", "impact": 15, "detail": "SPF authentication returned fail"},
    {"source": "email_auth", "indicator": "dkim_none", "impact": 5, "detail": "DKIM authentication is missing"},
    {"source": "email_auth", "indicator": "dmarc_fail", "impact": 20, "detail": "DMARC authentication returned fail"}
  ],
  "agreement_level": "strong",
  "summary": "Multiple sources agree on suspicious or malicious reputation. Final verdict is suspicious. Sources: email_auth."
}
```

**Cache note:** Sender TI reuses the sender domain's cache key. A prior `domain` lookup for `fake-bank.com` warms the cache for `ceo@fake-bank.com`. Auth context is always recomputed — a second sender request with different `auth_results` can change the score while `cache_hit` is `true`.

### `domain` — no TI match

```json
{
  "type": "domain",
  "value": "fake-bank.com",
  "normalized_value": "fake-bank.com",
  "entity_key": "rep:v1:domain:5716d4eb3219a98fdbcd1736773d3789abbab4b8a4011fa8f5b6644ce173d1d9",
  "verdict": "unknown",
  "score": 0,
  "confidence": 0.0,
  "cache_hit": false,
  "sources": ["dns", "ioc_feeds"],
  "indicators": [],
  "evidence": [],
  "agreement_level": "none",
  "summary": "No actionable reputation data found for domain; returning unknown."
}
```

### `url` — IOC feed + VirusTotal hit

When Redis IOC feeds and VirusTotal both flag a URL:

```json
{
  "type": "url",
  "value": "https://evil.example/malware",
  "normalized_value": "https://evil.example/malware",
  "entity_key": "rep:v1:url:02433badad1c24c65af44613ae4bd9a2fe53c2d4a2c70e4585783315df802263",
  "verdict": "malicious",
  "score": 85,
  "confidence": 0.92,
  "cache_hit": false,
  "sources": ["ioc_feeds", "virustotal"],
  "indicators": [
    "ioc_feed_url_match:ioc_urlhaus",
    "vt_malicious:8/90"
  ],
  "evidence": [
    {
      "source": "ioc_feeds",
      "indicator": "ioc_feed_url_match:ioc_urlhaus",
      "impact": 60,
      "detail": "URL matched Helios IOC threat feed entries"
    },
    {
      "source": "virustotal",
      "indicator": "vt_malicious:8/90",
      "impact": 50,
      "detail": "VirusTotal reported 8 malicious detections"
    }
  ],
  "agreement_level": "strong",
  "summary": "Multiple sources agree on malicious reputation."
}
```

### `url` — heuristic only (digit-prefix pattern)

```json
{
  "type": "url",
  "value": "https://1evil-domain.example/path",
  "normalized_value": "https://1evil-domain.example/path",
  "verdict": "suspicious",
  "score": 10,
  "confidence": 0.53,
  "cache_hit": false,
  "sources": ["heuristic"],
  "indicators": ["suspicious_url_digit_prefix"],
  "evidence": [
    {
      "source": "heuristic",
      "indicator": "suspicious_url_digit_prefix",
      "impact": 10,
      "detail": "URL matched suspicious pattern heuristics"
    }
  ],
  "agreement_level": "partial",
  "summary": "One source reported suspicious or malicious reputation. Final verdict is suspicious. Sources: heuristic."
}
```

### `file` — dangerous extension heuristic

Works without any external API keys:

```json
{
  "type": "file",
  "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "normalized_value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verdict": "suspicious",
  "score": 20,
  "confidence": 0.53,
  "cache_hit": false,
  "sources": ["heuristic"],
  "indicators": ["dangerous_attachment_extension:.xlsm"],
  "evidence": [
    {
      "source": "heuristic",
      "indicator": "dangerous_attachment_extension:.xlsm",
      "impact": 20,
      "detail": "Attachment extension is commonly abused"
    }
  ],
  "agreement_level": "partial",
  "summary": "One source reported suspicious or malicious reputation. Final verdict is suspicious. Sources: heuristic."
}
```

### `file` — MalwareBazaar known sample

Requires `ABUSECH_API_KEY`:

```json
{
  "type": "file",
  "value": "094fd325049b8a9cf6f3d3cb5f6b5cfdc327107c47a2a42f8f8f6514e2a88d7",
  "normalized_value": "094fd325049b8a9cf6f3d3cb5f6b5cfdc327107c47a2a42f8f8f6514e2a88d7",
  "verdict": "malicious",
  "score": 80,
  "confidence": 0.90,
  "cache_hit": false,
  "sources": ["malwarebazaar"],
  "indicators": [
    "malwarebazaar_known_sample",
    "mb_signature:Emotet",
    "mb_file_type:exe"
  ],
  "evidence": [
    {
      "source": "malwarebazaar",
      "indicator": "malwarebazaar_known_sample",
      "impact": 75,
      "detail": "Hash is a known malware sample in MalwareBazaar"
    }
  ],
  "agreement_level": "strong",
  "summary": "Multiple sources agree on malicious reputation. Sources: malwarebazaar."
}
```

### `ip` — IOC feed match

```json
{
  "type": "ip",
  "value": "192.0.2.100",
  "normalized_value": "192.0.2.100",
  "verdict": "malicious",
  "score": 30,
  "confidence": 0.90,
  "cache_hit": false,
  "sources": ["ioc_feeds"],
  "indicators": ["ioc_feed_ip_match:ioc_feodo,ioc_ipsum"],
  "evidence": [
    {
      "source": "ioc_feeds",
      "indicator": "ioc_feed_ip_match:ioc_feodo,ioc_ipsum",
      "impact": 30,
      "detail": "IP matched Helios IOC threat feed entries"
    }
  ],
  "agreement_level": "strong",
  "summary": "Multiple sources agree on malicious reputation. Sources: ioc_feeds."
}
```

### `include_raw_signals: true`

Adds adapter-level payloads to each result:

```json
{
  "entities": [
    {"type": "domain", "value": "example.com"}
  ],
  "options": {"include_raw_signals": true}
}
```

```json
{
  "type": "domain",
  "value": "example.com",
  "verdict": "unknown",
  "score": 0,
  "raw_signals": [
    {
      "source": "dns",
      "entity_type": "domain",
      "verdict": "unknown",
      "priority": 3,
      "confidence": 0.0,
      "indicators": ["no_dmarc_record"],
      "score_impact": 10,
      "detail": "Domain has no DMARC record",
      "raw": {"has_mx": true, "has_spf": true, "has_dmarc": false},
      "latency_ms": 42.1
    }
  ]
}
```

---

## Validation errors

Invalid input returns **422 Unprocessable Entity**:

```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "entities", 0, "value"],
      "msg": "File hash must be hexadecimal",
      "input": "not-a-hash"
    }
  ]
}
```

Common validation failures:

| Condition | Error |
|-----------|-------|
| File hash not hex | `File hash must be hexadecimal` |
| Hash length mismatch | `File hash length must match hash_type sha256` |
| Sender without `@` | `Sender value must be a valid email address` |
| Invalid IP | `IP value must be a valid IPv4 or IPv6 address` |
| Empty entities | `List should have at least 1 item` |
| > 25 entities | `List should have at most 25 items` |

---

## Health

```http
GET /api/v1/reputation/health
```

Returns service status, Redis connectivity, and per-adapter health.

### Example response

```json
{
  "service": "helios-reputation-service",
  "environment": "local",
  "status": "healthy",
  "redis": "connected",
  "sources": [
    {
      "name": "ioc_feeds",
      "enabled": true,
      "configured": true,
      "priority": 1,
      "supported_entities": ["domain", "ip", "url"],
      "status": "healthy",
      "detail": null
    },
    {
      "name": "virustotal",
      "enabled": true,
      "configured": false,
      "priority": 2,
      "supported_entities": ["domain", "file", "url"],
      "status": "not_configured",
      "detail": "VIRUSTOTAL_API_KEY is not set"
    },
    {
      "name": "malwarebazaar",
      "enabled": true,
      "configured": false,
      "priority": 2,
      "supported_entities": ["file"],
      "status": "not_configured",
      "detail": "ABUSECH_API_KEY is not set"
    },
    {
      "name": "dns",
      "enabled": true,
      "configured": true,
      "priority": 3,
      "supported_entities": ["domain"],
      "status": "healthy",
      "detail": null
    }
  ],
  "checked_at": "2026-06-25T20:24:07.783000Z"
}
```

| `status` | Meaning |
|----------|---------|
| `healthy` | All enabled adapters are healthy or `not_configured` |
| `degraded` | At least one enabled adapter is unhealthy |

| `redis` | Meaning |
|---------|---------|
| `connected` | Redis available for TI cache and IOC feeds |
| `memory_fallback` | In-process cache only (IOC feeds unavailable) |

---

## Sources

```http
GET /api/v1/reputation/sources
```

Lists all configured adapters with priority, supported entities, and configuration status. Response shape matches the `sources` array in `/health`.

### Configured adapters (v1)

| Adapter | Entities | API key env var |
|---------|----------|-----------------|
| `ioc_feeds` | domain, url, ip | — (uses `REDIS_URL`) |
| `virustotal` | domain, url, file | `VIRUSTOTAL_API_KEY` |
| `alienvault` | domain, url, file | `ALIENVAULT_OTX_API_KEY` |
| `urlscan` | domain, url, ip | `URLSCAN_API_KEY` |
| `malwarebazaar` | file | `ABUSECH_API_KEY` |
| `dns` | domain | — |
| `whois` | domain | — |

Unconfigured adapters are skipped at runtime — the lookup still succeeds using available sources.

---

## Cache admin

Requires header `X-Admin-Api-Key` matching `REPUTATION_ADMIN_API_KEY`.

Non-local environments without an admin key configured return **503**.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/cache/{key}` | Read cached TI entry |
| `DELETE` | `/cache/{key}` | Delete cache entry and any override |
| `PUT` | `/cache/{key}/override` | Set manual verdict override |

Use `entity_key` from a lookup result as the cache key (e.g. `rep:v1:url:02433bad...`).

### Override request

```json
{
  "verdict": "benign",
  "score": 10,
  "confidence": 1.0,
  "reason": "Confirmed safe by analyst",
  "expires_at": "2026-07-01T00:00:00Z"
}
```

### Override response

```json
{
  "key": "rep:v1:url:02433badad1c24c65af44613ae4bd9a2fe53c2d4a2c70e4585783315df802263",
  "status": "override_set",
  "expires_at": "2026-07-01T00:00:00Z"
}
```

Overrides take precedence over TI cache and external lookups until they expire or are deleted.

---

## Integration mapping (sentinel-mail)

| Entity in request | Processor field |
|-------------------|-----------------|
| `sender` | `reputation_score` |
| `url`, `file`, `ip` | Rolled into `link_score` (existing weights) |

See [SENTINEL_MAIL_INTEGRATION.md](./SENTINEL_MAIL_INTEGRATION.md) for the full wiring guide.

---

## Cache behavior summary

| What | Cached? | TTL |
|------|---------|-----|
| TI adapter signals (VT, OTX, IOC, DNS, WHOIS, urlscan, MalwareBazaar) | Yes | 72h (15m when all sources return unknown) |
| Email auth context (`spf_fail`, etc.) | No | Recomputed every request |
| URL/file heuristics | No | Recomputed every request |
| Admin overrides | Yes | Until `expires_at` or manual delete |

Set `force_refresh: true` to bypass TI cache for a single request.
