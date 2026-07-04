# Helios Reputation Service

Standalone FastAPI microservice for sender, domain, URL, attachment-hash, and IP reputation lookups.

It lives outside `sentinel-mail/` so threat intel can evolve independently. It does not parse emails — callers send structured entities.

## What it does

- Looks up **sender, domain, url, file, ip** against multiple sources
- Applies **heuristics** (URL patterns, dangerous attachment extensions)
- Scores **SPF/DKIM/DMARC** from caller-provided `auth_results`
- **Caches** threat-intel signals for 72 hours (context is always fresh)
- Returns **score, verdict, indicators, and explanation** per entity

## Sources (v1)

| Source | Entities | API key |
|--------|----------|---------|
| IOC feeds (URLhaus, OpenPhish, IP feeds) | domain, url, ip | No — uses shared Redis |
| VirusTotal | domain, url, file | `VIRUSTOTAL_API_KEY` |
| AlienVault OTX | domain, url, file | `ALIENVAULT_OTX_API_KEY` |
| urlscan.io | domain, url, ip | `URLSCAN_API_KEY` |
| MalwareBazaar | file | `ABUSECH_API_KEY` |
| DNS (MX, SPF, DMARC records) | domain | No |
| WHOIS (domain age) | domain | No — needs `python-whois` |

Future (disabled in config): openEDL, CrowdStrike, Recorded Future.

## Runtime flow

```text
POST /api/v1/reputation/lookup
  → validate + normalize entities
  → check manual override
  → load cached threat-intel signals (or query adapters)
  → apply fresh context (auth, heuristics)
  → correlate sources → score → return per-entity result
```

Threat-intel is cached. Request context (auth results, filenames) is **not** cached.

## Quick start

```bash
cd reputation-service
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8080
```

Docs: `http://localhost:8080/docs`

If Redis is unavailable, the service falls back to in-memory cache (fine for local dev; IOC feeds need Redis in production).

## Docker

### Build

From the repo root (or `reputation-service/`):

```bash
cd reputation-service
docker build -t helios-reputation-service .
```

### Run with Redis

IOC feeds require Redis. Easiest local setup: run Redis in a container, then start the service on the same Docker network.

```bash
# 1. Create a network (once)
docker network create helios-net

# 2. Start Redis
docker run -d --name helios-redis --network helios-net -p 6379:6379 redis:7-alpine

# 3. Configure env (copy and edit API keys as needed)
cp .env.example .env
# Set REDIS_URL=redis://helios-redis:6379 inside .env when using the network above

# 4. Start the reputation service
docker run -d \
  --name helios-reputation \
  --network helios-net \
  -p 8080:8080 \
  --env-file .env \
  helios-reputation-service
```

**Windows (PowerShell)** — same commands; use backtick line continuation or a single line:

```powershell
docker run -d --name helios-reputation --network helios-net -p 8080:8080 --env-file .env helios-reputation-service
```

If Redis runs on the host instead of Docker, use `REDIS_URL=redis://host.docker.internal:6379` in `.env` (Docker Desktop on Windows/macOS).

### Verify

```bash
curl http://localhost:8080/api/v1/reputation/health
```

OpenAPI docs: `http://localhost:8080/docs`

Example lookup:

```bash
curl -s -X POST http://localhost:8080/api/v1/reputation/lookup \
  -H "Content-Type: application/json" \
  -d '{"entities":[{"type":"url","value":"https://example.com"}]}'
```

### Point sentinel-mail at the container

On the sentinel-mail side:

```bash
REPUTATION_SERVICE_URL=http://localhost:8080          # local dev, service published on host
# or, if sentinel-mail also runs in Docker on helios-net:
REPUTATION_SERVICE_URL=http://helios-reputation:8080
```

Use the **same `REDIS_URL`** (or same Redis instance) as the Helios threat-feed worker so IOC sets (`ioc_urlhaus:entries`, etc.) are visible to the service. See [SENTINEL_MAIL_INTEGRATION.md](./docs/SENTINEL_MAIL_INTEGRATION.md).

### Image details

| Item | Value |
|------|--------|
| Base image | `python:3.12-slim` |
| Listen port | `8080` |
| Process | `uvicorn app.main:app --host 0.0.0.0 --port 8080` |
| Dockerfile | `reputation-service/Dockerfile` |

Rebuild after code changes: `docker build -t helios-reputation-service .` then recreate the container.

## Example request

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
    { "type": "url", "value": "https://fake-login.com/verify" },
    {
      "type": "file",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "hash_type": "sha256",
      "context": { "filename": "invoice.xlsm" }
    }
  ]
}
```

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_URL` | `redis://localhost:6379` | Cache + IOC feeds (share with Helios) |
| `REPUTATION_CACHE_TTL_SECONDS` | `259200` (72h) | TI cache for useful results |
| `REPUTATION_ERROR_TTL_SECONDS` | `900` (15m) | TI cache when all sources unknown |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal adapter |
| `ALIENVAULT_OTX_API_KEY` | — | AlienVault adapter |
| `URLSCAN_API_KEY` | — | urlscan.io adapter |
| `ABUSECH_API_KEY` | — | MalwareBazaar adapter (free at auth.abuse.ch) |
| `REPUTATION_ADMIN_API_KEY` | — | Protects cache admin endpoints |
| `REPUTATION_ENV` | `local` | Non-local requires admin key config |

Source priorities and enablement: `app/config/sources.yaml`

## Documentation

| Doc | Audience |
|-----|----------|
| [SENTINEL_MAIL_INTEGRATION.md](./docs/SENTINEL_MAIL_INTEGRATION.md) | **Sentinel-mail engineers** — integration status and wiring |
| [API.md](./docs/API.md) | Endpoint reference |
| [SCORING.md](./docs/SCORING.md) | Score bands and signal impacts |
| [WORKFLOW.md](./docs/WORKFLOW.md) | Internal pipeline and file guide |
| [ARCHITECTURE.md](./docs/ARCHITECTURE.md) | Component overview |

## Design principles

- Adapter pattern for threat-intel sources
- Source-agnostic `SourceSignal` model
- Cache-first TI lookup; fresh context every request
- Deterministic scoring
- Tolerates partial source failures
- No vendor secrets in API responses
