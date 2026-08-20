# dlp-classifier

Classification decision worker for the DLP gateway. Given the extracted text
of an email, it runs cheap deterministic detectors first and always follows
up with an LLM judgment call that gets the deterministic findings as context,
returning a combined result for the gateway to act on.

## Architecture

```
                POST /classify
                     │
                     ▼
          ┌─────────────────────┐
          │  ClassificationPipeline
          └─────────────────────┘
                     │
        ┌────────────┴─────────────┐
        │                          │
        ▼                          ▼
 Tier 0 — DeterministicRunner   (always runs first)
   ├─ PIIDetector        (Presidio + custom CreditCardValidator)
   ├─ NERDetector         (Presidio built-ins — PERSON/LOCATION/NRP/ORGANIZATION)
   ├─ LexiconDetector     (Aho-Corasick, tenant lexicon from Redis)
   └─ CredentialDetector  (BetterLeaks subprocess)
        │
        ▼
 build_classification_prompt(text, findings)
        │
        ▼
 Tier 2 — KimiClassifier (AWS Bedrock, Kimi K2.5)
   always runs, with Tier 0 findings as context
        │
        ▼
 ClassificationOutcome{ findings, llm_result }
```

Every Tier 0 detector implements the same `BaseDetector` contract
(`app/service/base.py`) — async `analyze(text, metadata) -> DetectionResult`
— and never raises; a failing detector returns `escalate=True` with `error`
set instead of taking down the request. `DeterministicRunner` runs all of
them concurrently via `asyncio.gather` since they have no interconnected
dependencies.

Tier 2 is deliberately not part of the same `BaseDetector` contract — it
returns a semantic verdict (`LLMClassificationResult`), not span-based
matches, and is always invoked after Tier 0 rather than conditionally.

`RecognizerRegistry.load_predefined_recognizers()` only auto-registers a
curated subset of Presidio's built-in recognizers (mostly US-focused).
`UK_NINO`, `UK_PASSPORT`, `IN_AADHAAR`, `IN_PAN`, and `IN_PASSPORT` — all
requested by `pii.py`'s entity lists — are NOT in that subset even though
the recognizer classes exist in the installed package, so `runner.py`'s
`_build_shared_engine()` registers them explicitly. If a future Presidio
upgrade changes what's auto-loaded, re-check this list against
`RecognizerRegistry().load_predefined_recognizers()`'s actual output rather
than assuming an entity in `pii.py`'s lists has a live recognizer.

## Directory layout

```
app/
  main.py                       FastAPI app, lifespan startup wiring, /health
  routes/classify.py            POST /classify — the only HTTP endpoint
  service/
    base.py                     BaseDetector, DetectionMatch, DetectionResult
    pipeline.py                 ClassificationPipeline — ties Tier 0 to Tier 2
    deterministic/
      runner.py                 DeterministicRunner — owns the shared Presidio
                                 AnalyzerEngine, runs all Tier 0 detectors
      pii.py                    PIIDetector (financial/contact/identity PII)
      ner.py                    NERDetector (PERSON/LOCATION/NRP/ORGANIZATION)
      lexicon.py                LexiconDetector (tenant banners/codenames/terms)
      credentials.py            CredentialDetector (BetterLeaks)
      edm.py                    Exact Data Match — NOT YET IMPLEMENTED
      recognizers/
        credit_card.py          CreditCardValidator (BIN + Luhn + denylist)
    llm/
      classifier.py             KimiClassifier — Bedrock Kimi K2.5 wrapper
  utils/
    automaton.py                build_automaton() — pyahocorasick helper
    prompt_builder.py           SYSTEM_PROMPT + build_classification_prompt()
config/
  settings.py                   pydantic-settings Settings, get_settings()
  redis_client.py               create_redis_client()
  aws.py                        boto3 bedrock_runtime client, Kimi model config
scripts/
  install_betterleaks.sh        Installs the pinned BetterLeaks binary
Dockerfile / .dockerignore
requirements.txt
```

## Services / dependencies used

| Concern | Library / Service | Where |
|---|---|---|
| HTTP API | FastAPI + uvicorn | `app/main.py`, `app/routes/classify.py` |
| PII + NER detection | Presidio Analyzer (+ spaCy `en_core_web_sm`) | `app/service/deterministic/pii.py`, `ner.py` |
| Credit card validation | Custom (BIN prefix, test-number denylist, Luhn) | `recognizers/credit_card.py` |
| Tenant lexicon matching | pyahocorasick (Aho-Corasick automaton) | `app/utils/automaton.py`, `lexicon.py` |
| Lexicon storage/cache | Redis (`redis.asyncio`) | `config/redis_client.py`, `lexicon.py` |
| Credential/secret scanning | BetterLeaks (external Go binary, subprocess) | `credentials.py`, `scripts/install_betterleaks.sh` |
| Tier 2 semantic judgment | AWS Bedrock, model `moonshotai.kimi-k2.5` | `config/aws.py`, `app/service/llm/classifier.py` |
| Config | pydantic-settings (`.env`-backed) | `config/settings.py` |

## Configuration

All settings are loaded via `pydantic-settings` from the environment / a
local `.env` file (see `config/settings.py`).

Example `.env`:

```env
# Required
REDIS_URL=redis://localhost:6379
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=eu-north-1

# LLM (Bedrock / Kimi)
KIMI_MODEL_ID=moonshotai.kimi-k2.5
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=20000

# Optional overrides
REDIS_KEY_PREFIX=dlp
LEXICON_TTL_SECONDS=3600
APP_HOST=0.0.0.0
APP_PORT=8000
LOG_LEVEL=info
```

| Variable | Default | Used by |
|---|---|---|
| `APP_HOST` | `0.0.0.0` | uvicorn |
| `APP_PORT` | `8000` | uvicorn |
| `LOG_LEVEL` | `info` | `logging.basicConfig` |
| `REDIS_URL` | *(required, no default)* | `config/redis_client.py` |
| `REDIS_KEY_PREFIX` | `dlp` | reserved for future key namespacing |
| `LEXICON_TTL_SECONDS` | `3600` | reserved for lexicon cache expiry |
| `BETTERLEAKS_BINARY` | `/usr/local/bin/betterleaks` | `credentials.py`, startup check |
| `BETTERLEAKS_TIMEOUT` | `10` | `credentials.py` subprocess timeout |
| `SPACY_MODEL` | `en_core_web_sm` | reserved, not yet wired into `AnalyzerEngine` |
| `TIER1_ENABLED` | `true` | reserved — Tier 1 is out of scope, unused |
| `TIER2_ENABLED` | `true` | reserved, not yet enforced |

Bedrock/Kimi config (`config/aws.py`, separate from `Settings`) reads
directly from env via `python-dotenv`: `KIMI_MODEL_ID`, `LLM_TIMEOUT_SECONDS`,
`LLM_TEMPERATURE`, `LLM_MAX_TOKENS`, `AWS_REGION`, plus standard AWS
credential env vars picked up by `boto3`.

Redis is **not** BullMQ here — it only stores tenant lexicon JSON under
`dlp:lexicon:{tenant_id}`. The app still `ping()`s Redis on boot, so Redis
must be up even if you have no lexicon data yet.

## Startup sequence (`app/main.py`)

1. Verify the BetterLeaks binary exists and is executable — fails fast with
   a `RuntimeError` pointing at `scripts/install_betterleaks.sh` if not.
2. Warm up BetterLeaks with a dummy scan so it's cached before real traffic.
3. Connect to Redis and `ping()` it — fails fast if unreachable.
4. Build `DeterministicRunner` (which builds the shared Presidio
   `AnalyzerEngine` — spaCy loads exactly once — and constructs all four
   Tier 0 detectors).
5. Build `ClassificationPipeline` from the runner + a `KimiClassifier`.

Everything is constructed once and hung off `app.state`.

## Prerequisites

- Python 3.12+
- Redis running and reachable (tenant lexicon store; required at startup)
- AWS credentials with access to Bedrock model `moonshotai.kimi-k2.5` (Tier 2)
- Docker (optional — only if you run via the image)

From the parent repo you can start Redis with compose:

```bash
cd ..   # himaya-prod-azure
docker compose up -d redis
```

## Running locally (without Docker)

```bash
cd dlp-classifier

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
./scripts/install_betterleaks.sh   # installs BetterLeaks v1.6.1 to /usr/local/bin

# ensure Redis is up, then:
python -m app.main
```

Service listens on `http://0.0.0.0:8000` by default.

## Running with Docker

Build:

```bash
cd dlp-classifier
docker build -t dlp-classifier:latest .
```

Run — Redis on the host (simplest on Linux):

```bash
docker run --rm --network host --env-file .env dlp-classifier:latest
```

Or bridge networking (map port 8000, point Redis at the host):

```bash
docker run --rm -p 8000:8000 --env-file .env \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  --add-host=host.docker.internal:host-gateway \
  dlp-classifier:latest
```

Do **not** use `REDIS_URL=redis://localhost:6379` inside a bridge-network
container — `localhost` is the container itself, not your host Redis.

The image installs BetterLeaks during build (pinned version, checksum
verified), installs Python deps (including the `en_core_web_sm` spaCy model,
pulled via its direct wheel URL in `requirements.txt`), and runs as a
non-root user. Redis is a separate service; it is not installed in the image.

## How to use

### Health check

```bash
curl -s http://localhost:8000/health
# {"status":"ok"}
```

### Classify text

```bash
curl -s -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Hi Alice, my card is 4111 1111 1111 1111 and SSN is 123-45-6789.",
    "tenant_id": "default",
    "message_id": "msg-001",
    "lexicon_version": "v1"
  }' | jq .
```

Request body:

| Field | Type | Default | Notes |
|---|---|---|---|
| `text` | string | *(required)* | Plain extracted email/body text |
| `tenant_id` | string | `"default"` | Used for lexicon lookup key |
| `message_id` | string \| null | `null` | Optional correlation id |
| `lexicon_version` | string | `"v1"` | Busts the in-process lexicon automaton cache |

Response shape:

```json
{
  "findings": [
    {
      "detector": "pii",
      "matches": [ /* span matches */ ],
      "escalate": false,
      "error": null
    }
  ],
  "llm_result": {
    "classification": "...",
    "confidence": 0.0,
    "categories": [],
    "reasoning": "..."
  }
}
```

`findings` has one entry per Tier 0 detector (`pii`, `ner`, `lexicon`,
`credentials`). `llm_result` is always populated by the Bedrock Kimi call
(with Tier 0 findings as context).

### Optional: seed a tenant lexicon in Redis

```bash
redis-cli SET 'dlp:lexicon:default' '["CONFIDENTIAL","PROJECT-ORION","trade secret"]'
```

Then call `/classify` with matching terms in `text` and
`tenant_id: "default"` — the lexicon detector should report matches.

## What's not built yet

- **`edm.py`** (Exact Data Match) — deferred, empty stub.
- **Content extraction / MIME decomposition** — every detector takes plain
  `text: str` today; nothing turns a raw email/MIME message into that text.
- **Context/policy fusion** — no per-tenant rule layer turning raw findings
  into a decision.
- **Verdict mapping** — nothing maps `ClassificationOutcome` to the
  gateway's 4-state contract (allow/hold/stop/defer).
- **Idempotency-key handling** — repeated calls for the same message
  currently re-run detection instead of returning a cached verdict.
