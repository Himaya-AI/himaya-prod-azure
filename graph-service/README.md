# Graph Service

**Production URL:** `http://graph-lb-926798979.us-east-1.elb.amazonaws.com`

FastAPI microservice that maintains a Neo4j trust graph for the Helios mail platform. It records email communication history, scores sender trust using a rule-based engine (with optional LLM analysis), and exposes that intelligence to downstream services.

---

## Responsibilities

- **Ingest** email events into the graph (senders, domains, recipients, attachments, URLs, threats)
- **Score** sender trust using rule-based heuristics + optional LLM override
- **Serve** trust verdicts to sentinel-mail before delivery decisions are made
- **Retract** threat labels when a sender is cleared

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | FastAPI + Uvicorn |
| Graph DB | Neo4j 5 (Async driver 5.14.0) |
| LLM Analysis | Claude (via `llm_analyst.py`) |
| Auth hints | Reputation-service (`ReputationHint`) |

---

## API Reference

All routes are prefixed with `/graph`.

### `GET /graph/health`

Liveness + Neo4j connectivity check.

**Response**
```json
{ "status": "ok", "neo4j": true }
```
`status` is `"degraded"` when Neo4j is unreachable.

---

### `POST /graph/evaluate`

Score a sender's trustworthiness for a given recipient and org.

**Request body**
```json
{
  "sender": "alice@example.com",
  "recipient": "bob@yourorg.com",
  "org_id": "org_abc123",
  "content_hint": "Optional plain-text summary of email body",
  "reputation_hint": {
    "reputation_score": 20,
    "spf_pass": true,
    "dkim_pass": true,
    "dmarc_pass": true,
    "indicators": []
  }
}
```

| Field | Required | Notes |
|---|---|---|
| `sender` | Yes | Full email address |
| `recipient` | Yes | Full email address |
| `org_id` | Yes | Tenant identifier |
| `content_hint` | No | Passed to LLM when invoked |
| `reputation_hint` | No | Output from reputation-service |

**Response**
```json
{
  "sender": { "email_count": 42, "threat_count": 0, "historical_threat_types": [] },
  "domain": { "total_emails": 1200, "flagged_emails": 3, "total_senders": 18, "orgs_targeted": 2 },
  "relationship": { "prior_emails_to_recipient": 5 },
  "intel": { "reported_by_other_orgs": 0, "similar_threat_senders": [] },
  "trust": {
    "trust_score": 75,
    "trust_method": "deterministic",
    "reasoning": "Established sender with no threat history",
    "domain_spread": 18,
    "indicators": [],
    "llm_adjustment": null,
    "llm_reasoning": null,
    "llm_confidence": null,
    "llm_model": null
  }
}
```

`trust_method` values: `block` | `insufficient_history` | `deterministic` | `deterministic+llm` | `insufficient_history+llm`

---

### `POST /graph/write`

Record an email event in the graph. Returns `202 Accepted` immediately — the write happens in the background.

**Request body**
```json
{
  "sender": "alice@example.com",
  "recipient": "bob@yourorg.com",
  "org_id": "org_abc123",
  "message_id": "<msg-id@example.com>",
  "subject_hash": "sha256-of-subject",
  "received_at": "2026-07-04T10:00:00Z",
  "llm_verdict": "benign",
  "risk_score": 0.12,
  "threat_type": null,
  "urls": ["https://example.com/link"],
  "attachments": [
    { "sha256": "abc123...", "filename": "invoice.pdf", "extension": "pdf" }
  ]
}
```

**Response**
```json
{ "accepted": true }
```

---

### `DELETE /graph/retract`

Remove threat labels from a sender (e.g. after an admin clears a false positive).

**Request body**
```json
{
  "sender": "alice@example.com",
  "threat_type": "PHISHING"
}
```
Omit `threat_type` to retract all threat edges for the sender.

**Response**
```json
{ "sender": "alice@example.com", "threat_type": "PHISHING", "edges_removed": 2 }
```

---

## Trust Scoring Logic

The `TrustScorer` runs rule-based heuristics first:

1. **Hard block** — sender reported by other orgs → score `0`, method `block`
2. **Insufficient history** — fewer than 5 emails seen → score based on domain reputation
3. **Deterministic** — full scoring using email count, threat history, domain flagged rate, prior relationship with recipient, and similar-threat-sender penalty

The LLM analyst (`analyze_trust`) is invoked on top of the rule engine when the verdict is ambiguous (e.g. `insufficient_history` or borderline score). It can adjust the score and add reasoning.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NEO4J_URL` | *(required)* | Bolt URL, e.g. `bolt://localhost:7687` |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | *(required)* | Neo4j password |
| `NEO4J_MAX_POOL_SIZE` | `20` | Connection pool size |
| `NEO4J_MAX_CONNECTION_LIFETIME` | `1800` | Max connection age (seconds) |
| `NEO4J_ACQUISITION_TIMEOUT` | `10.0` | Pool acquisition timeout (seconds) |
| `NEO4J_RETRY_ATTEMPTS` | `3` | Retry attempts on transient errors |
| `NEO4J_RETRY_BACKOFF_SECONDS` | `5` | Backoff between retries (seconds) |

---

## Running Locally

### 1. Start Neo4j

```bash
docker compose up -d neo4j
```

Neo4j browser: http://localhost:7474 (credentials: `neo4j` / `graph_dev_password`)

### 2. Set environment variables

Create a `.env` file in this directory:

```env
NEO4J_URL=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=graph_dev_password
```

### 3. Install dependencies and run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 4. Run with Docker

```bash
docker build -t graph-service .
docker run --env-file .env -p 8000:8000 graph-service
```

Interactive API docs: http://localhost:8000/docs

---

## Project Structure

```
graph-service/
├── app/
│   ├── main.py               # FastAPI app, lifespan, middleware
│   ├── routes/
│   │   ├── health.py         # GET  /graph/health
│   │   ├── evaluate.py       # POST /graph/evaluate
│   │   ├── write.py          # POST /graph/write
│   │   └── retract.py        # DELETE /graph/retract
│   └── services/
│       ├── neo4j.py          # Neo4j connection management
│       ├── migrations.py     # Schema constraint/index setup
│       ├── query.py          # Read queries for evaluate
│       ├── trust_scorer.py   # Rule-based trust engine
│       ├── llm_analyst.py    # LLM trust adjustment layer
│       ├── write.py          # Graph write logic
│       └── retract.py        # Threat retraction logic
├── config/
│   └── neo4j.py              # Driver factory + config constants
├── utils/
│   └── schemas.py            # Pydantic request/response models
├── Dockerfile
├── docker-compose.yml        # Local Neo4j for development
└── requirements.txt
```
