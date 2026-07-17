# Classifier Service — Developer Guide

**Production URL:** `http://classify-lb-556047835.us-east-1.elb.amazonaws.com`

---

## Overview

The classifier service is a standalone FastAPI microservice that classifies emails as threats (BEC, phishing, malware, etc.) using an LLM on AWS Bedrock. It was extracted from the main `sentinel-mail` backend into its own container so it can be scaled, deployed, and updated independently.

---

## Architecture

```
sentinel-mail backend
        │
        │ HTTP POST /classify
        ▼
classifier-service (FastAPI on port 8000)
        │
        ├─ AWS Bedrock (LLM inference — Kimi K2.5)
        └─ AWS S3     (prompt storage)
```

---

## Project Structure

```
classifier-service/
├── app/
│   ├── main.py           # FastAPI app, lifespan startup
│   ├── routes.py         # API endpoints
│   ├── classifier.py     # ContentClassifier class — calls Bedrock
│   └── kimi.py           # KimiClassifier (default model subclass)
├── config/
│   └── aws.py            # Boto3 clients + env config
├── utils/
│   ├── prompt_loader.py  # S3 prompt fetching + in-memory cache
│   └── schema.py         # Pydantic request/response models
├── Dockerfile
└── requirements.txt
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check — returns active model ID |
| POST | `/classify` | Classify a single email using the default model |
| POST | `/classify/{id}` | Classify using a specific Bedrock model ID |
| POST | `/classify/batch` | Classify a list of emails concurrently |

### Request body (`/classify`, `/classify/{id}`)

```json
{
  "sender": "attacker@evil.com",
  "recipient": "finance@company.sa",
  "subject": "Urgent wire transfer",
  "body": "Please transfer...",
  "attachments": ["invoice.docm"],
  "headers": {
    "SPF": "fail",
    "DKIM": "none"
  }
}
```

`attachments` and `headers` are optional.

---

## How Prompts Work

Prompts are **not hardcoded** in the codebase. They are stored in S3 and loaded at startup.

### S3 Bucket

```
classify-prompts-439055361147  (us-east-1)
├── system_prompt.txt     ← LLM system prompt (Gulf cybersecurity analyst persona)
└── few_shots.json        ← 16 few-shot email examples (32 message objects)
```

### How the cache works

On startup, `main.py` calls `reload_prompts()` which fetches both files from S3 and stores them in a module-level in-memory dict (`_cache`). All subsequent requests hit the cache — S3 is never called again until the container restarts.

A `threading.Lock` with double-checked locking prevents duplicate S3 fetches under concurrent requests.

```
Container start
  └── reload_prompts()
        ├── S3 → system_prompt.txt → _cache["system_prompt.txt"]
        └── S3 → few_shots.json   → _cache["few_shots.json"]

Incoming request
  ├── get_system_prompt()     → _cache hit
  └── get_few_shot_examples() → _cache hit
```

### Updating prompts without redeploying

Upload new files to S3:

```bash
aws s3 cp system_prompt.txt s3://classify-prompts-439055361147/system_prompt.txt
aws s3 cp few_shots.json s3://classify-prompts-439055361147/few_shots.json
```

Then restart the ECS task (or add a `/prompts/reload` endpoint — see Future Work).

### Uploading prompts for the first time

If setting up a new environment, run this from `classifier-service/`:

```bash
aws s3 cp utils/system_prompt.txt s3://classify-prompts-439055361147/system_prompt.txt
aws s3 cp few_shots.json s3://classify-prompts-439055361147/few_shots.json
```

Verify they exist:

```bash
aws s3 ls s3://classify-prompts-439055361147/
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KIMI_MODEL_ID` | `moonshotai.kimi-k2.5` | Bedrock model ID used by default |
| `AWS_REGION` | `us-east-1` | Region for Bedrock runtime |
| `PROMPT_BUCKET` | `classify-prompts-439055361147` | S3 bucket for prompts |
| `LLM_TIMEOUT_SECONDS` | `30` | Per-request LLM timeout |
| `LLM_TEMPERATURE` | `0.1` | LLM temperature |
| `LLM_MAX_TOKENS` | `2000` | Max output tokens |

---

## Running Locally

```bash
cd classifier-service
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set up AWS credentials (must have Bedrock + S3 access)
export AWS_PROFILE=your-profile

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Test it:

```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "ceo@evil.com",
    "recipient": "finance@company.sa",
    "subject": "Urgent transfer",
    "body": "Please transfer 500,000 SAR immediately."
  }'
```

---

## Docker

```bash
docker build -t classifier-service .
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_REGION=us-east-1 \
  classifier-service
```

In production (ECS), credentials come from the **task IAM role** — no env vars needed for auth.

---

## AWS IAM Requirements

The ECS task role must have these permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:Converse"
  ],
  "Resource": "arn:aws:bedrock:us-east-1::foundation-model/moonshotai.kimi-k2.5"
},
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::classify-prompts-439055361147/*"
}
```

---

## Adding a New Model

The `/classify/{id}` endpoint already supports any Bedrock model ID on the fly — no code changes needed:

```bash
curl -X POST http://localhost:8000/classify/anthropic.claude-3-5-sonnet-20241022-v2:0 \
  -H "Content-Type: application/json" \
  -d '{ "sender": "...", "recipient": "...", "subject": "...", "body": "..." }'
```

To change the **default** model, update `KIMI_MODEL_ID` in the ECS task definition or `.env`.

---

## What Changed from the Monolith

Before this refactor, classification was done inline inside the `sentinel-mail` backend. Here is what changed:

| Before | After |
|--------|-------|
| Classification logic in `sentinel-mail/models/content_classifier/` | Standalone `classifier-service/` container |
| `SYSTEM_PROMPT` and `FEW_SHOT_EXAMPLES` hardcoded in `prompts.py` | Loaded from S3 at startup, cached in memory |
| Single model, no way to swap at runtime | `/classify/{id}` endpoint supports any Bedrock model |
| `sentinel-mail` backend called the classifier directly in-process | `sentinel-mail` backend calls `classifier-service` over HTTP |

The `sentinel-mail` backend now uses `sentinel-mail/models/content_classifier/remote_classifier.py` to call this service via HTTP instead of running classification in-process.

---

## LLM Evaluation & Pricing

### Model Pricing Comparison

| Model | Input ($/MTok) | Output ($/MTok) | Cache Hits | Notes |
|-------|---------------|-----------------|------------|-------|
| Claude Opus 4.5 | $5.00 | $25.00 | $0.50 | Current model |
| Kimi K2.5 | $0.60 | $3.00 | N/A | Default model in this service |
| Kimi K2 Thinking | $0.60 | $2.50 | N/A | |
| DeepSeek V3.1 | $0.58 | $1.68 | N/A | |
| DeepSeek V4 Flash | $0.14 | $0.28 | $0.0028 | |
| DeepSeek V4 Pro | $1.74 | $3.48 | $0.0145 | |
| DeepSeek-R1 | $1.35 | $5.40 | N/A | |
| Qwen3-235B-A22B | $0.70 | $2.80 | N/A | 1h cache writes $2.80/MTok |
| MiniMax M2.5 | $0.30 | $1.20 | N/A | |
| Gemini 2.5 Pro (≤200K) | $1.25 | $10.00 | $0.125 | |
| Gemini 2.5 Pro (>200K) | $2.50 | $15.00 | $0.25 | |
| Gemini 3.1 Pro | $2.00 | $12.00 | $0.20 | |

### Token Baseline (Average Long Email)

| | Tokens |
|--|--------|
| Input | 12,230 |
| Output | 745 |

### Cost per Email

| Model | Price per Email |
|-------|----------------|
| Qwen3 235B A22B | 0.33 cents |
| MiniMax M2.5 | 0.46 cents |
| DeepSeek V3.1 | 0.83 cents |
| Kimi K2.5 | 0.96 cents |

### Production Scale — 100k Emails/Month

| Model | Monthly Cost |
|-------|-------------|
| Qwen3 235B A22B | ~$335 |
| MiniMax M2.5 | ~$456 |
| DeepSeek V3.1 | ~$835 |
| Kimi K2.5 | ~$957 |

### Recommendation

We should move away from Claude Opus 4.5 and benchmark alternative models on our own dataset. For email threat analysis and content classification — especially in Arabic — Opus is likely overkill and expensive. The goal is to find the point where reducing model size starts affecting accuracy, and to explore Arabic-focused open-source models that could deliver similar performance at a much lower cost.

Benchmarking branch: [feature/benchmark](https://github.com/AdnanAhmed-repo/helios-mail/tree/feature/benchmark)

