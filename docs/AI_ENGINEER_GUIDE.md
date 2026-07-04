# Helios — AI Engineer Guide

Welcome. This guide covers everything you need to work on Helios's AI/ML stack: the content classifier, threat investigation engine, Neo4j graph, SageMaker retraining pipeline, and Redis feedback loop.

---

## 1. Architecture Overview

```
Email arrives / Employee reports
        ↓
[email_processor.py]
  └─ ContentClassifier (Claude Opus → GPT-4o fallback)
        ↓
[auto_triage_service.py]
  ├─ VirusTotal API
  ├─ Threat feeds (threat_feeds_service.py)
  ├─ Neo4j graph (graph_service.py)
  ├─ Attachment heuristics
  ├─ EC2 sandbox detonation (ec2_sandbox_service.py)
  └─ Helios AI dossier (Claude Opus via Anthropic SDK)
        ↓
Verdict: QUARANTINE / DISMISS / ESCALATE / MARK_AS_SPAM
        ↓
[feedback_trainer.py]  ← employee reports feed back here
  └─ Redis accumulator → SageMaker retraining trigger
```

---

## 2. Key Files

| File | What it does |
|---|---|
| `backend/services/email_processor.py` | Email ingestion + ContentClassifier invocation |
| `backend/services/auto_triage_service.py` | Full 8-stage auto-triage pipeline |
| `backend/services/graph_service.py` | Neo4j queries: sender rep, domain graph |
| `backend/services/threat_feeds_service.py` | Threat feed lookups (URLhaus, SURBL, etc.) |
| `backend/services/ec2_sandbox_service.py` | EC2 ephemeral sandbox detonation |
| `backend/services/feedback_trainer.py` | Redis accumulator + SageMaker retraining trigger |
| `models/content_classifier/classifier.py` | LLM content classifier (Claude primary, GPT-4o fallback) |
| `models/content_classifier/prompts.py` | System + classification prompts |
| `models/shared/schemas.py` | Pydantic schemas: `ContentClassificationResult`, `ThreatClassification` |
| `models/shared/config.py` | Model names, timeouts, temperature settings |
| `models/risk_orchestrator/` | Risk score aggregation across signals |
| `models/sender_reputation/` | Sender reputation scoring model |

---

## 3. AWS Access

### Region
All AI/ML infra lives in `uaenorth`.

```bash
export AWS_DEFAULT_REGION=uaenorth
```

### SageMaker
```bash
# List training jobs
aws sagemaker list-training-jobs --region uaenorth --sort-by CreationTime --sort-order Descending

# Describe a specific job
aws sagemaker describe-training-job --training-job-name <job-name> --region uaenorth

# List endpoints (hosted inference — not currently active, reserved for future)
aws sagemaker list-endpoints --region uaenorth

# View training job logs
aws logs get-log-events \
  --log-group-name /aws/sagemaker/TrainingJobs \
  --log-stream-name <job-name>/algo-1-* \
  --region uaenorth
```

SageMaker is wired in `feedback_trainer.py`. It triggers a retraining job when employee feedback hits a threshold (default: 50 samples). The training script lives in `models/content_classifier/`. The base model is stored in S3:

```bash
# View model artifacts in S3
aws s3 ls s3://himaya-evidence/content_classifier/latest/ --region uaenorth

# Download latest model
aws s3 sync s3://himaya-evidence/content_classifier/latest/ ./local-model/
```

### Neo4j
Neo4j is running on an EC2 instance (not managed — check your team for the IP).

```bash
# Connection details (from ECS env)
NEO4J_URL=bolt://...  # ask team for current IP
NEO4J_USER=neo4j
NEO4J_PASSWORD=HeliosGraph2026!

# Connect via cypher-shell
cypher-shell -a bolt://<NEO4J_HOST>:7687 -u neo4j -p HeliosGraph2026!

# Or use Neo4j Browser at http://<NEO4J_HOST>:7474
```

Key Cypher queries:
```cypher
-- Sender reputation for a domain
MATCH (s:Sender {domain: 'suspicious.com'})-[:SENT]->(t:Threat)
RETURN s, count(t) as threat_count ORDER BY threat_count DESC;

-- Domain relationship graph
MATCH path = (d:Domain {name: 'suspicious.com'})-[:SIMILAR_TO|RESOLVES_TO*1..3]->(n)
RETURN path LIMIT 50;

-- Org behavior baseline
MATCH (o:Org {id: '<org_id>'})-[:BASELINE]->(b:Baseline)
RETURN b LIMIT 10;
```

### Redis
```bash
# Get Redis URL from ECS
aws ecs describe-task-definition --task-definition himaya-backend \
  --region uaenorth \
  --query "taskDefinition.containerDefinitions[0].environment[?name=='REDIS_URL'].value" \
  --output text

# Connect (requires VPC access or SSH tunnel)
redis-cli -u <REDIS_URL>

# Check feedback accumulator keys
redis-cli -u <REDIS_URL> KEYS "feedback:*"

# Check retrain queue
redis-cli -u <REDIS_URL> LRANGE "retrain_queue" 0 -1
```

### EC2 Sandbox
```bash
# List running sandbox instances (should be 0 when idle)
aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=helios-sandbox" "Name=instance-state-name,Values=running" \
  --region uaenorth \
  --query "Reservations[].Instances[].{id:InstanceId, state:State.Name, launched:LaunchTime}" \
  --output table

# View sandbox results in S3
aws s3 ls s3://himaya-evidence/sandbox-results/ --region uaenorth
aws s3 cp s3://himaya-evidence/sandbox-results/<threat-id>/sandbox_results.json -
```

---

## 4. The Content Classifier

**Location:** `models/content_classifier/classifier.py`

**How it works:**
1. Claude Opus gets the email (sender, subject, body, attachments)
2. Returns a structured `ContentClassificationResult` (Pydantic)
3. If Claude fails/times out → GPT-4o fallback
4. If both fail → deterministic heuristics

**Classification outputs:**
```python
class ThreatClassification(str, Enum):
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    BEC = "BEC"           # Business Email Compromise
    MALWARE = "MALWARE"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"
```

### Example: Swap Claude for a hosted DeepSeek model

Say you want to replace Claude Opus with a self-hosted DeepSeek-V3 on SageMaker.

**Step 1:** Deploy DeepSeek to SageMaker endpoint and get the endpoint name, e.g. `helios-deepseek-v3`.

**Step 2:** Edit `models/content_classifier/classifier.py`:

```python
# BEFORE (Claude primary)
async def _classify_with_claude(self, messages: list) -> ContentClassificationResult:
    response = await self._anthropic_client.messages.create(
        model="claude-opus-4-5",
        max_tokens=LLM_MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=messages,
    )
    return _parse_llm_response(response.content[0].text, "claude-opus-4-5")

# AFTER (DeepSeek via SageMaker)
import boto3, json

SAGEMAKER_ENDPOINT = "helios-deepseek-v3"
_sm_client = boto3.client("sagemaker-runtime", region_name="uaenorth")

async def _classify_with_deepseek(self, messages: list) -> ContentClassificationResult:
    body = json.dumps({
        "model": "deepseek-v3",
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
        "max_tokens": LLM_MAX_TOKENS,
        "temperature": LLM_TEMPERATURE,
    })
    import asyncio
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, lambda: _sm_client.invoke_endpoint(
        EndpointName=SAGEMAKER_ENDPOINT,
        ContentType="application/json",
        Body=body,
    ))
    raw = json.loads(response["Body"].read())
    text = raw["choices"][0]["message"]["content"]
    return _parse_llm_response(text, "deepseek-v3")
```

**Step 3:** Update `_get_classifier()` in `email_processor.py` to not require `anthropic_api_key`:
```python
_classifier = ContentClassifier(
    sagemaker_endpoint="helios-deepseek-v3",  # add this param
    timeout_seconds=25,
)
```

**Step 4:** Update `models/shared/config.py`:
```python
CLAUDE_MODEL = "deepseek-v3"  # or keep claude as fallback only
```

**Files touched:** `models/content_classifier/classifier.py`, `models/shared/config.py`, `backend/services/email_processor.py`

---

## 5. Auto-Triage Pipeline

**Location:** `backend/services/auto_triage_service.py`

The pipeline runs every 2 minutes via a background task. Key entry point:

```python
async def run_auto_triage_for_org(org_id: str, db: AsyncSession) -> None:
```

Each stage is a separate async function. To add a new signal source (e.g. a new threat feed or a new ML model), insert it between steps 4 and 5:

```python
# Step 4b: Your new signal
new_signal = await your_new_service.analyze(threat, email_data)
indicators.extend(new_signal.indicators)
```

---

## 6. Running Locally

```bash
# Clone and install
git clone https://github.com/AdnanAhmed-repo/helios-mail.git
cd helios-mail

pip install -r backend/requirements.txt

# Set env (minimum for AI work)
export DATABASE_URL="postgresql+asyncpg://sentinel:password@localhost:5432/sentinel_mail"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="local-dev-secret"
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export AWS_DEFAULT_REGION="uaenorth"

# Run backend
uvicorn backend.main:app --reload --port 8000

# Test the classifier directly
python3 - <<'EOF'
import asyncio
from models.content_classifier.classifier import ContentClassifier
import os

classifier = ContentClassifier(
    anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
    openai_api_key=os.environ["OPENAI_API_KEY"],
)

result = asyncio.run(classifier.classify({
    "sender": "ceo-impersonator@gmai1.com",
    "subject": "Urgent wire transfer needed",
    "body": "Please send $50,000 to this account immediately. Do not tell anyone.",
    "attachments": [],
}))
print(result)
EOF
```

---

## 7. Deploying Changes

```bash
# Push to dev branch
git checkout dev
git pull
git checkout -b feature/my-ai-change
# ... make changes ...
git add .
git commit -m "feat: ..."
git push origin feature/my-ai-change
# Open PR → dev (1 approver)
# dev → main requires Adnan + Faraz approval + all CI green
# Merge to main → auto-deploys to app.himaya.ai
```
