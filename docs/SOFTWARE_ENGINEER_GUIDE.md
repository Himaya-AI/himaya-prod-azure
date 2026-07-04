# Helios — Software Engineer Guide

Welcome. This guide covers everything you need to work on Helios's backend API, frontend, and infrastructure — from pulling the repo locally to shipping a feature to production.

---

## 1. Stack at a Glance

| Layer | Tech |
|---|---|
| Backend | FastAPI (Python 3.12), asyncpg, SQLAlchemy async |
| Frontend | Next.js 16, React, Tailwind CSS |
| Database | PostgreSQL (RDS, `uaenorth`) |
| Cache | Redis (ElastiCache or self-managed) |
| Graph | Neo4j (sender reputation) |
| Deploy | AWS ECS Fargate, ECR, CloudFront |
| CI/CD | GitHub Actions (`.github/workflows/`) |
| IaC | Manual (see `infra/`) |

---

## 2. Getting the Repo Running Locally

### Prerequisites
- Python 3.12+
- Node 22+
- Docker (for local Postgres/Redis if needed)
- AWS CLI configured (`aws configure`)

### Clone
```bash
git clone https://github.com/AdnanAhmed-repo/helios-mail.git
cd helios-mail
```

### Backend
```bash
cd helios-mail   # repo root

# Install Python deps
pip install -r backend/requirements.txt

# Spin up local Postgres + Redis
docker run -d --name pg -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=sentinel_mail -p 5432:5432 postgres:15
docker run -d --name redis -p 6379:6379 redis:7

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://sentinel:password@localhost:5432/sentinel_mail"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="local-dev-secret"
export ANTHROPIC_API_KEY="sk-ant-..."   # get from team
export OPENAI_API_KEY="sk-..."          # get from team
export FRONTEND_URL="http://localhost:3000"
export AWS_DEFAULT_REGION="uaenorth"

# Run migrations (first time only)
python -c "
import asyncio
from backend.database import engine
from backend.models.db_models import Base
asyncio.run(engine.run_sync(Base.metadata.create_all))
"

# Start backend
uvicorn backend.main:app --reload --port 8000
# API docs: http://localhost:8000/docs
```

### Frontend
```bash
cd frontend
npm install --legacy-peer-deps

# Point at local backend
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
# App: http://localhost:3000
```

---

## 3. Project Structure

```
helios-mail/
├── backend/
│   ├── main.py                 ← FastAPI app, middleware, router registration
│   ├── config.py               ← All env var settings (Pydantic BaseSettings)
│   ├── database.py             ← Async SQLAlchemy engine + session
│   ├── models/
│   │   └── db_models.py        ← ALL database models (User, Org, Threat, Policy, etc.)
│   ├── routers/                ← One file per feature area
│   │   ├── auth.py             ← Login, JWT, refresh, password reset
│   │   ├── threats.py          ← Threat CRUD + detail views
│   │   ├── people.py           ← Directory users + groups
│   │   ├── policies.py         ← Policy engine CRUD
│   │   ├── compliance.py       ← Compliance status + worker
│   │   ├── message_trace.py    ← Email message trace
│   │   ├── onboarding.py       ← Google/M365 OAuth, org setup
│   │   ├── quarantine.py       ← Quarantine queue management
│   │   ├── reports.py          ← PDF report generation + download
│   │   ├── phish_report.py     ← Employee phish reporting (Gmail + Outlook)
│   │   ├── settings.py         ← Org settings
│   │   ├── admin.py            ← Himaya vendor admin panel
│   │   ├── dashboard.py        ← Dashboard stats
│   │   └── sandbox.py          ← On-demand URL/attachment sandbox
│   └── services/               ← Business logic
│       ├── auto_triage_service.py
│       ├── email_processor.py
│       ├── google_workspace_service.py
│       ├── delta_sync.py       ← Email delta sync (Google + M365)
│       ├── graph_service.py    ← Neo4j
│       ├── policy_engine.py    ← Policy evaluation
│       ├── quarantine_service.py
│       ├── report_generator.py ← PDF reports
│       └── ...
├── frontend/
│   └── src/app/
│       ├── (dashboard)/        ← All authenticated pages
│       │   ├── dashboard/      ← Main dashboard
│       │   ├── threats/        ← Threat list + detail
│       │   ├── people/         ← Directory
│       │   ├── policies/       ← Policy management
│       │   ├── quarantine/     ← Quarantine queue
│       │   ├── compliance/     ← Compliance status
│       │   ├── reports/        ← Report downloads
│       │   ├── onboarding/     ← Integration setup
│       │   └── settings/       ← Org settings
│       ├── login/              ← Auth pages
│       └── admin/              ← Vendor admin panel
├── models/                     ← AI/ML models (see AI_ENGINEER_GUIDE.md)
├── tests/
│   ├── production_readiness/   ← Pre-deploy smoke tests
│   └── ...                     ← Unit tests
├── .github/workflows/
│   ├── ci.yml                  ← PR checks (lint, build, tests)
│   └── deploy.yml              ← Auto-deploy on main merge
└── deploy.sh                   ← Manual deploy script
```

---

## 4. How to Make and Ship a Change

### Example: Add a "severity" filter to the Threats list page

**Backend change** — `backend/routers/threats.py`:
```python
# BEFORE
@router.get("")
async def list_threats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
):
    query = select(Threat).where(Threat.org_id == current_user.org_id)

# AFTER — add severity filter
@router.get("")
async def list_threats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,   # ← new param
):
    query = select(Threat).where(Threat.org_id == current_user.org_id)
    if severity:
        query = query.where(Threat.severity == severity)  # ← filter
```

**Frontend change** — `frontend/src/app/(dashboard)/threats/page.tsx`:
```tsx
// Add to your fetch call
const response = await api.get(`/api/threats?severity=${selectedSeverity}`)

// Add filter UI
<select onChange={e => setSelectedSeverity(e.target.value)}>
  <option value="">All severities</option>
  <option value="critical">Critical</option>
  <option value="high">High</option>
</select>
```

**Files touched:** `backend/routers/threats.py`, `frontend/src/app/(dashboard)/threats/page.tsx`

**Write a test** — `tests/production_readiness/test_api_health.py`:
```python
def test_threats_severity_filter(client, auth_headers):
    r = client.get("/api/threats?severity=critical", headers=auth_headers)
    assert r.status_code == 200
```

---

## 5. Database Models

All models in `backend/models/db_models.py`. Key ones:

```python
class Organization(Base):
    id: UUID
    name: str
    domain: str
    phish_report_key: str       # Outlook/Gmail add-on auth
    # ... google/m365 tokens, settings

class User(Base):
    id: UUID
    org_id: UUID                # ALWAYS scope queries to this
    email: str
    role: str                   # admin | analyst | viewer
    # ...

class Threat(Base):
    id: UUID
    org_id: UUID
    subject: str
    sender: str
    status: str                 # new | open | quarantined | resolved
    verdict: str                # PHISHING | SPAM | BEC | MALWARE | SAFE
    ai_dossier: str             # Claude's full investigation report
    risk_score: float
    # ...

class Policy(Base):
    id: UUID
    org_id: UUID
    name: str
    status: str                 # active | inactive
    action: str                 # ALERT | TAG | QUARANTINE | NOTIFY_ADMIN
    conditions: dict            # JSON rule conditions
```

**Critical rule: every query MUST be scoped to `current_user.org_id`.** Never query without it.

```python
# ✅ Correct
query = select(Threat).where(Threat.org_id == current_user.org_id)

# ❌ Wrong — cross-tenant data leak
query = select(Threat)
```

---

## 6. Adding a New API Route

1. Create or edit a router file in `backend/routers/`
2. Register it in `backend/main.py`:
```python
from backend.routers import your_new_router
app.include_router(your_new_router.router)
```
3. Always use `Depends(get_current_user)` for auth
4. Always scope DB queries to `current_user.org_id`

**Route ordering matters in FastAPI.** If you have `/people/groups` and `/people/{user_id}`, put the specific route FIRST or FastAPI will try to match "groups" as a UUID.

```python
# ✅ Correct order
@router.get("/groups")      # specific first
@router.get("/{user_id}")   # parameterized second

# ❌ Wrong — "groups" gets matched as user_id
@router.get("/{user_id}")
@router.get("/groups")
```

---

## 7. Auth Pattern

All protected routes use:
```python
from backend.routers.auth import get_current_user

@router.get("/my-endpoint")
async def my_endpoint(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.org_id
    ...
```

JWT is issued on login, contains `{sub: user_id, org_id, role}`. The `get_current_user` dependency decodes it and returns the User object from DB.

---

## 8. Google & M365 Token Handling

**This is where regressions happen.** Both providers store encrypted OAuth tokens per org in the `Organization` model. If you change the token schema, test message trace immediately — this is what broke before.

- Google tokens: `org.google_access_token`, `org.google_refresh_token`
- M365 tokens: `org.m365_access_token`, `org.m365_refresh_token`
- Token encryption: `backend/routers/onboarding.py` → `encrypt_token` / `decrypt_token`

If you touch `onboarding.py` or `delta_sync.py`, always verify:
```bash
# After deploy, check message trace is still picking up emails
curl https://app.himaya.ai/api/message-trace \
  -H "Authorization: Bearer <token>" | jq length
# Should return > 0 if there are recent emails
```

---

## 9. Deploying

### Via GitHub Actions (normal path)
```bash
# Feature work
git checkout dev
git pull
git checkout -b feature/my-change
# ... make changes ...
git add . && git commit -m "feat: describe change"
git push origin feature/my-change

# Open PR → dev (1 approver, CI must pass)
# Open PR dev → main (Adnan + Faraz approval, all CI + production readiness tests)
# Merge → auto-deploys
```

### Via deploy.sh (emergency / local)
```bash
# Both services
./deploy.sh both

# Frontend only (faster, ~3 min)
./deploy.sh frontend

# Backend only
./deploy.sh backend
```

---

## 10. Checking Logs

```bash
# Get running task ARNs
aws ecs list-tasks --cluster himaya --service-name himaya-backend \
  --region uaenorth

# Stream backend logs
aws logs tail /ecs/himaya-backend --follow --region uaenorth

# Stream frontend logs  
aws logs tail /ecs/himaya-frontend --follow --region uaenorth

# Check ECS service events (deploy failures show here)
aws ecs describe-services \
  --cluster himaya \
  --services himaya-backend himaya-frontend \
  --region uaenorth \
  --query "services[].events[:5]"
```

---

## 11. Common Gotchas

| Problem | Fix |
|---|---|
| Message trace stops picking up emails | Token schema change in onboarding.py — check decrypt_token |
| People groups 500 error | Route ordering — `/groups` must be before `/{user_id}` |
| Policy count wrong | asyncpg doesn't support `func.cast(bool, Integer)` — use separate count queries |
| Frontend OOM on Pi | Next.js build is memory-heavy — build in Docker or on CI, not locally on Pi |
| CloudFront caching stale assets | `./deploy.sh frontend` already invalidates — wait 2 min |
| ECS task not starting | Check task definition env vars — missing required var causes silent crash |
