# Helios — AI-Powered Email Security Platform

> **Built by Himaya Technologies**  
> Production URL: [app.himaya.ai](https://app.himaya.ai)

---

## What Is Helios?

Helios is an enterprise email security platform that sits on top of Google Workspace and Microsoft 365. It uses AI to automatically investigate, triage, and respond to phishing threats — with zero manual work from security teams.

Employees report suspicious emails. Helios handles the rest.

---

## The Problem

Email is still the #1 attack vector. The current SOC workflow is:

1. Employee reports suspicious email
2. Analyst manually reviews sender, links, attachments
3. Analyst queries VirusTotal, threat feeds
4. Analyst decides: quarantine, dismiss, escalate
5. Repeat for hundreds of emails per week

This is slow, expensive, and doesn't scale. A mid-size company with 500 employees generates 50–200 phishing reports per week. Each takes 15–30 minutes of analyst time.

**Helios automates the entire investigation pipeline.**

---

## The Solution

### Auto-Triage Pipeline

Every reported or delta-synced email goes through a multi-stage AI investigation:

```
Email Arrives (delta-sync or employee report)
        ↓
[1] Content Classifier (Claude Opus → GPT-4o fallback)
    ↓ threat_type, confidence, indicators
[2] Sender Reputation Check
    ↓ SPF/DKIM/DMARC (real headers) + DNS (MX, SPF record, DMARC record)
    ↓ VirusTotal domain report → WHOIS domain age fallback
[3] Link & Attachment Analysis
    ↓ URL heuristics + VirusTotal URL scan + IOC feed lookup
    ↓ Attachment extension / entropy analysis
[4] Neo4j Graph Intelligence
    ↓ sender→recipient edge history, domain spread, FLAGGED_AS relationships
    ↓ Sender reputation_score (updated per email, retracted on FP)
[5] Risk Score Computation
    ↓ content 40% + graph 30% + reputation 30%
[6] Auto-Triage Agent (Claude Opus — Helios Analysis)
    ↓ Synthesizes all signals → QUARANTINE / DISMISS / ESCALATE / MARK_AS_SPAM
[7] EC2 Sandbox Detonation (URLs + attachments, background)
    ↓ Results stored in Postgres + S3 permanently (not just Redis)
[8] Physical Email Move
    ↓ Gmail API or M365 Graph API → quarantine / junk / inbox
[9] Neo4j Intelligence Update
    ↓ FLAGGED_AS edge written on QUARANTINE/BLOCK
    ↓ FLAGGED_AS edge retracted + reputation recomputed on FP report
```

### Verdicts

| Verdict | Action |
|---|---|
| `QUARANTINE` | Email physically moved to quarantine folder, Neo4j FLAGGED_AS written |
| `DISMISS` | Email confirmed clean. If user-reported, reinjected to inbox. |
| `ESCALATE` | Routed to human analyst for review |
| `MARK_AS_SPAM` | Moved to spam/junk folder |

---

## Key Features

### 🤖 AI Agents & System Prompts

Helios runs **3 distinct AI agents** with their own system prompts:

| Agent | Location | Model | Purpose |
|---|---|---|---|
| **Content Classifier** | `models/content_classifier/prompts.py` | Claude Opus → GPT-4o fallback | Classifies email body/subject/headers as PHISHING/BEC/MALWARE/SPAM/SAFE with confidence score |
| **Helios Analysis** (Auto-Triage) | `backend/services/auto_triage_service.py` → `HELIOS_ANALYSIS_SYSTEM_PROMPT` | Claude Opus | Receives full threat dossier (VT + feeds + graph + sandbox), returns QUARANTINE/DISMISS/ESCALATE/MARK_AS_SPAM verdict as JSON |
| **Sandbox Analyzer** | `backend/routers/sandbox.py` → `SANDBOX_PROMPT` | Claude Opus | Analyzes detonation results (URL behavior, redirects, login forms, screenshots) and produces a human-readable verdict |

The Content Classifier runs in-process in ECS. The Helios Analysis and Sandbox agents are called via Anthropic API during triage.

### 📊 Threat Intelligence Graph (Neo4j)

Real-time sender intelligence — updated on every email processed:

- `SENT_TO` edges: sender→recipient history with timestamps
- `FLAGGED_AS` edges: written on quarantine/block, **deleted on FP retraction**
- `Sender` node properties: `email_count`, `threat_count`, `reputation_score` (0–100, maintained per-email)
- Domain spread detection, lookalike domain analysis
- Reputation score automatically recomputed when analyst marks FP

### 🧪 EC2 Sandbox Detonation

- Ephemeral `t3.micro` Amazon Linux instances per threat
- Outbound-only security group (no inbound attack surface)
- Playwright/Chromium for URL detonation (screenshots, redirect chains, login form detection)
- `oletools` for Office attachment macro analysis
- Results stored in **Postgres permanently** (`score_breakdown.sandbox`, `threat_indicators.ec2_sandbox_verdict`)
- MALICIOUS / CLEAN / TIMEOUT verdict fed into Helios Analysis dossier

### 📬 Employee Phish Report Add-ons

- **Outlook Add-in** — deployed via M365 admin center, `manifest.xml` served dynamically per org
  - On report: email immediately quarantined
  - If auto-triage returns DISMISS: email reinjected to inbox automatically
- **Gmail Add-on** — published to Google Workspace Marketplace (pending external verification)
  - Internal use: deploy privately via Google Admin Console (no verification needed)

### 🏢 Multi-Tenant Architecture

- Full tenant isolation: every query scoped to `org_id`
- Per-org phish report keys (rotatable)
- Org `tier` field: `Launch` or `Enterprise` (for feature gating)
- Admin panel: separate auth (`X-Admin-API-Key`), protected endpoints at `/api/admin/*`

### 📋 Policy Engine

- Rule-based policies with AI risk scoring
- Actions: ALERT, TAG (Gmail label), QUARANTINE, NOTIFY_ADMIN
- "Apply Now" (retroactive): applies active policies to all existing inbox emails
- Confirmation modal guards against accidental large-scale runs

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    app.himaya.ai                      │
│              (CloudFront + ECS Frontend)                 │
│                    Next.js 16 / React                    │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS API
┌──────────────────────▼──────────────────────────────────┐
│                  ECS Backend (FastAPI)                   │
│                  Python 3.12 / asyncpg                   │
├─────────┬──────────┬──────────┬───────────┬─────────────┤
│  Auth   │ Threats  │ People   │ Policies  │ Compliance  │
│  JWT    │ Auto-    │ Directory│ Engine    │ Reports     │
│         │ Triage   │ Sync     │           │             │
└────┬────┴────┬─────┴────┬─────┴─────┬─────┴──────┬──────┘
     │         │          │           │            │
  RDS/PG   Neo4j      Redis       S3 Evidence  EC2 Sandbox
  (main    (graph     (cache,     (artifacts)  (detonation)
   store)   intel)    queues)
```

### Infrastructure (AWS, uaenorth)

- **Compute:** ECS Fargate (frontend + backend services)
- **Database:** RDS PostgreSQL (multi-tenant, asyncpg)
- **Graph:** Neo4j EC2 (`10.0.3.166:7687`, `neo4j / HeliosGraph2026!`)
- **Cache/Queue:** Redis ElastiCache (`himaya-redis.yuvxb0.0001.usw2.cache.amazonaws.com:6379`)
- **Storage:** S3 (`himaya-evidence` — threat artifacts, sandbox results, reports)
- **CDN:** CloudFront (`__AZURE_FD_PROFILE__`) → `app.himaya.ai`
- **Email:** AWS SES (us-east-1, admin notifications, daily/weekly digests)
- **Sandbox:** EC2 `t3.micro` ephemeral instances (outbound-only SG) + ECS Fargate sandbox tasks
- **Container Registry:** ECR (`himaya-frontend`, `himaya-backend`)

---

## Local Development Setup

A new engineer can run the full stack locally in prod-like mode. Here's exactly how:

### Prerequisites

```bash
# Required
brew install python@3.12 node@22 docker
# or apt/dnf equivalents

# AWS CLI (for ECR image pulls and ECS task inspection)
pip install awscli
aws configure  # use uaenorth, credentials from Adnan
```

### 1. Clone & configure

```bash
git clone https://github.com/AdnanAhmed-repo/helios-mail.git
cd helios-mail

# Copy and fill in env vars
cp .env.example .env
# Edit .env — minimum required:
#   DATABASE_URL — point to local Postgres or the prod RDS (for read-only dev)
#   ANTHROPIC_API_KEY — get from Adnan
#   VIRUSTOTAL_API_KEY — get from Adnan (0ccb9eae...)
#   JWT_SECRET — any 32+ char string for local
#   VENDOR_ADMIN_API_KEY — any string for local
```

### 2. Start local dependencies

```bash
# Postgres
docker run -d --name helios-pg \
  -e POSTGRES_USER=sentinel \
  -e POSTGRES_PASSWORD=sentinel_dev_password \
  -e POSTGRES_DB=sentinel_mail \
  -p 5432:5432 postgres:15

# Redis
docker run -d --name helios-redis -p 6379:6379 redis:7

# Neo4j (optional — system falls back to DB heuristics without it)
docker run -d --name helios-neo4j \
  -e NEO4J_AUTH=neo4j/sentinel_dev_password \
  -p 7687:7687 -p 7474:7474 neo4j:5-community
```

### 3. Backend

```bash
cd backend
pip install -r requirements.txt

# Run DB migrations (auto-runs on startup via main.py lifespan)
uvicorn backend.main:app --reload --port 8000
# → API available at http://localhost:8000
# → Swagger docs at http://localhost:8000/docs
```

### 4. Frontend

```bash
cd frontend
npm install --legacy-peer-deps

NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
# → UI available at http://localhost:3000
```

### 5. Create a test org locally

```bash
# Use the new CLI script (works against local or prod)
HELIOS_API_URL=http://localhost:8000 \
HELIOS_ADMIN_KEY=your-local-admin-key \
./scripts/new_org.sh "Test Corp" testcorp.com admin@testcorp.com "Test Admin" Launch
# Returns: org_id, temp_password, login_url
```

### 6. Deploy to production

```bash
# Both frontend + backend (ARM64, ECS, CloudFront invalidation)
./deploy.sh both

# Backend only
./deploy.sh backend

# Frontend only
./deploy.sh frontend
```

The deploy script:
1. Builds Docker image (`linux/arm64` for Fargate Graviton)
2. Pushes to ECR
3. Registers new ECS task definition
4. Forces ECS service redeployment
5. Runs 21-check production readiness test suite
6. Invalidates CloudFront cache (frontend only)

### 7. Production access

```
Production URL:    https://app.himaya.ai
Admin login:       adnan@himaya.ai / <set VENDOR_ADMIN_PASSWORD env var>
Admin API key:     <set VENDOR_ADMIN_API_KEY env var> (X-Admin-API-Key header)
Neo4j:             bolt://10.0.3.166:7687 (VPC private, use SSH tunnel or /api/admin/neo4j/* endpoints)
```

---

## Background Workers (always-on in ECS)

These run automatically on ECS startup and restore on restart:

| Worker | Interval | Description |
|---|---|---|
| **Delta Sync** | 1 min | Polls Gmail + M365 for new emails, runs full pipeline |
| **Auto-Triage Loop** | ~90s | Investigates unresolved threats, applies verdicts |
| **Threat Feed Refresh** | 1h | URLhaus, OpenPhish, IPsum, Feodo, CINS, Spamhaus DROP |
| **OpenDBL Refresh** | 6h | Emerging Threats, Tor exits, Brute Force, Blocklist.de |
| **M365 Token Refresh** | 45 min | Proactive OAuth token refresh to avoid mid-request expiry |
| **Compliance Worker** | On-demand | Auto-assesses SAMA/NCA compliance controls |
| **Daily Digest** | 08:00 UTC | Per-org summary email to admins |
| **Weekly Digest** | Monday 08:00 UTC | Weekly threat summary |
| **15-day Rebaseline** | Every 15d | Re-ingests 90-day email history for new orgs |
| **ANVA Feed** | 24h | Saudi CERT threat intelligence feed |

---

## AI Agents — System Prompt Reference

### 1. Content Classifier
**File:** `models/content_classifier/prompts.py`  
**Model:** Claude Opus (primary) → GPT-4o (fallback)  
**Trigger:** Every email ingested via delta sync  
**Input:** sender, recipient, subject, body (capped 4000 chars), attachments, SPF/DKIM/DMARC headers  
**Output:** `classification` (PHISHING/BEC/MALWARE/SPAM/SAFE/UNCERTAIN), `confidence` (0–1), `threat_indicators[]`, `signals[]`  
**Language:** Arabic/English bilingual prompt optimized for Gulf region context

### 2. Helios Analysis (Auto-Triage)
**File:** `backend/services/auto_triage_service.py` → `HELIOS_ANALYSIS_SYSTEM_PROMPT`  
**Model:** Claude Opus  
**Trigger:** Auto-triage loop picks up unresolved threats (~90s cycle)  
**Input:** Full threat dossier — VT domain/URL results, threat feed matches, Neo4j graph history, attachment findings, EC2 sandbox verdict, sender auth results, content classifier output  
**Output:** JSON `{verdict, threat_type, confidence, reasoning, key_evidence[], notify_recipient, notify_admin}`  
**Verdict options:** `QUARANTINE` | `DISMISS` | `ESCALATE` | `MARK_AS_SPAM`

### 3. Sandbox Analyzer
**File:** `backend/routers/sandbox.py` → `SANDBOX_PROMPT`  
**Model:** Claude Opus  
**Trigger:** On-demand sandbox session or auto-detonation background task  
**Input:** URL detonation results (redirect chains, page title, login form detection, screenshots), attachment oletools output  
**Output:** Human-readable threat verdict + risk assessment

---

## Integrations

### Google Workspace
- OAuth2 + Service Account (DWD — Domain-Wide Delegation)
- Gmail API: read, modify, label, move emails, quarantine
- Directory API: sync users, groups, aliases
- Delta sync every 1 minute per org

### Microsoft 365
- OAuth2 (delegated + application permissions)
- Mail API: read, move to quarantine/junk/inbox, folder management
- Directory API: sync users, groups
- Outlook Add-in: manifest served dynamically at `/api/phish-report/manifest.xml?key=<KEY>`

---

## New Customer Onboarding

### Via CLI (recommended)

```bash
# From the repo root on any machine with curl + python3
./scripts/new_org.sh "Acme Corp" acme.com admin@acme.com "John Smith" Enterprise
# Returns org_id, temp_password, login URL
# Sends SES activation email automatically

# Or set custom API target
HELIOS_API_URL=http://localhost:8000 \
HELIOS_ADMIN_KEY=my-local-key \
./scripts/new_org.sh "Local Test" local.com test@local.com "Test" Launch
```

### Via API

```bash
curl -X POST https://app.himaya.ai/api/admin/setup/new-org \
  -H "X-Admin-API-Key: $HELIOS_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "domain": "acme.com",
    "contact_email": "admin@acme.com",
    "contact_name": "John Smith",
    "tier": "Enterprise",
    "send_activation": true
  }'
```

**Org Tiers:** `Launch` (default) | `Enterprise`. Set on org creation, used for feature gating.

---

## Outlook Add-in Deployment

The manifest is served dynamically with your org's UUID and phish key pre-baked:

```
https://app.himaya.ai/api/phish-report/manifest.xml?key=<YOUR_PHISH_KEY>
```

**To deploy to a customer's M365:**
1. Go to [Microsoft 365 Admin Center](https://admin.microsoft.com) → Settings → Integrated apps
2. Click **Upload custom app** → **"Provide link to manifest file"**
3. Paste the manifest URL above
4. Deploy org-wide

**Behavior on report:**
- Email immediately quarantined in mailbox
- Auto-triage runs full investigation
- If verdict = DISMISS → email automatically reinjected to inbox
- If verdict = QUARANTINE → stays in quarantine, recipient notified

---

## API Reference

Interactive docs: [app.himaya.ai/docs](https://app.himaya.ai/docs)

| Endpoint | Auth | Description |
|---|---|---|
| `POST /api/auth/login` | — | JWT login |
| `GET /api/auth/me` | JWT | Current user + org info (includes `tier`) |
| `GET /api/threats` | JWT | List threats for org |
| `GET /api/threats/{id}` | JWT | Threat detail + dossier |
| `POST /api/threats/auto-triage` | JWT | Trigger auto-triage run now |
| `GET /api/threats/auto-triage/audit` | JWT | Full audit trail with sandbox verdicts |
| `POST /api/quarantine/{id}/report-fp` | JWT | Mark as false positive (retracts Neo4j edge) |
| `POST /api/quarantine/{id}/block-permanently` | JWT | Block sender (writes Neo4j edge) |
| `POST /api/phish-report/submit` | Phish Key | Employee report submission |
| `GET /api/phish-report/manifest.xml?key=` | Phish Key | Outlook add-in manifest |
| `POST /api/admin/setup/new-org` | Admin Key | Provision new customer org |
| `POST /api/admin/neo4j/install-step/graph-stats` | Admin Key | Run Cypher queries via SSH |
| `POST /api/admin/orgs/{id}/inject-inbox-threats` | Admin Key | Inject test phishing emails |

---

## Team & Agents

| Agent | Role |
|---|---|
| **Pikachu** (OpenClaw) | Primary engineering agent — architecture, backend, frontend, DevOps |
| **Claude Opus** | Runtime AI engine — Content Classifier, Helios Analysis, Sandbox Analyzer |
| **Claude Sonnet** | Development assistance, code review |

---

## Security Notes

- All phish report submissions are keyed (no unauthenticated ingestion)
- EC2 sandbox instances use outbound-only security groups, terminated immediately after analysis
- Sandbox results stored in S3 + Postgres — not just ephemeral Redis
- JWT secrets and API keys managed via ECS task definition environment variables
- Multi-tenant isolation enforced at every query layer (all queries scoped to `org_id`)
- Reports scoped to `current_user.org_id` — cross-tenant access impossible
- Neo4j intelligence is global (cross-org sender reputation) — not tenant-isolated by design

---

*Helios — Himaya Technologies © 2026*

---

## SaaS Security / DSPM

Helios includes a full Data Security Posture Management (DSPM) module for Microsoft 365 (Teams + SharePoint).

### Architecture
- **Content Classification**: DeepSeek engine (`DEEPSEEK_ENDPOINT`) classifies all scanned files/messages → labels: Public / Internal / Confidential / Highly Confidential
- **Alert Generation**: High/Critical findings create SaasAlerts + feed into the Threat Queue as `SAAS_DATA_LEAK` threat type
- **Posture Evaluation**: 53 checks across Identity, Access Control, Data Protection, Teams Security, Compliance, Endpoint (runs every 6h, or on-demand)
- **Admin Notifications**: High/Critical alerts trigger branded HTML email to org admins via SMTP
- **Delta Scanning**: Worker tracks `last_synced_at` per integration — only re-classifies files modified since last scan

### Required Environment Variables
| Variable | Description |
|---|---|
| `SAAS_M365_CLIENT_ID` | Azure AD app registration client ID |
| `SAAS_M365_CLIENT_SECRET` | Azure AD app registration client secret |
| `DEEPSEEK_ENDPOINT` | DeepSeek classification engine URL (e.g. http://10.0.1.113:8001) |
| `SMTP_HOST` | SMTP server hostname for alert emails |
| `SMTP_PORT` | SMTP port (default: 587) |
| `SMTP_USER` | SMTP auth username |
| `SMTP_PASS` | SMTP auth password |
| `ALERT_FROM_EMAIL` | From address for alert emails (default: alerts@himaya.ai) |

### Azure AD App Permissions Required
The Azure AD app registration needs these **Application permissions** (not delegated):
- `Team.ReadBasic.All` — List Teams
- `ChannelMessage.Read.All` — Read Teams messages
- `Files.Read.All` — Read SharePoint/OneDrive files
- `Sites.Read.All` — List SharePoint sites
- `AuditLog.Read.All` — Read audit logs
- `Policy.Read.All` — Read CA and auth policies
- `Directory.Read.All` — Read directory (users, groups, roles)
- `User.Read.All` — Read user profiles and properties
- `IdentityRiskyUser.Read.All` — Read Identity Protection risky users
- `DeviceManagementConfiguration.Read.All` — Read Intune policies
- `IdentityRiskySignIn.Read.All` — Read risky sign-ins
- `RoleManagement.Read.Directory` — Read role assignments

Grant admin consent for all permissions in the Azure portal.

### Redirect URI
Register: `https://app.himaya.ai/api/saas/callback`

---

## DLP (Data Loss Prevention)

Helios includes a DLP module that classifies and controls sensitive data in outbound emails.

### Features
- **AI Classification**: DeepSeek + regex patterns detect PII, financial data, credentials, ITAR, bulk exfiltration
- **Policy Actions**: ALLOW, WARN, HOLD (queue for review), BLOCK
- **M365 Transport Rule Sync**: Push DLP policies to Exchange Online as transport rules
- **Google Workspace Sync**: Push DLP policies to Gmail as Content Compliance rules

### Endpoints
| Endpoint | Description |
|---|---|
| `GET /api/dlp/policies` | List DLP policies |
| `POST /api/dlp/policies` | Create DLP policy |
| `POST /api/dlp/policies/{id}/sync-m365` | Sync policy to M365 transport rule |
| `POST /api/dlp/policies/{id}/sync-gsuite` | Sync policy to Google Workspace |
| `GET /api/dlp/queue` | Emails held for DLP review |
| `POST /api/dlp/queue/{id}/release` | Release held email |
| `POST /api/dlp/queue/{id}/block` | Block held email |

---

## SaaS Security Threat Detection

Behavioral threat detection beyond file classification:

| Threat Type | Detection Method |
|---|---|
| **Impossible Travel** | Sign-in from different countries within 2 hours |
| **Mass Download** | 10+ file downloads in short timeframe |
| **External Forwarding** | Inbox rules forwarding to external domains |
| **Permission Escalation** | Guest user granted broad org permissions |
| **Risky OAuth Apps** | Third-party apps with excessive permissions |
| **Suspicious Sharing** | Confidential files shared externally |

### Shadow IT Discovery
Scans OAuth app registrations from Graph API:
- Tracks app permissions, publisher, user count
- Risk scoring based on permission scope
- Admin can sanction/unsanction apps

### Entra ID Risk Signals
Imports risky users from Identity Protection:
- Creates alerts for high/medium risk users
- Tracks risk state and detail

### Privileged User Monitoring
Tracks admin actions from audit logs:
- Role changes (add/remove admin)
- Policy modifications
- Conditional Access changes
- Alerts on sensitive operations

### Conditional Access Audit
Evaluates CA policies for gaps:
- MFA enforcement for admins
- Device compliance requirements
- Legacy authentication blocking
- Named locations configured

### Endpoints
| Endpoint | Description |
|---|---|
| `GET /api/saas-security/risk-heatmap` | Aggregated risk by user/file/severity |
| `GET /api/saas-security/data-flows` | Sharing patterns (internal → external) |
| `GET /api/saas-security/oauth-apps` | Discovered OAuth apps |
| `PATCH /api/saas-security/oauth-apps/{id}/status` | Sanction/unsanction app |
| `GET /api/saas-security/risky-users` | Entra ID risky users |
| `GET /api/saas-security/admin-actions` | Admin action log |

---

## Database Schema (New Tables)

```sql
-- DLP sync tracking
ALTER TABLE dlp_policies ADD COLUMN m365_rule_id TEXT;
ALTER TABLE dlp_policies ADD COLUMN last_synced_at TIMESTAMPTZ;
ALTER TABLE dlp_policies ADD COLUMN sync_status TEXT DEFAULT 'not_synced';
ALTER TABLE dlp_policies ADD COLUMN gsuite_rule_id TEXT;
ALTER TABLE dlp_policies ADD COLUMN gsuite_last_synced_at TIMESTAMPTZ;
ALTER TABLE dlp_policies ADD COLUMN gsuite_sync_status TEXT DEFAULT 'not_synced';

-- User locations (impossible travel)
CREATE TABLE saas_user_locations (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    user_email TEXT NOT NULL,
    ip_address TEXT,
    city TEXT,
    country TEXT,
    latitude REAL,
    longitude REAL,
    provider TEXT NOT NULL,
    event_type TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- OAuth apps (shadow IT)
CREATE TABLE saas_oauth_apps (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    app_name TEXT NOT NULL,
    app_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    publisher TEXT,
    permissions JSONB,
    status TEXT DEFAULT 'unknown',
    risk_score REAL DEFAULT 0.5,
    user_count INT DEFAULT 0,
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    UNIQUE(org_id, app_id, provider)
);

-- Admin actions (privileged monitoring)
CREATE TABLE saas_admin_actions (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    admin_email TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    target_name TEXT,
    details JSONB,
    provider TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Risky users (Entra ID)
CREATE TABLE saas_risky_users (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    user_email TEXT NOT NULL,
    user_id TEXT,
    risk_level TEXT NOT NULL,
    risk_state TEXT,
    risk_detail TEXT,
    risk_last_updated_at TIMESTAMPTZ,
    provider TEXT DEFAULT 'microsoft',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, user_email, provider)
);
```

All tables are indexed on `org_id` for tenant isolation.

---

*Helios — Himaya Technologies © 2026*
