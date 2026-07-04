# Helios — Pitch Deck Content
**Himaya Technologies | 2026**

---

## Slide 1 — Cover

**HELIOS**  
*AI-Powered Email Security. Zero Manual Triage.*

Himaya Technologies  
app.himaya.ai

---

## Slide 2 — The Problem

### Email is Still the #1 Attack Vector

- **94%** of malware is delivered via email (Verizon DBIR)
- **$17,700** lost per minute during a phishing attack (Ponemon)
- The average breach goes **undetected for 197 days**

### The SOC Is Drowning

A 500-person company receives **50–200 phishing reports per week**.

Each one requires an analyst to:
- Review headers, sender, links, attachments manually
- Query VirusTotal, threat feeds, internal history
- Make a judgment call: quarantine, dismiss, or escalate
- Move the email, notify the user, log the action

**That's 15–30 minutes per report. 25–100 hours of analyst time per week. On one threat vector.**

Security teams can't hire fast enough. Tools don't talk to each other. Threats slip through.

---

## Slide 3 — The Solution

### Helios: Fully Automated Email Threat Investigation

Helios sits on top of Google Workspace and Microsoft 365.  
Employees click **"Report Phishing."** Helios handles everything else.

**From report to verdict in under 3 minutes — automatically.**

No manual review. No ticket queue. No analyst bottleneck.

---

## Slide 4 — How It Works

### The 8-Stage Auto-Triage Pipeline

```
Employee clicks "Report Phishing"
            ↓
① VirusTotal          → URL/domain reputation
② Threat Feeds        → Known malicious infrastructure
③ Graph Intelligence  → Sender history + org behavior baseline
④ Attachment Analysis → File heuristics, macro detection
⑤ EC2 Sandbox         → Live detonation in isolated VM
⑥ Helios AI (Claude)  → Synthesizes all signals → verdict + dossier
⑦ Automated Action    → Quarantine / Dismiss / Escalate / Spam
⑧ Email Moved         → Physical move in Gmail or Outlook mailbox
```

**Every step is logged. Every verdict is explainable. Every action is auditable.**

---

## Slide 5 — The Technology

### What Makes Helios Different

**EC2 Sandbox Detonation**  
Every suspicious email with URLs or attachments is detonated in an ephemeral cloud VM. We curl the links, run oletools on Office files, and get a MALICIOUS/CLEAN verdict before any human touches it.

**Neo4j Threat Graph**  
We build a graph of every sender, domain, and relationship across your org. Lookalike domains, unusual send patterns, first-contact senders — all surfaced automatically.

**Claude AI Dossier**  
Every threat gets a human-readable AI investigation report. Not just a score — a full explanation of why we flagged it, what we found, and what action we took.

**Native Email Integration**  
We physically move emails in your real mailbox via Gmail and Outlook APIs. No forwarding. No copies. The actual email goes where we say it goes — and comes back if it's clean.

---

## Slide 6 — Product

### What Admins Get

| Feature | Description |
|---|---|
| **Threat Dashboard** | Real-time feed of all threats, verdicts, and AI dossiers |
| **Auto-Triage** | Fully automated investigation pipeline, runs every 2 minutes |
| **Policy Engine** | Rule-based + AI risk scoring, custom actions per policy |
| **Threat Graph** | Neo4j-powered sender relationship visualization |
| **People Directory** | Synced from Google/M365 — users, groups, aliases |
| **Message Trace** | Full email metadata history per user |
| **Compliance Reports** | Downloadable PDF reports, tenant-isolated |
| **24h Rollup** | Daily email summary to all org admins |

### What Employees Get

- Gmail Add-on (Google Workspace Marketplace)
- Outlook Add-in (M365 admin-deployed)
- One-click "Report Phishing" button in their inbox
- Confirmation when their report is investigated

---

## Slide 7 — Architecture (Technical Slide)

### Built for Enterprise Scale

**Stack:**
- FastAPI (Python 3.12) — async, high-throughput backend
- Next.js 16 — modern React frontend
- PostgreSQL (RDS) — multi-tenant, fully isolated per org
- Neo4j — graph intelligence
- Redis — caching and retrain queue
- AWS ECS Fargate — containerized, auto-scaling
- CloudFront CDN — global edge delivery
- EC2 — ephemeral sandbox VMs (spun up and destroyed per threat)
- S3 — evidence and artifact storage
- SES — transactional email

**AI Models:**
- Claude Opus — threat investigation and verdict synthesis
- LLM Content Classifier — Claude Opus (primary) with GPT-4o fallback, in-process classification before auto-triage
- Feedback loop — employee reports feed a retraining pipeline (SageMaker-ready) that improves verdicts over time

**Security:**
- Org-scoped queries throughout — multi-tenant isolation enforced at every layer
- Phish keys for add-on authentication (rotatable per org)
- EC2 sandboxes use outbound-only security groups
- JWT + OTP for admin access

---

## Slide 8 — Traction

### Built and Deployed

- ✅ **Production live** at `app.himaya.ai`
- ✅ **Full auto-triage pipeline** operational
- ✅ **EC2 sandbox detonation** tested and confirmed
- ✅ **Gmail Add-on** deployed
- ✅ **Outlook Add-in** deployed (M365 manifest validated)
- ✅ **Multi-tenant** architecture — ready for multiple orgs
- ✅ **Policy engine** — 30+ active policies
- ✅ **Compliance reports** — PDF export live
- ✅ AI-augmented development — shipped in weeks, not months

---

## Slide 9 — Market Opportunity

### The Email Security Market

- **$4.2B** global email security market in 2024
- Growing at **11.5% CAGR** through 2030
- **SMB and mid-market severely underserved** — most solutions built for enterprise
- **Average cost of phishing attack:** $4.76M per incident (IBM Cost of Data Breach 2024)
- Every company with email has this problem. Most have no automated response.

### Our Target

**Primary:** SMBs and mid-market (50–2,000 employees) using Google Workspace or Microsoft 365  
**Secondary:** MSPs managing email security for multiple client orgs  

**Why now:** AI makes automated investigation possible at a price point SMBs can afford. Legacy tools (Proofpoint, Mimecast) cost $30–60/user/year and require dedicated security staff to operate. Helios doesn't.

---

## Slide 10 — Business Model

### SaaS, Per-Mailbox Pricing

| Tier | Price | Includes |
|---|---|---|
| **Starter** | $5/mailbox/month | Auto-triage, phish reporting, basic dashboard |
| **Professional** | $10/mailbox/month | + Policy engine, compliance reports, graph intel |
| **Enterprise** | Custom | + SSO, custom integrations, SLA, dedicated support |

**Unit economics (500-mailbox org, Professional tier):**
- MRR: $5,000
- ARR: $60,000
- Infrastructure cost: ~$800/month
- Gross margin: ~84%

**For MSPs:** Multi-tenant architecture ready. White-label option available.

---

## Slide 11 — Why Helios Wins

| | Proofpoint / Mimecast | SEGs (Secure Email Gateways) | **Helios** |
|---|---|---|---|
| Auto-investigation | ❌ Manual analyst | ❌ Block/allow only | ✅ Fully automated |
| Sandbox detonation | ✅ Enterprise only | ❌ | ✅ All tiers |
| Native email integration | Partial | Gateway only | ✅ Direct API |
| AI dossier / explainability | ❌ | ❌ | ✅ |
| Price for 500 users | $15–30k/yr | $10–25k/yr | **$30k/yr** |
| Setup complexity | High (weeks) | High (DNS changes) | Low (OAuth, 10 min) |
| Works with existing mail | Requires MX change | Requires MX change | ✅ No MX changes |

**No DNS changes. No MX record edits. Connect via OAuth in 10 minutes.**

---

## Slide 12 — Team

**Adnan Ahmed** — Founder, Himaya Technologies  
Building enterprise security tooling for SMBs and mid-market.

**AI Development Stack:**  
- Pikachu (OpenClaw agent) — primary engineering
- Claude Opus — runtime AI investigation engine
- Claude Sonnet — development assistance

*Helios was architected, built, and deployed to production using an AI-augmented development workflow — demonstrating the future of software development itself.*

---

## Slide 13 — Ask

### What We're Looking For

**Seeking:** [Seed / Series A / Strategic Partner]  
**Use of funds:**
- GTM: Sales and customer success
- Engineering: Mobile app, deeper SIEM integrations
- Compliance: SOC 2 Type II, ISO 27001
- Infrastructure: Multi-region deployment

**Contact:** adnan@himaya.ai  
**Demo:** app.himaya.ai  
**Docs:** app.himaya.ai/docs

---

## Appendix — Technical Details

### EC2 Sandbox Deep Dive

Every threat with URLs or attachments triggers:
1. `t3.micro` Amazon Linux 2023 instance launched in `uaenorth`
2. Outbound-only security group — no inbound attack surface
3. IAM instance profile with minimal permissions (`helios-sandbox-role`)
4. UserData script: curls URLs, runs `oletools` on Office attachments
5. Results written to `/tmp/sandbox_results.json`, uploaded to S3
6. Instance self-terminates (`shutdown -h now`)
7. Backend polls every 10s (max 180s timeout)
8. Verdict fed into Helios AI dossier

### Graph Intelligence

Neo4j stores:
- Every sender seen across all tenants (anonymized cross-tenant signals)
- Domain relationships (registrar, IP, MX, lookalike distance)
- Per-org behavior baseline (normal send patterns, first-contact senders)
- Employee report history as positive/negative training signal
- Retrain queue in Redis → periodic model update

### Multi-Tenant Isolation

Every database query is scoped to `current_user.org_id`:
- Threats table: `WHERE org_id = ?`
- People/directory: `WHERE org_id = ?`
- Policies: `WHERE org_id = ?`
- Reports: `WHERE org_id = ?`
- Phish report keys: unique per org, rotatable

Cross-tenant data access is architecturally impossible.

---

*Helios — Himaya Technologies © 2026 | app.himaya.ai*
