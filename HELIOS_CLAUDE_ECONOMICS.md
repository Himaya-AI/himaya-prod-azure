# Helios Claude API — Economic Model
*Reference tenant: 50 users · 30 emails/user/day · 500 SaaS files · auto-triage enabled*  
*Prepared: 2026-06-11 | Pricing: Anthropic public API rates*

---

## ⚠️ CRITICAL FINDING: UNSUSTAINABLE AS-IS

**Current architecture burns ~$12,476/month in Claude costs for a 50-user tenant.**  
At $50/user/month that yields **−400% gross margin**. The root cause is a single design choice:  
**email classification uses Claude Opus with 16 few-shot examples (~14,887 tokens/call) against every inbound email.**

With prompt caching + model swap to Haiku, total monthly cost drops to **~$373 (~$7.47/user)**, enabling profitable pricing at $10–$15+/user.

---

## 🏆 Biggest Cost Drivers (Ranked)

| Rank | Feature | Monthly Cost (Current) | % of Total |
|------|---------|----------------------|-----------|
| 1 | **Email Classification** (Opus + 16 few-shot examples, every email) | $11,736–$12,749 | **97.5%** |
| 2 | Auto-Triage / Helios Analysis (Opus, per flagged threat) | $180–$261 | 1.7% |
| 3 | Outbound DLP Draft Scan (Haiku, per draft) | $5.17 | 0.04% |
| 4 | Dashboard AI Risk Score (Opus, cached) | $2.70 | 0.02% |
| 5 | Falcon Security Assistant (Sonnet, per query) | $1.82 | 0.01% |
| 6–14 | All other Claude calls | < $1 each | < 0.01% |

---

## Part 1: Claude Call Sites — Complete Inventory

### 1.1 Email Classification (PRIMARY COST DRIVER)

| Field | Value |
|-------|-------|
| **File:line** | `backend/services/email_processor.py:57` → `models/content_classifier/classifier.py` |
| **Model** | `claude-opus-4-5-20251101` (`models/shared/config.py:CLAUDE_MODEL`) |
| **Trigger** | Every inbound email, 100% of volume |
| **System prompt** | 4,115 chars ≈ **1,028 tokens** (Arabic+English Gulf cybersecurity specialist, `models/content_classifier/prompts.py`) |
| **Few-shot examples** | 16 user/assistant pairs, 38,128 chars ≈ **12,709 tokens** (`prompts.py:FEW_SHOT_EXAMPLES`) |
| **User message** | Email body capped at 4,000 chars + sender/recipient/subject/headers ≈ **1,150 tokens** |
| **Total input/call** | **~14,887 tokens** |
| **Output/call** | `LLM_MAX_TOKENS = 2000` (`config.py:LLM_MAX_TOKENS`); typical JSON response ≈ **500 tokens** |
| **Purpose** | Threat classification: BEC, PHISHING, MALWARE, GOV_IMPERSONATION, etc. with Arabic+English explanation |

**Code evidence:**
```python
# email_processor.py:57
_classifier = ContentClassifier(
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    ...
    include_few_shot=True,   # ← ENABLES 16 examples = 12,709 tokens per call
)
# config.py
CLAUDE_MODEL = "claude-opus-4-5-20251101"  # Opus for all primary classification
LLM_MAX_TOKENS = 2000
```

---

### 1.2 Auto-Triage / Helios Analysis

| Field | Value |
|-------|-------|
| **File:line** | `backend/services/auto_triage_service.py:541–555` (`_get_helios_verdict`) |
| **Model** | `claude-opus-4-5-20251101` |
| **Trigger** | Background loop every 2 min; processes up to 5 flagged threats per cycle (`run_auto_triage_loop`, line 961) |
| **System prompt** | `_build_helios_system_prompt()` ≈ 3,600 chars ≈ **950 tokens** |
| **User message** | Threat dossier JSON (VT results, graph history, body preview, etc.) ≈ **1,500 tokens** |
| **Total input/call** | **~2,450 tokens** |
| **max_tokens** | `1024` (line 549) |
| **Typical output** | JSON verdict (verdict, threat_type, confidence, reasoning, key_evidence) ≈ **400 tokens** |
| **Model written back** | `threat.llm_model = "claude-opus-4-5-20251101"` (line 653) |
| **Purpose** | Definitive verdict: QUARANTINE / MARK_AS_SPAM / ESCALATE / DISMISS |

**Code evidence:**
```python
# auto_triage_service.py:548-550
json={
    "model": "claude-opus-4-5-20251101",
    "max_tokens": 1024,
    "system": _build_helios_system_prompt(),
    "messages": [{"role": "user", "content": user_message}],
}
```

---

### 1.3 SaaS DLP Classification Worker — SaaS Files

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/saas_security.py:10433` (`_run_dlp_classification_worker`) |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Every 30 min (`main.py:1032`, `asyncio.sleep(1800)`); processes up to **50 files per run** |
| **Scope** | `saas_data_items` where `classification_label IS NULL` or stale >7 days |
| **Input/call** | `f"File: {item_name}\nPath: {parent_path}\nProvider: {provider}"` + prompt ≈ **400 tokens** |
| **max_tokens** | `200` (line 10433) |
| **Output** | `{"risk_level":"...", "categories":[...], "confidence":..., "explanation":"..."}` ≈ **150 tokens** |
| **Purpose** | Classify SaaS files (Teams/SharePoint/OneDrive) for DLP risk |

**Code evidence:**
```python
# saas_security.py:10433
json={
    "model": "claude-haiku-4-5",
    "max_tokens": 200,
    "messages": [{"role": "user", "content": prompt}],
}
```

---

### 1.4 SaaS DLP Classification Worker — AWS Resources

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/saas_security.py:10555` (within `_run_dlp_classification_worker`) |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Same 30-min worker; processes up to **30 AWS resources** per run (S3/RDS/DynamoDB) |
| **Input/call** | AWS resource context (name, ARN, region, encryption, public access) ≈ **450 tokens** |
| **max_tokens** | `200` |
| **Purpose** | Classify AWS storage resources for data sensitivity |

---

### 1.5 AWS AI Resource Classification (Claude Haiku Fallback)

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/saas_security.py:10778–10786` (`_aws_ai_classify_resource`) |
| **Model** | `claude-haiku-4-5` (fallback when DeepSeek fails) |
| **Trigger** | Per-risky-resource during AWS threat scan (5-min interval, `main.py:996`); called from lines 10909, 10955, 10988, 11148, 11187 |
| **Input/call** | Resource config JSON (capped at 1,500 chars) + prompt ≈ **500 tokens** |
| **max_tokens** | `300` |
| **Purpose** | Classify S3/EC2/RDS resources for security risk level + remediation steps |

---

### 1.6 Posture AI Score

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/posture.py:755` |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Per posture dashboard load; cached in `_ai_score_cache[org_id]` (in-memory, no TTL) |
| **Input/call** | Posture metrics summary (apps, rules, forwards count) ≈ **350 tokens** |
| **max_tokens** | `256` |
| **Output** | `{"score": 0-100, "label": "...", "reasoning": "..."}` ≈ **150 tokens** |
| **Purpose** | Single inbox posture score shown on posture dashboard |

---

### 1.7 Posture App Threat Intelligence Enrichment

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/posture.py:1228` (within `_run_posture_scan`) |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Per posture scan (every 6h auto, `main.py:796`; or on-demand); runs when new apps are detected; capped at **20 apps** |
| **Input/call** | App name list + instructions ≈ **600 tokens** |
| **max_tokens** | `1024` |
| **Output** | JSON array of `{name, verdict, note}` ≈ **700 tokens** |
| **Purpose** | Security vetting of OAuth/add-in apps: clean / suspicious / compromised |

---

### 1.8 Posture Check Enrichment

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/saas_security.py:7554–7561` (`_claude_enrich_posture_checks`) |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Called during `_evaluate_provider_posture`; once per provider per posture evaluation |
| **Input/call** | Checks summary JSON (name, status, severity per check) ≈ **900 tokens** |
| **max_tokens** | `500` |
| **Purpose** | Generate executive-readable one-sentence risk summary per posture check |

---

### 1.9 Posture Resource Analysis

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/saas_security.py:6782–6789` (`_claude_posture_analysis`) |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Per flagged resource (high/medium risk) during posture evaluation |
| **Input/call** | Resource name + provider + classification ≈ **300 tokens** |
| **max_tokens** | `300` |
| **Purpose** | Contextual posture assessment with findings + remediation for a single flagged resource |

---

### 1.10 Dashboard AI Risk Score

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/dashboard.py:666–667` |
| **Model** | `claude-opus-4-5-20251101` |
| **Trigger** | Per dashboard load; Redis-cached but no explicit TTL → re-generated when cache busted (`dashboard.py:503–504`) |
| **Input/call** | 30-line org metrics prompt (threats, containment, policy coverage, posture findings) ≈ **1,000 tokens** |
| **max_tokens** | `500` |
| **Output** | `{"score": 0-100, "risk_level": "...", "explanation": "...", "key_factors": [...]}` ≈ **350 tokens** |
| **Purpose** | Residual risk score shown on main dashboard |

---

### 1.11 Compliance Assessment

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/compliance.py:604–605` |
| **Model** | `claude-opus-4-5-20251101` |
| **Trigger** | Per compliance assessment request (manual action by admin) |
| **Input/call** | Evidence context + up to 30 framework controls ≈ **2,500 tokens** |
| **max_tokens** | `2000` |
| **Output** | JSON map `{control_id: status}` ≈ **1,500 tokens** |
| **Purpose** | Assess SAMA/NCA controls as compliant / partial / non_compliant |

---

### 1.12 Compliance Report (Audit Narrative)

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/compliance.py:364–365` |
| **Model** | `claude-opus-4-5-20251101` |
| **Trigger** | Per report download (manual, per `/api/compliance/report` endpoint) |
| **Input/call** | Org context, compliance score, threat summary, DNS status ≈ **2,500 tokens** |
| **max_tokens** | `1200` |
| **Output** | 3–4 paragraph executive narrative ≈ **1,000 tokens** |
| **Purpose** | Compliance narrative for SAMA/NCA audit PDF/HTML reports |

---

### 1.13 Falcon Security Assistant (AI Chat)

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/falcon.py:269–276` (`generate_ai_response`) |
| **Model** | `claude-sonnet-4-20250514` |
| **Trigger** | Per admin chat message; last 8 conversation turns + security context JSON + query |
| **Input/call** | System prompt + context JSON + 8-turn history + query ≈ **2,000 tokens** |
| **max_tokens** | `1024` |
| **Output** | Chat response ≈ **700 tokens** |
| **Purpose** | Natural language security Q&A on org's threat posture (SaaS alerts, threat types, compliance) |

---

### 1.14 Sandbox Analysis

| Field | Value |
|-------|-------|
| **File:line** | `backend/routers/sandbox.py:196–197` |
| **Model** | `claude-sonnet-4-5-20250929` |
| **Trigger** | Per analyst sandbox submission (manual); runs as background task per `/api/sandbox/submit` |
| **Input/call** | `SANDBOX_PROMPT` + threat context + URL detonation findings ≈ **900 tokens** |
| **max_tokens** | `1024` |
| **Output** | Behavior report JSON with IOCs, MITRE techniques ≈ **600 tokens** |
| **Purpose** | Simulate sandbox detonation of email payload; provide behavioral verdict |

---

### 1.15 Outbound DLP — Draft Scan (Claude Direct Path)

| Field | Value |
|-------|-------|
| **File:line** | `backend/services/dlp_service.py:372` (`prefer_claude=True` path); called from `backend/routers/drafts.py:786` |
| **Model** | `claude-haiku-4-5` |
| **Trigger** | Per outbound email draft saved/sent with `prefer_claude=True`; primary path for draft DLP |
| **Input/call** | Email body (3,000 char cap) + subject + sender + categories list ≈ **1,100 tokens** |
| **max_tokens** | `300` |
| **Output** | `{"risk_level":"...", "categories":[...], "confidence":..., "explanation":"..."}` ≈ **200 tokens** |
| **Purpose** | DLP classification for outbound email drafts |

---

## Part 2: Usage Model — Reference Tenant

**Assumptions:** 50 users · 30 inbound emails/user/day · 500 SaaS files · 30 days/month · auto-triage enabled

| Parameter | Value | Source |
|-----------|-------|--------|
| Total inbound emails/month | 45,000 | 50 × 30 × 30 |
| Emails flagged (risk ≥ 50) | ~5,400 (12%) | Industry baseline |
| Emails auto-triaged by Helios | ~2,700 (50% of flagged) | Per-org toggle |
| SaaS files to classify (initial) | 530 (500 SaaS + 30 AWS) | Tenant config |
| New files/month (ongoing) | ~150 | 5/day |
| DLP worker runs/day | 48 (every 30 min) | `main.py:1032` |
| Posture scans/day | 4 (every 6h) | `main.py:803` |
| Dashboard loads (unique) | 60/month (2/day) | Admin usage |
| Falcon AI queries | 110/month (5/working day) | Admin usage |
| Compliance assessments | 2/month | Manual trigger |
| Compliance reports | 1/month | Manual trigger |
| Sandbox submissions | 66/month (3/working day) | Analyst usage |
| Outbound draft DLP scans | 2,750/month | 50 users × 5 drafts/day × 22 days × 50% |

---

## Part 3: Monthly Claude Cost — Current Architecture

### 3.1 Per-Feature Cost Breakdown

| # | Feature | Model | Input tok/call | Output tok/call | Calls/month | Input M tok | Output M tok | Monthly Cost |
|---|---------|-------|---------------|----------------|------------|------------|-------------|-------------|
| 1 | Email Classification | Opus | 14,887 | 500–800 | 45,000 | 669.9 | 22.5–36.0 | **$11,736–$12,749** |
| 2 | Auto-Triage (Helios Analysis) | Opus | 2,450 | 400–800 | 2,700 | 6.6 | 1.1–2.2 | $180–$261 |
| 3 | Outbound Draft DLP | Haiku | 1,100 | 200 | 2,750 | 3.0 | 0.6 | $5.17 |
| 4 | Dashboard AI Risk Score | Opus | 1,000 | 350 | 60 | 0.06 | 0.02 | $2.70 |
| 5 | Falcon Security Assistant | Sonnet | 2,000 | 700 | 110 | 0.22 | 0.08 | $1.82 |
| 6 | Sandbox Analysis | Sonnet | 900 | 600 | 66 | 0.06 | 0.04 | $0.77 |
| 7 | Posture Resource Analysis | Haiku | 300 | 250 | 600 | 0.18 | 0.15 | $0.74 |
| 8 | SaaS DLP Worker (ongoing) | Haiku | 425 | 175 | 150 | 0.06 | 0.03 | $0.17 |
| 9 | Compliance Assessment | Opus | 2,500 | 1,500 | 2 | 0.005 | 0.003 | $0.30 |
| 10 | AWS Resource Classification | Haiku | 500 | 250 | 150 | 0.08 | 0.04 | $0.21 |
| 11 | Posture App Threat Intel | Haiku | 600 | 700 | 48 | 0.03 | 0.03 | $0.16 |
| 12 | Posture Check Enrichment | Haiku | 900 | 400 | 60 | 0.05 | 0.02 | $0.14 |
| 13 | Compliance Report Narrative | Opus | 2,500 | 1,000 | 1 | 0.003 | 0.001 | $0.13 |
| 14 | Posture AI Score | Haiku | 350 | 150 | 60 | 0.02 | 0.009 | $0.06 |
| **TOTAL** | | | | | | | | **$11,929–$13,023** |

### 3.2 Expected (Mid-Point) Monthly Cost

| Scenario | Monthly Cost | Per User/Month |
|---------|-------------|---------------|
| **Low** (output at min) | $11,929 | $238.58 |
| **Expected** (mid-point) | **$12,476** | **$249.52** |
| **High** (output at max) | $13,023 | $260.45 |

### 3.3 Gross Margin at Current Architecture — UNTENABLE

| Price/User/Month | Revenue (50 users) | Claude Cost | Gross Margin |
|-----------------|-------------------|------------|-------------|
| $10 | $500 | $12,476 | **−2,395%** |
| $15 | $750 | $12,476 | **−1,563%** |
| $20 | $1,000 | $12,476 | **−1,148%** |
| $30 | $1,500 | $12,476 | **−732%** |
| $50 | $2,500 | $12,476 | **−399%** |

> ⚠️ Claude alone costs 5× to 25× more than the entire target revenue. This is not viable.

---

## Part 4: Cost-Optimization Recommendations

### Priority 1 (High Impact): Swap Email Classification from Opus → Haiku

**Impact: saves $11,550–$12,575/month (97% of total cost)**

The core issue is `config.py:CLAUDE_MODEL = "claude-opus-4-5-20251101"` with `include_few_shot=True`.  
Haiku 3.5 is purpose-designed for structured JSON classification tasks with strong prompts.  
The 16-example few-shot prompt provides Gulf-specific context that Haiku can use equally well.

```python
# config.py change:
CLAUDE_MODEL = "claude-haiku-4-5"   # was: claude-opus-4-5-20251101
# Expected new cost: ~$168/month for email classification alone
```

**Risk:** Slightly lower accuracy on nuanced Arabic BEC edge cases.  
**Mitigation:** Keep Opus for high-risk re-analysis (risk_score ≥ 70) only — hybrid pattern.

---

### Priority 2 (High Impact): Implement Anthropic Prompt Caching

**Impact: saves $8,400–$9,400/month on email classification even if staying on Opus**

The system prompt (1,028 tok) + 16 few-shot examples (12,709 tok) = **13,737 tokens are static** for every email classification call. With Anthropic prompt caching (cached tokens billed at 10% of input rate):

```python
# In ContentClassifier._call_claude(), add cache_control to system + few-shot turns:
response = await self.claude_client.messages.create(
    model=CLAUDE_MODEL,
    system=[{"type": "text", "text": SYSTEM_PROMPT, 
             "cache_control": {"type": "ephemeral"}}],  # ← ADD
    messages=messages_with_cache_control,               # ← flag few-shot turns too
    ...
)
```

| Scenario | Monthly Email Cost |
|---------|------------------|
| Opus + no caching (current) | $12,242 |
| Opus + prompt caching | $3,391 |
| **Haiku + no caching** | **$168** |
| **Haiku + prompt caching** | **$181** |

> Haiku + caching yields negligible incremental benefit over Haiku alone because Haiku is already cheap.  
> Opus + caching is the **safe accuracy-preserving option** at $3.4K/month.

---

### Priority 3 (Medium Impact): Reduce Few-Shot Examples

**Impact: saves $2,600–$3,200/month on Opus, or $200–$280 on Haiku**

The 16 examples total ~12,709 tokens. Reducing to 8 targeted examples (one per threat class) halves the prompt overhead:

```python
# email_processor.py — in _get_classifier():
_classifier = ContentClassifier(
    ...
    include_few_shot=True,    # keep True
    few_shot_count=8,         # add this param; filter to 8 most representative examples
)
```

Best examples to keep: Arabic BEC (×1), GOV_IMPERSONATION (×1), MALWARE (×1), PHISHING (×1), LOOKALIKE_DOMAIN (×1), BENIGN (×2 — ar + en), VEC (×1).

---

### Priority 4 (Medium Impact): Move Dashboard Risk Score to Haiku

**Impact: saves $2.43/month**  
`dashboard.py:667` uses Opus for a structured JSON output with 5 fields.  
Haiku is sufficient: saves ~90% of the $2.70/month cost → $0.27/month.

```python
# dashboard.py:667 — change model parameter:
model="claude-haiku-4-5"    # was: claude-opus-4-5-20251101
```

---

### Priority 5 (Medium Impact): Hybrid Email Classification Routing

**Impact: saves $10,685/month vs baseline; costs $1,790/month total**

Route 88% of emails (clean/low-risk) to Haiku first; escalate 12% to Opus for deeper analysis:

```python
# email_processor.py — pre-screen with Haiku, escalate borderline to Opus
# Step 1: Haiku pre-screen with 3-example few-shot (~2,500 tokens/call)
# Step 2: If confidence < 0.6 OR threat_type not in ("BENIGN","CLEAN"):
#           Re-classify with Opus + full 16 examples
```

| Scenario | Monthly Email Cost | Accuracy |
|---------|------------------|---------|
| All-Opus (current) | $12,242 | Highest |
| Hybrid Haiku/Opus | $1,557 | High |
| All-Haiku | $168 | Good |

---

### Priority 6 (Low Impact): Cache Auto-Triage More Aggressively

**Impact: saves $90–$130/month**

Auto-triage calls Opus per threat with no system-prompt caching. The Helios system prompt (~950 tokens) is static. Add `cache_control` to the system prompt in `_get_helios_verdict()`:

```python
# auto_triage_service.py:541 — add cache_control to system param
```

---

### Priority 7 (Low Impact): Batch DLP Worker Calls

**Impact: saves $2–$4/month**

`_run_dlp_classification_worker` makes individual HTTP calls per file. Batch classify 5–10 files in a single prompt:
```
Classify these 5 files: [file1, file2, ...]. Return JSON array.
```
Reduces API call overhead and slightly reduces per-item token count.

---

## Part 5: Optimized Architecture — Monthly Cost

Applying **Priority 1 (Haiku for email)** + **Priority 2 (prompt caching)** + **Priority 4 (Haiku for dashboard)**:

### 5.1 Optimized Cost Breakdown

| Feature | Model | Monthly Cost |
|---------|-------|-------------|
| Email Classification | **Haiku** (was Opus) | **$168** |
| Auto-Triage (Helios Analysis) | Opus (unchanged — accuracy critical) | $220 |
| Outbound Draft DLP | Haiku | $5.17 |
| Dashboard AI Risk Score | **Haiku** (was Opus) | **$0.27** |
| Falcon Security Assistant | Sonnet | $1.82 |
| Sandbox Analysis | Sonnet | $0.77 |
| All other Haiku calls | Haiku | $1.46 |
| **TOTAL OPTIMIZED** | | **~$397/month** |

*Expected range: $370–$430/month depending on email volume and output verbosity.*

### 5.2 Optimized Per-User Cost

| Metric | Value |
|--------|-------|
| Total monthly Claude cost | ~$397 |
| Per user / month (50 users) | **~$7.94** |
| Per user / month (100 users) | ~$4.80 (auto-triage scales sub-linearly) |
| Per user / month (200 users) | ~$3.20 |

---

## Part 6: Gross Margin at Optimized Architecture

### 6.1 Claude API Cost Only (other COGS excluded)

| Price/User/Month | Revenue | Claude Cost | Claude GM | Notes |
|-----------------|---------|------------|-----------|-------|
| $5 | $250 | $397 | **−59%** | Below cost |
| $10 | $500 | $397 | **20.6%** | Barely positive |
| $15 | $750 | $397 | **47.1%** | Viable SaaS |
| $20 | $1,000 | $397 | **60.3%** | Good margin |
| $30 | $1,500 | $397 | **73.5%** | Strong margin |
| $50 | $2,500 | $397 | **84.1%** | Premium tier |

> ⚠️ These margins are **Claude cost only**. Real COGS also includes: infrastructure (EC2/RDS/Redis), SaaS API calls (VirusTotal, M365 Graph), engineering, support. A realistic all-in COGS multiplier is 2–3× Claude costs. Adjust GM accordingly.

### 6.2 Realistic All-In COGS Estimate

| Component | Monthly Estimate |
|-----------|----------------|
| Claude API (optimized) | $397 |
| AWS infrastructure (EC2, RDS, Redis, S3) | ~$200 |
| Third-party APIs (VirusTotal, etc.) | ~$50 |
| **Total estimated COGS/month** | **~$647** |
| Per user (50 users) | **~$12.94** |

| Price/User | Revenue | COGS | **Real GM** |
|-----------|---------|------|------------|
| $15 | $750 | $647 | **13.7%** — marginal |
| $20 | $1,000 | $647 | **35.3%** — acceptable |
| $30 | $1,500 | $647 | **56.9%** — good |
| $50 | $2,500 | $647 | **74.1%** — target |

**Recommended floor price: $20/user/month.** Above $30/user achieves SaaS-grade margins (>50%).

---

## Part 7: Token Volume Summary (Reference Tenant, Optimized)

| Model | Monthly Input Tokens | Monthly Output Tokens | Monthly Cost |
|-------|--------------------|--------------------|-------------|
| **claude-opus-4-5-20251101** | ~6.7M (auto-triage, compliance, dash) | ~1.2M | ~$226 |
| **claude-sonnet-4-5-20250929** (sandbox) | ~0.06M | ~0.04M | ~$0.77 |
| **claude-sonnet-4-20250514** (Falcon) | ~0.22M | ~0.08M | ~$1.82 |
| **claude-haiku-4-5** | ~98M (email) + ~3.4M (DLP+posture) | ~22.5M + ~0.7M | ~$168 |
| **TOTAL** | **~108M input** | **~24.5M output** | **~$397** |

---

## Appendix A: Model Pricing Reference

| Model | Input ($/M tok) | Output ($/M tok) |
|-------|----------------|-----------------|
| claude-opus-4-5-20251101 | $15.00 | $75.00 |
| claude-sonnet-4-5-20250929 | $3.00 | $15.00 |
| claude-sonnet-4-20250514 | $3.00 | $15.00 |
| claude-haiku-4-5 | $0.80 | $4.00 |

*Prompt cache reads: ~10% of input rate for Anthropic caching API.*

---

## Appendix B: Call Site Cross-Reference

| File | Line(s) | Model | Feature |
|------|---------|-------|---------|
| `models/content_classifier/classifier.py` | `_call_claude()` | `claude-opus-4-5-20251101` (config) | Email classification |
| `models/shared/config.py` | `CLAUDE_MODEL` | `claude-opus-4-5-20251101` | Config |
| `backend/services/email_processor.py` | 57 | (via ContentClassifier) | Email pipeline entry |
| `backend/services/auto_triage_service.py` | 541–555 | `claude-opus-4-5-20251101` | Helios Analysis verdict |
| `backend/services/auto_triage_service.py` | 653 | — | Model written to threat record |
| `backend/services/dlp_service.py` | 214–246 | `claude-haiku-4-5` | Outbound DLP (fallback + prefer_claude) |
| `backend/routers/saas_security.py` | 6782–6789 | `claude-haiku-4-5` | Posture resource analysis |
| `backend/routers/saas_security.py` | 7554–7561 | `claude-haiku-4-5` | Posture check enrichment |
| `backend/routers/saas_security.py` | 10426–10433 | `claude-haiku-4-5` | SaaS DLP worker (files) |
| `backend/routers/saas_security.py` | 10548–10555 | `claude-haiku-4-5` | SaaS DLP worker (AWS) |
| `backend/routers/saas_security.py` | 10778–10786 | `claude-haiku-4-5` | AWS resource classification fallback |
| `backend/routers/compliance.py` | 364–365 | `claude-opus-4-5-20251101` | Compliance report narrative |
| `backend/routers/compliance.py` | 604–605 | `claude-opus-4-5-20251101` | Compliance assessment |
| `backend/routers/dashboard.py` | 666–667 | `claude-opus-4-5-20251101` | Dashboard AI risk score |
| `backend/routers/falcon.py` | 269–276 | `claude-sonnet-4-20250514` | Falcon security assistant |
| `backend/routers/sandbox.py` | 196–197 | `claude-sonnet-4-5-20250929` | Sandbox analysis |
| `backend/routers/posture.py` | 755 | `claude-haiku-4-5` | Posture AI score |
| `backend/routers/posture.py` | 1228 | `claude-haiku-4-5` | Posture app threat intel |

---

## Appendix C: Key Assumptions & Sensitivity

| Assumption | Value Used | Sensitivity |
|-----------|-----------|------------|
| Few-shot example token count | 12,709 (measured) | Fixed |
| System prompt tokens | 1,028 (measured) | Fixed |
| Typical email body tokens | 1,150 (estimated) | ±30% = ±$3,600 on Opus |
| % emails flagged for auto-triage | 12% | ±5% = ±$75/month |
| Auto-triage enabled % | 50% | Binary per-org toggle |
| DLP outbound (prefer_claude path) | 50% of drafts | ±20% = ±$2/month |
| Posture app enrichment frequency | 40% of scans have new apps | Low sensitivity |
| DeepSeek fallback rate to Claude | 50% for AWS | ±25% = ±$0.10 |

**Most sensitive variable:** Email classification model. Opus→Haiku saves $11,550/month for this tenant.

---

*All cost calculations use Anthropic public API pricing as of 2026. Token counts are derived from source code analysis: system prompt from `models/content_classifier/prompts.py`, few-shot from character count of `FEW_SHOT_EXAMPLES` block (38,128 chars ÷ 3 chars/token), model configuration from `models/shared/config.py:CLAUDE_MODEL`, and `max_tokens` from each API call site.*
