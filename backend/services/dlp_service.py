"""
Himaya DLP Service — classification, event persistence, email release.
"""
from __future__ import annotations

import base64
import email as _email_lib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

DEEPSEEK_ENDPOINT = os.getenv("DEEPSEEK_ENDPOINT", "http://10.0.1.113:8001")

# ── Regex patterns — extended with financial, PII, HR, legal, M&A ─────────

_PATTERNS = {
    # PII
    "pii_ssn":             re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "pii_credit_card":     re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
    "pii_iban":            re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'),
    "pii_passport":        re.compile(r'(?i)\bpassport\s*(?:no\.?|number|#)?\s*[:\s]*[A-Z]{1,2}\d{6,9}\b'),
    "pii_dob":             re.compile(r'(?i)\b(?:date.of.birth|\bdob\b|born.on)\b'),
    "pii_national_id":     re.compile(r'(?i)\b(?:national.?id|emirates.?id|iqama|civil.?id)\b'),
    # Financial
    "financial_swift":     re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'),
    "financial_routing":   re.compile(r'(?i)\brouting\s*(?:number|#|no\.?)\s*[:\s]*\d{9}\b'),
    "financial_account":   re.compile(r'(?i)\baccount\s*(?:number|#|no\.?)\s*[:\s]*\d{6,20}\b'),
    "financial_salary":    re.compile(r'(?i)\b(?:salary|payroll|compensation|bonus|stock.?option)\b'),
    "financial_invoice":   re.compile(r'(?i)\b(?:invoice|wire.?transfer|bank.?transfer|remittance)\b'),
    "financial_budget":    re.compile(r'(?i)\b(?:budget|forecast|quarterly.?results|balance.?sheet)\b'),
    # Credentials / Secrets
    "credential_privkey":  re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "credential_awskey":   re.compile(r'AKIA[0-9A-Z]{16}'),
    "credential_apikey":   re.compile(r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})'),
    "credential_password": re.compile(r'(?i)\bpassword\s*[:=]\s*\S{6,}'),
    "credential_connstr":  re.compile(r'(?i)(?:mongodb|postgresql|mysql|redis)://[^\s"]+'),
    # Legal / Compliance
    "legal_nda":           re.compile(r'(?i)\b(?:NDA|non.?disclosure|confidentiality.?agreement|attorney.?client)\b'),
    "legal_litigation":    re.compile(r'(?i)\b(?:lawsuit|litigation|settlement|without.?prejudice|legal.?hold)\b'),
    "legal_ma":            re.compile(r'(?i)\b(?:merger|acquisition|due.?diligence|term.?sheet|letter.?of.?intent)\b'),
    # HR
    "hr_performance":      re.compile(r'(?i)\b(?:performance.?review|PIP|termination|disciplinary|harassment|grievance)\b'),
    "hr_medical":          re.compile(r'(?i)\b(?:medical.?record|diagnosis|prescription|HIPAA|PHI)\b'),
    # Regulated
    "itar":                re.compile(r'(?i)\b(?:ITAR|EAR|ECCN|munitions|defense.?article)\b'),
    "gdpr":                re.compile(r'(?i)\b(?:GDPR|data.?subject|right.?to.?erasure)\b'),
    # Bulk exfil
    "bulk_exfil":          re.compile(r'(?i)(?:bcc:|to:)(?:[^,\n]+,\s*){19,}'),
    # Gulf/MENA region specific
    "pii_uae_id":          re.compile(r'\b784-\d{4}-\d{7}-\d{1}\b'),
    "pii_saudi_id":        re.compile(r'(?i)\b(?:iqama|national.?id|saudi.?id)(?:\s+\w+)?\s*[:\s]*\d{10}\b'),
    "pii_gcc_phone":       re.compile(r'(?:\+966|\+971|\+974|\+973|\+968|\+965)(?:[\s\-]?\d){7,10}(?!\d)'),
    # Crypto / Financial
    "crypto_wallet":       re.compile(r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    "crypto_mnemonic":     re.compile(r'(?i)\b(?:seed phrase|recovery phrase|mnemonic|private key)\b'),
    # Cloud credentials
    "aws_secret_key":      re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*[A-Za-z0-9/+]{40}'),
    "gcp_key":             re.compile(r'"type":\s*"service_account"'),
    "azure_conn_str":      re.compile(r'(?i)DefaultEndpointsProtocol=https;AccountName='),
    # Healthcare
    "hipaa_phi":           re.compile(r'(?i)\b(?:patient.?id|medical.?record.?number|MRN|diagnosis|treatment.?plan)\b'),
    # Source code secrets
    "jwt_token":           re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "slack_token":         re.compile(r'xox[baprs]-[0-9A-Za-z]{10,}'),
    "github_token":        re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
    # Medical / Healthcare
    "pii_blood_type":      re.compile(r'(?i)\b(?:blood.?type|blood.?group)\s*[:\s]*[ABO]{1,2}[+-]?'),
    "pii_health_insurance": re.compile(r'(?i)\b(?:health.?insurance|insurance.?number|insurance.?id|member.?id)\s*[:\s]?\w{5,15}\b'),
    # Legal docs
    "legal_court_order":   re.compile(r'(?i)\b(?:court.?order|injunction|restraining.?order|subpoena|warrant)\b'),
    "legal_ip_rights":     re.compile(r'(?i)\b(?:patent.?number|patent.?application|trade.?secret|intellectual.?property)\b'),
    # Financial - more
    "financial_tax":       re.compile(r'(?i)\b(?:tax.?return|taxable.?income|W-?2|1099|EIN|TIN|VAT.?number)\b'),
    "financial_wire":      re.compile(r'(?i)\b(?:wire.?transfer|swift.?code|correspondent.?bank|nostro|vostro)\b'),
    # Infrastructure secrets
    "infra_ssh_key":       re.compile(r'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----'),
    # Additional biometric
    "pii_biometric":       re.compile(r'(?i)\b(?:fingerprint|biometric|retinal.?scan|face.?recognition)\b'),
    # Database
    "db_sql_dump":         re.compile(r'(?i)\b(?:INSERT INTO|CREATE TABLE|DROP TABLE|ALTER TABLE)\s+\w+'),
    "db_connection":       re.compile(r'(?i)(?:Server=|Data Source=|Initial Catalog=|User Id=|Password=)[^\s;]+'),
}
_SEV = {
    "pii_ssn": "critical", "pii_credit_card": "critical", "pii_iban": "high",
    "pii_passport": "high", "pii_dob": "medium", "pii_national_id": "high",
    "financial_swift": "high", "financial_routing": "high", "financial_account": "high",
    "financial_salary": "medium", "financial_invoice": "medium", "financial_budget": "medium",
    "credential_privkey": "critical", "credential_awskey": "critical",
    "credential_apikey": "critical", "credential_password": "high",
    "credential_connstr": "critical",
    "legal_nda": "high", "legal_litigation": "high", "legal_ma": "high",
    "hr_performance": "medium", "hr_medical": "high",
    "itar": "high", "gdpr": "medium", "bulk_exfil": "high",
    # MENA
    "pii_uae_id": "high", "pii_saudi_id": "high", "pii_gcc_phone": "medium",
    # Crypto
    "crypto_wallet": "high", "crypto_mnemonic": "critical",
    # Cloud credentials
    "aws_secret_key": "critical", "gcp_key": "critical", "azure_conn_str": "critical",
    # Healthcare
    "hipaa_phi": "high",
    # Source code secrets
    "jwt_token": "high", "slack_token": "critical", "github_token": "critical",
    # Medical / Healthcare
    "pii_blood_type": "medium", "pii_health_insurance": "high",
    # Legal docs
    "legal_court_order": "high", "legal_ip_rights": "high",
    # Financial - more
    "financial_tax": "medium", "financial_wire": "high",
    # Infrastructure secrets
    "infra_ssh_key": "critical",
    # Additional biometric
    "pii_biometric": "high",
    # Database
    "db_sql_dump": "medium", "db_connection": "critical",
}
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ACT_MAP = {"low": "ALLOW", "medium": "WARN", "high": "HOLD", "critical": "BLOCK"}

# ── Public exports for dlp_inline ────────────────────────────────────────────

DLP_CATEGORIES = list(_PATTERNS.keys())


async def classify_text(text: str) -> dict:
    """
    Classify text for sensitive content. Used by dlp_inline for outbound scanning.
    Returns dict with 'detections' list, each having category, severity, match.
    """
    detections = []
    for name, pat in _PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            sev = _SEV.get(name, "medium")
            for match in matches[:3]:  # Limit to 3 matches per pattern
                detections.append({
                    "category": name,
                    "severity": sev,
                    "match": str(match)[:100] if match else "",
                    "pattern": name,
                })
    return {
        "detections": detections,
        "total_matches": len(detections),
    }


def _regex_classify(text: str) -> dict:
    categories, matched = [], []
    max_sev = "low"
    for name, pat in _PATTERNS.items():
        if pat.search(text):
            categories.append(name)
            matched.append(name)
            s = _SEV.get(name, "medium")
            if _SEV_ORDER[s] > _SEV_ORDER[max_sev]:
                max_sev = s
    return {
        "risk_level": max_sev,
        "action": _ACT_MAP[max_sev],
        "categories": categories,
        "confidence": 0.80 if categories else 0.55,
        "matched_patterns": matched,
        "explanation": (
            f"Regex matched: {', '.join(set(matched))}" if matched
            else "No sensitive patterns detected."
        ),
    }


async def _deepseek_classify(email_body: str, subject: str,
                              attachments: list[str], recipient_domains: list[str],
                              org_id: str) -> Optional[dict]:
    """Call DeepSeek inference server. Returns None if unavailable."""
    if not DEEPSEEK_ENDPOINT:
        return None
    try:
        # T4 GPU inference is slow (~120-180s per request); use longer timeout.
        # For production, upgrade to A10G/A100 or use smaller model.
        async with httpx.AsyncClient(timeout=300) as client:
            r = await client.post(
                f"{DEEPSEEK_ENDPOINT}/classify",
                json={
                    "email_body": email_body[:4000],
                    "subject": subject,
                    "attachments": attachments,
                    "recipient_domains": recipient_domains,
                    "org_id": org_id,
                },
            )
            if r.status_code == 200:
                return r.json()
            logger.warning(f"dlp_service: DeepSeek returned {r.status_code}")
    except Exception as exc:
        logger.debug(f"dlp_service: DeepSeek unreachable (will try Claude): {exc}")
    return None


async def _claude_classify(
    email_body: str, subject: str, attachments: list[str],
    sender: str, recipient_domains: list[str],
) -> Optional[dict]:
    """Claude fallback DLP when DeepSeek is offline. Uses claude-haiku for speed/cost."""
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return None
    try:
        att_note = f" Attachments: {', '.join(attachments)}" if attachments else ""
        cats = (
            "pii_ssn, pii_credit_card, pii_iban, pii_passport, pii_national_id, pii_dob, "
            "financial_account, financial_routing, financial_salary, financial_invoice, "
            "financial_budget, financial_swift, credential_privkey, credential_awskey, "
            "credential_apikey, credential_password, credential_connstr, "
            "legal_nda, legal_litigation, legal_ma, hr_performance, hr_medical, "
            "itar, gdpr, bulk_exfil"
        )
        prompt = (
            "You are a DLP classifier. Analyze this email draft for sensitive content.\n\n"
            f"Subject: {subject}\nFrom: {sender}\n"
            f"To domains: {', '.join(recipient_domains) or 'unknown'}{att_note}\n\n"
            f"Body:\n{email_body[:3000]}\n\n"
            f"Flag only clearly present categories from: {cats}\n\n"
            "Suspicious attachments (.xlsm macros, .exe, password-protected docs) = high risk.\n\n"
            'Respond with JSON only: {"risk_level":"low|medium|high|critical",'
            '"categories":[],"confidence":0.0,"explanation":"brief reason"}'
        )
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 300,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code == 200:
                raw = r.json()["content"][0]["text"].strip()
                raw = re.sub(r"^```[\w]*\n?", "", raw)
                raw = re.sub(r"```$", "", raw).strip()
                parsed = json.loads(raw)
                parsed.setdefault("matched_patterns", parsed.get("categories", []))
                parsed["action"] = _ACT_MAP.get(parsed.get("risk_level", "low"), "ALLOW")
                logger.info(
                    f"dlp_service: Claude DLP risk={parsed.get('risk_level')} "
                    f"cats={parsed.get('categories')}"
                )
                return parsed
            logger.warning(f"dlp_service: Claude returned {r.status_code}")
    except Exception as exc:
        logger.warning(f"dlp_service: Claude classify failed: {exc}")
    return None


async def _get_org_policies(org_id: str, db: AsyncSession) -> list[dict]:
    """Fetch enabled DLP policies for this org."""
    try:
        rows = (await db.execute(
            text(
                "SELECT id, name, severity, detect_pii, detect_financial, detect_credentials, "
                "detect_itar, detect_bulk_exfil, custom_keywords, custom_regex, action, "
                "notify_sender, notify_manager_email, external_only "
                "FROM dlp_policies WHERE org_id=:oid AND enabled=true"
            ),
            {"oid": org_id},
        )).fetchall()
        return [
            {
                "id": str(r[0]), "name": r[1], "severity": r[2],
                "detect_pii": r[3], "detect_financial": r[4],
                "detect_credentials": r[5], "detect_itar": r[6], "detect_bulk_exfil": r[7],
                "custom_keywords": json.loads(r[8]) if r[8] else [],
                "custom_regex": json.loads(r[9]) if r[9] else [],
                "action": r[10],
                "notify_sender": r[11],
                "notify_manager_email": r[12],
                "external_only": r[13],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning(f"dlp_service: policy fetch failed: {exc}")
        return []


def _apply_policy_filters(
    policy: dict,
    result: dict,
    is_external: bool,
) -> Optional[str]:
    """Return the policy's action if this result violates it, else None."""
    if policy["external_only"] and not is_external:
        return None

    cats = set(result.get("categories", []))
    matched = False

    if policy["detect_pii"] and any(c.startswith("pii_") for c in cats):
        matched = True
    if policy["detect_financial"] and any(c.startswith("financial_") for c in cats):
        matched = True
    if policy["detect_credentials"] and any(c.startswith("credential_") for c in cats):
        matched = True
    if policy["detect_itar"] and "itar" in cats:
        matched = True
    if policy["detect_bulk_exfil"] and "bulk_exfil" in cats:
        matched = True

    # Check custom keywords
    for kw in policy.get("custom_keywords", []):
        if kw.lower() in result.get("explanation", "").lower():
            matched = True
            break

    return policy["action"] if matched else None


async def classify_email(
    email_data: dict, org_id: str, db: AsyncSession,
    auto_commit: bool = True, prefer_claude: bool = False,
) -> dict:
    """
    Full DLP classification pipeline:
    1. Fetch org policies
    2. Regex classification (always)
    3. LLM classification (Claude preferred for drafts, DeepSeek for outbound)
    4. Apply policy filters
    5. Save dlp_event to DB
    6. If HOLD → save to dlp_queue
    Returns the verdict dict.
    
    Args:
        prefer_claude: If True, use Claude directly (for draft analysis where speed matters)
    """
    body = email_data.get("body", "")
    subject = email_data.get("subject", "")
    sender = email_data.get("sender", "")
    recipients = email_data.get("recipients", [])
    attachments = email_data.get("attachments", [])

    # Determine if external (recipient domains differ from sender domain)
    sender_domain = sender.split("@")[1].lower() if "@" in sender else ""
    recipient_domains = list({
        r.split("@")[1].lower() for r in recipients if "@" in r
    })
    is_external = any(d != sender_domain for d in recipient_domains)

    full_text = f"Subject: {subject}\n\n{body}"

    # Step 1: regex — supplementary signal only (not used as standalone verdict)
    regex_result = _regex_classify(full_text)

    # Step 2: LLM classification
    # For drafts (prefer_claude=True): Use Claude directly for speed and reliability
    # For outbound: Try DeepSeek first, then Claude fallback
    llm_result = None
    
    if prefer_claude:
        # Draft analysis: Claude is faster and more reliable
        llm_result = await _claude_classify(body, subject, attachments, sender, recipient_domains)
    else:
        # Outbound DLP: Try DeepSeek first
        llm_result = await _deepseek_classify(body, subject, attachments, recipient_domains, org_id)
        if not llm_result:
            logger.info(f"dlp_service: DeepSeek unavailable for org {org_id}, trying Claude fallback")
            llm_result = await _claude_classify(body, subject, attachments, sender, recipient_domains)
    
    if llm_result:
        # Merge LLM verdict with regex supplementary signal (take more severe)
        all_cats = list(set(llm_result.get("categories", []) + regex_result["categories"]))
        all_pats = list(set(llm_result.get("matched_patterns", []) + regex_result["matched_patterns"]))
        # Use LLM's risk level as base; boost if regex found something more severe
        llm_sev = _SEV_ORDER.get(llm_result.get("risk_level", "low"), 0)
        rx_sev = _SEV_ORDER.get(regex_result["risk_level"], 0)
        if rx_sev > llm_sev:
            final_result = {**regex_result}
            final_result["explanation"] = (
                f"LLM: {llm_result.get('explanation','')} | "
                f"Regex boosted severity: {regex_result.get('explanation','')}"
            )
        else:
            final_result = {**llm_result}
        final_result["categories"] = all_cats
        final_result["matched_patterns"] = all_pats
        final_result["action"] = _ACT_MAP.get(final_result.get("risk_level", "low"), "ALLOW")
    else:
        # Both DeepSeek and Claude unavailable — use regex-only with WARN action
        logger.warning(f"dlp_service: All LLM classifiers unavailable for org {org_id} — using regex-only")
        if regex_result["categories"]:
            final_result = {
                "risk_level": regex_result["risk_level"],
                "action": "WARN",
                "categories": regex_result["categories"],
                "matched_patterns": regex_result["matched_patterns"],
                "confidence": 0.6,
                "explanation": f"Regex detection (LLM unavailable): {regex_result.get('explanation', '')}",
            }
        else:
            final_result = {
                "risk_level": "low",
                "action": "ALLOW",
                "categories": [],
                "matched_patterns": [],
                "confidence": 0.5,
                "explanation": "No sensitive content detected (regex-only, LLM unavailable).",
            }

    # Step 3: apply policy filters
    policies = await _get_org_policies(org_id, db)
    matched_policy_id = None
    matched_policy_name = None
    policy_action = None

    for policy in policies:
        pa = _apply_policy_filters(policy, final_result, is_external)
        if pa:
            matched_policy_id = policy["id"]
            matched_policy_name = policy["name"]
            policy_action = pa
            break

    # Take stricter of classification action vs policy action
    class_action = final_result.get("action", "ALLOW")
    if policy_action:
        if _SEV_ORDER.get(policy_action, 0) > _SEV_ORDER.get(class_action, 0):
            final_result["action"] = policy_action

    # Step 4: persist event
    event_id = str(uuid.uuid4())
    body_preview = body[:200]
    now = datetime.now(timezone.utc)

    try:
        await db.execute(
            text(
                "INSERT INTO dlp_events "
                "(id, org_id, policy_id, sender_email, recipient_emails, subject, body_preview, "
                "risk_level, action_taken, categories_found, matched_patterns, confidence, created_at) "
                "VALUES (:id, :org_id, :policy_id, :sender, :recipients, :subject, :body_preview, "
                ":risk_level, :action_taken, :categories, :patterns, :confidence, :now)"
            ),
            {
                "id": event_id,
                "org_id": org_id,
                "policy_id": matched_policy_id,
                "sender": sender,
                "recipients": json.dumps(recipients),
                "subject": subject,
                "body_preview": body_preview,
                "risk_level": final_result.get("risk_level", "low"),
                "action_taken": final_result.get("action", "ALLOW"),
                "categories": json.dumps(final_result.get("categories", [])),
                "patterns": json.dumps(final_result.get("matched_patterns", [])),
                "confidence": float(final_result.get("confidence", 0.5)),
                "now": now,
            },
        )

        # Step 5: HOLD/BLOCK → queue
        if final_result.get("action") in ("HOLD", "BLOCK"):
            held_json = base64.b64encode(json.dumps(email_data).encode()).decode()
            queue_id = str(uuid.uuid4())
            from datetime import timedelta
            expires = now + timedelta(hours=4)
            await db.execute(
                text(
                    "INSERT INTO dlp_queue "
                    "(id, org_id, event_id, status, held_message_json, expires_at, created_at) "
                    "VALUES (:id, :org_id, :event_id, 'pending', :held_json, :expires, :now)"
                ),
                {
                    "id": queue_id,
                    "org_id": org_id,
                    "event_id": event_id,
                    "held_json": held_json,
                    "expires": expires,
                    "now": now,
                },
            )

        if auto_commit:
            await db.commit()

    except Exception as exc:
        logger.error(f"dlp_service: DB persist failed: {exc}")
        if auto_commit:
            await db.rollback()

    # Compute numeric score from risk_level + confidence for callers that need it
    _sev_scores = {"low": 5, "medium": 45, "high": 75, "critical": 95}
    _base_score = _sev_scores.get((final_result.get("risk_level") or "low").lower(), 5)
    _conf = float(final_result.get("confidence") or 0.5)
    if final_result.get("categories"):
        _base_score = min(100, max(0, int(_base_score + (_conf - 0.5) * 20)))
    computed_score = _base_score

    return {
        **final_result,
        "score": computed_score,
        "event_id": event_id,
        "policy_id": matched_policy_id,
        "policy_name": matched_policy_name,
    }


async def release_email(queue_item: dict, db: AsyncSession) -> bool:
    """
    Release a held email from the DLP queue.
    Decodes the held_message_json, determines provider (M365/Gmail),
    and re-sends via Graph API or Gmail API.
    """
    try:
        held_json = base64.b64decode(queue_item["held_message_json"]).decode()
        email_data = json.loads(held_json)
        provider = email_data.get("provider", "m365")
        org_id = queue_item["org_id"]

        # Get active integration tokens
        from sqlalchemy import select as _sel
        from backend.models.db_models import OrgIntegration

        res = await db.execute(
            _sel(OrgIntegration).where(
                OrgIntegration.org_id == org_id,
                OrgIntegration.provider == provider,
                OrgIntegration.status == "active",
            )
        )
        integ = res.scalar_one_or_none()
        if not integ:
            logger.warning(f"dlp release: no {provider} integration for org {org_id}")
            return False

        from backend.services.baseline_ingestion import _decrypt
        at = _decrypt(integ.access_token_enc) if integ.access_token_enc else ""

        headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}

        if provider == "m365":
            # Re-send via Graph API sendMail
            sender = email_data.get("sender", "")
            payload = {
                "message": {
                    "subject": email_data.get("subject", ""),
                    "body": {"contentType": "HTML", "content": email_data.get("body", "")},
                    "toRecipients": [
                        {"emailAddress": {"address": r}}
                        for r in email_data.get("recipients", [])
                    ],
                },
                "saveToSentItems": "true",
            }
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
                    json=payload,
                    headers=headers,
                )
                return r.status_code in (200, 202)

        elif provider == "google":
            # Re-send via Gmail API
            import email.mime.text as _mt
            import email.mime.multipart as _mm

            msg = _mm.MIMEMultipart()
            msg["to"] = ", ".join(email_data.get("recipients", []))
            msg["from"] = email_data.get("sender", "")
            msg["subject"] = email_data.get("subject", "")
            msg.attach(_mt.MIMEText(email_data.get("body", ""), "html"))
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

            sender = email_data.get("sender", "")
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"https://gmail.googleapis.com/gmail/v1/users/{sender}/messages/send",
                    json={"raw": raw},
                    headers=headers,
                )
                return r.status_code == 200

        return False

    except Exception as exc:
        logger.error(f"dlp release: failed: {exc}")
        return False
