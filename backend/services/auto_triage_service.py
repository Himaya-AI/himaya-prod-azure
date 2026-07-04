"""
Auto-Triage Agent — Himaya autonomous email security investigator.

When enabled (per-org toggle), a background loop runs every 2 minutes
examining new/open threats, performs deep investigation (VT, threat feeds,
Neo4j graph, attachment heuristics), synthesises evidence via Himaya Analysis,
and applies a definitive verdict.

Redis key for enabled state: auto_triage:enabled:{org_id}
Redis key for loop status:   auto_triage:status:{org_id}
Redis key for last rollup:   auto_triage:last_rollup:{org_id}
"""
import asyncio
import base64
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Attachment risk heuristics ─────────────────────────────────────────────────
ATTACHMENT_RISK = {
    "HIGH": {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif", ".com"},
    "MACRO_ENABLED": {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"},
    "ARCHIVE": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"},
    "LOW": {".pdf"},
}

_ALL_HIGH_RISK = ATTACHMENT_RISK["HIGH"] | ATTACHMENT_RISK["MACRO_ENABLED"]

def _build_helios_system_prompt() -> str:
    from datetime import datetime as _dt
    today = _dt.utcnow().strftime("%B %d, %Y")
    year = _dt.utcnow().year
    return (
        f"You are Himaya Analysis, an autonomous email security engine for enterprise organizations "
        f"in the Gulf region.\n\n"
        f"CURRENT DATE: {today}. This is the real current date - use it when reasoning about dates "
        f"in email content, filenames, or deadlines. Do not treat dates in {year} as future or unusual.\n\n"
        "You are given a full threat dossier for a suspicious email. Your job is to make a definitive, "
        "justified verdict.\n\n"
        "VERDICT OPTIONS:\n"
        "- QUARANTINE: High-confidence threat. Move to quarantine folder immediately. Notify recipient and admin.\n"
        "- MARK_AS_SPAM: Clear spam with no malicious payload. Move to junk. No admin alert needed.\n"
        "- ESCALATE: Uncertain or sophisticated threat requiring human review. Flag as high-risk, alert admin.\n"
        "- DISMISS: Low-risk or likely false positive. Mark as resolved, no action.\n\n"
        "ANALYSIS FRAMEWORK:\n"
        "1. Sender reputation: Is the domain newly registered? Does it appear on threat feeds? Graph history?\n"
        "2. Content analysis: AI classification confidence, threat type, urgency signals, impersonation markers\n"
        "3. URL analysis: Are URLs on malware/phishing feeds? VirusTotal results?\n"
        "4. Attachment analysis: Is the file type dangerous? What does the name suggest?\n"
        "5. Context: Is this sender known? Have they sent legitimate mail before?\n\n"
        "USER-REPORTED EMAILS: If user_reported=true, the email was flagged by an employee as suspicious.\n"
        "Weight this signal: employees rarely report legitimate emails. Lean toward ESCALATE or QUARANTINE\n"
        "unless there is very strong evidence it is clean (e.g., known internal sender, domain in allow list).\n\n"
        'RESPONSE FORMAT (JSON only, no markdown, no explanation outside JSON):\n'
        '{\n'
        '  "verdict": "QUARANTINE|MARK_AS_SPAM|ESCALATE|DISMISS",\n'
        '  "threat_type": "PHISHING|BEC|MALWARE|SPAM|SAFE",\n'
        '  "confidence": 0.0,\n'
        '  "reasoning": "2-3 sentence explanation of why",\n'
        '  "key_evidence": ["evidence point 1", "evidence point 2"],\n'
        '  "notify_recipient": true,\n'
        '  "notify_admin": true\n'
        '}\n\n'
        "THREAT TYPE DEFINITIONS:\n"
        "- PHISHING: Credential theft, fake login pages, deceptive links impersonating trusted brands\n"
        "- BEC: Business Email Compromise - impersonating executives/finance to request wire transfers or data\n"
        "- MALWARE: Malicious attachments, macro-enabled docs, drive-by downloads\n"
        "- SPAM: Unsolicited bulk email without malicious payload\n"
        "- SAFE: Legitimate email, no threat detected"
    )


HELIOS_ANALYSIS_SYSTEM_PROMPT = _build_helios_system_prompt()


# ── VirusTotal helpers ─────────────────────────────────────────────────────────

async def vt_lookup_domain(domain: str) -> dict:
    """
    Query VirusTotal for domain reputation.
    Returns: {"malicious": N, "suspicious": N, "categories": [...], "reputation": N}
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key or not domain:
        return {"malicious": 0, "suspicious": 0, "categories": [], "reputation": 0}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                cats = list(attrs.get("categories", {}).values())
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "categories": cats,
                    "reputation": attrs.get("reputation", 0),
                }
    except Exception as e:
        logger.debug(f"VT domain lookup failed for {domain}: {e}")
    return {"malicious": 0, "suspicious": 0, "categories": [], "reputation": 0}


async def vt_lookup_url(url: str) -> dict:
    """
    Query VirusTotal for URL reputation.
    Uses base64url-encoded URL ID for GET; POSTs if not yet analysed.
    Returns: {"malicious": N, "suspicious": N, "last_analysis_date": ...}
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key or not url:
        return {"malicious": 0, "suspicious": 0, "last_analysis_date": None}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_key},
            )
            if resp.status_code == 404:
                # Submit URL for analysis first
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": vt_key},
                    data={"url": url},
                )
                if submit.status_code == 200:
                    analysis_id = submit.json().get("data", {}).get("id", "")
                    await asyncio.sleep(3)  # Brief wait for analysis
                    get_resp = await client.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers={"x-apikey": vt_key},
                    )
                    if get_resp.status_code == 200:
                        attrs = get_resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("stats", {})
                        return {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "last_analysis_date": None,
                        }
            elif resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                }
    except Exception as e:
        logger.debug(f"VT URL lookup failed for {url}: {e}")
    return {"malicious": 0, "suspicious": 0, "last_analysis_date": None}


# ── Attachment analysis ────────────────────────────────────────────────────────

def analyze_attachment(filename: str, email_body: str = "") -> dict:
    """
    Heuristic-based attachment risk assessment from filename/extension only.
    No sandbox required at triage time.
    """
    if not filename:
        return {"risk": "UNKNOWN", "ext": "", "reason": "no filename"}

    ext = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""
    name_lower = filename.lower()

    if ext in ATTACHMENT_RISK["HIGH"]:
        return {"risk": "HIGH", "ext": ext, "reason": f"executable/script extension: {ext}"}

    if ext in ATTACHMENT_RISK["MACRO_ENABLED"]:
        return {"risk": "HIGH", "ext": ext, "reason": f"macro-enabled Office document: {ext}"}

    if ext in ATTACHMENT_RISK["ARCHIVE"]:
        # Check for password-protected hints in email body
        body_lower = email_body.lower()
        pw_hints = any(w in body_lower for w in ["password", "pass:", "pw:", "كلمة المرور"])
        if pw_hints:
            return {"risk": "HIGH", "ext": ext, "reason": f"password-protected archive (suspected payload delivery): {ext}"}
        return {"risk": "MEDIUM", "ext": ext, "reason": f"archive file — may contain malicious content: {ext}"}

    if ext == ".pdf":
        return {"risk": "LOW", "ext": ext, "reason": "PDF — low risk in isolation"}

    return {"risk": "MEDIUM", "ext": ext, "reason": f"unknown file type: {ext}"}


# ── Investigation pipeline ────────────────────────────────────────────────────

async def investigate_threat(threat_id: str, org_id: str) -> dict:
    """
    Full autonomous investigation pipeline:
    1. Load threat from DB
    2. VT lookups: sender domain + up to 3 URLs
    3. Threat feed checks: sender IP + URLs
    4. Neo4j graph query: prior sender history
    5. Attachment heuristic analysis
    6. Himaya Analysis verdict synthesis
    7. Apply verdict action
    """
    result = {
        "threat_id": threat_id,
        "verdict": None,
        "confidence": 0.0,
        "reasoning": "",
        "key_evidence": [],
        "applied": False,
        "error": None,
    }

    try:
        # ── 1. Load threat from DB ─────────────────────────────────────────────
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import Threat
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            t_res = await db.execute(
                select(Threat).where(
                    Threat.id == threat_id if not isinstance(threat_id, str) else True,
                ).where(
                    Threat.org_id == org_id if not isinstance(org_id, str) else True,
                )
            )
            # Use UUID conversion
            import uuid as _uuid
            t_result = await db.execute(
                select(Threat).where(
                    Threat.id == _uuid.UUID(threat_id),
                    Threat.org_id == _uuid.UUID(org_id),
                )
            )
            threat = t_result.scalar_one_or_none()
            if not threat:
                result["error"] = "Threat not found"
                return result

            # Mark as investigating immediately so the UI shows progress
            if threat.status in ("new", "open", "resolved"):
                threat.status = "investigating"
                await db.commit()

            threat_data = {
                "id": str(threat.id),
                "sender": threat.sender or "",
                "sender_domain": threat.sender_domain or "",
                "recipient_email": threat.recipient_email or "",
                "subject": threat.subject or "",
                "threat_type": threat.threat_type or "UNKNOWN",
                "risk_score": threat.risk_score or 0,
                "llm_classification": getattr(threat, "llm_classification", None),
                "llm_confidence": getattr(threat, "llm_confidence", None),
                "ai_explanation_en": threat.ai_explanation_en or "",
                "threat_indicators": threat.threat_indicators or {},
                "email_body_preview": getattr(threat, "email_body_preview", "") or "",
                "auth_results": getattr(threat, "auth_results", {}) or {},
                "impersonation_detected": getattr(threat, "impersonation_detected", False),
                "impersonation_target": getattr(threat, "impersonation_target", None),
                "urgency_score": getattr(threat, "urgency_score", 0),
                "score_breakdown": threat.score_breakdown or {},
                "status": threat.status or "new",
                "action_taken": threat.action_taken or "",
            }

        sender_domain = threat_data["sender_domain"] or (
            threat_data["sender"].split("@")[-1] if "@" in threat_data["sender"] else ""
        )
        body_preview = threat_data["email_body_preview"]
        auth_results = threat_data["auth_results"]
        score_breakdown = threat_data["score_breakdown"]

        # Extract URLs from score_breakdown and indicators
        malicious_urls = score_breakdown.get("malicious_urls", [])
        suspicious_urls = score_breakdown.get("suspicious_urls", [])
        all_urls = list(dict.fromkeys(malicious_urls + suspicious_urls))[:3]

        # Extract attachments
        all_attachments = score_breakdown.get("all_attachments", [])
        suspicious_attachments = score_breakdown.get("suspicious_attachments", [])

        # Sender IP from auth_results
        sender_ip = auth_results.get("sender_ip", "") if auth_results else ""

        # ── 2. VT lookups ──────────────────────────────────────────────────────
        vt_domain_result = {}
        vt_url_results = []

        if sender_domain:
            vt_domain_result = await vt_lookup_domain(sender_domain)

        for url in all_urls:
            vt_r = await vt_lookup_url(url)
            vt_url_results.append({"url": url, **vt_r})

        # ── 3. Threat feed checks ──────────────────────────────────────────────
        feed_url_matches: list[str] = []
        feed_ip_matches: list[str] = []

        try:
            import redis.asyncio as aioredis
            from backend.config import settings as _cfg
            from backend.services.threat_feeds_service import check_url_in_feeds, check_ip_in_feeds

            _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
            try:
                for url in all_urls:
                    hit, feeds = await check_url_in_feeds(url, redis=_redis)
                    if hit:
                        feed_url_matches.extend(feeds)

                if sender_ip:
                    hit, feeds = await check_ip_in_feeds(sender_ip, redis=_redis)
                    if hit:
                        feed_ip_matches.extend(feeds)
            finally:
                await _redis.aclose()
        except Exception as e:
            logger.debug(f"Threat feed checks failed (non-fatal): {e}")

        # ── 4. Neo4j graph query ───────────────────────────────────────────────
        graph_history = {"prior_emails": 0, "known_sender": False, "threat_history": False}
        try:
            from backend.services.graph_service import graph_service
            graph_r = await graph_service.analyze_sender_relationship(
                org_id=org_id,
                sender=threat_data["sender"],
                recipient=threat_data["recipient_email"],
            )
            prior = graph_r.get("email_count", 0) or graph_r.get("graph_score", 0)
            graph_history = {
                "prior_emails": prior,
                "known_sender": prior > 5,
                "graph_score": graph_r.get("graph_score", 0),
                "threat_history": graph_r.get("graph_score", 0) > 50,
            }
        except Exception as e:
            logger.debug(f"Graph query failed (non-fatal): {e}")

        # ── 5. Attachment analysis ─────────────────────────────────────────────
        attachment_findings = []
        for fname in all_attachments[:5]:
            finding = analyze_attachment(fname, body_preview)
            attachment_findings.append({"filename": fname, **finding})

        # ── 5b. EC2 Sandbox Detonation (if URLs or attachments present) ──────────
        ec2_sandbox_result = None
        if all_urls or all_attachments:
            try:
                from backend.services.aci_sandbox_service import detonate_in_aci
                logger.info(f"auto_triage: launching ACI sandbox for {threat_id} (urls={len(all_urls)}, attachments={len(all_attachments)})")
                ec2_sandbox_result = await detonate_in_aci(
                    threat_id=threat_id,
                    urls=all_urls,
                    attachment_names=all_attachments,
                    attachment_data={},
                    org_id=org_id,
                    timeout_seconds=90,
                )
                if ec2_sandbox_result and not ec2_sandbox_result.error:
                    logger.info(f"auto_triage: EC2 sandbox verdict={ec2_sandbox_result.verdict} for {threat_id}")
                    # Persist EC2 findings immediately
                    import uuid as _ec2_uuid
                    async with AsyncSessionLocal() as _ec2_db:
                        from sqlalchemy import select as _ec2_sel
                        _ec2_res = await _ec2_db.execute(_ec2_sel(Threat).where(
                            Threat.id == _ec2_uuid.UUID(threat_id),
                            Threat.org_id == _ec2_uuid.UUID(org_id),
                        ))
                        _ec2_threat = _ec2_res.scalar_one_or_none()
                        if _ec2_threat:
                            _ec2_ti = dict(_ec2_threat.threat_indicators or {})
                            _ec2_ti["ec2_sandbox_verdict"] = ec2_sandbox_result.verdict
                            _ec2_ti["ec2_sandbox_url_results"] = ec2_sandbox_result.url_results
                            _ec2_ti["ec2_sandbox_attachment_results"] = ec2_sandbox_result.attachment_results
                            _ec2_threat.threat_indicators = _ec2_ti
                            await _ec2_db.commit()
                else:
                    logger.warning(f"auto_triage: EC2 sandbox skipped/errored for {threat_id}: {getattr(ec2_sandbox_result, 'error', 'n/a')}")
            except Exception as _ec2_err:
                logger.warning(f"auto_triage: EC2 sandbox step non-fatal error: {_ec2_err}")

        # ── 6. Build Himaya Analysis dossier and get verdict ─────────────────────
        ti_data = threat_data["threat_indicators"]
        is_user_reported = isinstance(ti_data, dict) and ti_data.get("source") == "user_reported"

        dossier = {
            "threat_id": threat_data["id"],
            "threat_type": threat_data["threat_type"],
            "risk_score": threat_data["risk_score"],
            "llm_classification": threat_data["llm_classification"],
            "llm_confidence": threat_data["llm_confidence"],
            "ai_explanation": threat_data["ai_explanation_en"],
            "sender": threat_data["sender"],
            "sender_domain": sender_domain,
            "recipient": threat_data["recipient_email"],
            "subject": threat_data["subject"],
            "impersonation_detected": threat_data["impersonation_detected"],
            "impersonation_target": threat_data["impersonation_target"],
            "urgency_score": threat_data["urgency_score"],
            "auth_results": {
                "spf": auth_results.get("spf", "unknown"),
                "dkim": auth_results.get("dkim", "unknown"),
                "dmarc": auth_results.get("dmarc", "unknown"),
            },
            "vt_domain": vt_domain_result,
            "vt_urls": vt_url_results,
            "threat_feed_url_matches": feed_url_matches,
            "threat_feed_ip_matches": feed_ip_matches,
            "graph_history": graph_history,
            "attachments": attachment_findings,
            "body_preview": body_preview[:1000] if body_preview else "",
            # User-reported signal — employees rarely report legitimate emails
            "user_reported": is_user_reported,
            "reporter_email": ti_data.get("reporter_email", "") if isinstance(ti_data, dict) else "",
            "source": "user_reported" if is_user_reported else "system",
            "ec2_sandbox": {
                "verdict": getattr(ec2_sandbox_result, "verdict", None),
                "url_results": getattr(ec2_sandbox_result, "url_results", []),
                "attachment_results": getattr(ec2_sandbox_result, "attachment_results", []),
                "error": getattr(ec2_sandbox_result, "error", None),
            } if ec2_sandbox_result else None,
        }

        verdict_data = await _get_helios_verdict(dossier)
        result.update(verdict_data)

        # ── 7. Apply verdict ───────────────────────────────────────────────────
        verdict = verdict_data.get("verdict", "ESCALATE")

        # ── Compute component scores from dossier signals ──────────────────
        vt_malicious = sum(r.get("malicious", 0) for r in vt_url_results)
        vt_suspicious = sum(r.get("suspicious", 0) for r in vt_url_results)
        vt_domain_malicious = vt_domain_result.get("malicious", 0)
        feed_hits = len(feed_url_matches) + len(feed_ip_matches)
        graph_s = graph_history.get("graph_score", 0) or 0
        attachment_risk = sum(1 for f in attachment_findings if f.get("risk") in ("HIGH", "MEDIUM"))
        ec2_malicious = 1 if ec2_sandbox_result and getattr(ec2_sandbox_result, "verdict", "") == "MALICIOUS" else 0
        is_user_reported_boost = 10 if is_user_reported else 0

        # Claude's confidence is a primary content signal —
        # even when VT has no data on new/invented domains,
        # Claude's analysis of the email body/subject/sender IS content scoring
        claude_conf = verdict_data.get("confidence", 0.5)
        claude_content_boost = int(claude_conf * 50) if verdict in ("QUARANTINE", "ESCALATE") else 0

        content_s = min(100, (
            vt_malicious * 25 + vt_suspicious * 10 +
            vt_domain_malicious * 20 + feed_hits * 15 +
            attachment_risk * 15 + ec2_malicious * 30 +
            claude_content_boost  # LLM body analysis score
        ))
        reputation_s = min(100, graph_s + vt_domain_malicious * 20 + feed_hits * 10)
        computed_risk = min(100, max(
            threat_data.get("risk_score", 50),
            int((content_s * 0.4) + (reputation_s * 0.2) + (graph_s * 0.2) +
                (verdict_data.get("confidence", 0.5) * 40) + is_user_reported_boost)
        ))
        # Boost risk for definitive verdicts
        if verdict == "QUARANTINE":
            computed_risk = max(computed_risk, 70)
        elif verdict == "MARK_AS_SPAM":
            computed_risk = max(computed_risk, 40)

        # Build sandbox audit record to persist permanently in DB
        sandbox_audit = None
        if ec2_sandbox_result:
            sandbox_audit = {
                "verdict": getattr(ec2_sandbox_result, "verdict", None),
                "url_results": getattr(ec2_sandbox_result, "url_results", []),
                "attachment_results": getattr(ec2_sandbox_result, "attachment_results", []),
                "error": getattr(ec2_sandbox_result, "error", None),
                "ran_at": datetime.utcnow().isoformat(),
            }

        await _apply_verdict(
            threat_id=threat_id,
            org_id=org_id,
            verdict=verdict,
            threat_type=verdict_data.get("threat_type", "UNKNOWN"),
            confidence=verdict_data.get("confidence", 0.5),
            reasoning=verdict_data.get("reasoning", ""),
            key_evidence=verdict_data.get("key_evidence", []),
            notify_recipient=verdict_data.get("notify_recipient", False),
            notify_admin=verdict_data.get("notify_admin", False),
            graph_score=graph_s,
            content_score=content_s,
            reputation_score=reputation_s,
            risk_score=computed_risk,
            urgency_score=dossier.get("urgency_score", 0) or 0,
            impersonation_detected=dossier.get("impersonation_detected", False),
            impersonation_target=dossier.get("impersonation_target"),
            sandbox_audit=sandbox_audit,
            verdict_model=verdict_data.get("model_used"),
            verdict_cost_usd=verdict_data.get("cost_usd"),
        )
        result["applied"] = True

    except Exception as e:
        logger.error(f"auto_triage: investigate_threat failed for {threat_id}: {e}", exc_info=True)
        result["error"] = str(e)

    return result


# ── Verdict configuration ─────────────────────────────────────────────────────
# Primary: Himaya classifier-service /verdict (Bedrock Kimi K2.5)
# Fallback (TIMEOUT ONLY): Anthropic Claude Haiku
# Catastrophic: risk-score heuristic
_USE_REMOTE_VERDICT = os.getenv("USE_REMOTE_VERDICT", "true").lower() in ("true", "1", "yes")
_VERDICT_SERVICE_URL = os.getenv(
    "CLASSIFIER_SERVICE_URL",
    "http://classify-lb-556047835.us-east-1.elb.amazonaws.com",
).rstrip("/")
_VERDICT_PRIMARY_TIMEOUT = float(os.getenv("VERDICT_SERVICE_TIMEOUT", "60"))   # Kimi can be slow
_VERDICT_FALLBACK_TIMEOUT = float(os.getenv("VERDICT_FALLBACK_TIMEOUT", "25"))


def _heuristic_verdict(dossier: dict, reason: str = "") -> dict:
    """Risk-score heuristic verdict — last resort when both LLMs fail."""
    risk = dossier.get("risk_score", 0) or 0
    if risk >= 75:
        verdict = "QUARANTINE"
    elif risk >= 50:
        verdict = "ESCALATE"
    else:
        verdict = "DISMISS"
    return {
        "verdict": verdict,
        "threat_type": "UNKNOWN",
        "confidence": 0.5,
        "reasoning": (
            f"Himaya Analysis heuristic fallback ({reason}). "
            f"Verdict based on risk score ({risk})."
        ).strip(),
        "key_evidence": [f"risk_score:{risk}"],
        "notify_recipient": False,
        "notify_admin": verdict in ("QUARANTINE", "ESCALATE"),
        "model_used": "heuristic_fallback",
        "cost_usd": 0.0,
    }


async def _haiku_verdict_fallback(dossier: dict, anthropic_key: str) -> dict:
    """
    Claude Haiku Himaya-Analysis verdict — invoked ONLY when the remote
    /verdict service times out. Uses the same prompt + JSON contract.
    """
    user_message = (
        "Please analyse the following threat dossier and return your verdict as JSON:\n\n"
        + json.dumps(dossier, indent=2, default=str)
    )
    try:
        async with httpx.AsyncClient(timeout=_VERDICT_FALLBACK_TIMEOUT) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 1024,
                    "system": _build_helios_system_prompt(),
                    "messages": [{"role": "user", "content": user_message}],
                },
            )
            if resp.status_code != 200:
                logger.warning(f"auto_triage: Haiku fallback returned {resp.status_code}")
                return _heuristic_verdict(dossier, f"haiku HTTP {resp.status_code}")

            body = resp.json()
            content = body.get("content", [])
            raw_text = content[0].get("text", "") if content else ""
            json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if not json_match:
                logger.warning("auto_triage: Haiku fallback returned no JSON")
                return _heuristic_verdict(dossier, "haiku no JSON")
            parsed = json.loads(json_match.group())

            # Same validation as before
            valid_verdicts = {"QUARANTINE", "MARK_AS_SPAM", "ESCALATE", "DISMISS"}
            verdict = parsed.get("verdict", "ESCALATE")
            if verdict not in valid_verdicts:
                verdict = "ESCALATE"
            valid_threat_types = {"PHISHING", "BEC", "MALWARE", "SPAM", "SAFE", "UNKNOWN"}
            threat_type = parsed.get("threat_type", "UNKNOWN")
            if threat_type not in valid_threat_types:
                threat_type = "UNKNOWN"

            # Compute Haiku cost (BEDROCK Haiku is also separately priced, but here we
            # call Anthropic API direct: $1/M in, $5/M out for claude-haiku-4-5)
            usage = body.get("usage", {})
            in_tok = usage.get("input_tokens", 0)
            out_tok = usage.get("output_tokens", 0)
            cost = (in_tok * 1.0 + out_tok * 5.0) / 1_000_000

            logger.info(
                f"auto_triage: HAIKU FALLBACK ok verdict={verdict} "
                f"in={in_tok} out={out_tok} cost=${cost:.5f}"
            )

            return {
                "verdict": verdict,
                "threat_type": threat_type,
                "confidence": float(parsed.get("confidence", 0.5)),
                "reasoning": str(parsed.get("reasoning", "")),
                "key_evidence": list(parsed.get("key_evidence", []) or []),
                "notify_recipient": bool(parsed.get("notify_recipient", False)),
                "notify_admin": bool(parsed.get("notify_admin", verdict in ("QUARANTINE", "ESCALATE"))),
                "model_used": "claude-haiku-4-5-fallback",
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "cost_usd": cost,
            }
    except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.WriteTimeout, asyncio.TimeoutError) as exc:
        logger.warning(f"auto_triage: Haiku fallback ALSO timed out: {exc}")
        return _heuristic_verdict(dossier, "haiku timeout")
    except Exception as exc:
        logger.warning(f"auto_triage: Haiku fallback errored: {exc}")
        return _heuristic_verdict(dossier, f"haiku error: {exc}")


async def _get_helios_verdict(dossier: dict) -> dict:
    """
    Get verdict from the Himaya classifier-service /verdict endpoint (Bedrock Kimi K2.5).

    Fallback chain (matches Stage-1 design):
      Kimi (primary, 60s timeout)
        → on TIMEOUT only: Claude Haiku (25s timeout)
          → on any failure: risk-score heuristic
      Non-timeout HTTP error from primary: skip Haiku, go straight to heuristic
        (a 5xx or auth error means the system is broken — burning Anthropic spend
         won't help; the heuristic produces a sane verdict instantly).

    Legacy path (USE_REMOTE_VERDICT=false): direct Anthropic Opus call.
    """
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

    # ── Remote path (default) ──────────────────────────────────────────────
    if _USE_REMOTE_VERDICT:
        url = f"{_VERDICT_SERVICE_URL}/verdict"
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=_VERDICT_PRIMARY_TIMEOUT) as client:
                resp = await client.post(url, json=dossier)
            if resp.status_code != 200:
                logger.warning(
                    f"auto_triage: /verdict returned HTTP {resp.status_code} — "
                    f"using heuristic fallback (not Haiku — non-timeout error)"
                )
                return _heuristic_verdict(dossier, f"remote HTTP {resp.status_code}")

            verdict_data = resp.json()
            elapsed = (time.perf_counter() - t0) * 1000
            logger.info(
                f"auto_triage: remote verdict={verdict_data.get('verdict')} "
                f"model={verdict_data.get('model_used', '?')} "
                f"cost=${verdict_data.get('cost_usd', 0):.5f} "
                f"latency={elapsed:.0f}ms"
            )
            return verdict_data

        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.WriteTimeout,
                httpx.PoolTimeout, asyncio.TimeoutError) as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.warning(
                f"auto_triage: /verdict TIMEOUT after {elapsed:.0f}ms ({type(exc).__name__}) — "
                f"falling back to Haiku"
            )
            if anthropic_key:
                return await _haiku_verdict_fallback(dossier, anthropic_key)
            return _heuristic_verdict(dossier, "timeout, no Anthropic key")

        except Exception as exc:
            logger.warning(f"auto_triage: /verdict error: {exc} — using heuristic")
            return _heuristic_verdict(dossier, f"remote error: {exc}")

    # ── Legacy path (USE_REMOTE_VERDICT=false): direct Anthropic Opus ─────
    if not anthropic_key:
        logger.warning("auto_triage: Himaya Analysis engine not configured — defaulting to ESCALATE")
        return {
            "verdict": "ESCALATE",
            "confidence": 0.5,
            "reasoning": "Himaya Analysis engine unavailable. Manual review required.",
            "key_evidence": [f"risk_score:{dossier.get('risk_score', 0)}"],
            "notify_recipient": False,
            "notify_admin": True,
            "model_used": "unavailable",
            "cost_usd": 0.0,
        }

    user_message = (
        "Please analyse the following threat dossier and return your verdict as JSON:\n\n"
        + json.dumps(dossier, indent=2, default=str)
    )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-5-20251101",
                    "max_tokens": 1024,
                    "system": _build_helios_system_prompt(),
                    "messages": [{"role": "user", "content": user_message}],
                },
            )
            if resp.status_code != 200:
                logger.warning(f"auto_triage: Himaya Analysis engine returned {resp.status_code}")
                raise ValueError(f"Himaya Analysis engine error: {resp.status_code}")

            content = resp.json().get("content", [])
            raw_text = content[0].get("text", "") if content else ""
            json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON found in Himaya Analysis response")

            verdict_json = json.loads(json_match.group())
            verdict = verdict_json.get("verdict", "ESCALATE")
            valid_verdicts = {"QUARANTINE", "MARK_AS_SPAM", "ESCALATE", "DISMISS"}
            if verdict not in valid_verdicts:
                verdict = "ESCALATE"
            raw_threat_type = verdict_json.get("threat_type", "UNKNOWN")
            valid_threat_types = {"PHISHING", "BEC", "MALWARE", "SPAM", "SAFE", "UNKNOWN"}
            threat_type = raw_threat_type if raw_threat_type in valid_threat_types else "UNKNOWN"

            return {
                "verdict": verdict,
                "threat_type": threat_type,
                "confidence": float(verdict_json.get("confidence", 0.5)),
                "reasoning": str(verdict_json.get("reasoning", "")),
                "key_evidence": list(verdict_json.get("key_evidence", [])),
                "notify_recipient": bool(verdict_json.get("notify_recipient", False)),
                "notify_admin": bool(verdict_json.get("notify_admin", False)),
                "model_used": "claude-opus-4-5-20251101",
            }

    except Exception as e:
        logger.warning(f"auto_triage: legacy Opus verdict failed: {e}")
        return _heuristic_verdict(dossier, f"opus error: {e}")


async def _apply_verdict(
    threat_id: str,
    org_id: str,
    verdict: str,
    threat_type: str,
    confidence: float,
    reasoning: str,
    key_evidence: list,
    notify_recipient: bool,
    notify_admin: bool,
    graph_score: int = 0,
    content_score: int = 0,
    reputation_score: int = 0,
    risk_score: int = 50,
    urgency_score: int = 0,
    impersonation_detected: bool = False,
    impersonation_target: str = None,
    sandbox_audit: dict | None = None,
    verdict_model: str | None = None,
    verdict_cost_usd: float | None = None,
) -> None:
    """Apply auto-triage verdict to the threat record."""
    try:
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import Threat
        from sqlalchemy import select
        import uuid as _uuid

        now = datetime.utcnow()
        async with AsyncSessionLocal() as db:
            t_result = await db.execute(
                select(Threat).where(
                    Threat.id == _uuid.UUID(threat_id),
                    Threat.org_id == _uuid.UUID(org_id),
                )
            )
            threat = t_result.scalar_one_or_none()
            if not threat:
                return

            # Write back all computed scores and classification
            if threat_type and threat_type != "UNKNOWN":
                threat.threat_type = threat_type
                threat.llm_classification = threat_type  # alias for legacy compat
            threat.llm_confidence = float(confidence) if confidence is not None else 0.5
            # Tag the model that produced THIS verdict, so threats correctly show
            # moonshotai.kimi-k2.5 (or claude-haiku-4-5-fallback, or heuristic_fallback)
            # instead of the legacy hardcoded Opus string.
            if verdict_model:
                threat.llm_model = verdict_model
            else:
                threat.llm_model = "claude-opus-4-5-20251101"
            # Add the verdict (stage-2) cost on top of any stage-1 classifier cost so
            # the per-threat llm_cost_usd reflects total LLM spend, not just one stage.
            if verdict_cost_usd is not None:
                existing = float(threat.llm_cost_usd or 0)
                threat.llm_cost_usd = existing + float(verdict_cost_usd)
            threat.ai_explanation_en = reasoning
            threat.risk_score = risk_score
            threat.graph_score = graph_score
            threat.content_score = content_score
            threat.reputation_score = reputation_score
            threat.urgency_score = urgency_score
            threat.impersonation_detected = impersonation_detected
            if impersonation_target:
                threat.impersonation_target = impersonation_target
            # Update score breakdown — include full sandbox audit trail
            threat.score_breakdown = {
                "graph": graph_score,
                "content": content_score,
                "reputation": reputation_score,
                "confidence_boost": int(confidence * 40),
                "final": risk_score,
                "sources": {
                    "vt_domain": bool(graph_score > 35),
                    "llm_analysis": True,
                    "graph_history": graph_score > 0,
                    "ec2_sandbox": sandbox_audit is not None,
                },
                # Sandbox result persisted permanently here (not Redis)
                "sandbox": sandbox_audit,
            }

            # Tag auto-triage result in indicators
            existing_ti = dict(threat.threat_indicators or {})
            existing_ti["auto_triaged"] = True
            existing_ti["auto_triage_verdict"] = verdict
            existing_ti["auto_triage_threat_type"] = threat_type
            existing_ti["auto_triage_confidence"] = confidence
            existing_ti["auto_triage_reasoning"] = reasoning
            existing_ti["auto_triage_evidence"] = key_evidence
            existing_ti["auto_triage_at"] = now.isoformat()
            # Sandbox verdict in audit trail
            if sandbox_audit:
                existing_ti["ec2_sandbox_verdict"] = sandbox_audit.get("verdict")
                existing_ti["ec2_sandbox_url_results"] = sandbox_audit.get("url_results", [])
                existing_ti["ec2_sandbox_attachment_results"] = sandbox_audit.get("attachment_results", [])
                existing_ti["ec2_sandbox_ran_at"] = sandbox_audit.get("ran_at")
            threat.threat_indicators = existing_ti

            if verdict == "QUARANTINE":
                threat.action_taken = "QUARANTINED"
                threat.status = "resolved"   # resolved + action=QUARANTINED means contained
                threat.resolved_at = now
                # Physically move the email to quarantine folder
                try:
                    from backend.services.quarantine_service import quarantine_gmail_message, quarantine_m365_message_with_fallback
                    if threat.email_message_id and threat.recipient_email:
                        is_m365 = len(threat.email_message_id or '') > 100 or (threat.email_message_id or '').startswith('AAMk')
                        if is_m365:
                            asyncio.create_task(quarantine_m365_message_with_fallback(
                                user_email=threat.recipient_email,
                                m365_message_id=threat.email_message_id,
                                org_id=org_id,
                            ))
                        else:
                            asyncio.create_task(quarantine_gmail_message(
                                user_email=threat.recipient_email,
                                gmail_message_id=threat.email_message_id,
                            ))
                except Exception as _qe:
                    logger.warning(f"auto_triage: physical quarantine move failed (non-fatal): {_qe}")

                # Update Neo4j — add FLAGGED_AS edge so future graph scoring is informed
                try:
                    from backend.services.graph_service import graph_service
                    if threat.sender and threat_type and threat_type not in ("CLEAN", "SAFE", "UNKNOWN"):
                        await graph_service.record_threat(
                            sender=threat.sender,
                            threat_type=threat_type,
                        )
                except Exception as _gqe:
                    logger.debug(f"auto_triage: graph QUARANTINE update failed (non-fatal): {_gqe}")

            elif verdict == "MARK_AS_SPAM":
                threat.action_taken = "MARKED_SPAM"
                threat.status = "resolved"  # spam = resolved (moved to junk)
                threat.resolved_at = now
                # Physically move the email to spam/junk folder
                try:
                    from backend.services.quarantine_service import mark_as_spam_gmail, mark_as_spam_m365
                    if threat.email_message_id and threat.recipient_email:
                        is_m365 = len(threat.email_message_id or '') > 100 or (threat.email_message_id or '').startswith('AAMk')
                        if is_m365:
                            asyncio.create_task(mark_as_spam_m365(
                                user_email=threat.recipient_email,
                                m365_message_id=threat.email_message_id,
                                org_id=org_id,
                            ))
                        else:
                            asyncio.create_task(mark_as_spam_gmail(
                                user_email=threat.recipient_email,
                                gmail_message_id=threat.email_message_id,
                            ))
                except Exception as _se:
                    logger.warning(f"auto_triage: physical spam move failed (non-fatal): {_se}")

            elif verdict == "ESCALATE":
                # Escalated = needs human review, stays open
                threat.status = "open"
                threat.action_taken = "FLAGGED_HIGH"
                # Apply Himaya-Suspicious label/category so recipient sees it
                try:
                    from backend.services.quarantine_service import (
                        _get_or_create_named_label,
                        apply_category_m365,
                        _get_sa_headers_async,
                    )
                    import httpx as _hx
                    if threat.email_message_id and threat.recipient_email:
                        is_m365 = len(threat.email_message_id or '') > 100 or (threat.email_message_id or '').startswith('AAMk')
                        if is_m365:
                            asyncio.create_task(apply_category_m365(
                                user_email=threat.recipient_email,
                                m365_message_id=threat.email_message_id,
                                category_name="Himaya-Suspicious",
                                org_id=org_id,
                            ))
                        else:
                            # Gmail: apply orange Himaya-Suspicious label
                            async def _apply_escalated_label(email, msg_id):
                                try:
                                    hdrs = await _get_sa_headers_async(email)
                                    if not hdrs:
                                        return
                                    async with _hx.AsyncClient(timeout=15) as _cl:
                                        label_id = await _get_or_create_named_label(
                                            _cl, hdrs, email,
                                            name="Himaya-Suspicious",
                                            bg_color="#fb4c2f",  # bright-red — valid Gmail palette
                                            text_color="#ffffff",
                                        )
                                        if label_id:
                                            await _cl.post(
                                                f"https://gmail.googleapis.com/gmail/v1/users/{email}/messages/{msg_id}/modify",
                                                headers={**hdrs, "Content-Type": "application/json"},
                                                json={"addLabelIds": [label_id]},
                                            )
                                except Exception as _le:
                                    logger.debug(f"Himaya-Suspicious label failed: {_le}")
                            asyncio.create_task(_apply_escalated_label(
                                threat.recipient_email, threat.email_message_id
                            ))
                except Exception as _ee:
                    logger.warning(f"auto_triage: Himaya-Suspicious label failed (non-fatal): {_ee}")

                # Send recipient notification via SES
                if threat.recipient_email and threat.sender:
                    try:
                        import asyncio as _sus_asyncio
                        from backend.services.email_service import send_suspicious_recipient_notification as _send_sus
                        _sus_factors = []
                        _sus_ti = threat.threat_indicators or {}
                        for _k in ("content", "graph", "reputation"):
                            _sus_factors.extend(_sus_ti.get(_k, [])[:4])
                        _sus_asyncio.create_task(_sus_asyncio.to_thread(
                            _send_sus,
                            to_email=threat.recipient_email,
                            sender_email=threat.sender or "",
                            subject=threat.subject or "(No Subject)",
                            threat_type=threat.threat_type or "Suspicious Content",
                            risk_score=int(threat.risk_score or 0),
                            explanation=threat.ai_explanation_en or "",
                            key_factors=_sus_factors[:8],
                        ))
                        logger.info(f"Himaya-Suspicious recipient notification queued for {threat.recipient_email}")
                    except Exception as _sue:
                        logger.warning(f"auto_triage: Himaya-Suspicious SES notification failed (non-fatal): {_sue}")

            elif verdict == "DISMISS":
                # Dismissed = clean / false positive, mark resolved
                threat.status = "resolved"
                threat.action_taken = "CLEAN"
                threat.resolved_at = now
                # If user-reported and dismissed as SAFE/clean, mark as confirmed false positive
                # so it feeds back into graph training correctly and is visible in the UI
                _ti_dismiss = dict(threat.threat_indicators or {})
                if _ti_dismiss.get("source") == "user_reported":
                    threat.false_positive = True
                    logger.info(
                        f"auto_triage: user-reported threat={threat_id} dismissed as SAFE "
                        f"→ flagged false_positive=True for graph feedback"
                    )
                    try:
                        from backend.services.quarantine_service import (
                            apply_category_m365,
                            _get_sa_headers_async,
                            _get_or_create_named_label,
                        )
                        import httpx as _hx
                        if threat.email_message_id and threat.recipient_email:
                            is_m365 = len(threat.email_message_id or '') > 100 or (threat.email_message_id or '').startswith('AAMk')
                            if is_m365:
                                # Move back to inbox via Graph API
                                async def _restore_to_inbox_m365(_email, _msg_id, _oid):
                                    try:
                                        from backend.services.quarantine_service import _get_m365_token_for_user
                                        token = await _get_m365_token_for_user(_email, _oid)
                                        if not token:
                                            return
                                        async with _hx.AsyncClient(timeout=15) as _cl:
                                            await _cl.post(
                                                f"https://graph.microsoft.com/v1.0/users/{_email}/messages/{_msg_id}/move",
                                                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                                                json={"destinationId": "inbox"},
                                            )
                                    except Exception as _re:
                                        logger.debug(f"Restore to inbox (M365) failed: {_re}")
                                asyncio.create_task(_restore_to_inbox_m365(
                                    threat.recipient_email, threat.email_message_id, org_id
                                ))
                            else:
                                # Gmail: remove Himaya-Review label and restore INBOX
                                async def _restore_to_inbox_gmail(_email, _msg_id):
                                    try:
                                        hdrs = await _get_sa_headers_async(_email)
                                        if not hdrs:
                                            return
                                        async with _hx.AsyncClient(timeout=15) as _cl:
                                            label_id = await _get_or_create_named_label(
                                                _cl, hdrs, _email,
                                                name="Himaya-Review",
                                                bg_color="#16a765",
                                                text_color="#ffffff",
                                            )
                                            modify_body = {"addLabelIds": ["INBOX"], "removeLabelIds": []}
                                            if label_id:
                                                modify_body["removeLabelIds"].append(label_id)
                                            await _cl.post(
                                                f"https://gmail.googleapis.com/gmail/v1/users/{_email}/messages/{_msg_id}/modify",
                                                headers={**hdrs, "Content-Type": "application/json"},
                                                json=modify_body,
                                            )
                                    except Exception as _re:
                                        logger.debug(f"Restore to inbox (Gmail) failed: {_re}")
                                asyncio.create_task(_restore_to_inbox_gmail(
                                    threat.recipient_email, threat.email_message_id
                                ))
                    except Exception as _dismiss_e:
                        logger.warning(f"auto_triage: restore to inbox failed (non-fatal): {_dismiss_e}")

            # Capture values needed for post-commit training signals
            _ti_final = dict(threat.threat_indicators or {})
            _threat_sender = threat.sender or ""
            _threat_sender_domain = threat.sender_domain or ""
            _threat_type = threat.threat_type or "UNKNOWN"

            await db.commit()
            logger.info(
                f"auto_triage: applied verdict={verdict} conf={confidence:.2f} "
                f"to threat={threat_id}"
            )

        # ── Post-commit training signals (user_reported only) ─────────────────
        if _ti_final.get("source") == "user_reported":
            _reporter = _ti_final.get("reporter_email", "")

            # Neo4j training signal
            try:
                from backend.services.graph_service import graph_service
                label = "PHISHING" if verdict in ("QUARANTINE", "ESCALATE") else "BENIGN"
                await graph_service.record_report_signal(
                    org_id=org_id,
                    sender=_threat_sender,
                    reporter=_reporter,
                    label=label,
                    threat_id=threat_id,
                )
            except Exception as _ge:
                logger.debug(f"auto_triage: graph training signal failed: {_ge}")

            # Redis retrain queue
            try:
                import redis.asyncio as _rds
                import json as _j
                import os as _os
                _r = _rds.from_url(_os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
                signal = {
                    "type": "user_reported",
                    "verdict": verdict,
                    "threat_id": str(threat_id),
                    "sender_domain": _threat_sender_domain,
                    "sender_email": _threat_sender,
                    "threat_type": _threat_type,
                    "reporter": _reporter,
                    "org_id": org_id,
                    "reported_at": now.isoformat(),
                    "false_positive": verdict == "DISMISS",
                }
                await _r.lpush("helios:retrain_queue", _j.dumps(signal))
                await _r.expire("helios:retrain_queue", 86400 * 30)
                await _r.aclose()
            except Exception as _re:
                logger.debug(f"auto_triage: retrain queue push failed: {_re}")

    except Exception as e:
        logger.error(f"auto_triage: _apply_verdict failed: {e}", exc_info=True)


# ── Auto-triage background loop ───────────────────────────────────────────────

async def run_auto_triage_loop(org_id: str) -> None:
    """
    Runs continuously while the per-org toggle is enabled in Redis.
    Processes up to 5 threats per cycle on a 2-minute interval.
    Each org gets its own loop task when toggled on.
    """
    import redis.asyncio as aioredis
    from backend.config import settings as _cfg

    logger.info(f"auto_triage: loop started for org={org_id}")

    while True:
        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            enabled = await _redis.get(f"auto_triage:enabled:{org_id}")
            if not enabled:
                logger.info(f"auto_triage: loop stopping for org={org_id} (disabled)")
                break

            # Write loop status — TTL slightly longer than the 2-min sleep so it
            # never goes stale between cycles (was 300s which caused running=False)
            await _redis.set(
                f"auto_triage:status:{org_id}",
                json.dumps({"running": True, "last_run": time.time(), "org_id": org_id}),
                ex=180,  # 3 min — refreshed every 2 min cycle
            )

            # Find up to 5 open threats not yet auto-triaged
            threats_to_process = await _find_pending_threats(org_id, limit=5)
            logger.info(f"auto_triage: org={org_id} found {len(threats_to_process)} threats to investigate")

            for tid in threats_to_process:
                try:
                    inv_result = await investigate_threat(str(tid), org_id)
                    logger.info(
                        f"auto_triage: threat={tid} verdict={inv_result.get('verdict')} "
                        f"conf={inv_result.get('confidence', 0):.2f} applied={inv_result.get('applied')}"
                    )
                except Exception as e:
                    logger.warning(f"auto_triage: investigation failed for {tid}: {e}")

            # Update completion status — keep running=True since the loop continues;
            # only set running=False when the loop actually exits (disabled or error).
            await _redis.set(
                f"auto_triage:status:{org_id}",
                json.dumps({
                    "running": True,
                    "last_run": time.time(),
                    "last_processed": len(threats_to_process),
                    "org_id": org_id,
                }),
                ex=180,  # refreshed every cycle
            )

            # ── 24h rollup email ────────────────────────────────────────────
            # Fire once every 24h after auto-triage was first enabled.
            last_rollup_raw = await _redis.get(f"auto_triage:last_rollup:{org_id}")
            last_rollup_ts = float(last_rollup_raw) if last_rollup_raw else 0.0
            if time.time() - last_rollup_ts >= 86400:  # 24h
                try:
                    await send_triage_rollup_email(org_id)
                    await _redis.set(f"auto_triage:last_rollup:{org_id}", str(time.time()), ex=172800)
                    logger.info(f"auto_triage: 24h rollup email sent for org={org_id}")
                except Exception as _re:
                    logger.warning(f"auto_triage: rollup email failed for org={org_id}: {_re}")

        except Exception as e:
            logger.error(f"auto_triage: loop error for org={org_id}: {e}", exc_info=True)
        finally:
            await _redis.aclose()

        await asyncio.sleep(120)  # 2-minute interval


# ── 24h Auto-Triage Rollup Email ─────────────────────────────────────────────

async def send_triage_rollup_email(org_id: str) -> None:
    """
    Sends a 24-hour auto-triage rollup email to all tenant admins.
    Summarises every action Himaya Analysis took automatically in the past 24 hours:
    quarantined, marked spam, escalated, dismissed.
    Triggered once per 24h while auto-triage is enabled for the org.
    """
    from backend.database import AsyncSessionLocal
    from backend.models.db_models import Organization, User, Threat
    from backend.services.email_service import send_email
    from sqlalchemy import select, func
    import uuid as _uuid

    since = datetime.utcnow() - timedelta(hours=24)

    async with AsyncSessionLocal() as db:
        # Load org
        org_res = await db.execute(
            select(Organization).where(Organization.id == _uuid.UUID(org_id))
        )
        org = org_res.scalar_one_or_none()
        if not org:
            logger.warning(f"auto_triage rollup: org {org_id} not found")
            return

        # Load all threats auto-triaged in the past 24h
        triaged_res = await db.execute(
            select(Threat).where(
                Threat.org_id == _uuid.UUID(org_id),
                Threat.threat_indicators["auto_triaged"].as_boolean() == True,  # noqa: E712
            ).order_by(Threat.risk_score.desc()).limit(100)
        )
        all_triaged = triaged_res.scalars().all()

        # Filter to only those triaged in the past 24h
        recent_triaged = []
        for t in all_triaged:
            ti = t.threat_indicators or {}
            triaged_at_str = ti.get("auto_triage_at")
            if triaged_at_str:
                try:
                    ta = datetime.fromisoformat(triaged_at_str.replace("Z", "+00:00").replace("+00:00", ""))
                    if ta >= since:
                        recent_triaged.append(t)
                except Exception:
                    pass

        # Count by verdict
        counts = {"QUARANTINE": 0, "MARK_AS_SPAM": 0, "ESCALATE": 0, "DISMISS": 0}
        for t in recent_triaged:
            ti = t.threat_indicators or {}
            v = ti.get("auto_triage_verdict", "ESCALATE")
            counts[v] = counts.get(v, 0) + 1

        total = sum(counts.values())

        # Notify all admins
        admins_res = await db.execute(
            select(User).where(
                User.org_id == _uuid.UUID(org_id),
                User.role.in_(["admin"]),
                User.is_active == True,  # noqa: E712
            )
        )
        admins = admins_res.scalars().all()

        if not admins:
            logger.info(f"auto_triage rollup: no admins found for org={org_id}, skipping email")
            return

        html = _build_triage_rollup_html(
            org_name=org.name,
            counts=counts,
            total=total,
            top_threats=recent_triaged[:8],
        )

        subject = (
            f"Himaya Auto-Triage Report — {org.name} — "
            f"{datetime.utcnow().strftime('%b %d, %Y')}"
        )

        for admin in admins:
            try:
                send_email(to=admin.email, subject=subject, html_body=html)
                logger.info(f"auto_triage rollup: sent to {admin.email} for org={org_id}")
            except Exception as e:
                logger.warning(f"auto_triage rollup: email to {admin.email} failed: {e}")


def _build_triage_rollup_html(
    org_name: str,
    counts: dict,
    total: int,
    top_threats: list,
) -> str:
    """Build the HTML email for the 24h auto-triage rollup."""
    quarantined = counts.get("QUARANTINE", 0)
    spammed = counts.get("MARK_AS_SPAM", 0)
    escalated = counts.get("ESCALATE", 0)
    dismissed = counts.get("DISMISS", 0)

    summary_color = "#ef4444" if quarantined + escalated > 0 else "#22c55e"
    summary_text = (
        f"Himaya Analysis automatically handled {total} threat{'s' if total != 1 else ''} "
        f"in the past 24 hours."
        if total > 0
        else "Himaya Analysis reviewed your mailbox traffic — no threats required automated action."
    )

    # Action rows for top threats table
    verdict_labels = {
        "QUARANTINE": ("Quarantined", "#ef4444"),
        "MARK_AS_SPAM": ("Marked Spam", "#f59e0b"),
        "ESCALATE": ("Escalated", "#f97316"),
        "DISMISS": ("Dismissed", "#22c55e"),
    }
    threat_rows = ""
    for t in top_threats:
        ti = t.threat_indicators or {}
        verdict = ti.get("auto_triage_verdict", "ESCALATE")
        conf = ti.get("auto_triage_confidence", 0)
        label, color = verdict_labels.get(verdict, (verdict, "#94a3b8"))
        conf_pct = f"{int(conf * 100)}%" if conf else "—"
        triaged_at = ti.get("auto_triage_at", "")
        triaged_disp = ""
        if triaged_at:
            try:
                triaged_disp = datetime.fromisoformat(
                    triaged_at.replace("Z", "+00:00").replace("+00:00", "")
                ).strftime("%H:%M UTC")
            except Exception:
                triaged_disp = triaged_at[:16]

        threat_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
          <td style="padding:8px 12px;font-size:11px;color:#94a3b8;max-width:160px;overflow:hidden;">{t.sender or '—'}</td>
          <td style="padding:8px 12px;font-size:11px;color:#e2e8f0;max-width:140px;overflow:hidden;">{t.recipient_email or '—'}</td>
          <td style="padding:8px 12px;">
            <span style="font-size:11px;font-weight:700;color:{color};">{label}</span>
          </td>
          <td style="padding:8px 12px;font-size:11px;color:#64748b;">{conf_pct}</td>
          <td style="padding:8px 12px;font-size:10px;color:#475569;">{triaged_disp}</td>
        </tr>"""

    stat_blocks = f"""
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
        <tr>
          <td width="25%" style="padding-right:8px;">
            <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Quarantined</div>
              <div style="color:#ef4444;font-size:26px;font-weight:800;margin-top:4px;">{quarantined}</div>
            </div>
          </td>
          <td width="25%" style="padding-right:8px;">
            <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Marked Spam</div>
              <div style="color:#f59e0b;font-size:26px;font-weight:800;margin-top:4px;">{spammed}</div>
            </div>
          </td>
          <td width="25%" style="padding-right:8px;">
            <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Escalated</div>
              <div style="color:#f97316;font-size:26px;font-weight:800;margin-top:4px;">{escalated}</div>
            </div>
          </td>
          <td width="25%">
            <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Dismissed</div>
              <div style="color:#22c55e;font-size:26px;font-weight:800;margin-top:4px;">{dismissed}</div>
            </div>
          </td>
        </tr>
      </table>"""

    table_section = ""
    if top_threats:
        table_section = f"""
      <h3 style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin:0 0 12px 0;">Actions Taken by Himaya Analysis</h3>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#0d1117;border-radius:8px;border:1px solid #1e293b;margin-bottom:24px;">
        <thead>
          <tr style="border-bottom:1px solid #1e293b;">
            <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Sender</th>
            <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Target</th>
            <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Action</th>
            <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Confidence</th>
            <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Time</th>
          </tr>
        </thead>
        <tbody>{threat_rows}</tbody>
      </table>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:system-ui,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:40px auto;">
  <tr><td style="background:#111117;border-radius:12px 12px 0 0;padding:28px 32px;border-bottom:1px solid #1e293b;">
    <table cellpadding="0" cellspacing="0">
      <tr>
        <td bgcolor="#1a1f3c" style="padding:8px 18px;border-radius:10px;background:#1a1f3c;border:1px solid #2a3f80;">
          <img src="https://app.himaya.ai/himaya-logo.png" alt="Himaya" width="120" height="27"
               style="display:block;border:0;outline:0;height:auto;" />
        </td>
        <td style="padding-left:14px;">
          <div style="color:#3b6ef6;font-size:12px;font-weight:700;letter-spacing:.04em;">HELIOS ANALYSIS</div>
          <div style="color:#64748b;font-size:11px;margin-top:2px;">AUTO-TRIAGE REPORT — PAST 24 HOURS</div>
        </td>
      </tr>
    </table>
  </td></tr>
  <tr><td style="background:#111117;padding:24px 32px;">
    <div style="background:#0d1117;border-radius:8px;padding:16px 20px;border-left:4px solid {summary_color};margin-bottom:20px;">
      <div style="color:#e2e8f0;font-size:14px;font-weight:600;">{org_name}</div>
      <div style="color:{summary_color};font-size:13px;margin-top:4px;">{summary_text}</div>
    </div>
    {stat_blocks}
    {table_section}
    <div style="background:#0d1117;border-radius:8px;padding:14px 20px;border:1px solid #1e293b;">
      <p style="color:#64748b;font-size:11px;margin:0;">
        This report was generated automatically by Himaya Analysis.
        Actions reflect the Himaya Auto-Triage engine decisions based on threat intelligence,
        sender reputation, and behavioural analysis.
        To review or override any action, visit your
        <a href="https://app.himaya.ai/threats" style="color:#3b6ef6;">Threats dashboard</a>.
      </p>
    </div>
  </td></tr>
  <tr><td style="background:#0d0d12;padding:16px 32px;border-radius:0 0 12px 12px;border-top:1px solid #1e293b;">
    <p style="color:#475569;font-size:11px;margin:0;">Himaya by Himaya Technologies · <a href="https://app.himaya.ai" style="color:#3b6ef6;">app.himaya.ai</a></p>
  </td></tr>
</table>
</body></html>"""


async def _find_pending_threats(org_id: str, limit: int = 5) -> list:
    """
    Find threat IDs that have not yet been auto-triaged.
    Picks up ANY non-CLEAN threat regardless of status or score —
    the classifier label is the trigger, not the numeric score.
    Excludes already-quarantined, blocked, false-positive, and exclude_auto_triage threats.
    """
    try:
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import Threat
        from sqlalchemy import select, or_
        import uuid as _uuid

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Threat.id, Threat.threat_indicators).where(
                    Threat.org_id == _uuid.UUID(org_id),
                    # Any non-clean classification — score doesn't matter
                    Threat.threat_type.notin_(["CLEAN", "BENIGN"]),
                    Threat.threat_type.isnot(None),
                    # Skip already-actioned threats
                    Threat.action_taken.notin_([
                        "QUARANTINED", "QUARANTINE", "BLOCK_DELETE",
                        "FALSE_POSITIVE", "MARKED_SPAM",
                        "DRAFT_DLP_ALERT",  # analyst-review only, never auto-act
                    ]),
                    Threat.status.notin_(["false_positive", "quarantined"]),
                    # Skip threats explicitly excluded from auto-triage (DLP drafts, manual escalations)
                    or_(Threat.exclude_auto_triage.is_(None), Threat.exclude_auto_triage == False),
                ).order_by(Threat.detected_at.desc()).limit(limit * 3)  # fetch extra, filter in Python
            )
            rows = result.fetchall()

            # Filter out already-triaged in Python
            pending = []
            for row in rows:
                tid, ti = row[0], row[1]
                if ti and isinstance(ti, dict) and ti.get("auto_triaged"):
                    continue  # Already processed
                pending.append(str(tid))
                if len(pending) >= limit:
                    break

            return pending
    except Exception as e:
        logger.exception(f"auto_triage: _find_pending_threats failed: {e!r}")
        return []
