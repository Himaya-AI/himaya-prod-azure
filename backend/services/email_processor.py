"""
Core email processing pipeline.
SQS → content analysis → graph analysis → reputation check → risk scoring → DB storage
"""
import asyncio
import hashlib
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.db_models import Threat, ComplianceEvidence
from backend.services.reputation_client import analyze_email_reputation
from backend.services.graph_client import graph_client
from backend.services.websocket_manager import manager as ws_manager

logger = logging.getLogger(__name__)

THREAT_TYPES = [
    "BEC",                  # Business Email Compromise — wire transfer / CEO fraud
    "VEC",                  # Vendor/Supplier Email Compromise — impersonating a vendor
    "PHISHING",             # Generic phishing (credential harvesting, fake login)
    "CREDENTIAL_HARVESTING",# Dedicated credential theft pages / forms
    "MALWARE",              # Malicious attachments or drive-by downloads
    "ACCOUNT_TAKEOVER",     # Indicators of compromised account sending from within
    "SPAM",                 # Unsolicited bulk email
    "IMPERSONATION",        # Executive / colleague impersonation (display-name spoofing)
    "GOV_IMPERSONATION",    # Impersonating a government entity
    "LOOKALIKE_DOMAIN",     # Lookalike / typosquat domain
    "SUPPLY_CHAIN",         # Supply chain compromise (legitimate vendor account abused)
    "FAKE_INVOICE",         # Fraudulent invoice / payment request
    "SOCIAL_ENGINEERING",   # Broad social-engineering attempts
]

# ─────────────────────────────────────────────
# Real LLM classifier — singleton, lazy-loaded
# ─────────────────────────────────────────────

_classifier = None

# Default: use the remote Himaya classifier-service (Kimi K2.5 via Bedrock) for
# inbound email classification. Falls back to Claude Haiku on timeout only.
# Flip USE_REMOTE_CLASSIFIER=false in the ECS task env to revert to the legacy
# local Claude Opus -> GPT-4o ensemble.
_USE_REMOTE = os.getenv("USE_REMOTE_CLASSIFIER", "true").lower() in ("true", "1", "yes")


def _ensure_models_on_path() -> None:
    """Ensure the project-root `models/` package is importable."""
    import sys, pathlib
    project_root = pathlib.Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))


def _get_classifier():
    """
    Lazy-load the email classifier singleton.

    Primary path: RemoteContentClassifier (Kimi K2.5 via the classifier-service ELB)
    with Claude Haiku as a timeout-only fallback. Toggle via USE_REMOTE_CLASSIFIER.

    Legacy path: local ContentClassifier (Claude Opus → GPT-4o ensemble).
    """
    global _classifier
    if _classifier is not None:
        return _classifier

    _ensure_models_on_path()

    if _USE_REMOTE:
        try:
            from models.content_classifier.remote_classifier import RemoteContentClassifier
            _classifier = RemoteContentClassifier(
                # base_url + primary timeout come from env
                #   CLASSIFIER_SERVICE_URL (default: prod ELB)
                #   CLASSIFIER_SERVICE_TIMEOUT (default: 45s — widened for Kimi)
                anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
                fallback_enabled=True,
                # CLASSIFIER_FALLBACK_TIMEOUT (default: 25s for Haiku)
            )
            logger.info("RemoteContentClassifier (Kimi K2.5 + Haiku fallback) initialised ✓")
            return _classifier
        except Exception as e:
            logger.warning(
                f"RemoteContentClassifier unavailable, falling back to local Claude Opus: {e}"
            )
            # fall through to legacy path so the pipeline never goes dark

    try:
        from models.content_classifier.classifier import ContentClassifier
        _classifier = ContentClassifier(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            timeout_seconds=25,     # 25s — enough for cold LLM calls, still bounded
            include_few_shot=True,
        )
        logger.info("ContentClassifier (Claude/GPT-4o) initialised ✓")
    except Exception as e:
        logger.warning(f"ContentClassifier unavailable, falling back to heuristics: {e}")
        _classifier = None
    return _classifier


async def _classify_content(email_data: dict) -> dict:
    """
    Classify email content using the LLM ensemble (Claude → GPT-4o fallback).
    Falls back to deterministic heuristics if both LLMs are unavailable
    (no API keys configured, network timeout, etc.).
    """
    sender    = email_data.get("sender", "")
    recipient = email_data.get("recipient", "")
    subject   = email_data.get("subject", "")
    body      = email_data.get("body", "")
    # attachments may be a list of strings (M365 filenames) or dicts with "filename" key (Google)
    _raw_attachments = email_data.get("attachments", [])
    attachments = [
        a if isinstance(a, str) else a.get("filename", "")
        for a in _raw_attachments
        if (isinstance(a, str) and a) or (isinstance(a, dict) and a.get("filename"))
    ]
    auth_headers = email_data.get("authentication", {})

    classifier = _get_classifier()

    if classifier is not None:
        try:
            result = await classifier.classify(
                sender=sender,
                recipient=recipient,
                subject=subject,
                body=body[:4000],           # Cap to avoid token overflow
                attachments=attachments or None,
                headers={
                    "SPF":   "pass" if auth_headers.get("spf_pass") else "fail",
                    "DKIM":  "pass" if auth_headers.get("dkim_pass") else "fail",
                    "DMARC": "pass" if auth_headers.get("dmarc_pass") else "fail",
                } if auth_headers else None,
            )

            # Map confidence (0–1) → content_score (0–100)
            # BENIGN/UNCERTAIN get low scores; threats scale with confidence
            classification = result.classification.value  # e.g. "BEC"
            confidence     = result.confidence

            if classification in ("BENIGN",):
                content_score = max(0, int((1 - confidence) * 40))
            elif classification in ("UNCERTAIN",):
                content_score = 25
            else:
                # Base 30 pts for being a threat + up to 70 pts from confidence
                content_score = min(100, 30 + int(confidence * 70))

            # BENIGN/UNCERTAIN stay as-is — don't force-map to PHISHING
            if classification in ("BENIGN", "UNCERTAIN"):
                classification = "CLEAN"

            # Combine structured signals + human-readable indicators
            indicators = result.threat_indicators or []
            if result.signals:
                for sig in result.signals:
                    indicator_str = f"{sig.name}:{sig.value}"
                    if indicator_str not in indicators:
                        indicators.append(indicator_str)

            logger.info(
                f"LLM classify | model={result.model_used} "
                f"class={classification} conf={confidence:.2f} "
                f"score={content_score} latency={result.latency_ms:.0f}ms "
                f"cost=${result.cost_usd:.5f}"
            )

            return {
                "content_score": content_score,
                "threat_type": classification,  # CLEAN for benign, actual type for threats
                "indicators": indicators,
                "ai_explanation_en": result.explanation_en,
                "ai_explanation_ar": result.explanation_ar,
                "llm_classification": classification,
                "llm_confidence": confidence,
                "llm_model": result.model_used,
                "llm_cost_usd": result.cost_usd,
                "impersonation_detected": result.impersonation_detected,
                "impersonation_target": result.impersonation_target,
                "urgency_score": result.urgency_score,
            }

        except Exception as e:
            logger.error(f"LLM classification failed, falling back to heuristics: {e}")

    # ── Heuristic fallback (no API keys or both LLMs failed) ──────────────
    logger.warning("Using heuristic content classifier (LLM unavailable)")
    text = f"{sender} {subject} {body}".lower()
    score = 0
    threat_type = "CLEAN"   # Default to clean unless heuristics fire
    indicators = []

    if any(w in text for w in ["wire transfer", "urgent payment", "ceo", "executive", "تحويل عاجل", "رئيس تنفيذي"]):
        threat_type = "BEC"; score += 40; indicators.append("wire_transfer_language")
    if any(w in text for w in ["zatca", "sama", "moci", "ministry", "government", "زاتكا", "وزارة", "هيئة"]):
        threat_type = "GOV_IMPERSONATION"; score += 35; indicators.append("government_entity_mention")
    if any(w in text for w in ["malware", ".exe", ".docm", ".xlsm", "macro", "ماكرو", "تفعيل"]):
        threat_type = "MALWARE"; score += 45; indicators.append("malware_indicators")
    if any(w in text for w in ["password", "account", "verify", "login", "suspicious", "كلمة مرور", "تحقق"]):
        if threat_type == "CLEAN":
            threat_type = "PHISHING"
        score += 30; indicators.append("credential_phishing")
    if any(w in text for w in ["supplier", "vendor", "invoice", "supply chain", "مورد", "فاتورة"]):
        if threat_type == "CLEAN":
            threat_type = "SUPPLY_CHAIN"
        score += 25; indicators.append("supply_chain_language")

    sender_domain_h = sender.split("@")[-1] if "@" in sender else sender
    # Only flag lookalike if we haven't already classified it and the domain looks suspicious
    if threat_type == "CLEAN" and len(sender_domain_h) > 4:
        import re as _re
        if _re.search(r'[0-9]{2,}|[-_]{2,}', sender_domain_h):
            threat_type = "LOOKALIKE_DOMAIN"; score += 20; indicators.append("lookalike_domain")

    # No random noise — deterministic scores only
    content_score = min(score, 100)
    explanation = (
        f"[Heuristic] {threat_type} indicators detected: {', '.join(indicators)}."
        if indicators else
        "[Heuristic] No suspicious patterns detected. Email appears clean."
    )
    return {
        "content_score": content_score,
        "threat_type": threat_type,
        "indicators": indicators,
        "ai_explanation_en": explanation,
        "ai_explanation_ar": f"[تحليل اكتشافي] {explanation}",
        "llm_classification": None,
        "llm_confidence": None,
        "llm_model": "heuristic_fallback",
        "impersonation_detected": False,
        "impersonation_target": None,
        "urgency_score": 0,
    }


def _calculate_risk_score(content_score: int, graph_score: int, reputation_score: int) -> dict:
    """Weighted risk orchestrator."""
    # Weights: content 40%, graph 30%, reputation 30%
    risk = int(content_score * 0.4 + graph_score * 0.3 + reputation_score * 0.3)
    risk = max(0, min(100, risk))

    return {
        "risk_score": risk,
        "score_breakdown": {
            "content": content_score,
            "graph": graph_score,
            "reputation": reputation_score,
            "weights": {"content": 0.4, "graph": 0.3, "reputation": 0.3},
        },
    }


def _determine_action(risk_score: int, threat_type: str) -> str:
    """
    Post-delivery action — Himaya sits AFTER email is delivered (like Abnormal Security).
    Actions are retroactive analysis outcomes, not gateway interceptions.
    """
    # SPAM at high confidence — auto-move to junk/spam folder
    # SPAM is not a security threat so quarantine is overkill; junk folder is appropriate.
    if threat_type == "SPAM" and risk_score >= 80:
        return "MARKED_SPAM"

    # High-severity threat types get a lower quarantine threshold (65 vs 80).
    # These are confirmed attack categories where even mid-confidence warrants removal.
    _high_severity_types = {
        "PHISHING", "CREDENTIAL_HARVESTING", "BEC", "MALWARE",
        "RANSOMWARE", "GOV_IMPERSONATION", "ACCOUNT_TAKEOVER",
    }
    _quarantine_threshold = 65 if threat_type in _high_severity_types else 80

    if risk_score >= _quarantine_threshold:
        # High confidence threat — retroactively quarantine
        return "QUARANTINED"
    elif risk_score >= 50:
        # Suspicious — flagged for analyst review
        return "FLAGGED_HIGH"
    elif risk_score >= 30:
        # Low-medium risk — flagged informational
        return "FLAGGED_LOW"
    elif threat_type == "CLEAN":
        return "CLEAN"
    else:
        return "CLEAN"


def _map_compliance_controls(threat_type: str) -> tuple:
    sama = []
    nca = []
    mapping = {
        "BEC":                  (["3.3.3", "3.4.1"], ["2-7-3"]),
        "VEC":                  (["3.3.3", "3.4.1"], ["2-7-3"]),
        "PHISHING":             (["3.3.5", "3.4.1"], ["2-7-2", "2-7-5"]),
        "CREDENTIAL_HARVESTING":(["3.3.5", "3.4.1"], ["2-7-2"]),
        "GOV_IMPERSONATION":    (["3.3.3", "3.3.5"], ["2-7-4"]),
        "IMPERSONATION":        (["3.3.3"],           ["2-7-4"]),
        "MALWARE":              (["3.3.3"],            ["2-7-5"]),
        "LOOKALIKE_DOMAIN":     (["3.3.5"],            ["2-7-2"]),
        "ACCOUNT_TAKEOVER":     (["3.4.1"],            ["2-7-1"]),
        "SUPPLY_CHAIN":         (["3.3.3", "3.4.1"],  ["2-7-3"]),
        "FAKE_INVOICE":         (["3.3.3", "3.4.1"],  ["2-7-3"]),
        "SOCIAL_ENGINEERING":   (["3.3.5"],            ["2-7-2"]),
        "SPAM":                 (["3.3.5"],            ["2-7-5"]),
    }
    return mapping.get(threat_type, (["3.3.3"], ["2-7-1"]))


async def process_email(email_data: dict, org_id: str, db: AsyncSession) -> Optional[Threat]:
    """
    Full email processing pipeline:
    1. Extract fields
    2. Content classification
    3. Graph analysis
    4. Sender reputation
    5. Risk orchestration
    6. DB storage
    7. Compliance evidence
    8. WebSocket broadcast
    """
    # ── Guard: skip Himaya system notification emails to prevent alert loops ──
    _HELIOS_SYSTEM_SENDERS = {"noreply@himaya.ai", "no-reply@himaya.ai"}
    _raw_sender = (email_data.get("sender") or "").lower().strip()
    if _raw_sender in _HELIOS_SYSTEM_SENDERS:
        logger.debug(f"process_email: skipping Himaya system email from {_raw_sender} (loop guard)")
        return None

    try:
        sender = email_data.get("sender", "unknown@unknown.com")
        sender_domain = sender.split("@")[-1] if "@" in sender else "unknown.com"
        recipient_email = email_data.get("recipient", "")
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        message_id = email_data.get("message_id", str(uuid.uuid4()))

        # Parse actual email delivery time from Date: header (or pre-computed internalDate ISO string)
        email_received_at = None
        raw_date = email_data.get("date", "")
        if raw_date:
            try:
                from email.utils import parsedate_to_datetime
                email_received_at = parsedate_to_datetime(raw_date)
            except Exception:
                try:
                    from dateutil import parser as _dp
                    email_received_at = _dp.parse(raw_date)
                except Exception:
                    pass
        # DB column is TIMESTAMP WITHOUT TIME ZONE — strip tzinfo, normalise to UTC naive
        if email_received_at and email_received_at.tzinfo is not None:
            from datetime import timezone as _store_tz
            email_received_at = email_received_at.astimezone(_store_tz.utc).replace(tzinfo=None)

        # ── Dedup check ──────────────────────────────────────────────────────
        # Skip re-processing UNLESS the user moved the email back to inbox after quarantine.
        # If the existing record is 'false_positive', always skip (user explicitly said it's OK).
        # If the existing record was quarantined/spam and is now 'resolved', re-quarantine it.
        if message_id and recipient_email:
            try:
                _existing = await db.execute(
                    select(Threat.id, Threat.status, Threat.action_taken, Threat.false_positive).where(
                        Threat.email_message_id == message_id,
                        Threat.org_id == (uuid.UUID(org_id) if isinstance(org_id, str) else org_id),
                        Threat.recipient_email == recipient_email,
                    ).limit(1)
                )
                _row = _existing.one_or_none()
                if _row is not None:
                    _ex_status = _row[1]
                    _ex_action = _row[2]
                    _ex_fp     = _row[3]
                    # Always skip false positives — user confirmed it's benign
                    if _ex_fp:
                        logger.debug(f"Dedup: skipping false-positive {message_id} for {recipient_email}")
                        return None
                    # Skip if it's still actively quarantined/spam (not yet released)
                    if _ex_status in ("quarantined", "open", "new"):
                        logger.debug(f"Dedup: skipping still-quarantined {message_id} for {recipient_email}")
                        return None
                    # Skip if it was a clean/low-risk email — no need to re-analyse
                    if _ex_action in ("CLEAN", "ALLOW", "DELIVER") or _ex_status in ("resolved", "false_positive") and _ex_action not in ("QUARANTINED", "QUARANTINE", "MARKED_SPAM", "BLOCK_DELETE"):
                        logger.debug(f"Dedup: skipping already-resolved clean {message_id} for {recipient_email}")
                        return None
                    # If previously quarantined/spam but now 'resolved' (user moved it back to inbox),
                    # fall through to re-process — Himaya will re-quarantine it.
                    if _ex_action in ("QUARANTINED", "QUARANTINE", "MARKED_SPAM") and _ex_status == "resolved":
                        logger.info(f"Re-quarantine: {message_id} was released by user, re-processing for {recipient_email}")
                        # Don't return — let the full pipeline run again
            except Exception as _de:
                logger.debug(f"Dedup check failed (non-fatal): {_de}")

        # Authentication headers (SPF/DKIM/DMARC) passed from ingestion
        # Always default to a structured dict (never None) so auth_results is stored in DB
        auth_results = email_data.get("auth_results") or {"spf": "none", "dkim": "none", "dmarc": "none"}

        # Step 1b: Check if recipient is a VIP — affects risk thresholds and analysis strictness
        is_vip_recipient = False
        try:
            from backend.models.db_models import User as _VipUser
            _vip_check = await db.execute(
                select(_VipUser).where(
                    _VipUser.org_id == (uuid.UUID(org_id) if isinstance(org_id, str) else org_id),
                    _VipUser.email == recipient_email,
                    _VipUser.is_vip.is_(True),
                )
            )
            is_vip_recipient = _vip_check.scalar_one_or_none() is not None
            if is_vip_recipient:
                logger.info(f"VIP recipient detected: {recipient_email} — applying stricter analysis")
                # Force LLM classification for VIP recipients (no heuristic fallback allowed)
                email_data = {**email_data, "_force_llm": True, "_vip_recipient": True}
        except Exception:
            pass

        # Step 1c: Check false-positive feedback for this sender domain
        # If previous FP reports exist for this sender+org, apply a BENIGN bias
        fp_bias = 0
        try:
            import redis.asyncio as _fp_redis, json as _fp_json
            _fp_r = _fp_redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
            _fp_key = f"fp_feedback:{org_id}:{sender_domain}"
            _fp_raw = await _fp_r.get(_fp_key)
            await _fp_r.aclose()
            if _fp_raw:
                _fp_entries = _fp_json.loads(_fp_raw)
                # Each confirmed FP from this domain reduces risk score by 8 points (max -40)
                fp_bias = min(40, len(_fp_entries) * 8)
                logger.info(f"FP bias applied: -{fp_bias} for domain {sender_domain} ({len(_fp_entries)} FP signals)")
        except Exception:
            pass

        # Step 2: Reputation analysis first
        link_result, reputation_result = await analyze_email_reputation(email_data, auth_results)
        logger.info(
            "reputation | sender=%s score=%s verdict=%s spf=%s dkim=%s dmarc=%s indicators=%s link_score=%d urls=%d attachments=%s",
            sender,
            reputation_result.get("reputation_score") if reputation_result else "N/A",
            reputation_result.get("verdict") if reputation_result else "N/A",
            reputation_result.get("spf_pass") if reputation_result else "N/A",
            reputation_result.get("dkim_pass") if reputation_result else "N/A",
            reputation_result.get("dmarc_pass") if reputation_result else "N/A",
            reputation_result.get("indicators", []) if reputation_result else [],
            link_result.get("link_score", 0),
            link_result.get("urls_found", 0),
            link_result.get("suspicious_attachments", []),
        )

        # Step 2b: Content classification + graph evaluate — run in parallel
        graph_result, content_result = await asyncio.gather(
            graph_client.evaluate(
                sender=sender,
                recipient=recipient_email,
                org_id=org_id,
                reputation_hint=reputation_result,
            ),
            _classify_content(email_data),
        )
        logger.info(
            "graph | sender=%s trust_score=%s trust_method=%s reasoning=%s domain_spread=%s indicators=%s llm_adjustment=%s",
            sender,
            graph_result.get("trust", {}).get("trust_score"),
            graph_result.get("trust", {}).get("trust_method"),
            graph_result.get("trust", {}).get("reasoning"),
            graph_result.get("trust", {}).get("domain_spread"),
            graph_result.get("trust", {}).get("indicators"),
            graph_result.get("trust", {}).get("llm_adjustment"),
        )
        if link_result["link_score"] > 0:
            content_result["content_score"] = min(100, content_result["content_score"] + link_result["link_score"] // 2)
            content_result.setdefault("indicators", []).extend(link_result["indicators"])
            if link_result["malicious_urls"]:
                content_result["ai_explanation_en"] = (
                    f"{content_result.get('ai_explanation_en','')}\n\n"
                    f"⚠️ Malicious URLs detected: {', '.join(link_result['malicious_urls'][:3])}"
                )
            if link_result["suspicious_attachments"]:
                content_result["ai_explanation_en"] = (
                    f"{content_result.get('ai_explanation_en','')}\n\n"
                    f"⚠️ Dangerous attachments: {', '.join(link_result['suspicious_attachments'])}"
                )

        # Step 2b: Reply-To domain mismatch scoring
        # A reply-to that differs from the sender domain is a classic BEC/phishing signal.
        # We boost content score and set threat type before graph/reputation so the
        # threshold logic in _determine_action can apply the lower quarantine cutoff.
        _reply_to = (email_data.get("reply_to") or "").strip().lower()
        if _reply_to and "@" in _reply_to:
            _reply_domain = _reply_to.split("@")[-1].strip("<> ")
            _sender_domain_lower = sender_domain.lower()
            if _reply_domain and _reply_domain != _sender_domain_lower:
                # Different domain — score the mismatch
                _reply_boost = 0
                _reply_indicators: list[str] = []

                # Personal/consumer email domain in reply-to = BEC red flag
                _personal_doms = {
                    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "protonmail.com", "proton.me", "icloud.com", "aol.com",
                    "yandex.com", "mail.com", "zoho.com", "live.com",
                }
                if _reply_domain in _personal_doms:
                    _reply_boost = 35
                    _reply_indicators.append(f"reply_to_personal_email:{_reply_domain} (BEC exfil pattern)")
                    if content_result["threat_type"] in ("CLEAN", "UNCERTAIN"):
                        content_result["threat_type"] = "BEC"
                else:
                    # External lookalike domain in reply-to
                    _reply_boost = 20
                    _reply_indicators.append(f"reply_to_domain_mismatch:{_reply_domain} vs sender:{_sender_domain_lower}")
                    if content_result["threat_type"] in ("CLEAN", "UNCERTAIN"):
                        content_result["threat_type"] = "PHISHING"

                # Extra penalty if reply-to domain looks like a lookalike (hyphens, numbers, TLD swap)
                import re as _rt_re
                if _rt_re.search(r'[0-9]{2,}|[-_]{2,}|\.co$|\.net$|\.org$', _reply_domain):
                    _reply_boost += 10
                    _reply_indicators.append(f"reply_to_lookalike_pattern:{_reply_domain}")

                content_result["content_score"] = min(100, content_result["content_score"] + _reply_boost)
                content_result.setdefault("indicators", []).extend(_reply_indicators)
                if _reply_indicators:
                    _existing_exp = content_result.get("ai_explanation_en", "")
                    content_result["ai_explanation_en"] = (
                        f"{_existing_exp}\n\n⚠️ Reply-To mismatch: replies will go to "
                        f"{_reply_domain} instead of {_sender_domain_lower}"
                    ).strip()
                logger.info(
                    f"reply-to mismatch: sender={_sender_domain_lower} reply_to={_reply_domain} "
                    f"boost=+{_reply_boost} new_content_score={content_result['content_score']} "
                    f"threat_type={content_result['threat_type']}"
                )

        # Step 5: Risk orchestration
        _trust = graph_result["trust"]
        if _trust["trust_method"] == "block":
            graph_score = 100
        else:
            graph_score = 100 - _trust["trust_score"]

        risk_result = _calculate_risk_score(
            content_score=content_result["content_score"],
            graph_score=graph_score,
            reputation_score=reputation_result["reputation_score"],
        )
        # Embed link/attachment findings into score_breakdown for UI display
        risk_result["score_breakdown"]["suspicious_urls"] = link_result.get("suspicious_urls", [])
        risk_result["score_breakdown"]["malicious_urls"] = link_result.get("malicious_urls", [])
        risk_result["score_breakdown"]["suspicious_attachments"] = link_result.get("suspicious_attachments", [])
        # Store ALL attachment filenames (not just dangerous ones) so sandbox + UI can show them
        _all_att_names = link_result.get("all_attachments", [])
        risk_result["score_breakdown"]["all_attachments"] = _all_att_names
        # Store reputation detail (indicators + auth results) for UI
        risk_result["score_breakdown"]["reputation_detail"] = {
            "score": reputation_result["reputation_score"],
            "indicators": reputation_result.get("indicators", []),
            "spf_pass":   reputation_result.get("spf_pass"),
            "dkim_pass":  reputation_result.get("dkim_pass"),
            "dmarc_pass": reputation_result.get("dmarc_pass"),
        }

        # Apply FP bias (reduce risk for known-benign senders)
        if fp_bias > 0:
            risk_result["risk_score"] = max(0, risk_result["risk_score"] - fp_bias)
            risk_result["score_breakdown"]["fp_bias_applied"] = -fp_bias

        # Determine action — VIP recipients get stricter thresholds
        threat_type = content_result["threat_type"]
        effective_risk = risk_result["risk_score"]
        if is_vip_recipient and threat_type not in ("CLEAN",):
            # For VIP recipients, boost risk score by 15 points and lower quarantine threshold
            # Any threat detected against a VIP is automatically escalated
            effective_risk = min(100, effective_risk + 15)
            risk_result["risk_score"] = effective_risk
            logger.info(f"VIP risk boost applied: {risk_result['risk_score'] - 15} → {effective_risk} for {recipient_email}")
        action = _determine_action(effective_risk, threat_type)

        # Step 5b: Auto-action via Gmail API based on determined action
        auto_action_success = False
        if action == "QUARANTINED" and message_id and recipient_email:
            try:
                from backend.services.quarantine_service import quarantine_gmail_message
                auto_action_success = await quarantine_gmail_message(
                    user_email=recipient_email,
                    gmail_message_id=message_id,
                    access_token=None,
                )
                if auto_action_success:
                    logger.info(f"Auto-quarantined email {message_id} for {recipient_email}")
                else:
                    logger.warning(f"Auto-quarantine failed for {message_id} — email remains in inbox")
            except Exception as _aq_err:
                logger.warning(f"Auto-quarantine error (non-fatal): {_aq_err}")

        elif action == "MARKED_SPAM" and message_id and recipient_email:
            try:
                from backend.services.quarantine_service import mark_as_spam_gmail
                auto_action_success = await mark_as_spam_gmail(
                    user_email=recipient_email,
                    gmail_message_id=message_id,
                )
                if auto_action_success:
                    logger.info(f"Auto-marked spam {message_id} for {recipient_email}")
            except Exception as _sp_err:
                logger.warning(f"Auto-spam mark error (non-fatal): {_sp_err}")

        # Map compliance controls
        sama_controls, nca_controls = _map_compliance_controls(threat_type)

        # Combine all indicators — include link/attachment IOC data for digest
        # Filter out auth-related indicators that contradict actual parsed auth_results.
        # The LLM / heuristic may flag dkim_fail / spf_fail based on context clues, but
        # the ground-truth auth_results parsed from email headers takes priority.
        _auth_pass = {
            k for k, v in (auth_results or {}).items()
            if isinstance(v, str) and v.lower() in ("pass", "passed")
        }
        _auth_conflict_map = {
            "dkim_fail": "dkim", "dkim_softfail": "dkim",
            "spf_fail": "spf", "spf_softfail": "spf",
            "dmarc_fail": "dmarc", "dmarc_softfail": "dmarc",
        }

        def _strip_auth_conflicts(indicators: list) -> list:
            out = []
            for ind in indicators:
                if not isinstance(ind, str):
                    out.append(ind)
                    continue
                # e.g. "dkim_fail" or "dkim_fail:some_detail"
                key = ind.split(":")[0].lower()
                auth_proto = _auth_conflict_map.get(key)
                if auth_proto and auth_proto in _auth_pass:
                    # Real auth header says PASS — drop the conflicting indicator
                    logger.debug(f"Dropping indicator '{ind}' — auth_results[{auth_proto}] = pass")
                    continue
                out.append(ind)
            return out

        all_indicators = {
            "content": _strip_auth_conflicts(content_result.get("indicators", [])),
            "graph": _strip_auth_conflicts(graph_result["trust"].get("indicators", [])),
            "reputation": reputation_result.get("indicators", []),
            "suspicious_urls": link_result.get("suspicious_urls", []),
            "malicious_urls": link_result.get("malicious_urls", []),
            "suspicious_attachments": link_result.get("suspicious_attachments", []),
            "attachment_types": link_result.get("attachment_types", []),
            # Graph metadata — stored for UI display and audit
            "graph_mode": _trust["trust_method"],
            "prior_emails": graph_result["relationship"]["prior_emails_to_recipient"],
            "first_time_sender": graph_result["sender"]["email_count"] == 0,
            "domain_spread": _trust["domain_spread"],
        }

        # Subject hash (privacy — but also store plain text for search/display)
        subject_hash = hashlib.sha256(subject.encode()).hexdigest()[:64]

        # Step 6: Store threat in DB
        # If re-processing a previously-quarantined email (user moved it back to inbox),
        # UPDATE the existing row rather than INSERT (unique index blocks re-insert).
        _raw_body = (email_data.get("html_body") or email_data.get("body") or "").strip()
        _org_uuid = uuid.UUID(org_id) if isinstance(org_id, str) else org_id
        _existing_threat_check = await db.execute(
            select(Threat).where(
                Threat.email_message_id == message_id,
                Threat.org_id == _org_uuid,
                Threat.recipient_email == recipient_email,
            ).limit(1)
        )
        _existing_threat = _existing_threat_check.scalar_one_or_none()
        if _existing_threat:
            # Update the existing row with fresh analysis and reset to quarantined/open
            _existing_threat.threat_type      = threat_type
            _existing_threat.risk_score        = risk_result["risk_score"]
            _existing_threat.score_breakdown   = risk_result["score_breakdown"]
            _existing_threat.content_score     = content_result["content_score"]
            _existing_threat.graph_score       = graph_score
            _existing_threat.reputation_score  = reputation_result["reputation_score"]
            _existing_threat.action_taken      = action
            _existing_threat.status            = "open" if action in ("QUARANTINED", "FLAGGED_HIGH") else "resolved"
            _existing_threat.ai_explanation_en = content_result["ai_explanation_en"]
            _existing_threat.ai_explanation_ar = content_result["ai_explanation_ar"]
            _existing_threat.threat_indicators = all_indicators
            _existing_threat.detected_at       = datetime.utcnow()
            _existing_threat.false_positive    = False
            _existing_threat.resolved_at       = None
            await db.flush()
            threat = _existing_threat
            logger.info(f"Re-quarantine: updated existing threat {threat.id} for {recipient_email}")
        else:
        # ── Normal INSERT path ─────────────────────────────────────────────────────
          threat = Threat(
            org_id=uuid.UUID(org_id) if isinstance(org_id, str) else org_id,
            email_message_id=message_id,
            sender=sender,
            sender_domain=sender_domain,
            recipient_email=recipient_email,
            subject=subject[:500] if subject else None,
            subject_hash=subject_hash,
            email_received_at=email_received_at,
            auth_results=auth_results,
            threat_type=threat_type,
            risk_score=risk_result["risk_score"],
            score_breakdown=risk_result["score_breakdown"],
            graph_score=graph_score,
            content_score=content_result["content_score"],
            reputation_score=reputation_result["reputation_score"],
            status=(
                "quarantined" if action in ("QUARANTINED", "QUARANTINE", "BLOCK_DELETE") else
                "new" if action in ("FLAGGED_HIGH", "FLAGGED_LOW", "BANNER", "HOLD") else
                "resolved"
            ),
            action_taken=action,
            ai_explanation_en=content_result["ai_explanation_en"],
            ai_explanation_ar=content_result["ai_explanation_ar"],
            threat_indicators=all_indicators,
            sama_controls=sama_controls,
            nca_controls=nca_controls,
            detected_at=datetime.utcnow(),
            # Set body preview directly on ORM object — avoids raw SQL that aborts transaction
            email_body_preview=_raw_body[:8000] if _raw_body else None,
            # LLM metadata
            llm_classification=content_result.get("llm_classification"),
            llm_confidence=content_result.get("llm_confidence"),
            llm_model=content_result.get("llm_model"),
            llm_cost_usd=content_result.get("llm_cost_usd"),
            impersonation_detected=content_result.get("impersonation_detected", False),
            impersonation_target=content_result.get("impersonation_target"),
            urgency_score=content_result.get("urgency_score"),
          )
          db.add(threat)
          await db.flush()  # Single flush inside else block

        # Step 7: Create compliance evidence
        if action in ("QUARANTINED", "FLAGGED_HIGH", "FLAGGED_LOW"):
            evidence = ComplianceEvidence(
                org_id=threat.org_id,
                threat_id=threat.id,
                control_ids=sama_controls + nca_controls,
                framework="SAMA_CSF",
                action_taken=action,
                outcome=f"Threat {threat_type} detected and {action}",
                immutable=True,
                retention_tier="1_year",
            )
            db.add(evidence)

        await db.flush()

        # Step 7b: Track usage events (lightweight — fire and forget)
        try:
            from sqlalchemy import text as _text
            _org_id_str = str(threat.org_id)
            await db.execute(
                _text("INSERT INTO usage_events (org_id, event_type, count) VALUES (:org_id, 'email_scanned', 1)"),
                {"org_id": _org_id_str},
            )
            if threat.risk_score > 30:
                await db.execute(
                    _text("INSERT INTO usage_events (org_id, event_type, count) VALUES (:org_id, 'threat_detected', 1)"),
                    {"org_id": _org_id_str},
                )
            await db.flush()
        except Exception as _ue:
            logger.warning(f"Usage tracking failed (non-fatal): {_ue}")

        # Step 7b2: Update recipient user's risk score based on threat history
        try:
            from sqlalchemy import text as _text2
            from backend.models.db_models import User as _User
            # Find recipient user in this org
            _user_result = await db.execute(
                select(_User).where(
                    _User.org_id == (uuid.UUID(org_id) if isinstance(org_id, str) else org_id),
                    _User.email == recipient_email,
                )
            )
            _user = _user_result.scalar_one_or_none()
            if _user:
                # Get recent 30-day threat scores for this user
                _recent = await db.execute(
                    _text2("""
                        SELECT risk_score FROM threats
                        WHERE recipient_email = :email AND org_id = :org_id
                          AND detected_at >= NOW() - INTERVAL '30 days'
                        ORDER BY detected_at DESC LIMIT 50
                    """),
                    {"email": recipient_email, "org_id": str(_user.org_id)},
                )
                _scores = [r[0] for r in _recent.fetchall() if r[0] is not None]
                if _scores:
                    # Weighted: index 0 is newest (DESC order) — highest weight goes to index 0
                    _weights = [1.0 + ((len(_scores) - 1 - i) * 0.1) for i in range(len(_scores))]
                    _weighted_avg = sum(s * w for s, w in zip(_scores, _weights)) / sum(_weights)
                    # Clamp and round
                    _new_risk = min(100, max(0, round(_weighted_avg)))
                    _user.risk_score = _new_risk
                    await db.flush()
        except Exception as _re:
            logger.debug(f"Risk score update failed (non-fatal): {_re}")

        # Step 7c: Auto-detonate suspicious URLs in initial flow (non-blocking background task)
        try:
            targets_to_detonate = (
                (link_result.get("malicious_urls") or []) +
                (link_result.get("suspicious_urls") or [])
            )[:3]
            if targets_to_detonate:
                async def _background_detonate():
                    try:
                        from backend.services.url_detonation import detonate_email_urls
                        import redis.asyncio as _aioredis, json as _json
                        det_results = await detonate_email_urls(targets_to_detonate, max_urls=3, timeout_ms=12000)
                        # Store detonation results in Redis keyed by threat_id
                        _redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
                        _r = _aioredis.from_url(_redis_url, decode_responses=True)
                        stored = []
                        for dr in det_results:
                            stored.append({
                                "url": getattr(dr, "url", ""),
                                "final_url": getattr(dr, "final_url", ""),
                                "redirect_chain": getattr(dr, "redirect_chain", []),
                                "page_title": getattr(dr, "page_title", ""),
                                "has_login_form": getattr(dr, "has_login_form", False),
                                "phishing_keywords": getattr(dr, "phishing_keywords_found", []),
                                "risk_indicators": getattr(dr, "risk_indicators", []),
                                "detonation_risk_score": getattr(dr, "detonation_risk_score", 0),
                                "screenshot_b64": getattr(dr, "screenshot_b64", None),
                            })
                        await _r.set(f"detonation:{threat.id}", _json.dumps(stored), ex=86400)
                        await _r.aclose()
                        logger.info(f"Auto-detonated {len(det_results)} URLs for threat {threat.id}")
                    except Exception as _de:
                        logger.debug(f"Background URL detonation failed (non-fatal): {_de}")
                asyncio.create_task(_background_detonate())
        except Exception as _se:
            logger.debug(f"Sandbox auto-detonate task failed (non-fatal): {_se}")

        # Step 7d: Send threat alerts for high-confidence detections (risk >= 80, or >= 60 for VIPs)
        # Skip alerts when sender is a Himaya system address (loop guard)
        _HELIOS_SYSTEM_SENDERS_7D = {"noreply@himaya.ai", "no-reply@himaya.ai"}
        alert_threshold = 60 if is_vip_recipient else 80
        if (risk_result["risk_score"] >= alert_threshold
                and action in ("QUARANTINED", "FLAGGED_HIGH")
                and sender.lower() not in _HELIOS_SYSTEM_SENDERS_7D):
            try:
                import asyncio as _asyncio
                from backend.models.db_models import Organization as _Org, User as _User2
                from backend.services.email_service import send_threat_alert as _send_alert
                from backend.services.email_service import send_quarantine_notification as _send_qn

                # Fetch org admin email
                _org_res = await db.execute(
                    select(_Org).where(_Org.id == (uuid.UUID(org_id) if isinstance(org_id, str) else org_id))
                )
                _org = _org_res.scalar_one_or_none()

                # Find org admin user
                _admin_res = await db.execute(
                    select(_User2).where(
                        _User2.org_id == (uuid.UUID(org_id) if isinstance(org_id, str) else org_id),
                        _User2.role == "admin",
                        _User2.is_active.is_(True),
                    ).limit(1)
                )
                _admin = _admin_res.scalar_one_or_none()
                _org_name = _org.name if _org else "Your Organization"

                if _admin and _admin.email:
                    await _asyncio.to_thread(
                        _send_alert,
                        to_email=_admin.email,
                        org_name=_org_name,
                        threat_type=threat_type,
                        risk_score=risk_result["risk_score"],
                        recipient=recipient_email,
                        action=action,
                        detection_time=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                    )
                    logger.info(f"Admin threat alert sent to {_admin.email} for threat {threat.id}")

                # Send quarantine notification to the affected user — full context
                if recipient_email:
                    # Build body preview and attachment list from email_data
                    _body_prev = str(email_data.get("body") or "")[:800]
                    _att_list  = email_data.get("attachments") or []
                    _link_ct   = len(__import__('re').findall(r'https?://\S+', str(email_data.get("body") or "")))
                    _recv_at   = email_data.get("date") or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
                    # Check if recipient has dashboard access (admin/analyst roles only)
                    _recip_user_res = await db.execute(
                        select(_User2).where(_User2.email == recipient_email, _User2.is_active.is_(True))
                    )
                    _recip_user = _recip_user_res.scalar_one_or_none()
                    _is_admin_recip = _recip_user is not None and _recip_user.role in ("admin", "analyst")
                    await _asyncio.to_thread(
                        _send_qn,
                        to_email=recipient_email,
                        org_name=_org_name,
                        threat_type=threat_type,
                        risk_score=risk_result["risk_score"],
                        sender_email=sender,
                        subject=subject,
                        action=action,
                        ai_explanation=content_result.get("ai_explanation_en", ""),
                        body_preview=_body_prev,
                        attachments=_att_list,
                        link_count=_link_ct,
                        received_at=_recv_at,
                        is_admin_recipient=_is_admin_recip,
                    )
                    logger.info(f"Quarantine notification sent to {recipient_email} (admin={_is_admin_recip}) for threat {threat.id}")

                # ── Sender notification — always notify the sender on QUARANTINE/BLOCK ──
                # This mirrors the policy engine path. The external sender must be told
                # their email was intercepted — regardless of how it was detected.
                if sender and sender != recipient_email:
                    try:
                        from backend.services.email_service import send_sender_block_notification as _send_sender
                        _body_prev_s = str(email_data.get("body") or "")[:800]
                        _att_list_s  = email_data.get("attachments") or []
                        _link_ct_s   = len(__import__('re').findall(r'https?://\S+', str(email_data.get("body") or "")))
                        await _asyncio.to_thread(
                            _send_sender,
                            to_email=sender,
                            recipient_org=_org_name,
                            subject=subject or "",
                            threat_type=threat_type or "Unknown",
                            action=action,
                            recipient_email=recipient_email or "",
                            body_preview=_body_prev_s,
                            attachments=_att_list_s,
                            link_count=_link_ct_s,
                            ai_explanation=content_result.get("ai_explanation_en", ""),
                        )
                        logger.info(f"Sender block/quarantine notification sent to {sender} for threat {threat.id}")
                    except Exception as _se:
                        logger.warning(f"Sender notification failed (non-fatal): {_se}")

            except Exception as _ae:
                logger.warning(f"Alert send failed (non-fatal): {_ae}")

        # Step 7d2: Geo-enrich sender IP → country (stored in auth_results for threat map)
        # Only runs when sender_ip is present but country not yet resolved
        try:
            _ar = threat.auth_results or {}
            _sip = _ar.get("sender_ip", "")
            if _sip and not _ar.get("sender_country"):
                import httpx as _geo_httpx2
                _geo_resp = await _geo_httpx2.AsyncClient(timeout=4).get(
                    f"http://ip-api.com/json/{_sip}?fields=status,country,countryCode"
                )
                if _geo_resp.status_code == 200:
                    _gd = _geo_resp.json()
                    if _gd.get("status") == "success":
                        _updated_ar = dict(_ar)
                        _updated_ar["sender_country"] = _gd.get("country")
                        _updated_ar["sender_country_code"] = _gd.get("countryCode")
                        threat.auth_results = _updated_ar
                        await db.flush()
        except Exception as _geo_e:
            logger.debug(f"Geo lookup failed (non-fatal): {_geo_e}")

        # Step 7e: Record communication edge in graph-service (non-blocking)
        try:
            email_date_str = email_data.get("date") or datetime.utcnow().isoformat()
            await graph_client.write({
                "sender":       sender,
                "recipient":    recipient_email,
                "org_id":       str(threat.org_id),
                "message_id":   message_id,
                "subject_hash": subject_hash,
                "received_at":  email_date_str,
                "llm_verdict":  content_result.get("llm_classification"),
                "risk_score":   risk_result["risk_score"],
                "threat_type":  threat_type if threat_type not in ("CLEAN", "BENIGN") else None,
                "urls":         link_result.get("suspicious_urls", []) + link_result.get("malicious_urls", []),
            })
        except Exception as _ge:
            logger.debug(f"Graph write failed (non-fatal): {_ge}")

        # Step 8: Broadcast via WebSocket
        try:
            await ws_manager.broadcast_to_org(
                {
                    "event": "new_threat",
                    "threat": {
                        "id": str(threat.id),
                        "threat_type": threat_type,
                        "risk_score": threat.risk_score,
                        "sender": sender,
                        "action_taken": action,
                        "detected_at": threat.detected_at.isoformat(),
                    },
                },
                org_id=str(threat.org_id),
            )
        except Exception as e:
            logger.warning(f"WebSocket broadcast failed: {e}")

        logger.info(
            f"Processed email: threat_id={threat.id} type={threat_type} "
            f"risk={threat.risk_score} action={action}"
        )
        return threat

    except Exception as e:
        logger.error(f"Email processing failed: {e}", exc_info=True)
        return None
