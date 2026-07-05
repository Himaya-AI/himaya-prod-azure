"""
Policy Engine — evaluates active policies against email threats and applies actions.

Policies are evaluated in priority order (lowest number = first).
First matching ALLOW/BLOCK/QUARANTINE policy wins.
ALERT/TAG policies are additive and don't stop evaluation.

Used in two modes:
  1. Real-time: called during email processing to determine action before storing
  2. Retroactive: scans existing open/flagged threats and applies matching policies
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

logger = logging.getLogger(__name__)


def _match_policy(policy: dict, threat: dict, email_data: dict) -> bool:
    """
    Check if a policy's conditions match the given threat/email data.
    Returns True if ALL provided conditions match (AND logic within a policy).
    """
    conds = policy.get("conditions") or {}
    if not conds or conds.get("match_all"):
        return True

    # Helper: exact case-insensitive equality
    def exact_eq(val_a: str, val_b: str) -> bool:
        return val_a.strip().lower() == val_b.strip().lower()

    # Helper: case-insensitive substring match
    def contains(field: str, value: str) -> bool:
        field_val = str(threat.get(field) or email_data.get(field) or "").lower()
        return value.lower() in field_val

    for key, expected in conds.items():
        if key == "match_all":
            continue

        elif key == "$or":
            # expected is a list of condition dicts — match if ANY sub-condition matches
            or_conditions = expected if isinstance(expected, list) else [expected]
            or_matched = False
            for or_cond in or_conditions:
                sub_policy = {"conditions": dict(or_cond)}
                if _match_policy(sub_policy, threat, email_data):
                    or_matched = True
                    break
            if not or_matched:
                return False

        elif key == "ioc_match":
            # Check if the threat has been flagged as an IOC match by the threat pipeline
            ioc = bool(threat.get("ioc_match") or email_data.get("ioc_match"))
            if bool(expected) != ioc:
                return False

        elif key == "sender_email":
            sender = str(threat.get("sender") or email_data.get("sender") or "").lower()
            if isinstance(expected, list):
                # OR matching: match if sender equals ANY value in the list
                if not any(exact_eq(sender, str(e)) for e in expected):
                    return False
            elif not exact_eq(sender, str(expected)):
                return False

        elif key == "sender_domain":
            sender = str(threat.get("sender_domain") or email_data.get("sender_domain") or "").lower()
            if isinstance(expected, list):
                # OR matching: match if sender domain contains ANY value in the list
                if not any(str(e).lower() in sender for e in expected):
                    return False
            elif str(expected).lower() not in sender:
                return False

        elif key == "recipient_email":
            # Exact match — prevents "john@a.com" matching "john@bigcompany.com"
            recipient = str(
                threat.get("recipient_email") or
                email_data.get("recipient_email") or
                email_data.get("recipient") or ""
            ).lower()
            if isinstance(expected, list):
                # OR matching: match if recipient equals ANY value in the list
                if not any(exact_eq(recipient, str(e)) for e in expected):
                    return False
            elif not exact_eq(recipient, str(expected)):
                return False

        elif key == "recipient_domain":
            recipient = str(
                threat.get("recipient_email") or
                email_data.get("recipient", "")
            ).lower()
            if isinstance(expected, list):
                if not any(str(e).lower() in recipient for e in expected):
                    return False
            elif str(expected).lower() not in recipient:
                return False

        elif key == "threat_type":
            ttype = str(threat.get("threat_type") or email_data.get("threat_type") or "").lower()
            if str(expected).lower() != ttype:
                return False

        elif key == "risk_score_min":
            score = threat.get("risk_score") or email_data.get("risk_score") or 0
            if int(score) < int(expected):
                return False

        elif key == "risk_score_max":
            score = threat.get("risk_score") or email_data.get("risk_score") or 0
            if int(score) > int(expected):
                return False

        elif key == "has_attachment":
            has_att = bool(threat.get("has_attachment") or email_data.get("has_attachment"))
            if bool(expected) != has_att:
                return False

        elif key == "attachment_types":
            # Granular attachment type blocking: expected is a list of extensions e.g. [".pdf", ".exe"]
            # Normalise so all entries start with a dot
            allowed_types = []
            for t in (expected if isinstance(expected, list) else [expected]):
                t = str(t).lower().strip()
                allowed_types.append(t if t.startswith(".") else f".{t}")

            email_attachments = email_data.get("attachments") or threat.get("attachments") or []
            if not email_attachments:
                return False  # no attachments → condition can't match
            found = False
            for att in email_attachments:
                fname = (att.get("filename", "") if isinstance(att, dict) else str(att)).lower()
                ext = f".{fname.rsplit('.', 1)[1]}" if "." in fname else ""
                if ext in allowed_types:
                    found = True
                    break
            if not found:
                return False

        elif key == "has_link":
            has_link = bool(threat.get("has_link") or email_data.get("has_link"))
            if bool(expected) != has_link:
                return False

        elif key == "keywords":
            keywords = expected if isinstance(expected, list) else [expected]
            subject = str(threat.get("subject") or email_data.get("subject") or "").lower()
            body = str(email_data.get("body") or "").lower()
            haystack = subject + " " + body
            if not any(str(kw).lower() in haystack for kw in keywords):
                return False

        elif key == "subject_contains":
            # Match ONLY against subject line (not body) — more precise than keywords
            subject = str(threat.get("subject") or email_data.get("subject") or "").lower()
            patterns = expected if isinstance(expected, list) else [expected]
            if not any(str(p).lower() in subject for p in patterns):
                return False

        elif key == "opendbl_pack":
            # OpenDBL matching is async — cannot evaluate in sync _match_policy.
            # Skip here; handled in evaluate_policies() before calling _match_policy.
            pass

        elif key == "threat_feed_match":
            # Threat feed matching is async — skip here;
            # handled in evaluate_policies() before calling _match_policy.
            pass

    return True


async def _check_threat_feed_condition(email_data: dict, sub_conditions: dict) -> bool:
    """
    Async helper: evaluate threat_feed_match sub-conditions.
    sub_conditions may include:
      url_match  : list of feed IDs to check URLs against
      ip_match   : list of feed IDs to check sender IP against
      domain_match: list of feed IDs to check sender domain against
    Returns True if ANY sub-condition matches.
    """
    try:
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        from backend.services.threat_feeds_service import (
            check_url_in_feeds,
            check_ip_in_feeds,
            check_domain_in_feeds,
        )
        import re as _re

        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            # URL match
            if "url_match" in sub_conditions:
                feed_ids = sub_conditions["url_match"]
                body = str(email_data.get("body") or "")
                urls = _re.findall(r'https?://[^\s<>"\' ]+', body)[:10]
                score_breakdown = email_data.get("score_breakdown") or {}
                urls += score_breakdown.get("suspicious_urls", []) + score_breakdown.get("malicious_urls", [])
                for url in urls:
                    hit, matches = await check_url_in_feeds(url, redis=_redis)
                    if hit and any(m in feed_ids for m in matches):
                        logger.debug(f"threat_feed_match url_match: url={url} feeds={matches}")
                        return True

            # IP match
            if "ip_match" in sub_conditions:
                feed_ids = sub_conditions["ip_match"]
                auth_results = email_data.get("auth_results") or {}
                sender_ip = auth_results.get("sender_ip", "")
                if sender_ip:
                    hit, matches = await check_ip_in_feeds(sender_ip, redis=_redis)
                    if hit and any(m in feed_ids for m in matches):
                        logger.debug(f"threat_feed_match ip_match: ip={sender_ip} feeds={matches}")
                        return True

            # Domain match
            if "domain_match" in sub_conditions:
                feed_ids = sub_conditions["domain_match"]
                sender_domain = str(email_data.get("sender_domain") or "")
                if sender_domain:
                    hit, matches = await check_domain_in_feeds(sender_domain, redis=_redis)
                    if hit and any(m in feed_ids for m in matches):
                        logger.debug(f"threat_feed_match domain_match: domain={sender_domain} feeds={matches}")
                        return True
        finally:
            await _redis.aclose()
    except Exception as _e:
        logger.debug(f"threat_feed_condition check failed (non-fatal): {_e}")
    return False


async def _check_opendbl_condition(email_data: dict, pack_ids) -> bool:
    """
    Async helper: check whether any extracted IP from the email matches
    any of the given OpenDBL pack(s).
    """
    try:
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        from backend.services.opendbl_service import (
            extract_ips_from_email,
            check_ip_in_any_pack,
        )

        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            ips = extract_ips_from_email(email_data)
            if not ips:
                return False
            packs = pack_ids if isinstance(pack_ids, list) else [pack_ids]
            for ip in ips:
                hit = await check_ip_in_any_pack(_redis, ip, packs)
                if hit:
                    logger.debug(f"OpenDBL hit: ip={ip} pack={hit}")
                    return True
        finally:
            await _redis.aclose()
    except Exception as _e:
        logger.debug(f"opendbl_condition check failed (non-fatal): {_e}")
    return False


async def evaluate_policies(
    email_data: dict,
    org_id: str,
    db: AsyncSession,
) -> Optional[dict]:
    """
    Evaluate all active policies for an org against incoming email data.
    Returns the first matching policy dict, or None if no policy matches.

    email_data should contain: sender, sender_domain, recipient (or recipient_email),
    threat_type, risk_score, has_attachment, has_link, subject, body, attachments
    """
    from backend.models.db_models import Policy

    try:
        result = await db.execute(
            select(Policy).where(
                Policy.org_id == org_id,
                Policy.status == "active",
            ).order_by(Policy.priority.asc())
        )
        policies = result.scalars().all()
    except Exception as e:
        logger.warning(f"Policy load failed: {e}")
        return None

    # Normalise email_data so both "recipient" and "recipient_email" are available
    email_data_norm = dict(email_data)
    if "recipient" in email_data_norm and "recipient_email" not in email_data_norm:
        email_data_norm["recipient_email"] = email_data_norm["recipient"]
    elif "recipient_email" in email_data_norm and "recipient" not in email_data_norm:
        email_data_norm["recipient"] = email_data_norm["recipient_email"]

    threat_stub = {
        "sender": email_data_norm.get("sender", ""),
        "sender_domain": email_data_norm.get("sender_domain", ""),
        "recipient_email": email_data_norm.get("recipient_email", ""),
        "threat_type": email_data_norm.get("threat_type", ""),
        "risk_score": email_data_norm.get("risk_score", 0),
        "subject": email_data_norm.get("subject", ""),
        "has_attachment": email_data_norm.get("has_attachment", False),
        "has_link": email_data_norm.get("has_link", False),
    }

    for policy in policies:
        p = {
            "id": str(policy.id),
            "name": policy.name,
            "action": policy.action,
            "conditions": policy.conditions or {},
            "action_config": policy.action_config or {},
            "priority": policy.priority,
        }

        # ── Async pre-checks (OpenDBL + Threat Feeds) ─────────────────────────
        conds = p["conditions"]
        skip_keys = set()

        if "opendbl_pack" in conds:
            pack_ids = conds["opendbl_pack"]
            opendbl_matched = await _check_opendbl_condition(email_data_norm, pack_ids)
            if not opendbl_matched:
                continue
            skip_keys.add("opendbl_pack")

        if "threat_feed_match" in conds:
            sub_conds = conds["threat_feed_match"]
            feed_matched = await _check_threat_feed_condition(email_data_norm, sub_conds)
            if not feed_matched:
                continue
            skip_keys.add("threat_feed_match")

        if skip_keys:
            conds_filtered = {k: v for k, v in conds.items() if k not in skip_keys}
            p_check = dict(p, conditions=conds_filtered)
        else:
            p_check = p

        if _match_policy(p_check, threat_stub, email_data_norm):
            logger.info(
                f"Policy match: '{policy.name}' ({policy.action}) for "
                f"{email_data_norm.get('sender', '?')} → {email_data_norm.get('recipient_email', '?')}"
            )
            # Increment hit_count atomically
            try:
                from sqlalchemy import text as _text
                await db.execute(
                    _text("UPDATE policies SET hit_count = COALESCE(hit_count, 0) + 1 WHERE id = :pid"),
                    {"pid": str(policy.id)},
                )
            except Exception as _hce:
                logger.debug(f"hit_count increment failed (non-fatal): {_hce}")
            return p

    return None


async def apply_policy_action(
    policy: dict,
    threat_id: str,
    email_message_id: Optional[str],
    recipient_email: Optional[str],
    org_id: str,
    db: AsyncSession,
    access_token: Optional[str] = None,
    sender_email: Optional[str] = None,
    subject: Optional[str] = None,
    ai_explanation: Optional[str] = None,
    body_preview: str = "",
    attachments: Optional[list] = None,
    link_count: int = 0,
    received_at: str = "",
    provider: Optional[str] = None,   # "gmail" | "m365" — drives which mailbox API to call
) -> dict:
    """
    Apply a matched policy's action to a threat record.
    Sends notifications (admin + recipient) for BLOCK and QUARANTINE.
    Returns a result dict describing what was done.
    """
    from backend.models.db_models import Threat, Organization, User

    action = policy.get("action", "")
    result = {
        "policy_id": policy.get("id"),
        "policy_name": policy.get("name"),
        "action": action,
        "gmail_moved": False,
    }

    try:
        # ── Live policy status gate — never apply a paused/deleted policy ──
        # Checked here so even direct callers (delta_sync, etc.) are protected.
        policy_id_str = policy.get("id")
        if policy_id_str:
            try:
                import uuid as _uuid_mod
                from backend.models.db_models import Policy as _Policy
                _pol_check = await db.get(_Policy, _uuid_mod.UUID(policy_id_str))
                if not _pol_check or _pol_check.status != "active":
                    result["error"] = f"Policy is not active (status={getattr(_pol_check, 'status', 'deleted')}) — action skipped"
                    logger.info(f"apply_policy_action: skipping '{policy.get('name')}' — not active")
                    return result
            except Exception as _pce:
                logger.debug(f"Policy status pre-check failed (non-fatal): {_pce}")

        t_result = await db.execute(
            select(Threat).where(
                Threat.id == threat_id,
                Threat.org_id == org_id,
            )
        )
        threat = t_result.scalar_one_or_none()
        if not threat:
            result["error"] = "Threat not found"
            return result

        now = datetime.utcnow()
        _sender = sender_email or (threat.sender if threat else "")
        _subject = subject or (threat.subject if threat else "")
        _ai_exp = ai_explanation or (threat.ai_explanation_en if threat else "")
        _recipient = recipient_email or (threat.recipient_email if threat else "")
        _risk = threat.risk_score if threat else 0
        _threat_type = threat.threat_type if threat else "POLICY_BLOCK"

        # Resolve provider from hint, threat record, or access_token shape
        _provider = provider or (threat.provider if hasattr(threat, "provider") else None)
        if not _provider:
            # Infer: M365 message IDs are long base64 strings; Gmail uses short alphanumeric
            _provider = "m365" if (email_message_id and len(email_message_id) > 100) else "gmail"

        if action in ("BLOCK", "BLOCK_DELETE"):
            threat.action_taken = "BLOCK_DELETE"
            threat.status = "resolved"
            threat.resolved_at = now
            if email_message_id and _recipient:
                try:
                    if _provider == "m365":
                        from backend.services.quarantine_service import block_to_trash_m365
                        moved = await block_to_trash_m365(
                            user_email=_recipient,
                            m365_message_id=email_message_id,
                            access_token=access_token,
                            org_id=str(org_id),
                        )
                    else:
                        from backend.services.quarantine_service import block_to_trash_gmail
                        moved = await block_to_trash_gmail(
                            user_email=_recipient,
                            gmail_message_id=email_message_id,
                            access_token=access_token,
                        )
                    result["moved"] = moved
                except Exception as e:
                    logger.warning(f"Block trash failed ({_provider}): {e}")

            # Notify admin + recipient + sender (all three)
            await _send_policy_notifications(
                action="BLOCK_DELETE",
                recipient_email=_recipient,
                sender_email=_sender,
                subject=_subject,
                threat_type=_threat_type,
                risk_score=_risk,
                ai_explanation=_ai_exp,
                org_id=org_id,
                db=db,
                notify_sender=True,
                body_preview=body_preview,
                attachments=attachments,
                link_count=link_count,
                received_at=received_at,
                policy_name=policy.get("name", ""),
            )

        elif action in ("QUARANTINE",):
            threat.action_taken = "QUARANTINED"
            threat.status = "quarantined"
            threat.resolved_at = now
            # Move to Himaya-Quarantine folder/label (recoverable)
            if email_message_id and _recipient:
                try:
                    if _provider == "m365":
                        from backend.services.quarantine_service import quarantine_m365_message_with_fallback
                        moved = await quarantine_m365_message_with_fallback(
                            user_email=_recipient,
                            m365_message_id=email_message_id,
                            access_token=access_token,
                            org_id=str(org_id),
                        )
                    else:
                        from backend.services.quarantine_service import quarantine_gmail_message
                        moved = await quarantine_gmail_message(
                            user_email=_recipient,
                            gmail_message_id=email_message_id,
                            access_token=access_token,
                        )
                    result["moved"] = moved
                except Exception as e:
                    logger.warning(f"Quarantine move failed ({_provider}): {e}")

            # Notify admin + recipient + sender (sender also gets notified for quarantine)
            await _send_policy_notifications(
                action="QUARANTINED",
                recipient_email=_recipient,
                sender_email=_sender,
                subject=_subject,
                threat_type=_threat_type,
                risk_score=_risk,
                ai_explanation=_ai_exp,
                org_id=org_id,
                db=db,
                notify_sender=True,
                body_preview=body_preview,
                attachments=attachments,
                link_count=link_count,
                received_at=received_at,
                policy_name=policy.get("name", ""),
            )

        elif action in ("MARK_AS_SPAM", "SPAM"):
            threat.action_taken = "MARKED_SPAM"
            threat.status = "resolved"
            threat.resolved_at = now
            if email_message_id and _recipient:
                try:
                    from backend.services.quarantine_service import mark_as_spam_gmail
                    moved = await mark_as_spam_gmail(
                        user_email=_recipient,
                        gmail_message_id=email_message_id,
                    )
                    result["gmail_moved"] = moved
                except Exception as e:
                    logger.warning(f"Gmail spam mark failed: {e}")

        elif action in ("ALERT", "FLAGGED_HIGH", "ALERT_ONLY"):
            # Flag the threat — email stays in inbox, visible label applied, admin + recipient notified
            threat.action_taken = "FLAGGED_HIGH"
            threat.status = "flagged"

            if email_message_id and _recipient:
                try:
                    if _provider == "m365":
                        from backend.services.quarantine_service import apply_category_m365
                        labelled = await apply_category_m365(
                            user_email=_recipient,
                            m365_message_id=email_message_id,
                            category_name="Himaya-Flagged",  # unified label across providers
                            access_token=access_token,
                            org_id=str(org_id),
                        )
                    else:
                        from backend.services.quarantine_service import apply_alert_label_gmail
                        labelled = await apply_alert_label_gmail(
                            user_email=_recipient,
                            gmail_message_id=email_message_id,
                            fallback_access_token=access_token,
                        )
                    result["labelled"] = labelled
                    logger.info(f"ALERT ({_provider}): label applied={labelled} on {email_message_id} for {_recipient}")
                except Exception as e:
                    logger.warning(f"ALERT label failed ({_provider}) (non-fatal): {e}")

            try:
                await _send_policy_notifications(
                    action="ALERT",
                    recipient_email=_recipient,
                    sender_email=_sender,
                    subject=_subject,
                    threat_type=_threat_type,
                    risk_score=_risk,
                    ai_explanation=_ai_exp,
                    org_id=org_id,
                    db=db,
                    notify_sender=False,
                    notify_recipient=True,
                    body_preview=body_preview,
                    attachments=attachments,
                    link_count=link_count,
                    received_at=received_at,
                    policy_name=policy.get("name", ""),
                )
            except Exception as _ne:
                logger.warning(f"ALERT notification failed (non-fatal): {_ne}")
            result["alerted"] = True

        elif action in ("TAG", "DELIVER_WITH_BANNER"):
            # Deliver with flagged label/category — email stays in inbox but visibly marked.
            threat.action_taken = "BANNER"
            threat.status = "flagged"
            if email_message_id and _recipient:
                try:
                    if _provider == "m365":
                        from backend.services.quarantine_service import apply_category_m365
                        labelled = await apply_category_m365(
                            user_email=_recipient,
                            m365_message_id=email_message_id,
                            category_name="Himaya-Flagged",
                            access_token=access_token,
                            org_id=str(org_id),
                        )
                    else:
                        from backend.services.quarantine_service import apply_flagged_label_gmail
                        labelled = await apply_flagged_label_gmail(
                            user_email=_recipient,
                            gmail_message_id=email_message_id,
                            fallback_access_token=access_token,
                        )
                    result["labelled"] = labelled
                    logger.info(f"TAG ({_provider}): flagged label applied={labelled} on {email_message_id} for {_recipient}")
                except Exception as e:
                    logger.warning(f"TAG Gmail label failed: {e}")
                    result["gmail_labelled"] = False

        elif action == "ALLOW":
            threat.action_taken = "CLEAN"
            threat.status = "resolved"

        threat.policy_id = policy.get("id")
        await db.flush()

    except Exception as e:
        logger.error(f"apply_policy_action error: {e}")
        result["error"] = str(e)

    return result


async def _send_policy_notifications(
    action: str,
    recipient_email: str,
    sender_email: str,
    subject: str,
    threat_type: str,
    risk_score: int,
    ai_explanation: str,
    org_id: str,
    db: AsyncSession,
    notify_sender: bool = False,
    notify_recipient: bool = True,   # default True — recipients always get told
    # ── Richer email context ────────────────────────────────────
    body_preview: str = "",
    attachments: Optional[list] = None,
    link_count: int = 0,
    received_at: str = "",
    policy_name: str = "",
) -> None:
    """
    Send admin + recipient + sender notifications for a policy match.
    Recipient and sender both get full context: preview, attachments, links, AI explanation.
    """
    # ── Guard: never send notifications for Himaya system emails (breaks loops) ──
    _HELIOS_SYSTEM = {"noreply@himaya.ai", "no-reply@himaya.ai", "noreply@notify.himaya.ai"}
    if (sender_email or "").lower() in _HELIOS_SYSTEM:
        logger.debug(f"_send_policy_notifications: skipping — sender is Himaya system ({sender_email})")
        return

    import asyncio as _asyncio
    from backend.models.db_models import Organization as _Org, User as _User
    from backend.services.email_service import (
        send_threat_alert as _send_alert,
        send_quarantine_notification as _send_qn,
        send_sender_block_notification as _send_sender,
    )
    try:
        import uuid as _uuid
        org_uuid = _uuid.UUID(org_id) if isinstance(org_id, str) else org_id
        _org_res = await db.execute(select(_Org).where(_Org.id == org_uuid))
        _org = _org_res.scalar_one_or_none()

        _admin_res = await db.execute(
            select(_User).where(
                _User.org_id == org_uuid,
                _User.role == "admin",
                _User.is_active.is_(True),
            ).limit(1)
        )
        _admin = _admin_res.scalar_one_or_none()
        org_name = _org.name if _org else "Your Organization"

        # ── Admin alert ────────────────────────────────────────────
        if _admin and _admin.email:
            await _asyncio.to_thread(
                _send_alert,
                to_email=_admin.email,
                org_name=org_name,
                threat_type=threat_type or "POLICY_BLOCK",
                risk_score=risk_score or 0,
                recipient=recipient_email or "",
                action=action,
                detection_time=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            )
            logger.info(f"Policy admin alert sent to {_admin.email}")

        # ── Recipient notification (full context) ──────────────────
        if notify_recipient and recipient_email:
            # Only show dashboard button if recipient has portal access
            _recip_res = await db.execute(
                select(_User).where(_User.email == recipient_email, _User.is_active.is_(True))
            )
            _recip = _recip_res.scalar_one_or_none()
            _is_admin_recip = _recip is not None and _recip.role in ("admin", "analyst")
            await _asyncio.to_thread(
                _send_qn,
                to_email=recipient_email,
                org_name=org_name,
                threat_type=threat_type or "POLICY_BLOCK",
                risk_score=risk_score or 0,
                sender_email=sender_email or "",
                subject=subject or "",
                action=action,
                ai_explanation=ai_explanation or "",
                body_preview=body_preview,
                attachments=attachments or [],
                link_count=link_count,
                received_at=received_at,
                policy_name=policy_name,
                is_admin_recipient=_is_admin_recip,
            )
            logger.info(f"Policy recipient notification sent to {recipient_email} (admin={_is_admin_recip})")

        # ── Sender notification — BLOCK + QUARANTINE ───────────────
        # Sender always hears back regardless of action type
        if notify_sender and sender_email:
            await _asyncio.to_thread(
                _send_sender,
                to_email=sender_email,
                recipient_org=org_name,
                subject=subject or "",
                threat_type=threat_type or "POLICY_BLOCK",
                action=action,
                recipient_email=recipient_email or "",
                body_preview=body_preview,
                attachments=attachments or [],
                link_count=link_count,
                ai_explanation=ai_explanation or "",
                policy_name=policy_name,
            )
            logger.info(f"Policy sender notification sent to {sender_email}")

    except Exception as e:
        logger.warning(f"Policy notifications failed (non-fatal): {e}")


async def retroactive_apply(
    org_id: str,
    db: AsyncSession,
    limit: int = 0,  # 0 = no limit, process ALL
) -> dict:
    """
    Scan ALL existing open/flagged threats for this org and apply matching active policies.
    Paginates in batches of 200 to avoid memory pressure.
    """
    from backend.models.db_models import Threat, Policy, OrgIntegration
    from backend.services.baseline_ingestion import _decrypt

    # Load active policies
    pol_result = await db.execute(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.status == "active",
        ).order_by(Policy.priority.asc())
    )
    policies = pol_result.scalars().all()

    if not policies:
        return {"processed": 0, "matched": 0, "moved": 0, "message": "No active policies found."}

    # Get org OAuth fallback token (for Gmail quarantine)
    fallback_token = None
    try:
        int_res = await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_id == org_id,
                OrgIntegration.provider == "google",
                OrgIntegration.status == "active",
            )
        )
        integration = int_res.scalar_one_or_none()
        if integration and integration.access_token_enc:
            fallback_token = _decrypt(integration.access_token_enc)
    except Exception:
        pass

    # Check if any BLOCK policy exists — if so, also reprocess quarantined emails
    has_block_policy = any(p.action in ("BLOCK", "BLOCK_DELETE") for p in policies)

    eligible_statuses = ["FLAGGED_LOW", "FLAGGED_HIGH", "DELIVER", "CLEAN", None]
    if has_block_policy:
        eligible_statuses.append("QUARANTINED")

    BATCH = 200
    offset = 0
    threats = []
    while True:
        q = select(Threat).where(
            Threat.org_id == org_id,
            Threat.action_taken.in_(eligible_statuses),
        ).order_by(Threat.detected_at.desc()).offset(offset).limit(BATCH)
        batch_result = await db.execute(q)
        batch = batch_result.scalars().all()
        if not batch:
            break
        threats.extend(batch)
        if len(batch) < BATCH:
            break
        offset += BATCH
        if limit and len(threats) >= limit:
            threats = threats[:limit]
            break

    processed = 0
    matched = 0
    moved = 0

    for threat in threats:
        processed += 1
        email_data = {
            "sender": threat.sender or "",
            "sender_domain": threat.sender_domain or "",
            "recipient": threat.recipient_email or "",
            "recipient_email": threat.recipient_email or "",
            "threat_type": threat.threat_type or "",
            "risk_score": threat.risk_score or 0,
            "subject": threat.subject or "",
        }

        threat_stub = {
            "sender": threat.sender or "",
            "sender_domain": threat.sender_domain or "",
            "recipient_email": threat.recipient_email or "",
            "threat_type": threat.threat_type or "",
            "risk_score": threat.risk_score or 0,
            "subject": threat.subject or "",
        }

        for policy in policies:
            # ── Live status check — respect immediate pause/delete ─────────
            # Re-query the DB so a policy paused mid-run stops NOW, not at
            # the next batch boundary.
            try:
                _live = await db.get(Policy, policy.id)
                if not _live or _live.status != "active":
                    logger.info(f"Skipping policy '{policy.name}' — status is '{getattr(_live, 'status', 'deleted')}' (was active at batch start)")
                    continue
            except Exception:
                continue  # If we can't verify, skip rather than apply blindly

            p = {
                "id": str(policy.id),
                "name": policy.name,
                "action": policy.action,
                "conditions": policy.conditions or {},
                "action_config": policy.action_config or {},
                "priority": policy.priority,
            }
            # Handle async pre-checks in retroactive mode
            _p_check = p
            _skip_keys = set()
            _conds = p["conditions"] or {}

            if "opendbl_pack" in _conds:
                pack_ids = _conds["opendbl_pack"]
                opendbl_hit = await _check_opendbl_condition(email_data, pack_ids)
                if not opendbl_hit:
                    continue
                _skip_keys.add("opendbl_pack")

            if "threat_feed_match" in _conds:
                sub_conds = _conds["threat_feed_match"]
                feed_hit = await _check_threat_feed_condition(email_data, sub_conds)
                if not feed_hit:
                    continue
                _skip_keys.add("threat_feed_match")

            if _skip_keys:
                _conds_filtered = {k: v for k, v in _conds.items() if k not in _skip_keys}
                _p_check = dict(p, conditions=_conds_filtered)

            if _match_policy(_p_check, threat_stub, email_data):
                matched += 1
                # Increment hit_count
                try:
                    from sqlalchemy import text as _text
                    await db.execute(
                        _text("UPDATE policies SET hit_count = COALESCE(hit_count, 0) + 1 WHERE id = :pid"),
                        {"pid": str(policy.id)},
                    )
                except Exception:
                    pass
                # Infer provider from message ID length (M365 IDs are long base64)
                _retro_provider = "m365" if (
                    threat.email_message_id and len(threat.email_message_id) > 100
                ) else "gmail"
                res = await apply_policy_action(
                    policy=p,
                    threat_id=str(threat.id),
                    email_message_id=threat.email_message_id,
                    recipient_email=threat.recipient_email,
                    org_id=str(org_id),
                    db=db,
                    access_token=fallback_token,
                    sender_email=threat.sender,
                    subject=threat.subject,
                    ai_explanation=threat.ai_explanation_en,
                    provider=_retro_provider,
                )
                if res.get("moved") or res.get("gmail_moved"):
                    moved += 1
                break  # First-match wins

    await db.commit()

    return {
        "processed": processed,
        "matched": matched,
        "moved": moved,
        "message": (
            f"Scanned {processed} emails. {matched} matched active policies. "
            f"{moved} physically actioned in mailbox."
        ),
    }
