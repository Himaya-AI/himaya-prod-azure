import logging
from datetime import datetime, date, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
import uuid

logger = logging.getLogger(__name__)

from backend.database import get_db
from backend.models.db_models import Threat
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/api/quarantine", tags=["quarantine"])

QUARANTINE_ACTIONS = ("QUARANTINE", "QUARANTINED", "BLOCK_DELETE", "BLOCK")

# Actions that mean the message is no longer in the user's mailbox.
_CONTAINED_ACTIONS = ("QUARANTINE", "QUARANTINED", "MARKED_SPAM", "BLOCK_DELETE", "BLOCK")


def _already_contained(threat: Threat) -> bool:
    """True when Himaya has already pulled this message out of the mailbox.

    A provider move rewrites the message id in the destination folder and
    hard-capture deletes the original, so re-acting on the stored id 404s even
    though the desired end state (mail out of the inbox) is already true.
    Report that end state instead of a misleading failure.
    """
    return (
        (threat.action_taken or "") in _CONTAINED_ACTIONS
        or (threat.status or "") == "quarantined"
    )


def threat_to_dict(t: Threat) -> dict:
    return {
        "id": str(t.id),
        "org_id": str(t.org_id),
        "subject": getattr(t, "subject", None),
        "email_message_id": t.email_message_id,
        "sender": t.sender,
        "sender_domain": t.sender_domain,
        "recipient_email": t.recipient_email,
        "threat_type": t.threat_type,
        "risk_score": t.risk_score,
        "score_breakdown": t.score_breakdown,
        "graph_score": t.graph_score,
        "content_score": t.content_score,
        "reputation_score": t.reputation_score,
        "status": t.status,
        "action_taken": t.action_taken,
        "ai_explanation_en": t.ai_explanation_en,
        "ai_explanation_ar": t.ai_explanation_ar,
        "threat_indicators": t.threat_indicators,
        "sama_controls": t.sama_controls,
        "nca_controls": t.nca_controls,
        "false_positive": t.false_positive,
        "llm_confidence": getattr(t, "llm_confidence", None),
        "llm_classification": getattr(t, "llm_classification", None),
        "llm_model": getattr(t, "llm_model", None),
        "urgency_score": getattr(t, "urgency_score", None),
        "impersonation_detected": getattr(t, "impersonation_detected", None),
        "impersonation_target": getattr(t, "impersonation_target", None),
        "detected_at": t.detected_at.isoformat() if t.detected_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def quarantine_filter():
    return or_(
        Threat.action_taken.in_(QUARANTINE_ACTIONS),
        Threat.status == "quarantined",
    )


@router.get("")
async def list_quarantine(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [
        Threat.org_id == current_user.org_id,
        quarantine_filter(),
    ]

    if sender:
        filters.append(Threat.sender.ilike(f"%{sender}%"))
    if recipient:
        filters.append(Threat.recipient_email.ilike(f"%{recipient}%"))
    if threat_type:
        # DB stores types as uppercase (PHISHING, BEC etc.) but frontend may send lowercase
        filters.append(func.upper(Threat.threat_type) == threat_type.upper())
    if date_from:
        filters.append(Threat.detected_at >= datetime.fromisoformat(date_from))
    if date_to:
        filters.append(Threat.detected_at <= datetime.fromisoformat(date_to))
    if status and status != "all":
        if status == "unresolved":
            # "Unresolved" = still held in the Himaya-Quarantine folder awaiting an
            # analyst decision. Auto-triage marks CONTAINED mail status='resolved'
            # with action_taken='QUARANTINED' (auto_triage_service._apply_verdict),
            # so filtering on status alone wrongly hid every auto-quarantined email.
            # Released mail uses action_taken='CLEAN' (already excluded by
            # quarantine_filter); block/delete are terminal. So "unresolved" here =
            # still carrying a QUARANTINE action/status and not a confirmed FP.
            filters.append(Threat.status != "false_positive")
            filters.append(or_(
                Threat.action_taken.in_(["QUARANTINE", "QUARANTINED"]),
                Threat.status == "quarantined",
            ))
        else:
            filters.append(Threat.status == status)

    total_result = await db.execute(
        select(func.count()).select_from(Threat).where(and_(*filters))
    )
    total = total_result.scalar() or 0

    result = await db.execute(
        select(Threat)
        .where(and_(*filters))
        .order_by(Threat.detected_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = result.scalars().all()

    return {
        "items": [threat_to_dict(t) for t in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/stats")
async def quarantine_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_filter = Threat.org_id == current_user.org_id
    q_filter = quarantine_filter()

    # Total quarantined
    total_result = await db.execute(
        select(func.count()).select_from(Threat).where(and_(org_filter, q_filter))
    )
    total = total_result.scalar() or 0

    # Released today (status=resolved, action_taken=DELIVER, resolved_at today)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    released_result = await db.execute(
        select(func.count()).select_from(Threat).where(
            and_(
                org_filter,
                Threat.action_taken == "DELIVER",
                Threat.resolved_at >= today_start,
            )
        )
    )
    released_today = released_result.scalar() or 0

    # False positives
    fp_result = await db.execute(
        select(func.count()).select_from(Threat).where(
            and_(org_filter, Threat.status == "false_positive")
        )
    )
    false_positives = fp_result.scalar() or 0

    # High-risk blocked (risk_score >= 80 and quarantined)
    high_risk_result = await db.execute(
        select(func.count()).select_from(Threat).where(
            and_(org_filter, q_filter, Threat.risk_score >= 80)
        )
    )
    high_risk_blocked = high_risk_result.scalar() or 0

    # Counts by threat_type
    type_result = await db.execute(
        select(Threat.threat_type, func.count().label("count"))
        .where(and_(org_filter, q_filter))
        .group_by(Threat.threat_type)
    )
    by_type = {row.threat_type: row.count for row in type_result.all() if row.threat_type}

    return {
        "total_quarantined": total,
        "released_today": released_today,
        "false_positives": false_positives,
        "high_risk_blocked": high_risk_blocked,
        "by_threat_type": by_type,
    }


@router.post("/{threat_id}/release")
async def release_email(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Preferred restore: if the message was hard-captured (pulled fully out of
    # the mailbox with an encrypted copy held by Himaya), re-inject that copy.
    reinjected = False
    if threat.email_message_id and threat.recipient_email:
        try:
            from backend.services.mailbox_capture_service import (
                get_capture_for_release, reinject_gmail, reinject_m365, mark_capture_released,
            )
            cap = await get_capture_for_release(
                org_id=str(current_user.org_id),
                user_email=threat.recipient_email,
                original_message_id=threat.email_message_id,
            )
            if cap:
                if cap["provider"] == "m365":
                    new_id = await reinject_m365(threat.recipient_email, cap["raw"], str(current_user.org_id))
                else:
                    new_id = await reinject_gmail(threat.recipient_email, cap["raw"])
                if new_id:
                    await mark_capture_released(cap["id"])
                    reinjected = True
                    # The reinjected copy has a NEW provider message id — persist
                    # it so later analyst actions (re-quarantine/spam/trash) target
                    # the live message instead of the deleted original.
                    threat.email_message_id = new_id
                    logger.info(f"Released captured message back to {threat.recipient_email} as {new_id}")
        except Exception as _re:
            logger.warning(f"capture reinject failed, falling back to label restore: {_re}")

    # Legacy restore: re-add INBOX / strip the hidden quarantine label. Only runs
    # when there was no captured copy (hidden-folder fallback quarantine).
    gmail_restored = reinjected
    if not reinjected and threat.email_message_id and threat.recipient_email:
        try:
            import httpx as _httpx
            import asyncio as _asyncio
            from backend.services.baseline_ingestion import _get_service_account_headers_sync, _decrypt
            from backend.models.db_models import OrgIntegration as _OI
            from sqlalchemy import select as _sel

            headers = await _asyncio.to_thread(_get_service_account_headers_sync, threat.recipient_email)

            if not headers:
                # Fall back to org's stored OAuth token
                int_res = await db.execute(
                    _sel(_OI).where(
                        _OI.org_id == current_user.org_id,
                        _OI.provider == "google",
                        _OI.status == "active",
                    )
                )
                integ = int_res.scalar_one_or_none()
                if integ and integ.access_token_enc:
                    try:
                        token = _decrypt(integ.access_token_enc)
                        headers = {"Authorization": f"Bearer {token}"}
                    except Exception:
                        pass

            if headers:
                async with _httpx.AsyncClient(timeout=10) as client:
                    # Find the Himaya-Quarantine label ID so we can remove it
                    helios_label_id = None
                    try:
                        labels_resp = await client.get(
                            f"https://gmail.googleapis.com/gmail/v1/users/{threat.recipient_email}/labels",
                            headers=headers,
                        )
                        if labels_resp.status_code == 200:
                            for lbl in labels_resp.json().get("labels", []):
                                if lbl.get("name") == "Himaya-Quarantine":
                                    helios_label_id = lbl["id"]
                                    break
                    except Exception:
                        pass

                    # TRASH removal un-trashes the message (Trash is the current
                    # quarantine fallback); SPAM + the legacy Himaya-Quarantine
                    # label are removed for older quarantines.
                    remove_labels = ["SPAM", "TRASH"]
                    if helios_label_id:
                        remove_labels.append(helios_label_id)

                    # Restore INBOX and remove Trash / Himaya-Quarantine + SPAM labels
                    resp = await client.post(
                        f"https://gmail.googleapis.com/gmail/v1/users/{threat.recipient_email}/messages/{threat.email_message_id}/modify",
                        headers={**headers, "Content-Type": "application/json"},
                        json={"addLabelIds": ["INBOX"], "removeLabelIds": remove_labels},
                    )
                    gmail_restored = resp.status_code == 200
                    import logging
                    logging.getLogger(__name__).info(f"Gmail release: {resp.status_code} for {threat.email_message_id}")
        except Exception as _e:
            import logging
            logging.getLogger(__name__).warning(f"Gmail restore failed (non-fatal): {_e}")

    threat.status = "resolved"
    threat.action_taken = "CLEAN"
    threat.resolved_at = datetime.now(timezone.utc)
    await db.flush()
    return {"message": "Email released", "threat_id": threat_id, "gmail_restored": gmail_restored}


@router.post("/{threat_id}/block-permanently")
async def block_permanently(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Create block policy for this sender domain
    from backend.models.db_models import Policy
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    domain = threat.sender_domain or (threat.sender.split("@")[-1] if threat.sender and "@" in threat.sender else "")
    policy_created = False
    if domain:
        policy_name = f"Block: {domain}"
        # Use INSERT ... ON CONFLICT DO NOTHING to avoid race conditions / duplicate errors
        # that would abort the entire asyncpg transaction
        stmt = pg_insert(Policy.__table__).values(
            id=uuid.uuid4(),
            org_id=current_user.org_id,
            name=policy_name,
            description=f"Auto-created: block all mail from {domain}",
            priority=10,
            conditions={"sender_domain": domain, "sender_email": threat.sender or ""},
            action="BLOCK_DELETE",
            action_config={"move_to_trash": True},
            status="active",
        ).on_conflict_do_nothing(index_elements=None)
        # Fall back to name+org unique check if no unique index on those cols
        try:
            existing = await db.execute(
                select(Policy).where(
                    Policy.org_id == current_user.org_id,
                    Policy.name == policy_name,
                )
            )
            if not existing.scalar_one_or_none():
                db.add(Policy(
                    org_id=current_user.org_id,
                    name=policy_name,
                    description=f"Auto-created: block all mail from {domain}",
                    priority=10,
                    conditions={"sender_domain": domain, "sender_email": threat.sender or ""},
                    action="BLOCK_DELETE",
                    action_config={"move_to_trash": True},
                    status="active",
                ))
                await db.flush()  # flush policy only, inside try
                policy_created = True
        except Exception as e:
            # Policy already exists or race condition — not fatal, continue with threat update
            await db.rollback()
            logger.warning(f"block-permanently: policy upsert skipped (already exists or race): {e}")
            # Re-fetch threat after rollback
            result2 = await db.execute(
                select(Threat).where(
                    Threat.id == uuid.UUID(threat_id),
                    Threat.org_id == current_user.org_id,
                )
            )
            threat = result2.scalar_one_or_none()
            if not threat:
                raise HTTPException(status_code=404, detail="Threat not found after rollback")

    # Physically move the message to Trash / Deleted Items too — "block" must
    # remove the mail from the user's view, not just create a policy for
    # future mail. Best-effort: the block policy is created regardless.
    physically_trashed = False
    if threat.email_message_id and threat.recipient_email:
        try:
            import httpx as _httpx
            from backend.services.quarantine_service import (
                _get_m365_app_token, _get_sa_headers_async, _request_with_retry, GMAIL_API_BASE,
            )
            _is_m365 = len(threat.email_message_id or "") > 100 or (threat.email_message_id or "").startswith("AAMk")
            if _is_m365:
                _tok = await _get_m365_app_token(str(current_user.org_id))
                if _tok:
                    async with _httpx.AsyncClient(timeout=30) as _c:
                        _r = await _request_with_retry(
                            _c, "POST",
                            f"https://graph.microsoft.com/v1.0/users/{threat.recipient_email}/messages/{threat.email_message_id}/move",
                            headers={"Authorization": f"Bearer {_tok}"},
                            json={"destinationId": "deleteditems"},
                        )
                        physically_trashed = _r.status_code in (200, 201)
                        if physically_trashed:
                            _nid = (_r.json() or {}).get("id")
                            if _nid:
                                threat.email_message_id = _nid
            else:
                _headers = await _get_sa_headers_async(threat.recipient_email)
                if _headers:
                    async with _httpx.AsyncClient(timeout=30) as _c:
                        _r = await _request_with_retry(
                            _c, "POST",
                            f"{GMAIL_API_BASE}/users/{threat.recipient_email}/messages/{threat.email_message_id}/trash",
                            headers=_headers,
                        )
                        physically_trashed = _r.status_code == 200
            if not physically_trashed:
                logger.warning(f"block-permanently: physical trash failed for {threat.email_message_id} ({threat.recipient_email})")
        except Exception as _te:
            logger.warning(f"block-permanently: physical trash errored (policy still created): {_te}")

    threat.status = "resolved"
    threat.action_taken = "BLOCK_DELETE"
    threat.resolved_at = datetime.now(timezone.utc)
    await db.flush()

    # Update Neo4j — add FLAGGED_AS edge for this sender (strong block signal)
    try:
        from backend.services.graph_service import graph_service
        if threat.sender and threat.threat_type:
            await graph_service.record_threat(
                sender=threat.sender,
                threat_type=threat.threat_type or "BLOCKED",
            )
    except Exception as _ge:
        logger.debug(f"block-permanently: graph update failed (non-fatal): {_ge}")

    return {"message": "Email permanently blocked", "threat_id": threat_id, "policy_created": policy_created, "moved_to_trash": physically_trashed}


@router.post("/{threat_id}/quarantine")
async def manual_quarantine(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually quarantine an email from the Himaya UI.
    Calls Gmail/M365 API to physically move the email out of the inbox.
    Returns whether the physical move succeeded.
    """
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Attempt to physically move the email — detect provider by message_id format
    physically_moved = False
    is_m365 = len(threat.email_message_id or '') > 100 or (threat.email_message_id or '').startswith('AAMk')
    if threat.email_message_id and threat.recipient_email:
        try:
            if is_m365:
                from backend.services.quarantine_service import quarantine_m365_message_with_fallback
                physically_moved = await quarantine_m365_message_with_fallback(
                    user_email=threat.recipient_email,
                    m365_message_id=threat.email_message_id,
                    org_id=str(current_user.org_id),
                    internet_message_id=(threat.auth_results or {}).get("internet_message_id"),
                )
            else:
                from backend.services.quarantine_service import quarantine_gmail_message
                physically_moved = await quarantine_gmail_message(
                    user_email=threat.recipient_email,
                    gmail_message_id=threat.email_message_id,
                    access_token=None,
                    org_id=str(current_user.org_id),
                    threat_id=str(threat.id),
                    internet_message_id=(threat.auth_results or {}).get("internet_message_id"),
                )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Manual quarantine move failed ({'m365' if is_m365 else 'gmail'}): {e}")

    # Only record the quarantined state when the mailbox move actually succeeded —
    # otherwise the console would show "contained" while the email is still visible.
    if physically_moved:
        threat.status = "quarantined"
        threat.action_taken = "QUARANTINED"
        await db.flush()

    provider = 'M365' if is_m365 else 'Gmail'
    # Re-quarantining a message Himaya already removed is a no-op, not a failure.
    _already = (not physically_moved) and _already_contained(threat)
    if physically_moved:
        _msg = f"Email quarantined and moved ({provider})"
    elif _already:
        _msg = f"Already contained — Himaya has already removed this message from the {provider} mailbox"
    else:
        _msg = f"Quarantine FAILED — could not move the email out of the {provider} mailbox"
    return {
        "message": _msg,
        "threat_id": threat_id,
        "physically_moved": physically_moved or _already,
        "gmail_moved": physically_moved or _already,  # keep legacy field name
        "already_applied": _already,
        "gmail_message_id": threat.email_message_id,
    }


@router.post("/{threat_id}/mark-as-spam")
async def mark_as_spam(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark email as spam — moves to Gmail spam folder and records for future tuning."""
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    spam_moved = False
    if threat.email_message_id and threat.recipient_email:
        # Detect provider: M365 message IDs are long base64 strings starting with AAMk
        is_m365 = (threat.email_message_id or "").startswith("AAMk") or len(threat.email_message_id or "") > 100
        try:
            if is_m365:
                from backend.services.quarantine_service import mark_as_spam_m365
                spam_moved = await mark_as_spam_m365(
                    user_email=threat.recipient_email,
                    m365_message_id=threat.email_message_id,
                    org_id=str(current_user.org_id),
                    internet_message_id=(threat.auth_results or {}).get("internet_message_id"),
                )
            else:
                from backend.services.quarantine_service import mark_as_spam_gmail
                spam_moved = await mark_as_spam_gmail(
                    user_email=threat.recipient_email,
                    gmail_message_id=threat.email_message_id,
                    internet_message_id=(threat.auth_results or {}).get("internet_message_id"),
                )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Spam mark failed (provider={'m365' if is_m365 else 'gmail'}): {e}")

    provider_label = "Junk Email (M365)" if (threat.email_message_id or "").startswith("AAMk") or len(threat.email_message_id or "") > 100 else "Spam (Gmail)"
    # Only record MARKED_SPAM when the mailbox move actually succeeded.
    if spam_moved:
        threat.status = "resolved"
        threat.action_taken = "MARKED_SPAM"
        threat.resolved_at = datetime.now(timezone.utc)
        await db.flush()
        return {"message": f"Marked as spam — moved to {provider_label}", "threat_id": threat_id, "gmail_moved": True}

    # Idempotency: Himaya may have ALREADY moved this message to spam (e.g.
    # auto-triage). A provider move rewrites the message id in the destination
    # folder, so the id we stored no longer resolves and the retry 404s — even
    # though the mail is sitting in the spam folder exactly as intended. Report
    # the true end state instead of a misleading failure.
    if _already_contained(threat):
        _was_spam = (threat.action_taken or "") == "MARKED_SPAM"
        return {
            "message": (
                f"Already marked as spam — the message is in {provider_label}"
                if _was_spam else
                "Already contained — Himaya has removed this message from the mailbox, "
                "so there is nothing left to move to spam"
            ),
            "threat_id": threat_id,
            "gmail_moved": True,
            "already_applied": True,
        }

    raise HTTPException(
        status_code=502,
        detail=f"Could not move the email to {provider_label} (provider API error). The message was NOT marked as spam.",
    )


@router.post("/{threat_id}/report-fp")
async def report_false_positive(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat.status = "false_positive"
    threat.false_positive = True
    threat.resolved_at = datetime.now(timezone.utc)
    await db.commit()   # was db.flush() — changes were never persisted to DB

    # Store false positive as classifier feedback — biases future analysis
    # for emails from this sender/domain toward BENIGN
    try:
        import json as _json, os as _os
        import redis.asyncio as _aioredis   # async client — sync client blocks event loop
        feedback = {
            "org_id": str(current_user.org_id),
            "sender_domain": threat.sender_domain or "",
            "sender_email": threat.sender or "",
            "original_classification": threat.threat_type or "UNKNOWN",
            "true_label": "BENIGN",
            "subject_hint": (threat.subject or "")[:100],
            "llm_confidence": threat.llm_confidence,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }
        _r = _aioredis.from_url(_os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        key = f"fp_feedback:{current_user.org_id}:{threat.sender_domain}"
        existing_raw = await _r.get(key)
        existing = _json.loads(existing_raw) if existing_raw else []
        existing.append(feedback)
        existing = existing[-50:]  # keep last 50 FP signals per domain
        await _r.set(key, _json.dumps(existing), ex=86400 * 90)

        # Also queue a retraining signal so the content classifier learns from this
        retrain_signal = {
            "type": "false_positive",
            "threat_id": str(threat.id),
            "sender_domain": threat.sender_domain or "",
            "sender_email": threat.sender or "",
            "threat_type": threat.threat_type or "UNKNOWN",
            "subject": (threat.subject or "")[:200],
            "body_preview": (threat.email_body_preview or "")[:500],
            "org_id": str(current_user.org_id),
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }
        await _r.lpush("helios:retrain_queue", _json.dumps(retrain_signal))
        await _r.expire("helios:retrain_queue", 86400 * 30)
        await _r.aclose()
        logger.info(f"FP feedback + retrain signal stored for domain {threat.sender_domain} org {current_user.org_id}")
    except Exception as _fe:
        logger.warning(f"FP feedback storage failed (non-fatal): {_fe}")

    # Update Neo4j — retract FLAGGED_AS edge so future graph scoring reflects the correction
    try:
        from backend.services.graph_service import graph_service
        if threat.sender:
            await graph_service.retract_threat(
                sender=threat.sender,
                threat_type=threat.threat_type,  # remove only this specific type, not all
            )
        logger.info(f"FP: retracted Neo4j FLAGGED_AS edge for {threat.sender} ({threat.threat_type})")
    except Exception as _gfp:
        logger.debug(f"FP: graph retract failed (non-fatal): {_gfp}")

    return {"message": "Reported as false positive — model updated for future analysis", "threat_id": threat_id}
