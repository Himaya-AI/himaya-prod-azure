"""
Message Trace / Email Search - Similar to Proofpoint Message Center
Allows searching all processed emails by sender, recipient, subject hash, 
date range, status, threat type, etc.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, text
from typing import Optional
from datetime import datetime, date
from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.models.db_models import User

router = APIRouter(prefix="/api/message-trace", tags=["message-trace"])

# Threat types that aren't actual email send/receive events and don't belong
# in Message Trace. They live in dedicated UIs:
#   DLP_DRAFT         -> Outbound DLP / Draft alerts panel
#   SAAS_DATA_LEAK    -> Workspace Security > Alerts
# Message Trace is strictly for messages that hit the mail flow (inbound
# delivered/quarantined/blocked, outbound sent).
NON_MAIL_THREAT_TYPES = ("DLP_DRAFT", "SAAS_DATA_LEAK")


def _flat_indicators(ti) -> list:
    """
    Normalize threat_indicators to a flat list of strings regardless of storage format.
    The processor stores it as a dict:  {"content": [...], "graph": [...], ...}
    Legacy data or direct entries may be a plain list.
    Always returns list[str] — safe for JSON and frontend .map()/.filter().
    """
    if not ti:
        return []
    if isinstance(ti, list):
        return [str(x) for x in ti if x]
    if isinstance(ti, dict):
        out = []
        for v in ti.values():
            if isinstance(v, list):
                out.extend(str(x) for x in v if x)
            elif isinstance(v, str) and v:
                out.append(v)
        return out
    return []

@router.get("")
async def search_messages(
    # Search filters
    sender: Optional[str] = Query(None, description="Sender email or domain"),
    recipient: Optional[str] = Query(None, description="Recipient email"),
    subject_keyword: Optional[str] = Query(None, description="Subject keyword search"),
    keyword: Optional[str] = Query(None, description="Blanket search across sender, recipient, subject"),
    sender_domain: Optional[str] = Query(None, description="Sender domain"),
    
    # Date range
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    
    # Status filters
    status: Optional[str] = Query(None, description="open,resolved,false_positive,quarantined"),
    action_taken: Optional[str] = Query(None, description="DELIVER,QUARANTINE,BLOCK_DELETE,etc"),
    threat_type: Optional[str] = Query(None),
    
    # Risk score filter
    min_score: Optional[int] = Query(None, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),

    # Auth filter: "spf_fail" | "dkim_fail" | "dmarc_fail" | "any_fail"
    auth_fail: Optional[str] = Query(None, description="Filter by auth failure: spf_fail, dkim_fail, dmarc_fail, any_fail"),
    
    # Pagination
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    
    # Sort
    sort_by: str = Query("detected_at", description="detected_at, risk_score, sender"),
    sort_order: str = Query("desc"),
    
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Search and trace all emails processed by Himaya Helios.
    Returns paginated results with full threat metadata.
    """
    from backend.models.db_models import Threat
    
    org_id = current_user.org_id
    
    # Build query
    query = select(Threat).where(Threat.org_id == org_id)
    count_query = select(func.count(Threat.id)).where(Threat.org_id == org_id)
    
    # Apply filters
    # Exclude rows that aren't real email send/receive events:
    #  - user-reported threats (belong in Threat Queue)
    #  - DLP_DRAFT (drafts UI / outbound DLP panel)
    #  - SAAS_DATA_LEAK (Workspace Security alerts)
    filters = [
        Threat.action_taken != "USER_REPORTED",
        or_(Threat.threat_type.is_(None), Threat.threat_type.notin_(NON_MAIL_THREAT_TYPES)),
    ]
    if sender:
        filters.append(Threat.sender.ilike(f"%{sender}%"))
    if recipient:
        filters.append(Threat.recipient_email.ilike(f"%{recipient}%"))
    if sender_domain:
        filters.append(Threat.sender_domain.ilike(f"%{sender_domain}%"))
    if date_from:
        # Filter on email_received_at (actual delivery) when available, fall back to detected_at
        filters.append(
            or_(
                and_(Threat.email_received_at != None, Threat.email_received_at >= date_from),
                and_(Threat.email_received_at == None, Threat.detected_at >= date_from),
            )
        )
    if date_to:
        filters.append(
            or_(
                and_(Threat.email_received_at != None, Threat.email_received_at <= date_to),
                and_(Threat.email_received_at == None, Threat.detected_at <= date_to),
            )
        )
    if status:
        filters.append(Threat.status == status)
    if action_taken:
        filters.append(Threat.action_taken == action_taken)
    if threat_type:
        filters.append(Threat.threat_type == threat_type)
    if min_score is not None:
        filters.append(Threat.risk_score >= min_score)
    if max_score is not None:
        filters.append(Threat.risk_score <= max_score)
    if subject_keyword:
        try:
            filters.append(Threat.subject.ilike(f"%{subject_keyword}%"))
        except Exception:
            pass
    if keyword:
        # or_ is imported at module scope; do not reimport here (the inner
        # import would cause UnboundLocalError on the module-level or_ refs
        # earlier in the function body).
        try:
            filters.append(or_(
                Threat.sender.ilike(f"%{keyword}%"),
                Threat.recipient_email.ilike(f"%{keyword}%"),
                Threat.subject.ilike(f"%{keyword}%"),
                Threat.sender_domain.ilike(f"%{keyword}%"),
            ))
        except Exception:
            filters.append(or_(
                Threat.sender.ilike(f"%{keyword}%"),
                Threat.recipient_email.ilike(f"%{keyword}%"),
                Threat.sender_domain.ilike(f"%{keyword}%"),
            ))

    # Auth fail filter — query JSONB auth_results field
    if auth_fail:
        from sqlalchemy import cast as _cast, String as _String
        _fail_vals = ("fail", "softfail", "none", "temperror", "permerror")
        if auth_fail == "dkim_fail":
            filters.append(
                func.lower(_cast(Threat.auth_results["dkim"], _String)).in_(_fail_vals)
            )
        elif auth_fail == "spf_fail":
            filters.append(
                func.lower(_cast(Threat.auth_results["spf"], _String)).in_(_fail_vals)
            )
        elif auth_fail == "dmarc_fail":
            filters.append(
                func.lower(_cast(Threat.auth_results["dmarc"], _String)).in_(_fail_vals)
            )
        elif auth_fail == "any_fail":
            filters.append(
                or_(
                    func.lower(_cast(Threat.auth_results["dkim"], _String)).in_(_fail_vals),
                    func.lower(_cast(Threat.auth_results["spf"], _String)).in_(_fail_vals),
                    func.lower(_cast(Threat.auth_results["dmarc"], _String)).in_(_fail_vals),
                )
            )

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))
    
    # Sort — when sorting by time, prefer email_received_at (actual delivery), fall back to detected_at
    from sqlalchemy import case as _case
    if sort_by == "detected_at":
        effective_time_col = _case(
            (Threat.email_received_at != None, Threat.email_received_at),
            else_=Threat.detected_at,
        )
        if sort_order == "desc":
            query = query.order_by(effective_time_col.desc())
        else:
            query = query.order_by(effective_time_col.asc())
    else:
        sort_col = getattr(Threat, sort_by, Threat.detected_at)
        if sort_order == "desc":
            query = query.order_by(sort_col.desc())
        else:
            query = query.order_by(sort_col.asc())
    
    # Pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    # Execute
    result = await db.execute(query)
    threats = result.scalars().all()
    
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    return {
        "results": [
            {
                "id": str(t.id),
                "message_id": t.email_message_id,
                "sender": t.sender,
                "sender_domain": t.sender_domain,
                "recipient": t.recipient_email,
                "subject": t.subject or None,
                "subject_hash": t.subject_hash,
                "threat_type": t.threat_type,
                "risk_score": t.risk_score,
                "status": t.status,
                "action_taken": t.action_taken,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
                "email_received_at": t.email_received_at.isoformat() if getattr(t, "email_received_at", None) else None,
                "auth_results": getattr(t, "auth_results", None),
                "graph_score": t.graph_score,
                "content_score": t.content_score,
                "reputation_score": t.reputation_score,
                "ai_explanation_en": t.ai_explanation_en,
                "threat_indicators": _flat_indicators(t.threat_indicators),
                "sama_controls": list(t.sama_controls) if t.sama_controls else [],
                "nca_controls": list(t.nca_controls) if t.nca_controls else [],
            }
            for t in threats
        ],
        "pagination": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
        "filters_applied": {
            "sender": sender,
            "recipient": recipient,
            "sender_domain": sender_domain,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "status": status,
            "action_taken": action_taken,
            "threat_type": threat_type,
            "min_score": min_score,
            "max_score": max_score,
        }
    }

@router.get("/export")
async def export_messages(
    sender: Optional[str] = Query(None),
    recipient: Optional[str] = Query(None),
    sender_domain: Optional[str] = Query(None),
    subject_keyword: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    threat_type: Optional[str] = Query(None),
    action_taken: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),
    format: str = Query("csv"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export message trace results as CSV — respects all active filters."""
    from fastapi.responses import StreamingResponse
    from backend.models.db_models import Threat
    import csv, io

    org_id = current_user.org_id
    query = select(Threat).where(Threat.org_id == org_id)

    # Mirror the list endpoint: exclude non-mail rows so the CSV matches what
    # the user sees on screen.
    filters = [
        Threat.action_taken != "USER_REPORTED",
        or_(Threat.threat_type.is_(None), Threat.threat_type.notin_(NON_MAIL_THREAT_TYPES)),
    ]
    if sender:       filters.append(Threat.sender.ilike(f"%{sender}%"))
    if recipient:    filters.append(Threat.recipient_email.ilike(f"%{recipient}%"))
    if sender_domain: filters.append(Threat.sender_domain.ilike(f"%{sender_domain}%"))
    if threat_type:  filters.append(Threat.threat_type == threat_type)
    if action_taken: filters.append(Threat.action_taken == action_taken)
    if status:       filters.append(Threat.status == status)
    if min_score is not None: filters.append(Threat.risk_score >= min_score)
    if max_score is not None: filters.append(Threat.risk_score <= max_score)
    if subject_keyword:
        try: filters.append(Threat.subject.ilike(f"%{subject_keyword}%"))
        except Exception: pass
    if keyword:
        filters.append(or_(
            Threat.sender.ilike(f"%{keyword}%"),
            Threat.recipient_email.ilike(f"%{keyword}%"),
            Threat.subject.ilike(f"%{keyword}%"),
            Threat.sender_domain.ilike(f"%{keyword}%"),
        ))
    if date_from:
        filters.append(or_(
            and_(Threat.email_received_at != None, Threat.email_received_at >= date_from),
            and_(Threat.email_received_at == None, Threat.detected_at >= date_from),
        ))
    if date_to:
        filters.append(or_(
            and_(Threat.email_received_at != None, Threat.email_received_at <= date_to),
            and_(Threat.email_received_at == None, Threat.detected_at <= date_to),
        ))
    if filters:
        query = query.where(and_(*filters))

    query = query.order_by(Threat.detected_at.desc()).limit(10000)
    result = await db.execute(query)
    threats = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Delivered At", "Analysed At", "Sender", "Recipient", "Sender Domain",
        "Subject", "Classification", "Risk Score", "SPF", "DKIM", "DMARC",
        "Sender IP", "Helios Status", "Status",
    ])
    for t in threats:
        auth = getattr(t, "auth_results", None) or {}
        writer.writerow([
            t.email_received_at.isoformat() if getattr(t, "email_received_at", None) else "",
            t.detected_at.isoformat() if t.detected_at else "",
            t.sender or "",
            t.recipient_email or "",
            t.sender_domain or "",
            t.subject or "",
            t.threat_type or "",
            t.risk_score or 0,
            auth.get("spf", ""),
            auth.get("dkim", ""),
            auth.get("dmarc", ""),
            auth.get("sender_ip", ""),
            t.action_taken or "",
            t.status or "",
        ])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),  # utf-8-sig for Excel compatibility
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=helios-message-trace.csv"}
    )

@router.post("/{message_id}/action")
async def perform_action(
    message_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Perform an analyst action on a message:
      quarantine      — move to Helios-Quarantine label in Gmail, update status
      release         — restore from quarantine back to inbox
      block_sender    — create a policy rule blocking this sender domain
      false_positive  — mark as false positive, downgrade classification
    All actions also update analyst_verdict to feed back into model training.
    """
    from backend.models.db_models import Threat, Policy
    from fastapi import HTTPException
    import uuid as _uuid

    action = body.get("action", "")
    notes = body.get("notes", "")
    org_id = current_user.org_id

    result = await db.execute(
        select(Threat).where(Threat.id == message_id, Threat.org_id == org_id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Message not found")

    if action == "quarantine":
        # Move email out of inbox — detect provider, try M365 or Gmail accordingly
        success = False
        _is_m365_msg = len(t.email_message_id or '') > 100 or (t.email_message_id or '').startswith('AAMk')
        if t.email_message_id and t.recipient_email:
            try:
                if _is_m365_msg:
                    from backend.services.quarantine_service import quarantine_m365_message_with_fallback
                    success = await quarantine_m365_message_with_fallback(
                        user_email=t.recipient_email,
                        m365_message_id=t.email_message_id,
                        org_id=str(org_id),
                    )
                else:
                    from backend.services.quarantine_service import quarantine_gmail_message
                    from backend.models.db_models import OrgIntegration
                    from backend.services.baseline_ingestion import _decrypt
                    int_res = await db.execute(
                        select(OrgIntegration).where(
                            OrgIntegration.org_id == org_id,
                            OrgIntegration.provider == "google",
                            OrgIntegration.status == "active",
                        )
                    )
                    integration = int_res.scalar_one_or_none()
                    fallback_token = None
                    if integration and integration.access_token_enc:
                        try:
                            fallback_token = _decrypt(integration.access_token_enc)
                        except Exception:
                            pass
                    success = await quarantine_gmail_message(
                        t.recipient_email, t.email_message_id, access_token=fallback_token
                    )
            except Exception as _e:
                import logging as _logging
                _logging.getLogger(__name__).warning(f"Quarantine {'M365' if _is_m365_msg else 'Gmail'} call failed: {_e}")
        t.action_taken = "QUARANTINED"
        t.status = "quarantined"
        t.analyst_verdict = "confirmed_malicious"
        t.analyst_email = current_user.email if hasattr(current_user, "email") else None
        t.analyst_notes = notes or f"Manually quarantined by analyst"
        t.reviewed_at = datetime.utcnow()
        await db.commit()
        return {"status": "ok", "action": "quarantined", "gmail_moved": success}

    elif action == "release":
        # Restore from quarantine — move back to inbox
        if t.email_message_id and t.recipient_email:
            try:
                from backend.services.quarantine_service import _get_sa_headers
                import httpx as _httpx
                headers = _get_sa_headers(t.recipient_email)
                if headers:
                    async with _httpx.AsyncClient(timeout=15) as client:
                        await client.post(
                            f"https://gmail.googleapis.com/gmail/v1/users/{t.recipient_email}/messages/{t.email_message_id}/modify",
                            headers={**headers, "Content-Type": "application/json"},
                            json={"addLabelIds": ["INBOX"], "removeLabelIds": ["SPAM"]},
                        )
            except Exception:
                pass
        t.action_taken = "CLEAN"
        t.status = "resolved"
        t.analyst_verdict = "false_positive"
        t.analyst_email = current_user.email if hasattr(current_user, "email") else None
        t.analyst_notes = notes or "Released from quarantine by analyst"
        t.reviewed_at = datetime.utcnow()
        await db.commit()
        return {"status": "ok", "action": "released"}

    elif action == "block_sender":
        # Create a policy rule that blocks all future emails from this sender/domain
        sender_id = t.sender or ""
        domain = t.sender_domain or (sender_id.split("@")[-1] if "@" in sender_id else sender_id)
        policy_name = f"Block: {domain}"
        # Upsert: find existing block policy for this domain or create new
        existing = await db.execute(
            select(Policy).where(
                Policy.org_id == org_id,
                Policy.name == policy_name,
            )
        )
        existing_policy = existing.scalar_one_or_none()
        if not existing_policy:
            new_policy = Policy(
                org_id=org_id,
                name=policy_name,
                description=f"Auto-created by analyst action: block all mail from {domain}",
                priority=10,  # high priority — runs before default policies
                conditions={"sender_domain": domain, "sender_email": sender_id},
                action="BLOCK_DELETE",
                action_config={"move_to_trash": True, "reason": "Blocked sender"},
                status="active",
                created_by=current_user.id,
            )
            db.add(new_policy)
        # Update the threat record
        t.analyst_verdict = "confirmed_malicious"
        t.analyst_email = current_user.email if hasattr(current_user, "email") else None
        t.analyst_notes = notes or f"Sender blocked: {domain}"
        t.reviewed_at = datetime.utcnow()
        await db.commit()
        return {"status": "ok", "action": "blocked", "domain": domain, "policy": policy_name}

    elif action == "false_positive":
        t.false_positive = True
        t.status = "false_positive"
        t.threat_type = "CLEAN"
        t.action_taken = "CLEAN"
        t.analyst_verdict = "false_positive"
        t.analyst_email = current_user.email if hasattr(current_user, "email") else None
        t.analyst_notes = notes or "Marked as false positive by analyst"
        t.reviewed_at = datetime.utcnow()
        await db.commit()
        return {"status": "ok", "action": "false_positive"}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


@router.get("/{message_id}/detail")
async def get_message_detail(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get enriched detail for a single message/threat including:
    - Email flow timeline
    - Similar threat counts
    - Recipient threat history
    """
    from backend.models.db_models import Threat
    from datetime import timedelta

    org_id = current_user.org_id

    import uuid as _uuid
    try:
        _msg_uuid = _uuid.UUID(message_id)
    except (ValueError, AttributeError):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid message ID format")

    result = await db.execute(
        select(Threat).where(Threat.id == _msg_uuid, Threat.org_id == org_id)
    )
    t = result.scalar_one_or_none()
    if t is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Message not found")

    # ── Build email flow timeline ──────────────────────────────────────────
    base_time = t.detected_at
    flow = []

    def ts(offset_seconds: int = 0) -> str:
        if base_time is None:
            return ""
        return (base_time + timedelta(seconds=offset_seconds)).isoformat()

    auth = getattr(t, "auth_results", None) or {}
    spf = auth.get("spf", "unknown").upper()
    dkim = auth.get("dkim", "unknown").upper()
    dmarc = auth.get("dmarc", "unknown").upper()
    sender_ip = auth.get("sender_ip", "")
    auth_summary = f"SPF: {spf} · DKIM: {dkim} · DMARC: {dmarc}"
    auth_status = "ok" if all(v == "PASS" for v in [spf, dkim, dmarc]) else ("flagged" if any(v in ("FAIL","SOFTFAIL") for v in [spf, dkim, dmarc]) else "ok")
    delivered_at = t.email_received_at.strftime("%Y-%m-%d %H:%M UTC") if getattr(t, "email_received_at", None) else "unknown time"

    # Stage 1: Delivery
    flow.append({
        "stage": "Email Delivered",
        "timestamp": ts(0),
        "status": "ok",
        "detail": (
            f"Message delivered to {t.recipient_email or 'recipient'} at {delivered_at}. "
            f"Sent from {t.sender or 'unknown sender'}"
            + (f" (originating IP: {sender_ip})" if sender_ip else "")
            + f". {auth_summary}. "
            "Helios detected this email during the next background scan cycle and queued it for analysis."
        ),
    })

    # Stage 2: Reputation Check — pull VT/WHOIS/DNS from score_breakdown
    rep = t.reputation_score or 0
    rep_status = "ok" if rep <= 30 else ("flagged" if rep <= 70 else "blocked")
    _sb = t.score_breakdown or {}
    _rep_detail_raw = _sb.get("reputation_detail", {})
    _rep_indicators = _rep_detail_raw.get("indicators", []) if isinstance(_rep_detail_raw, dict) else []
    # Also pull from threat_indicators top-level (auto-triage path stores some here)
    _ti_raw = t.threat_indicators or {}
    if isinstance(_ti_raw, dict):
        _ti_rep = _ti_raw.get("reputation_indicators", [])
        if _ti_rep: _rep_indicators = list(set((_rep_indicators or []) + _ti_rep))
    # Build human-readable signal list
    _vt_signals = [i for i in _rep_indicators if i.startswith("vt_")]
    _whois_signals = [i for i in _rep_indicators if i.startswith("whois_")]
    _dns_signals = [i for i in _rep_indicators if any(i.startswith(p) for p in ("no_mx", "no_spf", "no_dmarc", "spf_", "dkim_", "dmarc_"))]
    # Compose detail string
    if rep <= 30:
        rep_detail = f"Sender domain '{t.sender_domain or 'unknown'}' passed reputation check (score: {rep}/100). No known blacklist matches."
    elif rep <= 70:
        rep_detail = f"Sender domain '{t.sender_domain or 'unknown'}' has a moderate reputation score ({rep}/100). Flagged for deeper inspection."
    else:
        rep_detail = f"Sender domain '{t.sender_domain or 'unknown'}' has a poor reputation score ({rep}/100). Domain found on threat intelligence feeds."
    if _vt_signals:
        rep_detail += f" VirusTotal: {', '.join(_vt_signals)}."
    if _whois_signals:
        rep_detail += f" WHOIS: {', '.join(_whois_signals)}."
    if _dns_signals:
        rep_detail += f" DNS checks: {', '.join(_dns_signals)}."
    if not _rep_indicators:
        rep_detail += " SPF/DKIM/DMARC authentication results used for scoring."
    flow.append({
        "stage": "Sender Reputation Check",
        "timestamp": ts(1),
        "status": rep_status,
        "detail": rep_detail,
        "vt_signals": _vt_signals,
        "whois_signals": _whois_signals,
        "dns_signals": _dns_signals,
        "all_rep_indicators": _rep_indicators,
    })

    # Stage 3: Content Analysis
    cs = t.content_score or 0
    cs_status = "ok" if cs <= 30 else ("flagged" if cs <= 70 else "blocked")
    threat_label = t.threat_type or "suspicious content"
    if cs <= 30:
        cs_detail = f"Email body and subject analysed. No phishing patterns, suspicious links, social engineering language, or malicious attachments detected (content score: {cs}/100)."
    elif cs <= 70:
        cs_detail = f"Email content shows moderate risk indicators consistent with {threat_label} patterns (content score: {cs}/100). Subject line and body were flagged for social engineering language or suspicious link patterns. Human review recommended."
    else:
        cs_detail = f"High-confidence {threat_label} content detected (score: {cs}/100). Email exhibits strong indicators: suspicious urgency, credential harvesting patterns, or malicious payload signatures. Immediate action recommended."
    flow.append({
        "stage": "Content Analysis",
        "timestamp": ts(2),
        "status": cs_status,
        "detail": cs_detail,
    })

    # Stage 4: Graph / Relationship Analysis
    gs = t.graph_score or 0
    gs_status = "ok" if gs <= 30 else ("flagged" if gs <= 70 else "blocked")
    if gs <= 30:
        gs_detail = f"Communication graph analysis: the sender-recipient relationship appears normal (graph score: {gs}/100). Sender has an established communication history with this org or follows expected external contact patterns."
    elif gs <= 70:
        gs_detail = f"Communication graph shows unusual patterns (score: {gs}/100). Sender-recipient relationship is atypical — this sender has limited or no prior contact with the recipient, or the email arrived during an unusual time window."
    else:
        gs_detail = f"Anomalous communication pattern detected (score: {gs}/100). Sender has no prior relationship with the recipient and the message deviates significantly from normal email flow patterns — a strong indicator of spoofing or targeted attack."
    flow.append({
        "stage": "Relationship Graph",
        "timestamp": ts(3),
        "status": gs_status,
        "detail": gs_detail,
    })

    # Stage 5: AI Classification
    risk = t.risk_score or 0
    llm_conf = getattr(t, "llm_confidence", None)
    llm_class = getattr(t, "llm_classification", None)
    llm_model_raw = getattr(t, "llm_model", None) or "Helios"
    # Mark as inconclusive when confidence is low or model fell back to heuristics
    is_inconclusive = (
        (llm_conf is not None and llm_conf < 0.5)
        or llm_model_raw == "heuristic_fallback"
        or (llm_class and "inconclusive" in str(llm_class).lower())
    )
    conf_pct = f"{int(llm_conf * 100)}%" if llm_conf is not None else None
    model_label = "Helios AI"
    if is_inconclusive:
        ai_status = "flagged"
        conf_str = f" ({conf_pct} confidence)" if conf_pct else ""
        ai_detail = (
            f"{model_label} could not reach a definitive conclusion{conf_str}. "
            f"Risk score is {risk}/100 based on content, reputation, and graph signals combined. "
            "The individual scoring layers produced conflicting signals — manual analyst review is recommended "
            "before taking action on this email."
        )
    elif risk <= 30:
        conf_str = f" ({conf_pct} confidence)" if conf_pct else " (high confidence)"
        ai_detail = f"{model_label} classified this email as clean{conf_str}. No threat patterns match known attack types. Email is consistent with legitimate communication from this sender type."
        ai_status = "ok"
    elif risk <= 70:
        conf_str = f" ({conf_pct} confidence)" if conf_pct else ""
        ai_detail = f"{model_label} classified this email as {threat_label} with moderate risk{conf_str}. Risk score {risk}/100. Concerning patterns detected but definitive confirmation requires analyst review."
        ai_status = "flagged"
    else:
        conf_str = f" ({conf_pct} confidence)" if conf_pct else " (high confidence)"
        ai_detail = f"{model_label} classified this email as high-risk {threat_label}{conf_str} — score: {risk}/100. Multiple corroborating threat signals detected across content, reputation, and relationship layers."
        ai_status = "blocked"
    flow.append({
        "stage": "AI Classification",
        "timestamp": ts(4),
        "status": ai_status,
        "detail": ai_detail,
        "llm_confidence": llm_conf,
        "llm_classification": llm_class,
        "llm_model": llm_model_raw,
        "inconclusive": is_inconclusive,
    })

    # Stage 6: Action Applied
    action = t.action_taken or "CLEAN"
    action_status_map = {
        "CLEAN": "ok",
        "DELIVER": "ok",
        "FLAGGED_LOW": "flagged",
        "FLAGGED_HIGH": "flagged",
        "BANNER": "flagged",
        "HOLD": "flagged",
        "QUARANTINE": "blocked",
        "QUARANTINED": "blocked",
        "BLOCK_DELETE": "blocked",
        "BLOCK": "blocked",
    }
    action_status = action_status_map.get(action, "ok")
    action_labels = {
        "CLEAN": "Email assessed as clean and left in inbox. No action required. Helios will continue monitoring future emails from this sender.",
        "DELIVER": "Email assessed as clean and left in inbox. No action required. Helios will continue monitoring future emails from this sender.",
        "FLAGGED_LOW": "Email flagged as low risk. Left in inbox but marked for analyst review. The recipient has not been notified — monitor for follow-up suspicious activity.",
        "FLAGGED_HIGH": "Email flagged as high risk and left in inbox. Analyst review is strongly recommended. Consider quarantining if the recipient has not yet acted on this email.",
        "QUARANTINED": "Email removed from inbox and moved to the Helios-Quarantine folder. The recipient can no longer see this email in their inbox. Analyst can review and release from the Quarantine tab.",
        "QUARANTINE": "Email removed from inbox and moved to the Helios-Quarantine folder. The recipient can no longer see this email in their inbox. Analyst can review and release from the Quarantine tab.",
        "BLOCK_DELETE": "Email has been blocked and deleted. A policy rule is active to reject future emails from this sender. No further action required unless the block needs to be reviewed.",
        "BLOCK": "Email has been blocked and deleted. A policy rule is active to reject future emails from this sender. No further action required unless the block needs to be reviewed.",
    }
    flow.append({
        "stage": "Helios Action",
        "timestamp": ts(5),
        "status": action_status,
        "detail": action_labels.get(action, f"Action applied: {action}"),
    })

    # ── Sender IP → Country lookup ─────────────────────────────────────────
    sender_country: str | None = None
    sender_country_code: str | None = None
    if sender_ip:
        try:
            import httpx as _geo_httpx
            _geo = await _geo_httpx.AsyncClient(timeout=5).get(
                f"http://ip-api.com/json/{sender_ip}?fields=status,country,countryCode"
            )
            if _geo.status_code == 200:
                _gd = _geo.json()
                if _gd.get("status") == "success":
                    sender_country = _gd.get("country")
                    sender_country_code = _gd.get("countryCode")
        except Exception:
            pass  # geo lookup is best-effort, never block the response

    # Inject country into auth_results so the frontend gets it in one place
    if sender_country and isinstance(auth, dict):
        auth = {**auth, "sender_country": sender_country, "sender_country_code": sender_country_code}

    # ── Similar threats count (same sender_domain, last 30 days) ──────────
    similar_count = 0
    if t.sender_domain:
        cutoff_30d = base_time - timedelta(days=30) if base_time else datetime.utcnow() - timedelta(days=30)
        sim_q = await db.execute(
            select(func.count(Threat.id)).where(
                Threat.org_id == org_id,
                Threat.sender_domain == t.sender_domain,
                Threat.id != t.id,
                Threat.detected_at >= cutoff_30d,
            )
        )
        similar_count = sim_q.scalar() or 0

    # ── Recipient threat history (last 90 days) ────────────────────────────
    recipient_history = 0
    if t.recipient_email:
        cutoff_90d = base_time - timedelta(days=90) if base_time else datetime.utcnow() - timedelta(days=90)
        rec_q = await db.execute(
            select(func.count(Threat.id)).where(
                Threat.org_id == org_id,
                Threat.recipient_email == t.recipient_email,
                Threat.id != t.id,
                Threat.detected_at >= cutoff_90d,
            )
        )
        recipient_history = rec_q.scalar() or 0

    # ── DLP event lookup — find most recent DLP event for this sender+subject ──
    dlp_summary: dict | None = None
    try:
        cutoff_dlp = base_time - timedelta(hours=24) if base_time else datetime.utcnow() - timedelta(hours=24)
        dlp_rows = await db.execute(
            text(
                "SELECT id, risk_level, action_taken, categories_found, matched_patterns, "
                "confidence, created_at "
                "FROM dlp_events "
                "WHERE org_id = :oid "
                "AND sender_email = :sender "
                "AND created_at >= :cutoff "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {
                "oid": str(org_id),
                "sender": t.sender or "",
                "cutoff": cutoff_dlp,
            },
        )
        dlp_row = dlp_rows.fetchone()
        if dlp_row:
            dlp_summary = {
                "event_id": str(dlp_row[0]),
                "risk_level": dlp_row[1],
                "action_taken": dlp_row[2],
                "categories_found": dlp_row[3] if isinstance(dlp_row[3], list) else [],
                "matched_patterns": dlp_row[4] if isinstance(dlp_row[4], list) else [],
                "confidence": dlp_row[5],
                "score": {"low": 10, "medium": 50, "high": 75, "critical": 95}.get(dlp_row[1] or "low", 10),
                "label": {
                    "low": "Clean",
                    "medium": "Internal Only",
                    "high": "Confidential",
                    "critical": "Highly Confidential",
                }.get(dlp_row[1] or "low", "Unknown"),
                "scanned_at": dlp_row[6].isoformat() if dlp_row[6] else None,
            }
    except Exception as _dlp_exc:
        import logging as _log
        _log.getLogger(__name__).warning(f"message_trace: DLP lookup failed: {_dlp_exc}")

    return {
        "id": str(t.id),
        "message_id": t.email_message_id,
        "sender": t.sender,
        "sender_domain": t.sender_domain,
        "recipient": t.recipient_email,
        "subject": t.subject or None,
        "subject_hash": t.subject_hash,
        "threat_type": t.threat_type,
        "risk_score": t.risk_score,
        "status": t.status,
        "action_taken": t.action_taken,
        "detected_at": t.detected_at.isoformat() if t.detected_at else None,
        "email_received_at": t.email_received_at.isoformat() if getattr(t, "email_received_at", None) else None,
        "auth_results": auth,  # enriched with sender_country/sender_country_code if geo lookup succeeded
        "graph_score": t.graph_score,
        "content_score": t.content_score,
        "reputation_score": t.reputation_score,
        "score_breakdown": t.score_breakdown or {},
        "ai_explanation_en": t.ai_explanation_en,
        "ai_explanation_ar": t.ai_explanation_ar,
        # AI / LLM fields
        "llm_confidence": getattr(t, "llm_confidence", None),
        "llm_classification": getattr(t, "llm_classification", None),
        "llm_model": getattr(t, "llm_model", None),
        # Threat signal fields
        "urgency_score": getattr(t, "urgency_score", None),
        "impersonation_detected": getattr(t, "impersonation_detected", None),
        "impersonation_target": getattr(t, "impersonation_target", None),
        "threat_indicators": _flat_indicators(t.threat_indicators),
        "sama_controls": list(t.sama_controls) if t.sama_controls else [],
        "nca_controls": list(t.nca_controls) if t.nca_controls else [],
        "email_flow": flow,
        "similar_threats_count": similar_count,
        "recipient_threat_history": recipient_history,
        # score_breakdown sub-fields — exposed so frontend can show URLs/attachments
        "suspicious_urls": (t.score_breakdown or {}).get("suspicious_urls", []),
        "malicious_urls": (t.score_breakdown or {}).get("malicious_urls", []),
        "suspicious_attachments": (t.score_breakdown or {}).get("suspicious_attachments", []),
        # all_attachments: every attachment filename, not just dangerous ones
        "all_attachments": (t.score_breakdown or {}).get("all_attachments", []),
        # ── Reputation intelligence (VT, WHOIS, DNS) ──────────────────────
        "reputation_intel": {
            "score": rep,
            "indicators": _rep_indicators,
            "vt_signals": _vt_signals,
            "whois_signals": _whois_signals,
            "dns_signals": _dns_signals,
            "spf_pass": _rep_detail_raw.get("spf_pass") if isinstance(_rep_detail_raw, dict) else None,
            "dkim_pass": _rep_detail_raw.get("dkim_pass") if isinstance(_rep_detail_raw, dict) else None,
            "dmarc_pass": _rep_detail_raw.get("dmarc_pass") if isinstance(_rep_detail_raw, dict) else None,
        },
        # ── DLP classification (linked from dlp_events for this sender) ───
        "dlp": dlp_summary,
    }


@router.get("/stats")
async def message_stats(
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get aggregate stats for the message trace timeframe"""
    from backend.models.db_models import Threat
    from sqlalchemy import func
    
    org_id = current_user.org_id
    
    # Mirror list/export: exclude non-mail threat types so stats line up with
    # the visible rows.
    base_where = and_(
        Threat.org_id == org_id,
        Threat.action_taken != "USER_REPORTED",
        or_(Threat.threat_type.is_(None), Threat.threat_type.notin_(NON_MAIL_THREAT_TYPES)),
    )

    total_q = await db.execute(select(func.count(Threat.id)).where(base_where))
    total = total_q.scalar()
    
    by_action_q = await db.execute(
        select(Threat.action_taken, func.count(Threat.id))
        .where(base_where)
        .group_by(Threat.action_taken)
    )
    by_action = {row[0]: row[1] for row in by_action_q.fetchall()}
    
    by_type_q = await db.execute(
        select(Threat.threat_type, func.count(Threat.id))
        .where(base_where)
        .group_by(Threat.threat_type)
    )
    by_type = {row[0]: row[1] for row in by_type_q.fetchall()}
    
    return {
        "total_messages": total,
        "by_action": by_action,
        "by_threat_type": by_type,
    }
