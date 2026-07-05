from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, and_, text
import uuid

from backend.database import get_db
from backend.models.db_models import User, Threat
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/api/people", tags=["people"])

# Job-title patterns that indicate executive / high-value targets
VIP_TITLE_PATTERNS = (
    "ceo", "cfo", "cto", "ciso", "coo", "cpo",
    "chief", "president", "vice president", "vp ",
    "director", "head of", "managing director", "md",
    "executive", "partner", "chairman",
    # Arabic equivalents
    "رئيس تنفيذي", "مدير عام", "نائب الرئيس", "رئيس مجلس",
)


def _is_vip_by_title(job_title: str | None) -> bool:
    if not job_title:
        return False
    lt = job_title.lower()
    return any(p in lt for p in VIP_TITLE_PATTERNS)


def _compute_risk_score(threats: list) -> int:
    """
    Dynamically compute a 0-100 inbox risk score from the user's threat history.
    Weights by threat type / severity, with recency decay over 90 days.
    """
    # Points per threat type (use threat_type field)
    TYPE_WEIGHT = {
        "bec": 30, "executive_impersonation": 30,
        "phishing": 22, "spear_phishing": 25,
        "malware": 20, "ransomware": 28,
        "credential_harvesting": 18,
        "spam": 5, "graymail": 3,
    }
    now = datetime.utcnow()
    cutoff_90d = now - timedelta(days=90)
    score = 0.0
    for t in threats:
        detected = t.get("detected_at")
        # Azure PostgreSQL returns detected_at as tz-aware (TIMESTAMPTZ); normalise to
        # naive UTC so comparisons with datetime.utcnow() don't raise TypeError.
        if detected is not None and getattr(detected, "tzinfo", None) is not None:
            detected = detected.replace(tzinfo=None)
        if detected and detected < cutoff_90d:
            continue
        type_pts = TYPE_WEIGHT.get((t.get("threat_type") or "").lower(), 8)
        # Risk score from the threat itself (0-100) adds weight
        trs = min(100, t.get("risk_score") or 0)
        pts = type_pts + (trs / 10)
        # Recency multiplier: full weight in last 7 days, decays to 40% at 90 days
        if detected:
            age_days = max(0, (now - detected).total_seconds() / 86400)
            recency = max(0.4, 1.0 - (age_days / 90) * 0.6)
        else:
            recency = 0.7
        score += pts * recency
    return min(100, round(score))


def _is_vip_by_analysis(job_title: str | None, db_is_vip: bool, threats_30d: int) -> bool:
    """
    Determine VIP status from job title patterns OR
    if they're heavily targeted (>=10 threats in 30 days → high-value target).
    """
    if _is_vip_by_title(job_title):
        return True
    if db_is_vip:
        return True
    # Heavily targeted users in the last 30 days are high-value targets
    if threats_30d >= 10:
        return True
    return False


@router.get("")
async def list_people(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query(""),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cutoff_30d = datetime.utcnow() - timedelta(days=30)
    cutoff_90d = datetime.utcnow() - timedelta(days=90)

    # Count potential threats in last 30 days (non-CLEAN action_taken)
    threats_30d_expr = func.sum(
        case(
            (
                and_(
                    Threat.detected_at >= cutoff_30d,
                    Threat.action_taken.isnot(None),
                    Threat.action_taken != "CLEAN",
                ),
                1,
            ),
            else_=0,
        )
    ).label("threats_30d")

    # Total threat count (90d) for VIP inference
    threats_90d_expr = func.sum(
        case(
            (
                and_(
                    Threat.detected_at >= cutoff_90d,
                    Threat.action_taken.isnot(None),
                    Threat.action_taken != "CLEAN",
                ),
                1,
            ),
            else_=0,
        )
    ).label("threats_90d")

    # Join threats by recipient_email
    base_q = select(
        User.id, User.email, User.name, User.department,
        User.job_title, User.role, User.risk_score, User.is_vip,
        threats_30d_expr,
        threats_90d_expr,
        func.max(Threat.detected_at).label("last_threat_at"),
    ).outerjoin(
        Threat,
        and_(
            Threat.recipient_email == User.email,
            Threat.org_id == User.org_id,
        )
    ).where(
        User.org_id == current_user.org_id,
        User.is_active.is_(True),
    ).group_by(
        User.id, User.email, User.name, User.department,
        User.job_title, User.role, User.risk_score, User.is_vip,
    )

    if search:
        base_q = base_q.where(
            (User.email.ilike(f"%{search}%")) | (User.name.ilike(f"%{search}%"))
        )

    total_result = await db.execute(
        select(func.count()).select_from(
            select(User.id).where(
                User.org_id == current_user.org_id,
                User.is_active.is_(True),
            ).subquery()
        )
    )
    total = total_result.scalar() or 0

    result = await db.execute(
        base_q.offset((page - 1) * page_size).limit(page_size)
    )
    rows = result.all()

    # For each user, fetch recent threats for dynamic risk scoring
    items = []
    for r in rows:
        threat_rows = await db.execute(
            select(Threat.threat_type, Threat.risk_score, Threat.detected_at)
            .where(
                Threat.recipient_email == r.email,
                Threat.org_id == current_user.org_id,
                Threat.detected_at >= cutoff_90d,
                Threat.action_taken.isnot(None),
                Threat.action_taken != "CLEAN",
            )
            .order_by(Threat.detected_at.desc())
            .limit(50)
        )
        threat_list = [
            {
                "threat_type": t.threat_type,
                "risk_score": t.risk_score,
                "detected_at": t.detected_at,
            }
            for t in threat_rows.all()
        ]

        computed_risk = _compute_risk_score(threat_list)
        threats_30d_count = int(r.threats_30d or 0)
        is_vip = _is_vip_by_analysis(r.job_title, r.is_vip or False, threats_30d_count)

        items.append({
            "id": str(r.id),
            "email": r.email,
            "name": r.name,
            "job_title": r.job_title,
            "role": r.role,
            "is_vip": is_vip,
            "risk_score": computed_risk,
            "threats_30d": int(r.threats_30d or 0),
            "last_threat_at": r.last_threat_at.isoformat() if r.last_threat_at else None,
        })

    # Sort by computed risk score descending
    items.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/groups")
async def list_groups(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns email groups / distribution lists.
    Primary source: email_groups DB table (populated by delta sync every 60s).
    Falls back to live Google/M365 API if DB table is empty (first load).
    """
    from backend.models.db_models import OrgIntegration, Organization
    from backend.services.baseline_ingestion import _decrypt
    from sqlalchemy import text as _text
    import logging
    log = logging.getLogger(__name__)

    # ── Fast path: read from DB (delta-sync populated), enrich with threat data ──
    try:
        rows = (await db.execute(_text(
            "SELECT group_email, group_name, description, member_count, provider, external_id "
            "FROM email_groups WHERE org_id = :oid ORDER BY group_name"
        ), {"oid": current_user.org_id})).fetchall()
        if rows:
            from backend.models.db_models import OrgIntegration, Threat
            from backend.services.baseline_ingestion import _decrypt as _dec
            from sqlalchemy import func as _func
            import httpx as _httpx

            # Load active integrations once (reused across all groups)
            _google_intg = (await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == current_user.org_id,
                    OrgIntegration.provider == "google",
                    OrgIntegration.status == "active",
                )
            )).scalar_one_or_none()
            _m365_intg = (await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == current_user.org_id,
                    OrgIntegration.provider == "m365",
                    OrgIntegration.status == "active",
                )
            )).scalar_one_or_none()
            # Always refresh tokens — stored tokens expire in 1h, same as delta_sync does
            from backend.services.baseline_ingestion import _refresh_google_token, _refresh_m365_token
            _google_token: str | None = None
            if _google_intg:
                if _google_intg.refresh_token_enc:
                    _google_token = await _refresh_google_token(_dec(_google_intg.refresh_token_enc))
                if not _google_token and _google_intg.access_token_enc:
                    _google_token = _dec(_google_intg.access_token_enc)  # fallback

            _m365_token: str | None = None
            if _m365_intg:
                if _m365_intg.refresh_token_enc:
                    _m365_token = await _refresh_m365_token(_dec(_m365_intg.refresh_token_enc))
                if not _m365_token and _m365_intg.access_token_enc:
                    _m365_token = _dec(_m365_intg.access_token_enc)  # fallback

            enriched = []
            for r in rows:
                member_emails: list[str] = []
                is_shared_mailbox = (r.description or "").lower() == "shared mailbox"
                provider = (r.provider or "").lower()

                # ── Google groups: Admin SDK ───────────────────────────────
                if provider == "google" and _google_token and not is_shared_mailbox:
                    try:
                        from backend.services.google_workspace_service import GoogleWorkspaceService
                        _svc = GoogleWorkspaceService(
                            access_token=_google_token,
                            refresh_token=_dec(_google_intg.refresh_token_enc) if _google_intg and _google_intg.refresh_token_enc else "",
                            org_id=str(current_user.org_id),
                        )
                        member_emails = await _svc.list_group_members(r.group_email)
                    except Exception as _me:
                        log.debug(f"Google list_group_members failed for {r.group_email}: {_me}")

                # ── M365 DL / mail groups: Graph /groups/{id}/members ──────
                elif provider == "m365" and _m365_token and not is_shared_mailbox and r.external_id:
                    try:
                        async with _httpx.AsyncClient(timeout=15) as _hc:
                            _mr = await _hc.get(
                                f"https://graph.microsoft.com/v1.0/groups/{r.external_id}/members",
                                headers={"Authorization": f"Bearer {_m365_token}"},
                                params={"$select": "mail,userPrincipalName", "$top": "500"},
                            )
                            if _mr.status_code == 200:
                                member_emails = [
                                    m.get("mail") or m.get("userPrincipalName", "")
                                    for m in _mr.json().get("value", [])
                                    if m.get("mail") or m.get("userPrincipalName")
                                ]
                    except Exception as _me:
                        log.debug(f"M365 group members failed for {r.group_email}: {_me}")

                # ── M365 shared mailboxes: Graph memberOf (delegates) ──────
                elif provider == "m365" and _m365_token and is_shared_mailbox and r.external_id:
                    try:
                        async with _httpx.AsyncClient(timeout=15) as _hc:
                            _mr = await _hc.get(
                                f"https://graph.microsoft.com/v1.0/users/{r.external_id}/memberOf",
                                headers={"Authorization": f"Bearer {_m365_token}"},
                                params={"$select": "mail,userPrincipalName", "$top": "100"},
                            )
                            if _mr.status_code == 200:
                                member_emails = [
                                    m.get("mail") or m.get("userPrincipalName", "")
                                    for m in _mr.json().get("value", [])
                                    if m.get("mail") or m.get("userPrincipalName")
                                ]
                    except Exception as _me:
                        log.debug(f"M365 shared mailbox delegates failed for {r.group_email}: {_me}")

                # ── Threat hits ───────────────────────────────────────────
                threat_hits = 0
                try:
                    if is_shared_mailbox:
                        # Count threats delivered directly to the shared mailbox address
                        direct_hits = (await db.execute(
                            select(_func.count(Threat.id)).where(
                                Threat.org_id == current_user.org_id,
                                Threat.recipient_email == r.group_email,
                                Threat.action_taken != "CLEAN",
                            )
                        )).scalar() or 0
                        # Also count threats to individual delegates who have access
                        member_hits = 0
                        if member_emails:
                            member_hits = (await db.execute(
                                select(_func.count(Threat.id)).where(
                                    Threat.org_id == current_user.org_id,
                                    Threat.recipient_email.in_(member_emails),
                                    Threat.action_taken != "CLEAN",
                                )
                            )).scalar() or 0
                        threat_hits = direct_hits + member_hits
                    elif member_emails:
                        threat_hits = (await db.execute(
                            select(_func.count(Threat.id)).where(
                                Threat.org_id == current_user.org_id,
                                Threat.recipient_email.in_(member_emails),
                                Threat.action_taken != "CLEAN",
                            )
                        )).scalar() or 0
                except Exception as _te:
                    log.debug(f"Threat hits failed for {r.group_email}: {_te}")

                enriched.append({
                    "id": r.external_id or r.group_email,
                    "email": r.group_email,
                    "name": r.group_name or r.group_email,
                    "description": r.description or "",
                    "member_count": max(r.member_count or 0, len(member_emails)),
                    "members": member_emails[:50],
                    "threat_hits": threat_hits,
                    "provider": provider,
                    "is_shared_mailbox": is_shared_mailbox,
                })
            return {"items": enriched, "total": len(enriched), "source": "cache"}
    except Exception as _dbe:
        log.warning(f"groups DB read failed: {_dbe}")
    # ── Slow path: live API (first load / before delta sync populates DB) ─

    integrations_result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.status == "active",
        )
    )
    integrations = integrations_result.scalars().all()

    # Fetch org domain for Google Admin SDK
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()
    org_domain = org.domain if org else ""

    all_groups: list[dict] = []

    for integration in integrations:
        provider = (integration.provider or "").lower()
        try:
            if provider in ("google", "google_workspace", "gmail"):
                from backend.services.google_workspace_service import GoogleWorkspaceService
                from backend.services.baseline_ingestion import _refresh_google_token

                refresh_token = _decrypt(integration.refresh_token_enc) if integration.refresh_token_enc else ""
                access_token = await _refresh_google_token(refresh_token) if refresh_token else None
                if not access_token:
                    access_token = _decrypt(integration.access_token_enc) if integration.access_token_enc else ""
                if not access_token:
                    log.warning("list_groups: no access token for Google integration")
                    continue

                svc = GoogleWorkspaceService(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    org_id=str(current_user.org_id),
                )

                groups = await svc.list_groups(domain=org_domain)
                for g in groups:
                    all_groups.append({
                        "id": g.get("id", ""),
                        "email": g.get("email", ""),
                        "name": g.get("name", ""),
                        "description": g.get("description", ""),
                        "member_count": int(g.get("directMembersCount") or 0),
                        "provider": "google",
                    })

            elif provider in ("microsoft", "m365", "azure", "office365"):
                import httpx as _httpx
                from backend.services.baseline_ingestion import _refresh_m365_token

                refresh_token = _decrypt(integration.refresh_token_enc) if integration.refresh_token_enc else ""
                access_token = await _refresh_m365_token(refresh_token) if refresh_token else None
                if not access_token:
                    access_token = _decrypt(integration.access_token_enc) if integration.access_token_enc else ""
                if not access_token:
                    log.warning("list_groups: no access token for M365 integration")
                    continue

                async with _httpx.AsyncClient(timeout=20) as client:
                    # Fetch mail-enabled groups (DLs, M365 groups)
                    resp = await client.get(
                        "https://graph.microsoft.com/v1.0/groups",
                        headers={"Authorization": f"Bearer {access_token}"},
                        params={
                            "$filter": "mailEnabled eq true",
                            "$select": "id,displayName,mail,description,mailEnabled",
                            "$top": "200",
                        },
                    )
                    if resp.status_code == 200:
                        for g in resp.json().get("value", []):
                            if g.get("mail"):
                                all_groups.append({
                                    "id": g.get("id", ""),
                                    "email": g.get("mail", ""),
                                    "name": g.get("displayName", ""),
                                    "description": g.get("description", ""),
                                    "member_count": 0,
                                    "provider": "microsoft",
                                })
                    else:
                        log.warning(f"M365 groups fetch failed: {resp.status_code} {resp.text[:200]}")

                    # Also discover shared mailboxes (users with no license, accountEnabled may be False)
                    sh_resp = await client.get(
                        "https://graph.microsoft.com/v1.0/users",
                        headers={"Authorization": f"Bearer {access_token}"},
                        params={
                            "$select": "id,mail,displayName,userPrincipalName,assignedLicenses",
                            "$top": "999",
                        },
                    )
                    if sh_resp.status_code == 200:
                        for u in sh_resp.json().get("value", []):
                            if u.get("mail") and not u.get("assignedLicenses"):
                                all_groups.append({
                                    "id": u.get("id", ""),
                                    "email": u["mail"],
                                    "name": u.get("displayName", u["mail"]),
                                    "description": "Shared Mailbox",
                                    "member_count": 0,
                                    "provider": "microsoft",
                                    "is_shared_mailbox": True,
                                })

        except Exception as e:
            log.warning(f"Failed to fetch groups for provider '{provider}': {e}")

    return {
        "items": all_groups,
        "total": len(all_groups),
    }


@router.get("/{user_id}")
async def get_person(
    user_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(user_id),
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    threats_result = await db.execute(
        select(Threat)
        .where(Threat.recipient_user_id == user.id)
        .order_by(Threat.detected_at.desc())
        .limit(10)
    )
    threats = threats_result.scalars().all()

    return {
        "id": str(user.id),
        "email": user.email,
        "name": user.name,
        "department": user.department,
        "job_title": user.job_title,
        "manager_email": user.manager_email,
        "role": user.role,
        "is_vip": user.is_vip,
        "is_active": user.is_active,
        "risk_score": user.risk_score,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "threat_history": [
            {
                "id": str(t.id),
                "threat_type": t.threat_type,
                "risk_score": t.risk_score,
                "status": t.status,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in threats
        ],
    }


@router.post("/{user_id}/vip")
async def toggle_vip(
    user_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(user_id),
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_vip = not user.is_vip
    await db.flush()
    return {"user_id": user_id, "is_vip": user.is_vip}

