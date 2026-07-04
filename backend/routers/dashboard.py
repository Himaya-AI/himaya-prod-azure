from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
import uuid
import os
import json
import logging

from backend.database import get_db
from backend.models.db_models import Threat, User, Organization, ComplianceStatus, ComplianceControl, Policy, PolicyEvaluation
from backend.routers.auth import get_current_user
from backend.utils.response_cache import cached_endpoint

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# ─── In-memory cache for AI risk/compliance scores (per org, TTL 24h) ─────────
_ai_risk_cache: dict[str, dict] = {}
_AI_RISK_TTL_HOURS = 24


@router.get("/summary")
@cached_endpoint("dash:summary", ttl=30)
async def get_summary(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.org_id
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    # Threat counts
    def mk_count_query(since=None):
        q = select(func.count()).select_from(Threat).where(Threat.org_id == org_id)
        if since:
            q = q.where(Threat.detected_at >= since)
        return q

    total_today = (await db.execute(mk_count_query(today_start))).scalar() or 0
    total_week = (await db.execute(mk_count_query(week_start))).scalar() or 0
    total_month = (await db.execute(mk_count_query(month_start))).scalar() or 0

    # By status
    status_result = await db.execute(
        select(Threat.status, func.count().label("cnt"))
        .where(Threat.org_id == org_id)
        .group_by(Threat.status)
    )
    threat_counts = {row.status: row.cnt for row in status_result}

    # By type
    type_result = await db.execute(
        select(Threat.threat_type, func.count().label("cnt"))
        .where(Threat.org_id == org_id)
        .where(Threat.threat_type.isnot(None))
        .where(Threat.threat_type.notin_(["CLEAN", "BENIGN", "UNCERTAIN"]))
        .group_by(Threat.threat_type)
        .order_by(func.count().desc())
        .limit(1)
    )
    top_type_row = type_result.first()
    top_threat_type = top_type_row.threat_type if top_type_row else None

    # Org risk score
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    risk_score = org.risk_score if org else 0
    compliance_score = org.compliance_score if org else 0

    # Blend posture score into org risk score (inbox posture is a risk signal)
    # Uses a fresh DB session to avoid poisoning the main transaction on error
    try:
        from sqlalchemy import text as _pt
        from backend.database import AsyncSessionLocal as _ADSL
        async with _ADSL() as _pdb:
            _pa = await _pdb.execute(_pt(
                "SELECT COUNT(*) FILTER (WHERE risk='high') FROM posture_apps WHERE org_id=:oid"
            ), {"oid": str(org_id)})
            _pr = await _pdb.execute(_pt(
                "SELECT COUNT(*) FILTER (WHERE risk='high') FROM posture_rules WHERE org_id=:oid"
            ), {"oid": str(org_id)})
            _pf = await _pdb.execute(_pt(
                "SELECT COUNT(*) FILTER (WHERE is_external=true) FROM posture_forwards WHERE org_id=:oid"
            ), {"oid": str(org_id)})
            _high_apps = int((_pa.scalar() or 0))
            _high_rules = int((_pr.scalar() or 0))
            _ext_fwds = int((_pf.scalar() or 0))
            _posture_delta = min(20, _high_apps * 3 + _high_rules * 4 + _ext_fwds * 5)
            risk_score = min(100, risk_score + _posture_delta)
    except Exception:
        pass  # posture tables may not exist yet — non-fatal

    # If compliance_score is 0, compute live from ComplianceStatus table
    if compliance_score == 0:
        try:
            cs_result = await db.execute(
                select(ComplianceStatus.status, func.count().label("cnt"))
                .join(ComplianceControl, ComplianceControl.id == ComplianceStatus.control_id)
                .where(ComplianceControl.org_id == org_id)
                .group_by(ComplianceStatus.status)
            )
            cs_rows = cs_result.all()
            if cs_rows:
                status_map = {row.status: row.cnt for row in cs_rows}
                total_controls = sum(status_map.values())
                compliant = status_map.get("compliant", 0)
                partial = status_map.get("partial", 0)
                compliance_score = round((compliant + partial * 0.5) / total_controls * 100) if total_controls else 0
                # Persist back so dashboard doesn't recompute every time
                if org and compliance_score > 0:
                    org.compliance_score = compliance_score
                    await db.flush()
        except Exception as _ce:
            logger.debug(f"Compliance live compute failed: {_ce}")

    active_threats = (threat_counts.get("open", 0) + threat_counts.get("new", 0)
                       + threat_counts.get("investigating", 0))
    if risk_score >= 70 or active_threats >= 5:
        status = "critical"
    elif risk_score >= 40 or active_threats >= 1:
        status = "warning"
    else:
        status = "healthy"

    # Quarantined today (needed for MetricCard)
    quarantined_today_result = await db.execute(
        select(func.count()).select_from(Threat)
        .where(
            Threat.org_id == org_id,
            Threat.detected_at >= today_start,
            Threat.action_taken.in_(["QUARANTINE", "QUARANTINED", "BLOCK_DELETE", "BLOCK"]),
        )
    )
    quarantined_today = quarantined_today_result.scalar() or 0

    # Threat type breakdown (top 5)
    type_breakdown_result = await db.execute(
        select(Threat.threat_type, func.count().label("cnt"))
        .where(Threat.org_id == org_id)
        .where(Threat.threat_type.isnot(None))
        .where(Threat.threat_type != "CLEAN")
        .group_by(Threat.threat_type)
        .order_by(func.count().desc())
        .limit(5)
    )
    threat_type_breakdown = {row.threat_type: row.cnt for row in type_breakdown_result}

    # Active policies count
    active_policies_count = 0
    emails_scanned_total = 0
    try:
        import uuid as _uuid
        from backend.models.db_models import Policy as _Policy
        _oid = org_id if isinstance(org_id, _uuid.UUID) else _uuid.UUID(str(org_id))
        pol_res = await db.execute(
            select(func.count()).select_from(_Policy)
            .where(_Policy.org_id == _oid, _Policy.status == "active")
        )
        active_policies_count = pol_res.scalar() or 0

        # Total emails scanned = all threat records (CLEAN + threats)
        scan_res = await db.execute(
            select(func.count()).select_from(Threat).where(Threat.org_id == _oid)
        )
        emails_scanned_total = scan_res.scalar() or 0
    except Exception as _e:
        import logging as _lg
        _lg.getLogger(__name__).warning(f"dashboard summary extras failed: {_e}")

    return {
        "org_id": str(org_id),
        "risk_score": risk_score,
        "threat_counts": threat_counts,
        "compliance_score": compliance_score,
        "total_threats_today": total_today,
        "total_threats_week": total_week,
        "total_threats_month": total_month,
        # Frontend-expected aliases
        "threats_this_week": total_week,
        "quarantined_today": quarantined_today,
        "top_threat_type": top_threat_type,
        "threat_type_breakdown": threat_type_breakdown,
        "status": status,
        "active_threats": active_threats,
        "active_policies": active_policies_count,
        "emails_scanned": emails_scanned_total,
    }


@router.get("/threats/recent")
async def get_recent_threats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(Threat)
            .where(Threat.org_id == current_user.org_id)
            .where(Threat.threat_type != "CLEAN")
            .where(Threat.risk_score > 20)
            .order_by(Threat.detected_at.desc())
            .limit(20)
        )
        threats = result.scalars().all()

        def severity(score: int) -> str:
            if score >= 90: return "critical"
            if score >= 70: return "high"
            if score >= 50: return "medium"
            return "low"

        return [
            {
                "id": str(t.id),
                # Frontend ThreatFeedEvent fields
                "type": t.threat_type or "unknown",
                "severity": severity(t.risk_score or 0),
                "sender_domain": t.sender_domain or t.sender or "",
                "recipient": t.recipient_email or "",
                "received_at": t.detected_at.isoformat() if t.detected_at else None,
                # Extra fields for detail views
                "sender": t.sender,
                "threat_type": t.threat_type,
                "risk_score": t.risk_score,
                "status": t.status,
                "action_taken": t.action_taken,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in threats
        ]
    except Exception:
        return []


@router.get("/trends")
@cached_endpoint("dash:trends", ttl=60)
async def get_trends(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        since = datetime.utcnow() - timedelta(days=30)
        from sqlalchemy import text as _sql

        # Use raw SQL with literal 'day' to avoid asyncpg date_trunc param binding issue
        rows = (await db.execute(_sql("""
            SELECT DATE(detected_at) AS day,
                   COUNT(*) AS count,
                   COALESCE(AVG(risk_score), 0) AS avg_risk
            FROM threats
            WHERE org_id = :oid
              AND detected_at >= :since
              AND threat_type != 'CLEAN'
            GROUP BY DATE(detected_at)
            ORDER BY day
        """), {"oid": str(current_user.org_id), "since": since})).all()

        date_map: dict = {}
        for row in rows:
            d = str(row.day)[:10]
            date_map[d] = {"count": row.count, "avg_risk": float(row.avg_risk)}

        q_rows = (await db.execute(_sql("""
            SELECT DATE(detected_at) AS day, COUNT(*) AS q_count
            FROM threats
            WHERE org_id = :oid
              AND detected_at >= :since
              AND action_taken IN ('QUARANTINED', 'BLOCK_DELETE', 'MARKED_SPAM')
            GROUP BY DATE(detected_at)
        """), {"oid": str(current_user.org_id), "since": since})).all()

        q_map: dict = {}
        for row in q_rows:
            q_map[str(row.day)[:10]] = row.q_count

        # Fill ALL 30 days (0 for days with no threats — gives a complete chart)
        full_series = []
        for i in range(30):
            day = (datetime.utcnow() - timedelta(days=29 - i)).date()
            d_str = day.strftime("%Y-%m-%d")
            entry = date_map.get(d_str, {"count": 0, "avg_risk": 0.0})
            full_series.append({
                "date": d_str,
                "threats_detected": entry["count"],
                "quarantined": q_map.get(d_str, 0),
                "count": entry["count"],
                "avg_risk": round(entry["avg_risk"], 1),
            })
        return full_series
    except Exception as e:
        logger.warning(f"Trends endpoint error: {e}")
        return []


@router.get("/at-risk-employees")
async def get_at_risk_employees(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import and_ as _and
    # Join on email (recipient_user_id is often unset; email is always populated)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    result = await db.execute(
        select(
            User.id,
            User.email,
            User.name,
            User.department,
            User.risk_score,
            func.count(Threat.id).label("threat_count"),
            func.max(Threat.detected_at).label("last_threat_at"),
        )
        .outerjoin(
            Threat,
            _and(
                Threat.recipient_email == User.email,
                Threat.org_id == current_user.org_id,
                Threat.detected_at >= thirty_days_ago,
                Threat.threat_type != "CLEAN",
            ),
        )
        .where(User.org_id == current_user.org_id)
        .where(User.is_active == True)
        .group_by(User.id, User.email, User.name, User.department, User.risk_score)
        .order_by(User.risk_score.desc())
        .limit(10)
    )
    rows = result.all()

    # Total active mailboxes in org
    total_result = await db.execute(
        select(func.count(User.id)).where(
            User.org_id == current_user.org_id,
            User.is_active == True,
        )
    )
    total_mailboxes = total_result.scalar() or 0

    employees = []
    for row in rows:
        tc = row.threat_count or 0
        # Compute dynamic risk score: base on threat count, cap at 100
        dynamic_risk = min(100, (row.risk_score or 0) + tc * 8)
        # Note: dynamic_risk is computed for display only — not written back
        # to avoid fluctuating risk scores on every page load.
        employees.append({
            "user_id": str(row.id),
            "email": row.email,
            "name": row.name or row.email.split("@")[0],
            "department": row.department,
            "risk_score": dynamic_risk,
            "threat_count": tc,
            "threats_30d": tc,
            "last_threat_at": row.last_threat_at.isoformat() if row.last_threat_at else None,
        })
    return {"total_mailboxes": total_mailboxes, "employees": employees}


@router.get("/at-risk-groups")
async def get_at_risk_groups(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Top 5 most targeted groups/DLs/shared inboxes by threat volume.
    Delegates to the people/groups endpoint which uses member-based hit counting
    (same logic as the People page — sums threats on all member accounts).
    """
    try:
        from backend.routers.people import list_groups as _list_groups
        groups_resp = await _list_groups(current_user=current_user, db=db)
        # groups_resp is {items: [...], total: N, source: ...}
        items = groups_resp.get("items", []) if isinstance(groups_resp, dict) else []
        # Sort by threat_hits descending
        items_sorted = sorted(items, key=lambda x: x.get("threat_hits", 0), reverse=True)
        return [
            {
                "id": str(g.get("id", "")),
                "email": g.get("email", ""),
                "name": g.get("name") or g.get("email", ""),
                "group_type": "shared" if g.get("is_shared_mailbox") else "group",
                "threat_count": g.get("threat_hits", 0),
                "last_threat_at": None,
            }
            for g in items_sorted[:5]
        ]
    except Exception as e:
        logger.warning(f"at-risk-groups error: {e}")
        return []


@router.get("/threat-map")
async def get_threat_map(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text as _tm
    try:
        rows = (await db.execute(_tm("""
            SELECT
                UPPER(auth_results->>'sender_country_code') AS country_code,
                MAX(auth_results->>'sender_country') AS country,
                COUNT(*) AS threat_count
            FROM threats
            WHERE org_id = :org_id
              AND threat_type NOT IN ('CLEAN', 'BENIGN')
              AND auth_results->>'sender_country_code' IS NOT NULL
              AND auth_results->>'sender_country_code' != ''
            GROUP BY UPPER(auth_results->>'sender_country_code')
            ORDER BY COUNT(*) DESC
            LIMIT 9
        """), {"org_id": str(current_user.org_id)})).all()
        return [
            {"country": r.country, "country_code": (r.country_code or "").upper(), "threat_count": int(r.threat_count)}
            for r in rows if r.country_code
        ]
    except Exception as e:
        logger.warning(f"threat-map error: {e}")
        return []


# ─── Rule Usage & Top Hit Policies ───────────────────────────────────────────

@router.get("/rule-usage")
async def get_rule_usage(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return top hit policies (live, from PolicyEvaluation) and rule usage stats."""
    try:
        # Top policies by hit_count (stored directly on Policy row, incremented atomically)
        result = await db.execute(
            select(
                Policy.id,
                Policy.name,
                Policy.action,
                Policy.status,
                func.coalesce(Policy.hit_count, 0).label("hit_count"),
            )
            .where(Policy.org_id == current_user.org_id)
            .order_by(func.coalesce(Policy.hit_count, 0).desc())
            .limit(5)
        )
        rows = result.all()

        # Total evaluations (all time)
        total_result = await db.execute(
            select(func.count(PolicyEvaluation.id))
            .join(Policy, Policy.id == PolicyEvaluation.policy_id)
            .where(Policy.org_id == current_user.org_id)
        )
        total_evals = total_result.scalar() or 0

        # Active policy count
        active_result = await db.execute(
            select(func.count()).select_from(Policy)
            .where(Policy.org_id == current_user.org_id, Policy.status == "active")
        )
        active_count = active_result.scalar() or 0

        return {
            "total_evaluations": total_evals,
            "active_policies": active_count,
            "top_policies": [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "action": r.action,
                    "status": r.status,
                    "hit_count": r.hit_count or 0,
                }
                for r in rows
            ],
        }
    except Exception as e:
        logger.warning(f"rule-usage endpoint error: {e}")
        return {"total_evaluations": 0, "active_policies": 0, "top_policies": []}


# ─── AI Risk Score (Claude-based, 24h cache) ──────────────────────────────────

@router.get("/ai-risk-score")
async def get_ai_risk_score(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    force_refresh: bool = Query(False),
):
    """
    Returns a Claude-powered organizational risk score (0-100).
    Cached per-org for 24 hours. Re-evaluates on first call or after cache expiry.
    Pass force_refresh=true to bypass the cache.
    """
    org_id_str = str(current_user.org_id)

    # Return cached result if still valid (skip if force_refresh requested)
    if not force_refresh:
        cached = _ai_risk_cache.get(org_id_str)
        if cached:
            elapsed_hours = (datetime.utcnow() - cached["evaluated_at"]).total_seconds() / 3600
            # Bust cache if result was non-AI but key is now available
            if not cached.get("ai_powered") and os.getenv("ANTHROPIC_API_KEY"):
                logger.info(f"ai-risk-score: busting cache for org={org_id_str} — ANTHROPIC_API_KEY now available")
            elif elapsed_hours < _AI_RISK_TTL_HOURS:
                return cached

    # Fetch recent threat data
    now = datetime.utcnow()
    month_start = now - timedelta(days=30)

    threats_result = await db.execute(
        select(Threat.threat_type, Threat.risk_score, Threat.action_taken, Threat.detected_at)
        .where(Threat.org_id == current_user.org_id, Threat.detected_at >= month_start)
        .order_by(Threat.detected_at.desc())
        .limit(500)
    )
    threats = threats_result.all()

    # -- Threat-side metrics --
    total_threats = len(threats)
    high_risk     = sum(1 for t in threats if (t.risk_score or 0) >= 70)
    medium_risk   = sum(1 for t in threats if 40 <= (t.risk_score or 0) < 70)
    contained     = sum(1 for t in threats if t.action_taken in (
        "QUARANTINE", "QUARANTINED", "BLOCK", "BLOCK_DELETE", "MARKED_SPAM"
    ))
    flagged_no_action = sum(1 for t in threats if t.action_taken in (
        "FLAGGED_HIGH", "FLAGGED_LOW", "BANNER", "HOLD"
    ))
    by_type: dict[str, int] = {}
    for t in threats:
        if t.threat_type and t.threat_type not in ("CLEAN", "BENIGN"):
            by_type[t.threat_type] = by_type.get(t.threat_type, 0) + 1
    severe_types = {k: v for k, v in by_type.items() if k in (
        "BEC", "MALWARE", "RANSOMWARE", "GOV_IMPERSONATION",
        "CREDENTIAL_HARVESTING", "ACCOUNT_TAKEOVER",
    )}
    containment_rate = round(contained / total_threats * 100) if total_threats > 0 else 100

    # -- Policy-side metrics (how well defences cover the threat landscape) --
    try:
        # Active policies count (separate query — func.cast boolean doesn't work in asyncpg)
        _active_res = await db.execute(
            select(func.count(Policy.id)).where(
                Policy.org_id == current_user.org_id,
                Policy.status == "active"
            )
        )
        active_policies = _active_res.scalar() or 0

        # Total policy hits
        _hits_res = await db.execute(
            select(func.sum(Policy.hit_count)).where(
                Policy.org_id == current_user.org_id
            )
        )
        total_policy_hits = int(_hits_res.scalar() or 0)

        # Policy breakdown by action (active only)
        _ar = await db.execute(
            select(Policy.action, func.count(Policy.id).label("cnt"))
            .where(Policy.org_id == current_user.org_id, Policy.status == "active")
            .group_by(Policy.action)
        )
        policy_by_action = {r.action: r.cnt for r in _ar.all()}
    except Exception:
        active_policies = 0
        total_policy_hits = 0
        policy_by_action = {}

    has_quarantine_policy = any(a in policy_by_action for a in ("QUARANTINE", "QUARANTINED", "BLOCK_DELETE"))
    has_block_policy      = "BLOCK_DELETE" in policy_by_action
    has_strip_policy      = "STRIP_ATTACHMENTS" in policy_by_action

    # Fetch org info
    org_result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = org_result.scalar_one_or_none()
    mailbox_count = org.mailbox_count if org else 0

    # ── Fetch inbox posture signals to include in AI risk assessment ──────────
    _posture_high_apps = 0
    _posture_high_rules = 0
    _posture_ext_fwds = 0
    _posture_last_scanned: str | None = None
    try:
        from sqlalchemy import text as _pt2
        from backend.database import AsyncSessionLocal as _ADSL2
        async with _ADSL2() as _pdb2:
            _pa2 = await _pdb2.execute(_pt2(
                "SELECT COUNT(*) FILTER (WHERE risk='high') FROM posture_apps WHERE org_id=:oid"
            ), {"oid": str(current_user.org_id)})
            _pr2 = await _pdb2.execute(_pt2(
                "SELECT COUNT(*) FILTER (WHERE risk='high') FROM posture_rules WHERE org_id=:oid"
            ), {"oid": str(current_user.org_id)})
            _pf2 = await _pdb2.execute(_pt2(
                "SELECT COUNT(*) FILTER (WHERE is_external=true) FROM posture_forwards WHERE org_id=:oid"
            ), {"oid": str(current_user.org_id)})
            _ps2 = await _pdb2.execute(_pt2(
                "SELECT last_scanned_at FROM posture_scan_log WHERE org_id=:oid ORDER BY last_scanned_at DESC LIMIT 1"
            ), {"oid": str(current_user.org_id)})
            _posture_high_apps = int((_pa2.scalar() or 0))
            _posture_high_rules = int((_pr2.scalar() or 0))
            _posture_ext_fwds = int((_pf2.scalar() or 0))
            _ps2_row = _ps2.fetchone()
            _posture_last_scanned = _ps2_row[0].isoformat() if _ps2_row and _ps2_row[0] else None
    except Exception:
        pass  # posture tables may not exist — non-fatal

    score = 0
    explanation = ""
    risk_level = "low"
    key_factors: list[str] = []

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            import anthropic as _anthropic
            _cl = _anthropic.Anthropic(api_key=anthropic_key)
            _posture_scanned_note = (
                f"Last posture scan: {_posture_last_scanned}"
                if _posture_last_scanned else "Posture scan: never run"
            )
            _lines = [
                "You are an enterprise email security risk analyst scoring an organisation's NET (residual) security posture.",
                "",
                "KEY PRINCIPLE: score = RESIDUAL RISK after mitigating controls. An org receiving 500 phishing emails",
                "but auto-quarantining 498 via policies is SAFER than one receiving 10 with zero policies.",
                "High containment rate + active policies = strong reduction in score.",
                "Inbox posture gaps (OAuth apps, inbox rules, forwarding) ADD to residual risk even if email threats are contained.",
                "",
                "SCORE BANDS:",
                "  0-20  LOW      - Strong defence. Threats contained. Minimal exposure.",
                "  21-40 GUARDED  - Mostly contained. Minor gaps or limited policy coverage.",
                "  41-60 ELEVATED - Notable uncontained threats or policy coverage gaps.",
                "  61-80 HIGH     - Significant uncontained high-severity threats or major gaps.",
                "  81-100 CRITICAL - Active uncontrolled BEC/malware, little containment.",
                "",
                "THREAT PICTURE (last 30 days):",
                f"  Total non-clean emails: {total_threats}",
                f"  High-severity (score>=70): {high_risk} | Medium (40-69): {medium_risk}",
                f"  Severe types present: {list(severe_types.keys()) if severe_types else 'None'}",
                f"  All threat types: {list(by_type.keys()) if by_type else 'None'}",
                f"  Auto-contained: {contained} ({containment_rate}% containment rate)",
                f"  Flagged but NO action taken: {flagged_no_action}",
                f"  Connected mailboxes: {mailbox_count}",
                "",
                "DEFENCE POSTURE:",
                f"  Active security policies: {active_policies}",
                f"  Has quarantine/block policy: {has_quarantine_policy}",
                f"  Has permanent block policy: {has_block_policy}",
                f"  Has attachment-strip policy: {has_strip_policy}",
                f"  Policy enforcements this month: {total_policy_hits}",
                f"  Policy breakdown: {policy_by_action if policy_by_action else 'None configured'}",
                "",
                "INBOX POSTURE (OAuth apps, rules, auto-forwarding — from posture scanner):",
                f"  High-risk OAuth apps: {_posture_high_apps} (each adds 3pts residual risk)",
                f"  High-risk inbox rules: {_posture_high_rules} (each adds 4pts residual risk)",
                f"  External auto-forwards: {_posture_ext_fwds} (each adds 5pts residual risk)",
                f"  {_posture_scanned_note}",
                "  Note: posture=0 across all categories means either scan not run or no findings.",
                "",
                'Return ONLY valid JSON: {"score":<int 0-100>,"risk_level":"low|guarded|elevated|high|critical",',
                '"explanation":"<2-3 sentences about residual risk including posture findings>","key_factors":["<f1>","<f2>","<f3>"]}',
            ]
            _prompt = "\n".join(_lines)
            _resp = _cl.messages.create(
                model="claude-opus-4-5-20251101",
                max_tokens=500,
                messages=[{"role": "user", "content": _prompt}]
            )
            raw = _resp.content[0].text.strip()
            _s, _e = raw.find("{"), raw.rfind("}") + 1
            if _s >= 0 and _e > _s:
                parsed = json.loads(raw[_s:_e])
                score       = max(0, min(100, int(parsed.get("score", 0))))
                risk_level  = parsed.get("risk_level", "low")
                explanation = parsed.get("explanation", "")
                key_factors = parsed.get("key_factors", [])
            else:
                raise ValueError("No JSON in response")
        except Exception as e:
            logger.warning(f"Claude AI risk score failed, using heuristic: {e}")
            anthropic_key = None

    if not anthropic_key:
        # Deterministic heuristic fallback (policy-aware, residual risk model)
        raw_score = 0
        if total_threats == 0:
            raw_score = 5
        else:
            raw_score += min(35, high_risk * 2)           # high-severity exposure
            raw_score += min(15, flagged_no_action * 3)   # flagged-but-ignored = real risk
            raw_score += min(15, len(severe_types) * 5)   # severe type penalty

            # Inbox posture additions (mirrors the blended score logic in /summary)
            raw_score += min(20, _posture_high_apps * 3 + _posture_high_rules * 4 + _posture_ext_fwds * 5)

            # Policy mitigations (subtract for active defences)
            if active_policies >= 3:  raw_score -= 15
            elif active_policies >= 1: raw_score -= 8
            if has_quarantine_policy:  raw_score -= 10
            if has_block_policy:       raw_score -= 5
            if has_strip_policy:       raw_score -= 3

            # Containment rate bonus
            if containment_rate >= 90:    raw_score -= 20
            elif containment_rate >= 70:  raw_score -= 10
            elif containment_rate >= 50:  raw_score -= 5

        score = max(3, min(100, raw_score))
        if score <= 20:   risk_level = "low"
        elif score <= 40: risk_level = "guarded"
        elif score <= 60: risk_level = "elevated"
        elif score <= 80: risk_level = "high"
        else:             risk_level = "critical"

        _pol = f"{active_policies} active {'policy' if active_policies == 1 else 'policies'}"
        if total_threats == 0:
            explanation = "No threats detected in the last 30 days. Security posture is clean."
            _posture_summary_0 = []
            if _posture_high_apps:  _posture_summary_0.append(f"{_posture_high_apps} high-risk OAuth app{'s' if _posture_high_apps != 1 else ''}")
            if _posture_high_rules: _posture_summary_0.append(f"{_posture_high_rules} high-risk inbox rule{'s' if _posture_high_rules != 1 else ''}")
            if _posture_ext_fwds:   _posture_summary_0.append(f"{_posture_ext_fwds} external auto-forward{'s' if _posture_ext_fwds != 1 else ''}")
            key_factors = [
                "Zero threats detected",
                "System monitoring active",
                (f"Posture gaps: {', '.join(_posture_summary_0)}" if _posture_summary_0 else f"{active_policies} {'policy' if active_policies == 1 else 'policies'} enforced"),
            ]
        else:
            explanation = (
                f"{total_threats} threats detected this month with a {containment_rate}% auto-containment rate "
                f"via {_pol}. "
                + (f"{flagged_no_action} remain flagged with no action taken — these represent unresolved exposure."
                   if flagged_no_action else "All detected threats have been actioned.")
            )
            _posture_summary = []
            if _posture_high_apps:  _posture_summary.append(f"{_posture_high_apps} high-risk OAuth app{'s' if _posture_high_apps != 1 else ''}")
            if _posture_high_rules: _posture_summary.append(f"{_posture_high_rules} high-risk inbox rule{'s' if _posture_high_rules != 1 else ''}")
            if _posture_ext_fwds:   _posture_summary.append(f"{_posture_ext_fwds} external auto-forward{'s' if _posture_ext_fwds != 1 else ''}")
            key_factors = [
                f"{containment_rate}% containment rate via {_pol}",
                f"{high_risk} high-severity threats detected",
                (f"Posture gaps: {', '.join(_posture_summary)}" if _posture_summary else "No posture findings detected"),
            ]


    result = {
        "score": score,
        "risk_level": risk_level,
        "explanation": explanation,
        "key_factors": key_factors if "key_factors" in dir() else [],
        "evaluated_at": datetime.utcnow().isoformat(),
        "next_evaluation_hours": _AI_RISK_TTL_HOURS,
        "ai_powered": bool(os.getenv("ANTHROPIC_API_KEY")),
    }

    # Update cache
    _ai_risk_cache[org_id_str] = {**result, "evaluated_at": datetime.utcnow()}

    # Persist score to org table
    if org:
        org.risk_score = score
        await db.flush()

    return result


# ─── Threat map geo backfill (one-shot, populates sender_country on existing records) ──

@router.post("/threat-map/backfill")
async def backfill_threat_map(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Backfill sender_country/sender_country_code into auth_results for threats
    that have sender_ip but no country data yet.  Rate-limited: processes up to
    200 records per call against ip-api.com (free tier: 45 req/min).
    """
    import httpx as _hx
    from sqlalchemy import text as _bt

    org_id = str(current_user.org_id)
    # Deduplicate at DB level: get distinct IPs first, then bulk-update all threats for each IP
    # This handles the common case where thousands of threats share the same handful of relay IPs
    ip_rows = (await db.execute(_bt("""
        SELECT DISTINCT auth_results->>'sender_ip' AS sender_ip
        FROM threats
        WHERE org_id = CAST(:org_id AS uuid)
          AND auth_results->>'sender_ip' IS NOT NULL
          AND auth_results->>'sender_ip' != ''
          AND (auth_results->>'sender_country' IS NULL OR auth_results->>'sender_country' = '')
        LIMIT 100
    """).bindparams(org_id=org_id))).all()

    # rows = distinct IPs only (not individual threat rows)
    rows = ip_rows

    if not rows:
        return {"message": "Nothing to backfill", "updated": 0}

    updated = 0
    import asyncio as _aio
    # rows = distinct IPs; look up each once, then bulk-update ALL threats with that IP
    async with _hx.AsyncClient(timeout=5) as client:
        for row in rows:
            sip = row.sender_ip if hasattr(row, 'sender_ip') else (row[0] if row else None)
            if not sip:
                continue
            try:
                r = await client.get(f"http://ip-api.com/json/{sip}?fields=status,country,countryCode")
                if r.status_code == 200:
                    gd = r.json()
                    if gd.get("status") == "success":
                        geo = {"sender_country": gd["country"], "sender_country_code": gd["countryCode"]}
                        # Bulk-update ALL threats sharing this IP in one query
                        result = await db.execute(
                            _bt("""
                                UPDATE threats
                                SET auth_results = auth_results || CAST(:geo AS jsonb)
                                WHERE org_id = CAST(:org_id AS uuid)
                                  AND auth_results->>'sender_ip' = :sip
                                  AND (auth_results->>'sender_country' IS NULL OR auth_results->>'sender_country' = '')
                            """)
                            .bindparams(geo=json.dumps(geo), org_id=org_id, sip=sip)
                        )
                        updated += result.rowcount or 0
            except Exception:
                pass
            await _aio.sleep(0.07)  # ~14 req/s — safely under 45/min

    await db.commit()
    # If there were exactly 200 results, more may remain — report how many are still pending
    pending_result = (await db.execute(_bt("""
        SELECT COUNT(*) FROM threats
        WHERE org_id = CAST(:org_id AS uuid)
          AND auth_results->>'sender_ip' IS NOT NULL
          AND auth_results->>'sender_ip' != ''
          AND (auth_results->>'sender_country' IS NULL OR auth_results->>'sender_country' = '')
    """).bindparams(org_id=org_id))).scalar() or 0
    return {
        "message": f"Backfilled {updated} threats with geo data",
        "updated": updated,
        "remaining": int(pending_result),
    }


@router.post("/dedup-threats")
async def dedup_threats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """One-shot cleanup: remove duplicate threat rows for this org. Safe to call multiple times."""
    from sqlalchemy import text as _dt
    org_id = str(current_user.org_id)
    try:
        # First delete compliance_evidence rows referencing the duplicate threat ids
        await db.execute(_dt("""
            DELETE FROM compliance_evidence
            WHERE threat_id IN (
              SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                         PARTITION BY email_message_id, org_id, recipient_email
                         ORDER BY detected_at ASC, id ASC
                       ) AS rn
                FROM threats
                WHERE org_id = CAST(:oid AS uuid)
                  AND email_message_id IS NOT NULL AND email_message_id != ''
                  AND recipient_email IS NOT NULL
              ) ranked
              WHERE rn > 1
            )
        """).bindparams(oid=org_id))
        # Then delete the duplicate threat rows
        result = await db.execute(_dt("""
            DELETE FROM threats
            WHERE id IN (
              SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                         PARTITION BY email_message_id, org_id, recipient_email
                         ORDER BY detected_at ASC, id ASC
                       ) AS rn
                FROM threats
                WHERE org_id = CAST(:oid AS uuid)
                  AND email_message_id IS NOT NULL AND email_message_id != ''
                  AND recipient_email IS NOT NULL
              ) ranked
              WHERE rn > 1
            )
        """).bindparams(oid=org_id))
        deleted = result.rowcount or 0
        await db.commit()
        return {"deleted": deleted, "message": f"Removed {deleted} duplicate threat rows for your org"}
    except Exception as e:
        logger.warning(f"dedup-threats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
