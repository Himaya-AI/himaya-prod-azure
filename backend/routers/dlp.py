"""
Himaya DLP (Data Loss Prevention) Router — enterprise tier only.
Manages policies, events, held-email queue, and classification.

DB tables created at startup (raw SQL, no Alembic):
  - dlp_policies
  - dlp_events
  - dlp_queue
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization as _Org
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dlp", tags=["dlp"])


# ── Enterprise gate (same pattern as posture.py) ──────────────────────────────

async def _require_enterprise(current_user, db: AsyncSession):
    """Raise 403 if org is not on Enterprise tier."""
    _org = (await db.execute(
        select(_Org).where(_Org.id == current_user.org_id)
    )).scalar_one_or_none()
    _tier = (getattr(_org, "tier", None) or "Launch").strip().lower()
    if _tier not in ("enterprise", "enterprise trial"):
        raise HTTPException(
            status_code=403,
            detail="Data Loss Prevention requires an Enterprise plan. Upgrade to access this feature.",
        )


# ── Table creation (idempotent, called at import time via lifespan) ───────────

async def ensure_dlp_tables(db: AsyncSession):
    """Create DLP tables if they don't exist (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dlp_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            detect_pii BOOLEAN NOT NULL DEFAULT TRUE,
            detect_financial BOOLEAN NOT NULL DEFAULT TRUE,
            detect_credentials BOOLEAN NOT NULL DEFAULT TRUE,
            detect_itar BOOLEAN NOT NULL DEFAULT FALSE,
            detect_bulk_exfil BOOLEAN NOT NULL DEFAULT TRUE,
            custom_keywords JSONB DEFAULT '[]'::jsonb,
            custom_regex JSONB DEFAULT '[]'::jsonb,
            action TEXT NOT NULL DEFAULT 'WARN',
            notify_sender BOOLEAN NOT NULL DEFAULT FALSE,
            notify_manager_email TEXT,
            external_only BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dlp_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            policy_id UUID,
            sender_email TEXT,
            recipient_emails JSONB DEFAULT '[]'::jsonb,
            subject TEXT,
            body_preview TEXT,
            risk_level TEXT NOT NULL DEFAULT 'low',
            action_taken TEXT NOT NULL DEFAULT 'ALLOW',
            categories_found JSONB DEFAULT '[]'::jsonb,
            matched_patterns JSONB DEFAULT '[]'::jsonb,
            confidence REAL DEFAULT 0.5,
            reviewed_by UUID,
            reviewed_at TIMESTAMPTZ,
            review_action TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dlp_queue (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            event_id UUID NOT NULL REFERENCES dlp_events(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            held_message_json TEXT,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    # Indexes
    # M365 transport rule sync columns (idempotent additions)
    try:
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS m365_rule_id TEXT"
        ))
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ"
        ))
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS sync_status TEXT DEFAULT 'not_synced'"
        ))
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS gsuite_rule_id TEXT"
        ))
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS gsuite_last_synced_at TIMESTAMPTZ"
        ))
        await db.execute(text(
            "ALTER TABLE dlp_policies ADD COLUMN IF NOT EXISTS gsuite_sync_status TEXT DEFAULT 'not_synced'"
        ))
    except Exception:
        pass
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_dlp_policies_org ON dlp_policies(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_dlp_events_org ON dlp_events(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_dlp_queue_org_status ON dlp_queue(org_id, status)"
    ))
    await db.commit()
    logger.info("DLP tables ensured")


# ── Pydantic models ───────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    severity: str = "medium"
    enabled: bool = True
    detect_pii: bool = True
    detect_financial: bool = True
    detect_credentials: bool = True
    detect_itar: bool = False
    detect_bulk_exfil: bool = True
    custom_keywords: list[str] = []
    custom_regex: list[str] = []
    action: str = "WARN"
    notify_sender: bool = False
    notify_manager_email: Optional[str] = None
    external_only: bool = False


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    detect_pii: Optional[bool] = None
    detect_financial: Optional[bool] = None
    detect_credentials: Optional[bool] = None
    detect_itar: Optional[bool] = None
    detect_bulk_exfil: Optional[bool] = None
    custom_keywords: Optional[list[str]] = None
    custom_regex: Optional[list[str]] = None
    action: Optional[str] = None
    notify_sender: Optional[bool] = None
    notify_manager_email: Optional[str] = None
    external_only: Optional[bool] = None


class ClassifyRequest(BaseModel):
    sender: str
    recipients: list[str]
    subject: str = ""
    body: str
    attachments: list[str] = []
    provider: str = "m365"


# ── Helper: parse policy row ──────────────────────────────────────────────────

def _parse_policy_row(row) -> dict:
    d = {
        "id": str(row[0]),
        "org_id": str(row[1]),
        "name": row[2],
        "severity": row[3],
        "enabled": bool(row[4]),
        "detect_pii": bool(row[5]),
        "detect_financial": bool(row[6]),
        "detect_credentials": bool(row[7]),
        "detect_itar": bool(row[8]),
        "detect_bulk_exfil": bool(row[9]),
        "custom_keywords": json.loads(row[10]) if isinstance(row[10], str) else (row[10] or []),
        "custom_regex": json.loads(row[11]) if isinstance(row[11], str) else (row[11] or []),
        "action": row[12],
        "notify_sender": bool(row[13]),
        "notify_manager_email": row[14],
        "external_only": bool(row[15]),
        "created_at": row[16].isoformat() if row[16] else None,
        "m365_rule_id": row[17] if len(row) > 17 else None,
        "last_synced_at": row[18].isoformat() if len(row) > 18 and row[18] else None,
        "sync_status": row[19] if len(row) > 19 else "not_synced",
        "gsuite_rule_id": row[20] if len(row) > 20 else None,
        "gsuite_last_synced_at": row[21].isoformat() if len(row) > 21 and row[21] else None,
        "gsuite_sync_status": row[22] if len(row) > 22 else "not_synced",
    }
    return d


def _parse_event_row(row) -> dict:
    return {
        "id": str(row[0]),
        "org_id": str(row[1]),
        "policy_id": str(row[2]) if row[2] else None,
        "sender_email": row[3],
        "recipient_emails": json.loads(row[4]) if isinstance(row[4], str) else (row[4] or []),
        "subject": row[5],
        "body_preview": row[6],
        "risk_level": row[7],
        "action_taken": row[8],
        "categories_found": json.loads(row[9]) if isinstance(row[9], str) else (row[9] or []),
        "matched_patterns": json.loads(row[10]) if isinstance(row[10], str) else (row[10] or []),
        "confidence": float(row[11]) if row[11] is not None else None,
        "reviewed_by": str(row[12]) if row[12] else None,
        "reviewed_at": row[13].isoformat() if row[13] else None,
        "review_action": row[14],
        "created_at": row[15].isoformat() if row[15] else None,
    }


def _parse_queue_row(row) -> dict:
    return {
        "id": str(row[0]),
        "org_id": str(row[1]),
        "event_id": str(row[2]),
        "status": row[3],
        "expires_at": row[4].isoformat() if row[4] else None,
        "created_at": row[5].isoformat() if row[5] else None,
        # Expose partial event fields joined in query
        "sender_email": row[6] if len(row) > 6 else None,
        "subject": row[7] if len(row) > 7 else None,
        "risk_level": row[8] if len(row) > 8 else None,
        "action_taken": row[9] if len(row) > 9 else None,
        "categories_found": (
            json.loads(row[10]) if isinstance(row[10], str) else (row[10] or [])
        ) if len(row) > 10 else [],
        "body_preview": row[11] if len(row) > 11 else None,
    }


# ── Policy routes ─────────────────────────────────────────────────────────────

@router.get("/policies")
async def list_policies(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all DLP policies for the org."""
    await _require_enterprise(current_user, db)
    try:
        rows = (await db.execute(
            text(
                "SELECT id, org_id, name, severity, enabled, detect_pii, detect_financial, "
                "detect_credentials, detect_itar, detect_bulk_exfil, custom_keywords, custom_regex, "
                "action, notify_sender, notify_manager_email, external_only, created_at, "
                "m365_rule_id, last_synced_at, sync_status, "
                "gsuite_rule_id, gsuite_last_synced_at, gsuite_sync_status "
                "FROM dlp_policies WHERE org_id=:oid ORDER BY created_at DESC"
            ),
            {"oid": str(current_user.org_id)},
        )).fetchall()
        return [_parse_policy_row(r) for r in rows]
    except Exception as exc:
        logger.warning(f"dlp policies list: {exc}")
        return []


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new DLP policy."""
    await _require_enterprise(current_user, db)

    if body.action not in ("ALLOW", "WARN", "HOLD", "BLOCK"):
        raise HTTPException(status_code=422, detail="action must be ALLOW, WARN, HOLD, or BLOCK")
    if body.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=422, detail="severity must be low, medium, high, or critical")

    policy_id = str(uuid.uuid4())
    await db.execute(
        text(
            "INSERT INTO dlp_policies "
            "(id, org_id, name, severity, enabled, detect_pii, detect_financial, detect_credentials, "
            "detect_itar, detect_bulk_exfil, custom_keywords, custom_regex, action, "
            "notify_sender, notify_manager_email, external_only) "
            "VALUES (:id, :org_id, :name, :severity, :enabled, :detect_pii, :detect_financial, "
            ":detect_credentials, :detect_itar, :detect_bulk_exfil, :custom_keywords, :custom_regex, "
            ":action, :notify_sender, :notify_manager_email, :external_only)"
        ),
        {
            "id": policy_id,
            "org_id": str(current_user.org_id),
            "name": body.name,
            "severity": body.severity,
            "enabled": body.enabled,
            "detect_pii": body.detect_pii,
            "detect_financial": body.detect_financial,
            "detect_credentials": body.detect_credentials,
            "detect_itar": body.detect_itar,
            "detect_bulk_exfil": body.detect_bulk_exfil,
            "custom_keywords": json.dumps(body.custom_keywords),
            "custom_regex": json.dumps(body.custom_regex),
            "action": body.action,
            "notify_sender": body.notify_sender,
            "notify_manager_email": body.notify_manager_email,
            "external_only": body.external_only,
        },
    )
    await db.commit()
    return {"id": policy_id, "ok": True}


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a DLP policy."""
    await _require_enterprise(current_user, db)

    # Build dynamic SET clause from non-None fields
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    # Serialize list fields
    if "custom_keywords" in updates:
        updates["custom_keywords"] = json.dumps(updates["custom_keywords"])
    if "custom_regex" in updates:
        updates["custom_regex"] = json.dumps(updates["custom_regex"])

    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    params = {**updates, "id": policy_id, "org_id": str(current_user.org_id)}

    result = await db.execute(
        text(f"UPDATE dlp_policies SET {set_clause} WHERE id=:id AND org_id=:org_id"),
        params,
    )
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a DLP policy."""
    await _require_enterprise(current_user, db)
    result = await db.execute(
        text("DELETE FROM dlp_policies WHERE id=:id AND org_id=:oid"),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


# ── Queue routes ──────────────────────────────────────────────────────────────

@router.get("/queue")
async def list_queue(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List held emails pending human review."""
    await _require_enterprise(current_user, db)
    try:
        rows = (await db.execute(
            text(
                "SELECT q.id, q.org_id, q.event_id, q.status, q.expires_at, q.created_at, "
                "e.sender_email, e.subject, e.risk_level, e.action_taken, e.categories_found, e.body_preview "
                "FROM dlp_queue q "
                "JOIN dlp_events e ON q.event_id = e.id "
                "WHERE q.org_id=:oid AND q.status='pending' "
                "ORDER BY q.created_at DESC"
            ),
            {"oid": str(current_user.org_id)},
        )).fetchall()
        return [_parse_queue_row(r) for r in rows]
    except Exception as exc:
        logger.warning(f"dlp queue list: {exc}")
        return []


@router.post("/queue/{queue_id}/release")
async def release_queue_item(
    queue_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Release a held email — attempts actual delivery via provider API."""
    await _require_enterprise(current_user, db)

    row = (await db.execute(
        text(
            "SELECT id, org_id, event_id, status, held_message_json, expires_at "
            "FROM dlp_queue WHERE id=:id AND org_id=:oid"
        ),
        {"id": queue_id, "oid": str(current_user.org_id)},
    )).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Queue item not found")
    if row[3] != "pending":
        raise HTTPException(status_code=409, detail=f"Item is already {row[3]}")

    queue_item = {
        "id": str(row[0]), "org_id": str(row[1]), "event_id": str(row[2]),
        "held_message_json": row[4] or "",
    }

    from backend.services.dlp_service import release_email
    success = await release_email(queue_item, db)

    # Update queue status regardless of delivery success (admin decision is final)
    await db.execute(
        text("UPDATE dlp_queue SET status='released' WHERE id=:id"),
        {"id": queue_id},
    )
    # Update event review info
    await db.execute(
        text(
            "UPDATE dlp_events SET reviewed_by=:uid, reviewed_at=NOW(), review_action='release' "
            "WHERE id=:eid"
        ),
        {"uid": str(current_user.id), "eid": str(row[2])},
    )
    await db.commit()
    return {"ok": True, "delivered": success}


@router.post("/queue/{queue_id}/block")
async def block_queue_item(
    queue_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently block a held email (delete from queue, mark event)."""
    await _require_enterprise(current_user, db)

    row = (await db.execute(
        text("SELECT id, org_id, event_id FROM dlp_queue WHERE id=:id AND org_id=:oid"),
        {"id": queue_id, "oid": str(current_user.org_id)},
    )).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Queue item not found")

    await db.execute(
        text("UPDATE dlp_queue SET status='blocked' WHERE id=:id"),
        {"id": queue_id},
    )
    await db.execute(
        text(
            "UPDATE dlp_events SET reviewed_by=:uid, reviewed_at=NOW(), review_action='block' "
            "WHERE id=:eid"
        ),
        {"uid": str(current_user.id), "eid": str(row[2])},
    )
    await db.commit()
    return {"ok": True}


# ── Events routes ─────────────────────────────────────────────────────────────

@router.get("/events")
async def list_events(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    risk_level: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
):
    """Paginated DLP event log with optional filters."""
    await _require_enterprise(current_user, db)

    where_clauses = ["org_id=:oid"]
    params: dict = {"oid": str(current_user.org_id)}

    if risk_level:
        where_clauses.append("risk_level=:risk_level")
        params["risk_level"] = risk_level
    if action:
        where_clauses.append("action_taken=:action")
        params["action"] = action

    where_sql = " AND ".join(where_clauses)
    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset

    try:
        total_row = (await db.execute(
            text(f"SELECT COUNT(*) FROM dlp_events WHERE {where_sql}"),
            params,
        )).fetchone()
        total = int(total_row[0]) if total_row else 0

        rows = (await db.execute(
            text(
                f"SELECT id, org_id, policy_id, sender_email, recipient_emails, subject, "
                f"body_preview, risk_level, action_taken, categories_found, matched_patterns, "
                f"confidence, reviewed_by, reviewed_at, review_action, created_at "
                f"FROM dlp_events WHERE {where_sql} "
                f"ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            ),
            params,
        )).fetchall()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "events": [_parse_event_row(r) for r in rows],
        }
    except Exception as exc:
        logger.warning(f"dlp events list: {exc}")
        return {"total": 0, "page": page, "page_size": page_size, "events": []}


# ── Stats route ───────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """DLP statistics for the dashboard stats row — includes risk/action distributions."""
    await _require_enterprise(current_user, db)
    oid = str(current_user.org_id)

    try:
        # Basic counts for today
        events_r = (await db.execute(
            text(
                "SELECT COUNT(*), "
                "SUM(CASE WHEN action_taken='HOLD' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN action_taken='BLOCK' THEN 1 ELSE 0 END) "
                "FROM dlp_events "
                "WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '1 day'"
            ),
            {"oid": oid},
        )).fetchone()
        total_today = int(events_r[0] or 0)
        held_today = int(events_r[1] or 0)
        blocked_today = int(events_r[2] or 0)

        # Week total
        week_r = (await db.execute(
            text(
                "SELECT COUNT(*) FROM dlp_events "
                "WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '7 days'"
            ),
            {"oid": oid},
        )).fetchone()
        total_week = int(week_r[0] or 0) if week_r else 0

        # Risk distribution (all time or last 30 days for perf)
        risk_r = (await db.execute(
            text(
                "SELECT risk_level, COUNT(*) FROM dlp_events "
                "WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '30 days' "
                "GROUP BY risk_level"
            ),
            {"oid": oid},
        )).fetchall()
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in risk_r:
            level = (row[0] or "low").lower()
            if level in risk_distribution:
                risk_distribution[level] = int(row[1] or 0)

        # Action distribution
        action_r = (await db.execute(
            text(
                "SELECT action_taken, COUNT(*) FROM dlp_events "
                "WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '30 days' "
                "GROUP BY action_taken"
            ),
            {"oid": oid},
        )).fetchall()
        action_distribution = {"allow": 0, "warn": 0, "hold": 0, "block": 0}
        for row in action_r:
            act = (row[0] or "ALLOW").lower()
            if act in action_distribution:
                action_distribution[act] = int(row[1] or 0)

        # Category breakdown (top 10)
        cat_r = (await db.execute(
            text(
                "SELECT cat, COUNT(*) as cnt FROM ("
                "  SELECT jsonb_array_elements_text(categories_found) as cat "
                "  FROM dlp_events WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '30 days'"
                ") sub GROUP BY cat ORDER BY cnt DESC LIMIT 10"
            ),
            {"oid": oid},
        )).fetchall()
        category_breakdown = [{"category": row[0], "count": int(row[1])} for row in cat_r]

        # 7-day trend
        trend_r = (await db.execute(
            text(
                "SELECT DATE(created_at) as d, COUNT(*) as events, "
                "SUM(CASE WHEN action_taken IN ('HOLD','BLOCK') THEN 1 ELSE 0 END) as blocked "
                "FROM dlp_events WHERE org_id=:oid AND created_at >= NOW() - INTERVAL '7 days' "
                "GROUP BY DATE(created_at) ORDER BY d"
            ),
            {"oid": oid},
        )).fetchall()
        trend = [{"date": row[0].isoformat() if row[0] else "", "events": int(row[1] or 0), "blocked": int(row[2] or 0)} for row in trend_r]

        # Top policy by event count
        policy_r = (await db.execute(
            text(
                "SELECT p.name, COUNT(e.id) AS cnt "
                "FROM dlp_events e "
                "JOIN dlp_policies p ON e.policy_id = p.id "
                "WHERE e.org_id=:oid AND e.created_at >= NOW() - INTERVAL '7 days' "
                "GROUP BY p.name ORDER BY cnt DESC LIMIT 1"
            ),
            {"oid": oid},
        )).fetchone()
        top_policy = policy_r[0] if policy_r else None

        # Active policies count
        active_r = (await db.execute(
            text("SELECT COUNT(*) FROM dlp_policies WHERE org_id=:oid AND enabled=true"),
            {"oid": oid},
        )).fetchone()
        active_policies = int(active_r[0] or 0) if active_r else 0

        return {
            "total_events_today": total_today,
            "total_events_week": total_week,
            "held_today": held_today,
            "blocked_today": blocked_today,
            "top_policy": top_policy,
            "active_policies": active_policies,
            "risk_distribution": risk_distribution,
            "action_distribution": action_distribution,
            "category_breakdown": category_breakdown,
            "trend": trend,
        }
    except Exception as exc:
        logger.warning(f"dlp stats: {exc}")
        return {
            "total_events_today": 0,
            "total_events_week": 0,
            "held_today": 0,
            "blocked_today": 0,
            "top_policy": None,
            "active_policies": 0,
            "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "action_distribution": {"allow": 0, "warn": 0, "hold": 0, "block": 0},
            "category_breakdown": [],
            "trend": [],
        }


# ── Engine status route ──────────────────────────────────────────────────────

@router.get("/engine/status")
async def engine_status(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check DeepSeek inference engine health."""
    await _require_enterprise(current_user, db)
    import os
    import httpx
    endpoint = os.getenv("DEEPSEEK_ENDPOINT", "")
    if not endpoint:
        return {"llm_status": "not_configured", "model": None, "fallback": "regex"}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{endpoint}/health")
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {"llm_status": "offline", "model": None, "fallback": "regex"}


# ── Internal classify route (called by webhook) ───────────────────────────────

@router.post("/classify")
async def classify_endpoint(
    body: ClassifyRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Internal endpoint: classifies an email, saves event, returns verdict.
    Called by the DLP webhook routers after MIME parsing.
    Also enterprise-gated here, but webhook router calls dlp_service directly.
    """
    await _require_enterprise(current_user, db)

    from backend.services.dlp_service import classify_email
    email_data = {
        "sender": body.sender,
        "recipients": body.recipients,
        "subject": body.subject,
        "body": body.body,
        "attachments": body.attachments,
        "provider": body.provider,
    }
    verdict = await classify_email(email_data, str(current_user.org_id), db)
    return verdict


# ── M365 Transport Rule Sync ──────────────────────────────────────────────

@router.post("/policies/{policy_id}/sync-m365")
async def sync_policy_to_m365(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync a DLP policy to Microsoft 365 as an Exchange Online transport rule.
    Requires M365 integration to be connected and M365_CLIENT_ID/SECRET env vars.
    """
    await _require_enterprise(current_user, db)

    # Fetch the policy
    try:
        rows = (await db.execute(
            text(
                "SELECT id, org_id, name, severity, enabled, detect_pii, detect_financial, "
                "detect_credentials, detect_itar, detect_bulk_exfil, custom_keywords, custom_regex, "
                "action, notify_sender, notify_manager_email, external_only, created_at, "
                "m365_rule_id, last_synced_at, sync_status, "
                "gsuite_rule_id, gsuite_last_synced_at, gsuite_sync_status "
                "FROM dlp_policies WHERE id=:id AND org_id=:oid"
            ),
            {"id": policy_id, "oid": str(current_user.org_id)},
        )).fetchall()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not rows:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = _parse_policy_row(rows[0])

    # Get M365 access token for org's tenant
    import os
    import httpx
    from backend.models.db_models import SaasIntegration, OrgIntegration
    from sqlalchemy import select as _select
    from backend.database import get_db as _get_db
    from backend.routers.saas_security import _get_valid_token, _decrypt
    from cryptography.fernet import Fernet

    # Find active SaaS integration or main M365 integration for tenant_id
    saas_integ = (await db.execute(
        _select(SaasIntegration).where(
            SaasIntegration.org_id == current_user.org_id,
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()

    m365_integ = (await db.execute(
        _select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.provider == "m365",
        ).limit(1)
    )).scalar_one_or_none()

    tenant_id = (
        (saas_integ.tenant_id if saas_integ else None) or
        os.getenv("M365_TENANT_ID", "")
    )

    # Try to get access token
    access_token = ""
    if tenant_id and tenant_id != "common":
        client_id = os.getenv("M365_CLIENT_ID", "")
        client_secret = os.getenv("M365_CLIENT_SECRET", "")
        if client_id and client_secret:
            try:
                async with httpx.AsyncClient(timeout=15) as c:
                    r = await c.post(
                        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                        data={
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "scope": "https://graph.microsoft.com/.default",
                            "grant_type": "client_credentials",
                        },
                    )
                    if r.status_code == 200:
                        access_token = r.json().get("access_token", "")
            except Exception as exc:
                logger.warning(f"m365_sync: token request failed: {exc}")

    # Use the policy pusher (falls back to mock mode if no token)
    from backend.services.m365_policy_push import M365PolicyPusher
    pusher = M365PolicyPusher(access_token=access_token or None)

    result = await pusher.sync_dlp_policy(policy, str(current_user.org_id))

    # Update policy with sync result
    new_rule_id = result.get("m365_rule_id") or result.get("rule", {}).get("id")
    sync_status = "synced" if result.get("status") in ("success", "mock_success", "updated") else "error"

    try:
        await db.execute(
            text(
                "UPDATE dlp_policies SET m365_rule_id=:rule_id, last_synced_at=NOW(), "
                "sync_status=:sync_status WHERE id=:id AND org_id=:oid"
            ),
            {
                "rule_id": new_rule_id,
                "sync_status": sync_status,
                "id": policy_id,
                "oid": str(current_user.org_id),
            },
        )
        await db.commit()
    except Exception as exc:
        logger.warning(f"m365_sync: DB update failed: {exc}")
        await db.rollback()

    return {
        "ok": True,
        "policy_id": policy_id,
        "sync_status": sync_status,
        "m365_rule_id": new_rule_id,
        "mode": "mock" if pusher.mock_mode else "live",
        "detail": result,
    }


@router.delete("/policies/{policy_id}/sync-m365")
async def unsync_policy_from_m365(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the M365 transport rule for a DLP policy."""
    await _require_enterprise(current_user, db)

    rows = (await db.execute(
        text("SELECT m365_rule_id FROM dlp_policies WHERE id=:id AND org_id=:oid"),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="Policy not found")

    rule_id = rows[0][0] if rows[0][0] else None
    result = {"ok": True, "removed": False}

    if rule_id:
        import os, httpx
        client_id = os.getenv("M365_CLIENT_ID", "")
        client_secret = os.getenv("M365_CLIENT_SECRET", "")
        from backend.services.m365_policy_push import M365PolicyPusher
        pusher = M365PolicyPusher()
        remove_result = await pusher.remove_transport_rule(rule_id)
        result["removed"] = True
        result["remove_detail"] = remove_result

    await db.execute(
        text(
            "UPDATE dlp_policies SET m365_rule_id=NULL, sync_status='not_synced', "
            "last_synced_at=NULL WHERE id=:id AND org_id=:oid"
        ),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    return result


# ── GSuite Content Compliance Sync ────────────────────────────────────────────

@router.post("/policies/{policy_id}/sync-gsuite")
async def sync_policy_to_gsuite(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync a DLP policy to Google Workspace as a Content Compliance Rule.
    Requires Google Workspace integration to be connected with Admin SDK access.
    """
    await _require_enterprise(current_user, db)

    # Fetch the policy
    try:
        rows = (await db.execute(
            text(
                "SELECT id, org_id, name, severity, enabled, detect_pii, detect_financial, "
                "detect_credentials, detect_itar, detect_bulk_exfil, custom_keywords, custom_regex, "
                "action, notify_sender, notify_manager_email, external_only, created_at, "
                "m365_rule_id, last_synced_at, sync_status, "
                "gsuite_rule_id, gsuite_last_synced_at, gsuite_sync_status "
                "FROM dlp_policies WHERE id=:id AND org_id=:oid"
            ),
            {"id": policy_id, "oid": str(current_user.org_id)},
        )).fetchall()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not rows:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = _parse_policy_row(rows[0])

    # Get Google access token for org
    import os
    from backend.models.db_models import SaasIntegration
    from sqlalchemy import select as _select

    access_token = None
    customer_id = None
    try:
        integ = (await db.execute(
            _select(SaasIntegration).where(
                SaasIntegration.org_id == current_user.org_id,
                SaasIntegration.provider == "google",
            )
        )).scalar_one_or_none()
        if integ and integ.encrypted_token:
            from backend.routers.saas_security import _decrypt, _get_valid_token
            token_data = json.loads(_decrypt(integ.encrypted_token))
            # For service accounts, we'd mint tokens; for OAuth, use refresh
            access_token = token_data.get("access_token")
            customer_id = token_data.get("customer_id", "my_customer")
    except Exception as exc:
        logger.warning(f"gsuite_sync: could not get access token: {exc}")

    from backend.services.gsuite_policy_push import GSuitePolicyPusher
    pusher = GSuitePolicyPusher(access_token=access_token, customer_id=customer_id)
    result = await pusher.sync_dlp_policy(policy, str(current_user.org_id))

    new_rule_id = result.get("gsuite_rule_id")
    sync_status = "synced" if result.get("status") in ("success", "mock_success", "updated") else "error"

    try:
        await db.execute(
            text(
                "UPDATE dlp_policies SET gsuite_rule_id=:rid, gsuite_last_synced_at=NOW(), "
                "gsuite_sync_status=:status WHERE id=:id AND org_id=:oid"
            ),
            {
                "rid": new_rule_id,
                "status": sync_status,
                "id": policy_id,
                "oid": str(current_user.org_id),
            },
        )
        await db.commit()
    except Exception as exc:
        logger.warning(f"gsuite_sync: DB update failed: {exc}")
        await db.rollback()

    return {
        "ok": True,
        "policy_id": policy_id,
        "sync_status": sync_status,
        "gsuite_rule_id": new_rule_id,
        "mode": "mock" if pusher.mock_mode else "live",
        "detail": result,
    }


@router.delete("/policies/{policy_id}/sync-gsuite")
async def unsync_policy_from_gsuite(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the GSuite content compliance rule for a DLP policy."""
    await _require_enterprise(current_user, db)

    rows = (await db.execute(
        text("SELECT gsuite_rule_id FROM dlp_policies WHERE id=:id AND org_id=:oid"),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="Policy not found")

    rule_id = rows[0][0] if rows[0][0] else None
    result = {"ok": True, "removed": False}

    if rule_id:
        from backend.services.gsuite_policy_push import GSuitePolicyPusher
        pusher = GSuitePolicyPusher()
        remove_result = await pusher.remove_content_compliance_rule(rule_id)
        result["removed"] = True
        result["remove_detail"] = remove_result

    await db.execute(
        text(
            "UPDATE dlp_policies SET gsuite_rule_id=NULL, gsuite_sync_status='not_synced', "
            "gsuite_last_synced_at=NULL WHERE id=:id AND org_id=:oid"
        ),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    return result


# ── DLP Test endpoint ─────────────────────────────────────────────────────────

class DLPTestRequest(BaseModel):
    text: str
    subject: str = "Test"
    sender: str = "test@example.com"
    recipients: list[str] = []


@router.post("/test")
async def test_dlp_classification(
    body: DLPTestRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Test DLP classification on arbitrary text. Enterprise only."""
    await _require_enterprise(current_user, db)
    from backend.services.dlp_service import classify_email
    result = await classify_email(
        {
            "body": body.text,
            "subject": body.subject,
            "sender": body.sender,
            "recipients": body.recipients,
            "attachments": [],
        },
        str(current_user.org_id),
        db,
        auto_commit=False,
    )
    await db.rollback()  # Don't persist test events
    return result


# ══════════════════════════════════════════════════════════════════════════════
# ONE-CLICK DLP SETUP — API-based scanning via existing integrations
# ══════════════════════════════════════════════════════════════════════════════

class OneClickDLPSetup(BaseModel):
    """Configuration for one-click DLP setup."""
    scan_outbound: bool = True
    scan_inbound: bool = False
    action_pii: str = "warn"  # warn, hold, block, recall
    action_financial: str = "warn"
    action_credentials: str = "block"
    action_legal: str = "hold"
    notify_sender: bool = True
    notify_admin: bool = True
    admin_emails: list[str] = []


@router.get("/setup/status")
async def get_dlp_setup_status(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get the current DLP setup status for the organization.
    Returns whether DLP is enabled and the current configuration.
    """
    await _require_enterprise(current_user, db)
    
    result = await db.execute(
        text("""
            SELECT 
                dlp_enabled,
                dlp_scan_outbound,
                dlp_scan_inbound,
                dlp_action_pii,
                dlp_action_financial,
                dlp_action_credentials,
                dlp_action_legal,
                dlp_notify_sender,
                dlp_notify_admin,
                dlp_admin_emails,
                dlp_enabled_at
            FROM organizations
            WHERE id = :org_id
        """),
        {"org_id": str(current_user.org_id)}
    )
    row = result.fetchone()
    
    if not row:
        return {"enabled": False, "config": None}
    
    return {
        "enabled": bool(row[0]) if row[0] is not None else False,
        "config": {
            "scan_outbound": bool(row[1]) if row[1] is not None else True,
            "scan_inbound": bool(row[2]) if row[2] is not None else False,
            "action_pii": row[3] or "warn",
            "action_financial": row[4] or "warn",
            "action_credentials": row[5] or "block",
            "action_legal": row[6] or "hold",
            "notify_sender": bool(row[7]) if row[7] is not None else True,
            "notify_admin": bool(row[8]) if row[8] is not None else True,
            "admin_emails": row[9] or [],
        },
        "enabled_at": row[10].isoformat() if row[10] else None,
    }


@router.post("/setup/enable")
async def enable_one_click_dlp(
    body: OneClickDLPSetup,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Enable one-click DLP protection.
    
    This enables API-based DLP scanning that works through your existing
    Gmail or M365 integration — no external transport rules or SMTP
    routing required.
    
    DLP scanning happens automatically during delta sync when emails
    are processed. Violations are logged and actions taken based on
    the configuration.
    """
    await _require_enterprise(current_user, db)
    
    # Ensure the DLP columns exist on organizations table
    try:
        await db.execute(text("""
            ALTER TABLE organizations
            ADD COLUMN IF NOT EXISTS dlp_enabled BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS dlp_scan_outbound BOOLEAN DEFAULT TRUE,
            ADD COLUMN IF NOT EXISTS dlp_scan_inbound BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS dlp_action_pii TEXT DEFAULT 'warn',
            ADD COLUMN IF NOT EXISTS dlp_action_financial TEXT DEFAULT 'warn',
            ADD COLUMN IF NOT EXISTS dlp_action_credentials TEXT DEFAULT 'block',
            ADD COLUMN IF NOT EXISTS dlp_action_legal TEXT DEFAULT 'hold',
            ADD COLUMN IF NOT EXISTS dlp_notify_sender BOOLEAN DEFAULT TRUE,
            ADD COLUMN IF NOT EXISTS dlp_notify_admin BOOLEAN DEFAULT TRUE,
            ADD COLUMN IF NOT EXISTS dlp_admin_emails JSONB DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS dlp_enabled_at TIMESTAMPTZ
        """))
        await db.commit()
    except Exception as e:
        logger.warning(f"DLP columns may already exist: {e}")
        await db.rollback()
    
    # Update organization with DLP config
    await db.execute(
        text("""
            UPDATE organizations SET
                dlp_enabled = TRUE,
                dlp_scan_outbound = :scan_outbound,
                dlp_scan_inbound = :scan_inbound,
                dlp_action_pii = :action_pii,
                dlp_action_financial = :action_financial,
                dlp_action_credentials = :action_credentials,
                dlp_action_legal = :action_legal,
                dlp_notify_sender = :notify_sender,
                dlp_notify_admin = :notify_admin,
                dlp_admin_emails = :admin_emails,
                dlp_enabled_at = NOW()
            WHERE id = :org_id
        """),
        {
            "org_id": str(current_user.org_id),
            "scan_outbound": body.scan_outbound,
            "scan_inbound": body.scan_inbound,
            "action_pii": body.action_pii,
            "action_financial": body.action_financial,
            "action_credentials": body.action_credentials,
            "action_legal": body.action_legal,
            "notify_sender": body.notify_sender,
            "notify_admin": body.notify_admin,
            "admin_emails": json.dumps(body.admin_emails),
        }
    )
    await db.commit()
    
    logger.info(f"DLP enabled for org {current_user.org_id}")
    
    return {
        "success": True,
        "message": "DLP protection enabled. Emails will be automatically scanned during sync.",
        "config": {
            "scan_outbound": body.scan_outbound,
            "scan_inbound": body.scan_inbound,
            "action_pii": body.action_pii,
            "action_financial": body.action_financial,
            "action_credentials": body.action_credentials,
            "action_legal": body.action_legal,
        }
    }


@router.post("/setup/disable")
async def disable_one_click_dlp(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable DLP protection."""
    await _require_enterprise(current_user, db)
    
    await db.execute(
        text("""
            UPDATE organizations SET
                dlp_enabled = FALSE
            WHERE id = :org_id
        """),
        {"org_id": str(current_user.org_id)}
    )
    await db.commit()
    
    return {
        "success": True,
        "message": "DLP protection disabled."
    }


@router.put("/setup/config")
async def update_dlp_config(
    body: OneClickDLPSetup,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update DLP configuration without disabling/enabling."""
    await _require_enterprise(current_user, db)
    
    await db.execute(
        text("""
            UPDATE organizations SET
                dlp_scan_outbound = :scan_outbound,
                dlp_scan_inbound = :scan_inbound,
                dlp_action_pii = :action_pii,
                dlp_action_financial = :action_financial,
                dlp_action_credentials = :action_credentials,
                dlp_action_legal = :action_legal,
                dlp_notify_sender = :notify_sender,
                dlp_notify_admin = :notify_admin,
                dlp_admin_emails = :admin_emails
            WHERE id = :org_id
        """),
        {
            "org_id": str(current_user.org_id),
            "scan_outbound": body.scan_outbound,
            "scan_inbound": body.scan_inbound,
            "action_pii": body.action_pii,
            "action_financial": body.action_financial,
            "action_credentials": body.action_credentials,
            "action_legal": body.action_legal,
            "notify_sender": body.notify_sender,
            "notify_admin": body.notify_admin,
            "admin_emails": json.dumps(body.admin_emails),
        }
    )
    await db.commit()
    
    return {
        "success": True,
        "message": "DLP configuration updated."
    }
