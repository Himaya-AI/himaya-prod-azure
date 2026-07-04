"""
Toxic Combinations API
======================

Exposes the toxic combinations engine to the DSPM frontend:

  GET  /api/dspm/toxic-combinations              list open combinations
  GET  /api/dspm/toxic-combinations/stats        counts by severity / rule
  GET  /api/dspm/toxic-combinations/rules        rule catalogue
  POST /api/dspm/toxic-combinations/{id}/resolve mark one resolved
  POST /api/dspm/toxic-combinations/run          force a synchronous run (admin)
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.services.toxic_combinations import (
    ensure_schema, get_rules, run_for_org,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dspm/toxic-combinations", tags=["dspm-toxic"])


@router.get("")
async def list_toxic_combinations(
    severity: Optional[str] = Query(None),
    rule_id:  Optional[str] = Query(None),
    status:   str = Query("open"),
    limit:    int = Query(100, ge=1, le=500),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    await ensure_schema(db)
    where = ["org_id = CAST(:org_id AS UUID)"]
    params: dict = {"org_id": org_id, "limit": limit}
    if status and status != "all":
        where.append("status = :status")
        params["status"] = status
    if severity:
        where.append("severity = :severity")
        params["severity"] = severity
    if rule_id:
        where.append("rule_id = :rule_id")
        params["rule_id"] = rule_id

    sql = text(f"""
        SELECT id::text, rule_id, severity, title, description,
               resources, factors, status,
               first_seen_at, last_seen_at, resolved_at, metadata
        FROM toxic_combinations
        WHERE {' AND '.join(where)}
        ORDER BY
            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
            last_seen_at DESC
        LIMIT :limit
    """)
    rows = (await db.execute(sql, params)).mappings().all()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "rule_id": r["rule_id"],
            "severity": r["severity"],
            "title": r["title"],
            "description": r["description"],
            "resources": r["resources"] or [],
            "factors": r["factors"] or [],
            "status": r["status"],
            "first_seen_at": r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
            "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
            "resolved_at": r["resolved_at"].isoformat() if r["resolved_at"] else None,
            "metadata": r["metadata"] or {},
        })
    return {"items": items, "total": len(items)}


@router.get("/stats")
async def toxic_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    await ensure_schema(db)
    by_sev = (await db.execute(text("""
        SELECT severity, COUNT(*) AS n
        FROM toxic_combinations
        WHERE org_id = CAST(:org_id AS UUID) AND status = 'open'
        GROUP BY severity
    """), {"org_id": org_id})).mappings().all()
    by_rule = (await db.execute(text("""
        SELECT rule_id, COUNT(*) AS n
        FROM toxic_combinations
        WHERE org_id = CAST(:org_id AS UUID) AND status = 'open'
        GROUP BY rule_id
    """), {"org_id": org_id})).mappings().all()
    return {
        "by_severity": {r["severity"]: r["n"] for r in by_sev},
        "by_rule":     {r["rule_id"]:  r["n"] for r in by_rule},
        "total_open":  sum(r["n"] for r in by_sev),
    }


@router.get("/rules")
async def toxic_rules(_=Depends(get_current_user)):
    return {"rules": await get_rules()}


@router.post("/{combination_id}/resolve")
async def resolve_combination(
    combination_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    res = await db.execute(text("""
        UPDATE toxic_combinations
        SET status = 'resolved', resolved_at = NOW()
        WHERE id = CAST(:id AS UUID) AND org_id = CAST(:org_id AS UUID)
        RETURNING id::text
    """), {"id": combination_id, "org_id": org_id})
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Combination not found")
    await db.commit()
    return {"success": True, "id": row["id"]}


@router.post("/run")
async def force_run(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin trigger to run toxic combinations engine for the caller's org now."""
    org_id = str(current_user.org_id)
    summary = await run_for_org(org_id, db)
    # Clean up the debug rule_id row that earlier diagnostic runs may have
    # written so it doesn't show up in the UI.
    try:
        await db.execute(text(
            "DELETE FROM toxic_combinations "
            "WHERE org_id = CAST(:org_id AS UUID) AND rule_id = 'debug'"
        ), {"org_id": org_id})
        await db.commit()
    except Exception:
        pass
    return summary
