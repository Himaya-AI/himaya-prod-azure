"""
Helios CSPM unified router — cross-cloud overview, findings list, scan history.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.services.cspm import ensure_cspm_tables

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cspm", tags=["cspm"])


@router.get("/overview")
async def overview(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cross-cloud severity + category counts for the org."""
    await ensure_cspm_tables(db)
    org_id = str(current_user.org_id)
    by_cloud = await db.execute(text("""
        SELECT cloud, severity, COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NULL
        GROUP BY cloud, severity
    """), {"org": org_id})

    out: dict[str, dict[str, int]] = {}
    for cloud, sev, n in by_cloud.fetchall():
        out.setdefault(cloud, {})[sev] = int(n)

    total_open = await db.execute(text("""
        SELECT COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NULL
    """), {"org": org_id})
    total_resolved = await db.execute(text("""
        SELECT COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NOT NULL
    """), {"org": org_id})

    last = await db.execute(text("""
        SELECT cloud, MAX(finished_at) FROM cspm_scans
        WHERE org_id = CAST(:org AS UUID)
        GROUP BY cloud
    """), {"org": org_id})
    last_by_cloud = {c: (t.isoformat() if t else None) for c, t in last.fetchall()}

    return {
        "by_cloud": out,
        "total_open": int(total_open.scalar() or 0),
        "total_resolved": int(total_resolved.scalar() or 0),
        "last_scan_by_cloud": last_by_cloud,
    }


@router.get("/findings")
async def all_findings(
    cloud: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_cspm_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)"]
    params: dict = {"org": org_id, "lim": min(limit, 1000)}
    if cloud:
        where.append("cloud = :c")
        params["c"] = cloud
    if severity:
        where.append("severity = :sev")
        params["sev"] = severity
    if status == "open":
        where.append("resolved_at IS NULL")
    elif status == "resolved":
        where.append("resolved_at IS NOT NULL")

    sql = f"""
        SELECT id, cloud, plugin_id, severity, status, category, title, message,
               resource, resource_type, region, recommendation, compliance,
               first_seen_at, last_seen_at, resolved_at
        FROM cspm_findings
        WHERE {' AND '.join(where)}
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                              WHEN 'low' THEN 4 ELSE 5 END, last_seen_at DESC
        LIMIT :lim
    """
    rows = await db.execute(text(sql), params)
    return [
        {
            "id": str(r[0]),
            "cloud": r[1], "plugin_id": r[2], "severity": r[3], "status": r[4],
            "category": r[5], "title": r[6], "message": r[7],
            "resource": r[8], "resource_type": r[9], "region": r[10],
            "recommendation": r[11], "compliance": r[12],
            "first_seen_at": r[13].isoformat() if r[13] else None,
            "last_seen_at": r[14].isoformat() if r[14] else None,
            "resolved_at": r[15].isoformat() if r[15] else None,
        }
        for r in rows.fetchall()
    ]


@router.get("/scans")
async def list_scans(
    cloud: Optional[str] = None,
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent scan run history."""
    await ensure_cspm_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)"]
    params: dict = {"org": org_id, "lim": min(limit, 200)}
    if cloud:
        where.append("cloud = :c")
        params["c"] = cloud
    sql = f"""
        SELECT id, cloud, started_at, finished_at, duration_ms,
               plugins_run, plugins_ok, plugins_fail, plugins_unknown,
               findings_count, severity_counts, status
        FROM cspm_scans WHERE {' AND '.join(where)}
        ORDER BY started_at DESC LIMIT :lim
    """
    rows = await db.execute(text(sql), params)
    return [
        {
            "id": str(r[0]), "cloud": r[1],
            "started_at": r[2].isoformat() if r[2] else None,
            "finished_at": r[3].isoformat() if r[3] else None,
            "duration_ms": r[4],
            "plugins_run": r[5], "plugins_ok": r[6], "plugins_fail": r[7],
            "plugins_unknown": r[8],
            "findings_count": r[9],
            "severity_counts": r[10],
            "status": r[11],
        }
        for r in rows.fetchall()
    ]


@router.post("/findings/{finding_id}/resolve")
async def resolve_finding(
    finding_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually mark a finding as resolved."""
    await ensure_cspm_tables(db)
    org_id = str(current_user.org_id)
    res = await db.execute(text("""
        UPDATE cspm_findings SET resolved_at = NOW()
        WHERE id = CAST(:fid AS UUID) AND org_id = CAST(:org AS UUID)
        RETURNING id
    """), {"fid": finding_id, "org": org_id})
    if not res.first():
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.commit()
    return {"success": True}


@router.post("/findings/{finding_id}/reopen")
async def reopen_finding(
    finding_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_cspm_tables(db)
    org_id = str(current_user.org_id)
    res = await db.execute(text("""
        UPDATE cspm_findings SET resolved_at = NULL
        WHERE id = CAST(:fid AS UUID) AND org_id = CAST(:org AS UUID)
        RETURNING id
    """), {"fid": finding_id, "org": org_id})
    if not res.first():
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.commit()
    return {"success": True}


@router.get("/plugins")
async def list_plugins():
    """Return registered plugin catalog (no auth needed — informational)."""
    from backend.services.cspm.plugins import (
        AZURE_PLUGINS, ORACLE_PLUGINS, GITHUB_PLUGINS, AWS_PLUGINS, GCP_PLUGINS,
    )
    out = []
    for cloud, plist in (
        ("aws", AWS_PLUGINS),
        ("azure", AZURE_PLUGINS),
        ("oracle", ORACLE_PLUGINS),
        ("github", GITHUB_PLUGINS),
        ("gcp", GCP_PLUGINS),
    ):
        for meta, _ in plist:
            out.append(meta.as_dict())
    return {"plugins": out, "total": len(out)}
