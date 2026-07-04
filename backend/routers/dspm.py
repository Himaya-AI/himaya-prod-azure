"""
Helios DSPM (Data Security Posture Management) router.

Endpoints:
    POST /api/dspm/scan/aws/{connection_id}    — trigger scan against AWS conn
    GET  /api/dspm/overview                    — severity + category roll-up
    GET  /api/dspm/findings                    — filterable list
    POST /api/dspm/findings/{id}/resolve       — mark resolved
    POST /api/dspm/findings/{id}/reopen        — un-resolve
    GET  /api/dspm/scans                       — recent scan history
    GET  /api/dspm/patterns                    — pattern catalogue (no auth)
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.services.dspm import (
    DEFAULT_PATTERNS,
    ensure_dspm_tables,
    run_aws_s3_scan,
    run_m365_dspm_scan,
    run_azure_dspm_scan,
    run_gcs_dspm_scan,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dspm", tags=["dspm"])


# ── Scans ──────────────────────────────────────────────────────────────────

@router.post("/scan/aws/{connection_id}")
async def scan_aws(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger a DSPM scan against an AWS connection. Reuses the AWS connection
    credentials already stored by the AWS connector. Runs in the background.
    """
    from backend.database import AsyncSessionLocal as _ASL
    from backend.routers.aws_connector import _decrypt

    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    row = (await db.execute(
        text("""
            SELECT id, access_key_id_enc, secret_access_key_enc, default_region
            FROM aws_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id},
    )).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="AWS connection not found")

    access_key = _decrypt(row["access_key_id_enc"])
    secret_key = _decrypt(row["secret_access_key_enc"])
    default_region = row["default_region"] or "us-east-1"

    async def _run():
        try:
            async with _ASL() as db_bg:
                report = await run_aws_s3_scan(
                    db_bg,
                    org_id=org_id,
                    connection_id=str(row["id"]),
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    default_region=default_region,
                )
            logger.info(
                "DSPM AWS scan complete: org=%s findings=%d sev=%s",
                org_id, len(report.findings), report.severity_counts,
            )
        except Exception as exc:
            logger.exception("DSPM AWS scan failed: %s", exc)

    import asyncio as _asyncio
    _asyncio.create_task(_run())
    return {"success": True, "message": "DSPM AWS scan started"}


@router.post("/scan/m365/{integration_id}")
async def scan_m365(
    integration_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger a DSPM scan against an M365 SaaS integration (SharePoint +
    OneDrive). Reuses the SaaS layer's Graph access token. Runs in the
    background.
    """
    from backend.database import AsyncSessionLocal as _ASL
    from backend.models.db_models import SaasIntegration as _Integ
    from backend.routers.saas_security import _get_valid_token
    from sqlalchemy import select as _select
    import uuid as _uuid

    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    integ = (await db.execute(
        _select(_Integ).where(
            _Integ.id == _uuid.UUID(integration_id),
            _Integ.org_id == _uuid.UUID(org_id),
            _Integ.provider.in_(("m365", "teams", "sharepoint")),
        )
    )).scalar_one_or_none()
    if not integ:
        raise HTTPException(status_code=404, detail="M365 integration not found")

    token = await _get_valid_token(integ, db)
    if not token:
        raise HTTPException(status_code=400, detail="No valid M365 token")

    async def _run():
        try:
            async with _ASL() as db_bg:
                report = await run_m365_dspm_scan(
                    db_bg,
                    org_id=org_id,
                    integration_id=str(integ.id),
                    access_token=token,
                )
            logger.info(
                "DSPM M365 scan complete: org=%s findings=%d sev=%s",
                org_id, len(report.findings), report.severity_counts,
            )
        except Exception as exc:
            logger.exception("DSPM M365 scan failed: %s", exc)

    import asyncio as _asyncio
    _asyncio.create_task(_run())
    return {"success": True, "message": "DSPM M365 scan started"}


@router.post("/scan/azure/{connection_id}")
async def scan_azure(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a DSPM scan against an Azure subscription's Blob Storage."""
    from backend.database import AsyncSessionLocal as _ASL
    from backend.routers.azure_connector import _decrypt as _az_decrypt

    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    row = (await db.execute(
        text("""
            SELECT id, tenant_id, client_id, client_secret_enc, subscription_id
            FROM azure_connections
            WHERE id = CAST(:id AS UUID) AND org_id = CAST(:org AS UUID)
        """),
        {"id": connection_id, "org": org_id},
    )).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Azure connection not found")

    _decrypted_secret = _az_decrypt(row["client_secret_enc"])

    async def _run():
        try:
            async with _ASL() as db_bg:
                report = await run_azure_dspm_scan(
                    db_bg,
                    org_id=org_id,
                    connection_id=str(row["id"]),
                    tenant_id=row["tenant_id"],
                    client_id=row["client_id"],
                    client_secret=_decrypted_secret,
                    subscription_id=row["subscription_id"],
                )
            logger.info(
                "DSPM Azure scan complete: org=%s findings=%d sev=%s",
                org_id, len(report.findings), report.severity_counts,
            )
        except Exception as exc:
            logger.exception("DSPM Azure scan failed: %s", exc)

    import asyncio as _asyncio
    _asyncio.create_task(_run())
    return {"success": True, "message": "DSPM Azure scan started"}


@router.post("/scan/gcp/{connection_id}")
async def scan_gcp(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a DSPM scan against a GCS project."""
    from backend.database import AsyncSessionLocal as _ASL
    from backend.routers.gcp_connector import _decrypt as _gcp_decrypt

    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    row = (await db.execute(
        text("""
            SELECT id, project_id, service_account_json_enc
            FROM gcp_connections
            WHERE id = CAST(:id AS UUID) AND org_id = CAST(:org AS UUID)
        """),
        {"id": connection_id, "org": org_id},
    )).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="GCP connection not found")

    sa_json = _gcp_decrypt(row["service_account_json_enc"])

    async def _run():
        try:
            async with _ASL() as db_bg:
                report = await run_gcs_dspm_scan(
                    db_bg,
                    org_id=org_id,
                    connection_id=str(row["id"]),
                    project_id=row["project_id"],
                    service_account_json=sa_json,
                )
            logger.info(
                "DSPM GCS scan complete: org=%s findings=%d sev=%s",
                org_id, len(report.findings), report.severity_counts,
            )
        except Exception as exc:
            logger.exception("DSPM GCS scan failed: %s", exc)

    import asyncio as _asyncio
    _asyncio.create_task(_run())
    return {"success": True, "message": "DSPM GCP scan started"}


# ── Overview ───────────────────────────────────────────────────────────────

@router.get("/overview")
async def overview(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Severity + category roll-up across all clouds for this org."""
    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    sev_by_cloud = (await db.execute(text("""
        SELECT cloud, severity, COUNT(*)
        FROM dspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NULL
        GROUP BY cloud, severity
    """), {"org": org_id})).fetchall()

    out_by_cloud: dict[str, dict[str, int]] = {}
    for cloud, sev, n in sev_by_cloud:
        out_by_cloud.setdefault(cloud, {})[sev] = int(n)

    cat_rows = (await db.execute(text("""
        SELECT category, COUNT(*) FROM dspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NULL
        GROUP BY category
        ORDER BY 2 DESC
    """), {"org": org_id})).fetchall()
    categories = {c: int(n) for c, n in cat_rows}

    total_open = int((await db.execute(text("""
        SELECT COUNT(*) FROM dspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NULL
    """), {"org": org_id})).scalar() or 0)
    total_resolved = int((await db.execute(text("""
        SELECT COUNT(*) FROM dspm_findings
        WHERE org_id = CAST(:org AS UUID) AND resolved_at IS NOT NULL
    """), {"org": org_id})).scalar() or 0)

    last_rows = (await db.execute(text("""
        SELECT cloud, MAX(finished_at) FROM dspm_scans
        WHERE org_id = CAST(:org AS UUID)
        GROUP BY cloud
    """), {"org": org_id})).fetchall()
    last_by_cloud = {c: (t.isoformat() if t else None) for c, t in last_rows}

    return {
        "by_cloud": out_by_cloud,
        "categories": categories,
        "total_open": total_open,
        "total_resolved": total_resolved,
        "last_scan_by_cloud": last_by_cloud,
    }


# ── Findings list ──────────────────────────────────────────────────────────

@router.get("/findings")
async def list_findings(
    cloud: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    where = ["org_id = CAST(:org AS UUID)"]
    params: dict = {"org": org_id, "lim": min(limit, 1000)}
    if cloud:
        where.append("cloud = :c")
        params["c"] = cloud
    if severity:
        where.append("severity = :sev")
        params["sev"] = severity
    if category:
        where.append("category = :cat")
        params["cat"] = category
    if status == "open":
        where.append("resolved_at IS NULL")
    elif status == "resolved":
        where.append("resolved_at IS NOT NULL")

    sql = f"""
        SELECT id, cloud, resource_type, resource_id, object_key,
               category, severity, pattern_name, match_count,
               redacted_sample, confidence, region, metadata,
               first_seen_at, last_seen_at, resolved_at
        FROM dspm_findings
        WHERE {' AND '.join(where)}
        ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4
                    ELSE 5
                 END,
                 last_seen_at DESC
        LIMIT :lim
    """
    rows = (await db.execute(text(sql), params)).fetchall()
    return [
        {
            "id": str(r[0]),
            "cloud": r[1],
            "resource_type": r[2],
            "resource_id": r[3],
            "object_key": r[4],
            "category": r[5],
            "severity": r[6],
            "pattern_name": r[7],
            "match_count": r[8],
            "redacted_sample": r[9],
            "confidence": r[10],
            "region": r[11],
            "metadata": r[12],
            "first_seen_at": r[13].isoformat() if r[13] else None,
            "last_seen_at": r[14].isoformat() if r[14] else None,
            "resolved_at": r[15].isoformat() if r[15] else None,
        }
        for r in rows
    ]


@router.post("/findings/{finding_id}/resolve")
async def resolve_finding(
    finding_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)
    res = await db.execute(text("""
        UPDATE dspm_findings SET resolved_at = NOW()
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
    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)
    res = await db.execute(text("""
        UPDATE dspm_findings SET resolved_at = NULL
        WHERE id = CAST(:fid AS UUID) AND org_id = CAST(:org AS UUID)
        RETURNING id
    """), {"fid": finding_id, "org": org_id})
    if not res.first():
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.commit()
    return {"success": True}


# ── Scan history ───────────────────────────────────────────────────────────

@router.get("/scans")
async def list_scans(
    cloud: Optional[str] = None,
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_dspm_tables(db)
    org_id = str(current_user.org_id)

    where = ["org_id = CAST(:org AS UUID)"]
    params: dict = {"org": org_id, "lim": min(limit, 200)}
    if cloud:
        where.append("cloud = :c")
        params["c"] = cloud

    sql = f"""
        SELECT id, cloud, started_at, finished_at, duration_ms,
               resources_scanned, objects_sampled, bytes_inspected,
               findings_count, severity_counts, category_counts, status
        FROM dspm_scans
        WHERE {' AND '.join(where)}
        ORDER BY started_at DESC
        LIMIT :lim
    """
    rows = (await db.execute(text(sql), params)).fetchall()
    return [
        {
            "id": str(r[0]),
            "cloud": r[1],
            "started_at": r[2].isoformat() if r[2] else None,
            "finished_at": r[3].isoformat() if r[3] else None,
            "duration_ms": r[4],
            "resources_scanned": r[5],
            "objects_sampled": r[6],
            "bytes_inspected": r[7],
            "findings_count": r[8],
            "severity_counts": r[9],
            "category_counts": r[10],
            "status": r[11],
        }
        for r in rows
    ]


# ── Pattern catalogue ──────────────────────────────────────────────────────

@router.get("/patterns")
async def list_patterns():
    """Return the DSPM pattern catalogue (informational, no auth)."""
    return {
        "total": len(DEFAULT_PATTERNS),
        "patterns": [
            {
                "name": p.name,
                "description": p.description,
                "category": p.category.value,
                "confidence": p.confidence,
                "enabled": p.enabled,
                "has_validator": bool(p.validation),
            }
            for p in DEFAULT_PATTERNS
        ],
    }
