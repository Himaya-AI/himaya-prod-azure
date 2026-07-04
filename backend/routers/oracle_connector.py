"""
Helios Oracle Cloud Infrastructure (OCI) Connector Router.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user
from backend.services.cspm import ScanContext, ensure_cspm_tables, run_scan, write_findings
from backend.services.cspm.collectors.oracle import (
    OracleCollectorConfig,
    make_oracle_collector,
)
from backend.services.cspm.plugins.oracle import ORACLE_PLUGINS
from backend.services.cspm.sink import mark_resolved, write_scan_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/oracle", tags=["oracle"])


# ── Models ───────────────────────────────────────────────────────────────────

class OracleConnectRequest(BaseModel):
    name: str = Field(default="OCI Tenancy")
    tenancy_id: str
    user_id: str
    key_fingerprint: str
    private_key_pem: str = Field(..., min_length=64)
    region: str = Field(default="us-ashburn-1")
    compartment_id: Optional[str] = None


# ── Table setup ───────────────────────────────────────────────────────────────

async def ensure_oracle_tables(db: AsyncSession):
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS oracle_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            tenancy_id VARCHAR(255) NOT NULL,
            user_id VARCHAR(255) NOT NULL,
            key_fingerprint VARCHAR(255) NOT NULL,
            private_key_pem_enc TEXT NOT NULL,
            region VARCHAR(64) NOT NULL,
            compartment_id VARCHAR(255),
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, tenancy_id)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_oracle_connections_org ON oracle_connections(org_id)"
    ))
    await ensure_cspm_tables(db)
    await db.commit()


def _encrypt(value: str) -> str:
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().encrypt(value.encode()).decode()
    except Exception:
        return value


def _decrypt(enc: str) -> str:
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return enc


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/connect")
async def connect_oracle(
    request: OracleConnectRequest,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_oracle_tables(db)
    org_id = str(current_user.org_id)

    # Verify creds by listing users (lightweight identity call)
    try:
        import oci  # type: ignore
        cfg = {
            "user": request.user_id,
            "key_content": request.private_key_pem,
            "fingerprint": request.key_fingerprint,
            "tenancy": request.tenancy_id,
            "region": request.region,
        }
        identity = oci.identity.IdentityClient(cfg)
        identity.list_users(request.tenancy_id)
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="OCI SDK not installed on the backend. Please contact support.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"OCI authentication failed: {exc}",
        )

    existing = await db.execute(text(
        "SELECT id FROM oracle_connections WHERE org_id = CAST(:org AS UUID) AND tenancy_id = :t"
    ), {"org": org_id, "t": request.tenancy_id})
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This OCI tenancy is already connected.")

    cid = str(uuid.uuid4())
    enc_key = _encrypt(request.private_key_pem)
    await db.execute(text("""
        INSERT INTO oracle_connections
            (id, org_id, name, tenancy_id, user_id, key_fingerprint,
             private_key_pem_enc, region, compartment_id, status)
        VALUES
            (CAST(:id AS UUID), CAST(:org AS UUID), :name, :tenancy, :user, :fp,
             :pem, :region, :comp, 'active')
    """), {
        "id": cid, "org": org_id, "name": request.name,
        "tenancy": request.tenancy_id, "user": request.user_id, "fp": request.key_fingerprint,
        "pem": enc_key, "region": request.region, "comp": request.compartment_id or request.tenancy_id,
    })
    await db.commit()

    background.add_task(_run_background_scan, org_id, cid)
    return {"success": True, "connection_id": cid, "message": "OCI tenancy connected. Initial scan started."}


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_oracle_tables(db)
    org_id = str(current_user.org_id)
    rows = await db.execute(text("""
        SELECT id, name, tenancy_id, region, status, created_at, last_scan_at
        FROM oracle_connections WHERE org_id = CAST(:org AS UUID)
        ORDER BY created_at DESC
    """), {"org": org_id})
    return [
        {
            "id": str(r[0]), "name": r[1], "tenancy_id": r[2], "region": r[3],
            "status": r[4],
            "created_at": r[5].isoformat() if r[5] else "",
            "last_scan_at": r[6].isoformat() if r[6] else None,
        }
        for r in rows.fetchall()
    ]


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    await db.execute(text(
        "DELETE FROM oracle_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
    ), {"cid": connection_id, "org": org_id})
    await db.commit()
    return {"success": True}


@router.post("/connections/{connection_id}/scan")
async def trigger_scan(
    connection_id: str,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    row = await db.execute(text(
        "SELECT id FROM oracle_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
    ), {"cid": connection_id, "org": org_id})
    if not row.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")
    background.add_task(_run_background_scan, org_id, connection_id)
    return {"success": True, "message": "Scan started"}


@router.get("/stats")
async def get_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_oracle_tables(db)
    org_id = str(current_user.org_id)
    sev = await db.execute(text("""
        SELECT severity, COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'oracle' AND resolved_at IS NULL
        GROUP BY severity
    """), {"org": org_id})
    sc = {s: int(n) for s, n in sev.fetchall()}
    total = await db.execute(text("""
        SELECT COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'oracle' AND resolved_at IS NULL
    """), {"org": org_id})
    last = await db.execute(text("""
        SELECT MAX(finished_at) FROM cspm_scans
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'oracle'
    """), {"org": org_id})
    last_at = last.scalar()
    return {
        "total_findings": int(total.scalar() or 0),
        "critical_findings": sc.get("critical", 0),
        "high_findings": sc.get("high", 0),
        "medium_findings": sc.get("medium", 0),
        "low_findings": sc.get("low", 0),
        "last_scan_at": last_at.isoformat() if last_at else None,
    }


@router.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_oracle_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)", "cloud = 'oracle'"]
    params: dict = {"org": org_id, "lim": min(limit, 500)}
    if severity:
        where.append("severity = :sev")
        params["sev"] = severity
    if status == "open":
        where.append("resolved_at IS NULL")
    elif status == "resolved":
        where.append("resolved_at IS NOT NULL")
    sql = f"""
        SELECT id, plugin_id, severity, status, category, title, message,
               resource, resource_type, region, recommendation,
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
            "id": str(r[0]), "plugin_id": r[1], "severity": r[2], "status": r[3],
            "category": r[4], "title": r[5], "message": r[6], "resource": r[7],
            "resource_type": r[8], "region": r[9], "recommendation": r[10],
            "first_seen_at": r[11].isoformat() if r[11] else None,
            "last_seen_at": r[12].isoformat() if r[12] else None,
            "resolved_at": r[13].isoformat() if r[13] else None,
        }
        for r in rows.fetchall()
    ]


# ── Background scan ───────────────────────────────────────────────────────────

async def _run_background_scan(org_id: str, connection_id: str) -> None:
    try:
        async with AsyncSessionLocal() as db:
            row = await db.execute(text("""
                SELECT tenancy_id, user_id, key_fingerprint, private_key_pem_enc,
                       region, compartment_id
                FROM oracle_connections
                WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
            """), {"cid": connection_id, "org": org_id})
            data = row.first()
            if not data:
                return
            tid, uid, fp, key_enc, region, comp = data
            key = _decrypt(key_enc)
            cfg = OracleCollectorConfig(
                tenancy_id=tid, user_id=uid, key_fingerprint=fp,
                private_key_pem=key, region=region, compartment_id=comp,
            )
            ctx = ScanContext(
                org_id=org_id, connection_id=connection_id, cloud="oracle",
                regions=[region],
            )
            report = await run_scan(
                cloud="oracle",
                collector=make_oracle_collector(cfg),
                plugins=ORACLE_PLUGINS,
                ctx=ctx,
            )
            await write_findings(db, org_id, connection_id, report.findings)
            seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
            await mark_resolved(db, org_id, "oracle", seen)
            await write_scan_report(db, report)
            await db.execute(text(
                "UPDATE oracle_connections SET last_scan_at = NOW() WHERE id = CAST(:cid AS UUID)"
            ), {"cid": connection_id})
            await db.commit()
            logger.info(
                f"OCI scan complete: org={org_id} conn={connection_id} "
                f"findings={len(report.findings)} sev={report.severity_counts}"
            )
    except Exception as exc:
        logger.exception(f"OCI background scan failed: {exc}")
