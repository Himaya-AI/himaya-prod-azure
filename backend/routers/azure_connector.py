"""
Helios Azure Connector Router — manages Azure subscription integrations and
CSPM scanning via the unified CSPM engine.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user
from backend.services.cspm import (
    ScanContext,
    ensure_cspm_tables,
    run_scan,
    write_findings,
)
from backend.services.cspm.collectors.azure import (
    AzureCollectorConfig,
    acquire_token,
    collect_azure,
    make_azure_collector,
)
from backend.services.cspm.plugins.azure import AZURE_PLUGINS
from backend.services.cspm.sink import mark_resolved, write_scan_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/azure", tags=["azure"])


# ── Models ───────────────────────────────────────────────────────────────────

class AzureConnectRequest(BaseModel):
    name: str = Field(default="Azure Subscription")
    tenant_id: str = Field(..., min_length=10)
    client_id: str = Field(..., min_length=10)
    client_secret: str = Field(..., min_length=10)
    subscription_id: str = Field(..., min_length=10)
    scan_locations: list[str] = Field(
        default_factory=lambda: [
            "eastus", "westus", "westus2", "westeurope", "northeurope",
        ]
    )


class AzureConnectionResponse(BaseModel):
    id: str
    name: str
    tenant_id: str
    subscription_id: str
    status: str
    scan_locations: list[str]
    created_at: str
    last_scan_at: Optional[str]


# ── Table setup ───────────────────────────────────────────────────────────────

async def ensure_azure_tables(db: AsyncSession):
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS azure_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            tenant_id VARCHAR(128) NOT NULL,
            client_id VARCHAR(128) NOT NULL,
            client_secret_enc TEXT NOT NULL,
            subscription_id VARCHAR(128) NOT NULL,
            scan_locations TEXT[],
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, subscription_id)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_azure_connections_org ON azure_connections(org_id)"
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
async def connect_azure(
    request: AzureConnectRequest,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify Azure credentials, store the connection, and trigger an initial scan."""
    await ensure_azure_tables(db)
    org_id = str(current_user.org_id)

    # Verify creds by acquiring a token
    token = await acquire_token(
        request.tenant_id, request.client_id, request.client_secret,
        scope="https://management.azure.com/.default",
    )
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Could not authenticate with Azure. Check tenant_id / client_id / client_secret.",
        )

    # Verify the SP has read on the subscription
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://management.azure.com/subscriptions/{request.subscription_id}?api-version=2022-12-01",
                headers={"Authorization": f"Bearer {token}"},
            )
            if r.status_code >= 400:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Service principal cannot read subscription {request.subscription_id} "
                        f"(HTTP {r.status_code}). Open Azure portal → Subscriptions → your subscription "
                        "→ Access control (IAM) → Add role assignment, and assign the app registration "
                        "the 'Reader' role (and 'Security Reader' for Defender for Cloud checks). "
                        "Role propagation can take up to 5 minutes."
                    ),
                )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Subscription verification failed: {exc}")

    enc_secret = _encrypt(request.client_secret)

    # Dedup
    existing = await db.execute(
        text("SELECT id FROM azure_connections WHERE org_id = CAST(:org AS UUID) AND subscription_id = :sub"),
        {"org": org_id, "sub": request.subscription_id},
    )
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This Azure subscription is already connected.")

    cid = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO azure_connections
                (id, org_id, name, tenant_id, client_id, client_secret_enc,
                 subscription_id, scan_locations, status)
            VALUES
                (CAST(:id AS UUID), CAST(:org AS UUID), :name, :tenant, :client, :secret,
                 :sub, :locs, 'active')
        """),
        {
            "id": cid, "org": org_id, "name": request.name,
            "tenant": request.tenant_id, "client": request.client_id, "secret": enc_secret,
            "sub": request.subscription_id, "locs": request.scan_locations,
        },
    )
    await db.commit()

    # Kick off initial scan in background
    background.add_task(_run_background_scan, org_id, cid)

    return {
        "success": True,
        "connection_id": cid,
        "subscription_id": request.subscription_id,
        "message": "Azure subscription connected. Initial scan started.",
    }


@router.get("/connections", response_model=list[AzureConnectionResponse])
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_azure_tables(db)
    org_id = str(current_user.org_id)
    rows = await db.execute(text("""
        SELECT id, name, tenant_id, subscription_id, scan_locations, status, created_at, last_scan_at
        FROM azure_connections WHERE org_id = CAST(:org AS UUID)
        ORDER BY created_at DESC
    """), {"org": org_id})
    out = []
    for r in rows.fetchall():
        out.append({
            "id": str(r[0]),
            "name": r[1] or "Azure Subscription",
            "tenant_id": r[2],
            "subscription_id": r[3],
            "status": r[5],
            "scan_locations": r[4] or [],
            "created_at": r[6].isoformat() if r[6] else "",
            "last_scan_at": r[7].isoformat() if r[7] else None,
        })
    return out


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    await db.execute(text(
        "DELETE FROM azure_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
        "SELECT id FROM azure_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
    """Return CSPM stats for the org's Azure findings."""
    await ensure_azure_tables(db)
    org_id = str(current_user.org_id)
    sev_row = await db.execute(text("""
        SELECT severity, COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'azure' AND resolved_at IS NULL
        GROUP BY severity
    """), {"org": org_id})
    sev_counts = {sev: int(cnt) for sev, cnt in sev_row.fetchall()}

    cat_row = await db.execute(text("""
        SELECT category, COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'azure' AND resolved_at IS NULL
        GROUP BY category
    """), {"org": org_id})
    by_category = {c: int(n) for c, n in cat_row.fetchall()}

    total_row = await db.execute(text("""
        SELECT COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'azure' AND resolved_at IS NULL
    """), {"org": org_id})
    total = int(total_row.scalar() or 0)

    last_scan_row = await db.execute(text("""
        SELECT MAX(finished_at) FROM cspm_scans
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'azure'
    """), {"org": org_id})
    last_scan = last_scan_row.scalar()

    return {
        "total_findings": total,
        "critical_findings": sev_counts.get("critical", 0),
        "high_findings": sev_counts.get("high", 0),
        "medium_findings": sev_counts.get("medium", 0),
        "low_findings": sev_counts.get("low", 0),
        "by_category": by_category,
        "last_scan_at": last_scan.isoformat() if last_scan else None,
    }


@router.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_azure_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)", "cloud = 'azure'"]
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
               resource, resource_type, region, recommendation, first_seen_at, last_seen_at, resolved_at
        FROM cspm_findings
        WHERE {' AND '.join(where)}
        ORDER BY
            CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                         WHEN 'low' THEN 4 ELSE 5 END,
            last_seen_at DESC
        LIMIT :lim
    """
    rows = await db.execute(text(sql), params)
    return [
        {
            "id": str(r[0]),
            "plugin_id": r[1],
            "severity": r[2],
            "status": r[3],
            "category": r[4],
            "title": r[5],
            "message": r[6],
            "resource": r[7],
            "resource_type": r[8],
            "region": r[9],
            "recommendation": r[10],
            "first_seen_at": r[11].isoformat() if r[11] else None,
            "last_seen_at": r[12].isoformat() if r[12] else None,
            "resolved_at": r[13].isoformat() if r[13] else None,
        }
        for r in rows.fetchall()
    ]


# ── Background scan helper ────────────────────────────────────────────────────

async def _run_background_scan(org_id: str, connection_id: str) -> None:
    """Run a full Azure scan for one connection. Spawned via BackgroundTasks."""
    try:
        async with AsyncSessionLocal() as db:
            row = await db.execute(text("""
                SELECT tenant_id, client_id, client_secret_enc, subscription_id, scan_locations
                FROM azure_connections
                WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
            """), {"cid": connection_id, "org": org_id})
            data = row.first()
            if not data:
                logger.warning(f"Azure scan: connection {connection_id} not found")
                return
            tenant_id, client_id, secret_enc, sub_id, locs = data

            secret = _decrypt(secret_enc)
            cfg = AzureCollectorConfig(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret,
                subscription_id=sub_id,
                locations=list(locs or []),
            )
            collector = make_azure_collector(cfg)
            ctx = ScanContext(
                org_id=org_id,
                connection_id=connection_id,
                cloud="azure",
                regions=list(locs or []),
            )
            report = await run_scan(
                cloud="azure",
                collector=collector,
                plugins=AZURE_PLUGINS,
                ctx=ctx,
            )

            await write_findings(db, org_id, connection_id, report.findings)
            seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
            await mark_resolved(db, org_id, "azure", seen)
            await write_scan_report(db, report)

            await db.execute(text("""
                UPDATE azure_connections SET last_scan_at = NOW()
                WHERE id = CAST(:cid AS UUID)
            """), {"cid": connection_id})
            await db.commit()
            logger.info(
                f"Azure scan complete: org={org_id} conn={connection_id} "
                f"plugins={report.plugins_run} findings={len(report.findings)} "
                f"sev={report.severity_counts}"
            )
    except Exception as exc:
        logger.exception(f"Azure background scan failed: {exc}")
