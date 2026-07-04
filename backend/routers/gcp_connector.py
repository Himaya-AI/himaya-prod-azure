"""
Helios GCP Connector Router — manages Google Cloud Platform integrations and security scanning.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/gcp", tags=["gcp"])


# ── Request/Response Models ───────────────────────────────────────────────────

class GCPConnectRequest(BaseModel):
    project_id: str = Field(..., min_length=6, max_length=30)
    service_account_json: str = Field(..., min_length=100)
    name: str = Field(default="GCP Project")


class GCPConnectionResponse(BaseModel):
    id: str
    name: str
    project_id: Optional[str]
    status: str
    created_at: Optional[str]
    last_scan_at: Optional[str]


# ── Table Creation ────────────────────────────────────────────────────────────

async def ensure_gcp_tables(db: AsyncSession):
    """Create GCP connector tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS gcp_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            project_id VARCHAR(100),
            service_account_json_enc TEXT,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, project_id)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS gcp_resources (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES gcp_connections(id) ON DELETE CASCADE,
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_name VARCHAR(500),
            name VARCHAR(255),
            location VARCHAR(100),
            size_bytes BIGINT,
            created_at TIMESTAMPTZ,
            last_modified TIMESTAMPTZ,
            encryption_enabled BOOLEAN DEFAULT FALSE,
            encryption_type VARCHAR(50),
            public_access BOOLEAN DEFAULT FALSE,
            labels JSONB,
            metadata JSONB,
            scanned_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, resource_name)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS gcp_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES gcp_connections(id) ON DELETE CASCADE,
            finding_id VARCHAR(255),
            severity VARCHAR(20),
            category VARCHAR(50),
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_name VARCHAR(500),
            title VARCHAR(500),
            description TEXT,
            recommendation TEXT,
            status VARCHAR(50) DEFAULT 'open',
            detected_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,
            metadata JSONB,
            UNIQUE (org_id, finding_id)
        )
    """))
    
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_gcp_resources_org_id ON gcp_resources(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_gcp_findings_org_id ON gcp_findings(org_id)
    """))
    
    await db.commit()


# ── Encryption helpers ────────────────────────────────────────────────────────

def _encrypt(value: str) -> str:
    """Encrypt a value using Fernet."""
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().encrypt(value.encode()).decode()
    except Exception:
        return value


def _decrypt(enc: str) -> str:
    """Decrypt a Fernet-encrypted value."""
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return enc


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/connect")
async def connect_gcp(
    request: GCPConnectRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect a GCP project using service account credentials.
    Tests the connection and stores encrypted credentials.
    """
    from backend.services.gcp_security_service import GCPSecurityService
    
    await ensure_gcp_tables(db)
    org_id = str(current_user.org_id)

    # Validate JSON
    try:
        sa_data = json.loads(request.service_account_json)
        if sa_data.get("type") != "service_account":
            raise ValueError("Invalid service account JSON")
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid service account JSON: {e}")

    # Test the connection
    service = GCPSecurityService(
        project_id=request.project_id,
        service_account_json=request.service_account_json,
    )
    
    test_result = await service.test_connection()
    if not test_result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to GCP: {test_result.get('error', 'Unknown error')}"
        )

    # Encrypt credentials
    enc_sa_json = _encrypt(request.service_account_json)

    # Check if connection already exists
    existing = await db.execute(
        text("SELECT id FROM gcp_connections WHERE org_id = :org_id AND project_id = :project_id"),
        {"org_id": org_id, "project_id": request.project_id}
    )
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This GCP project is already connected.")

    # Insert new connection
    connection_id = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO gcp_connections
                (id, org_id, name, project_id, service_account_json_enc, status)
            VALUES
                (:id, :org_id, :name, :project_id, :sa_json_enc, 'active')
        """),
        {
            "id": connection_id,
            "org_id": org_id,
            "name": request.name,
            "project_id": request.project_id,
            "sa_json_enc": enc_sa_json,
        }
    )
    await db.commit()

    return {
        "success": True,
        "connection_id": connection_id,
        "project_id": request.project_id,
        "message": "GCP project connected successfully.",
    }


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all GCP connections for the organization."""
    await ensure_gcp_tables(db)
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, name, project_id, status, created_at, last_scan_at
            FROM gcp_connections
            WHERE org_id = :org_id
            ORDER BY created_at DESC
        """),
        {"org_id": org_id}
    )
    
    connections = []
    for row in result.mappings():
        connections.append({
            "id": str(row["id"]),
            "name": row["name"],
            "project_id": row["project_id"],
            "status": row["status"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "last_scan_at": row["last_scan_at"].isoformat() if row["last_scan_at"] else None,
        })

    return {"connections": connections}


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a GCP connection and all associated data."""
    org_id = str(current_user.org_id)

    # Verify ownership
    result = await db.execute(
        text("SELECT id FROM gcp_connections WHERE id = :id AND org_id = :org_id"),
        {"id": connection_id, "org_id": org_id}
    )
    if not result.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")

    # Delete associated data
    await db.execute(text("DELETE FROM gcp_findings WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM gcp_resources WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM gcp_connections WHERE id = :id"), {"id": connection_id})
    await db.commit()

    return {"success": True, "message": "GCP connection deleted"}


@router.post("/scan/{connection_id}")
async def trigger_scan(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a GCP security scan for a connection."""
    from backend.services.gcp_security_service import GCPSecurityService
    
    org_id = str(current_user.org_id)

    # Get connection details
    result = await db.execute(
        text("""
            SELECT id, project_id, service_account_json_enc
            FROM gcp_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Decrypt credentials
    sa_json = _decrypt(row["service_account_json_enc"])

    # Run scan
    service = GCPSecurityService(
        project_id=row["project_id"],
        service_account_json=sa_json,
    )
    
    scan_result = await service.scan_all()

    # Store resources
    for resource in scan_result.get("resources", []):
        await db.execute(
            text("""
                INSERT INTO gcp_resources
                    (org_id, connection_id, resource_type, resource_id, resource_name,
                     name, location, size_bytes, created_at, last_modified,
                     encryption_enabled, encryption_type, public_access, labels, metadata, scanned_at)
                VALUES
                    (:org_id, :conn_id, :resource_type, :resource_id, :resource_name,
                     :name, :location, :size_bytes, :created_at, :last_modified,
                     :encryption_enabled, :encryption_type, :public_access,
                     :labels, :metadata, NOW())
                ON CONFLICT (org_id, resource_name) DO UPDATE SET
                    name = EXCLUDED.name,
                    size_bytes = EXCLUDED.size_bytes,
                    last_modified = EXCLUDED.last_modified,
                    encryption_enabled = EXCLUDED.encryption_enabled,
                    encryption_type = EXCLUDED.encryption_type,
                    public_access = EXCLUDED.public_access,
                    labels = EXCLUDED.labels,
                    -- Preserve DLP keys written by the classifier between scans.
                    metadata = EXCLUDED.metadata || COALESCE(
                        (SELECT jsonb_object_agg(key, value)
                         FROM jsonb_each(gcp_resources.metadata)
                         WHERE key IN ('dlp_classified','dlp_categories','dlp_risk_level','ai_categories')),
                        '{}'::jsonb
                    ),
                    scanned_at = NOW()
            """),
            {
                "org_id": org_id,
                "conn_id": connection_id,
                "resource_type": resource["resource_type"],
                "resource_id": resource["resource_id"],
                "resource_name": resource["resource_name"],
                "name": resource["name"],
                "location": resource.get("location"),
                "size_bytes": resource.get("size_bytes"),
                "created_at": resource.get("created_at"),
                "last_modified": resource.get("last_modified"),
                "encryption_enabled": resource.get("encryption_enabled", False),
                "encryption_type": resource.get("encryption_type"),
                "public_access": resource.get("public_access", False),
                "labels": json.dumps(resource.get("labels", {})),
                "metadata": json.dumps(resource.get("metadata", {})),
            }
        )

    # Store findings
    for finding in scan_result.get("findings", []):
        await db.execute(
            text("""
                INSERT INTO gcp_findings
                    (org_id, connection_id, finding_id, severity, category,
                     resource_type, resource_id, resource_name,
                     title, description, recommendation, detected_at, metadata)
                VALUES
                    (:org_id, :conn_id, :finding_id, :severity, :category,
                     :resource_type, :resource_id, :resource_name,
                     :title, :description, :recommendation, :detected_at, :metadata)
                ON CONFLICT (org_id, finding_id) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    recommendation = EXCLUDED.recommendation,
                    detected_at = EXCLUDED.detected_at
            """),
            {
                "org_id": org_id,
                "conn_id": connection_id,
                "finding_id": finding["finding_id"],
                "severity": finding["severity"],
                "category": finding["category"],
                "resource_type": finding["resource_type"],
                "resource_id": finding["resource_id"],
                "resource_name": finding["resource_name"],
                "title": finding["title"],
                "description": finding["description"],
                "recommendation": finding["recommendation"],
                "detected_at": finding.get("detected_at"),
                "metadata": json.dumps(finding.get("metadata", {})),
            }
        )

    # Update last scan time
    await db.execute(
        text("UPDATE gcp_connections SET last_scan_at = NOW() WHERE id = :id"),
        {"id": connection_id}
    )
    await db.commit()

    return {
        "success": True,
        "stats": scan_result.get("stats"),
        "scanned_at": scan_result.get("scanned_at"),
    }


@router.get("/stats")
async def get_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get GCP resource and finding statistics."""
    await ensure_gcp_tables(db)
    org_id = str(current_user.org_id)

    # Resource stats
    resources = await db.execute(
        text("""
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE encryption_enabled) as encrypted,
                COUNT(*) FILTER (WHERE public_access) as public
            FROM gcp_resources WHERE org_id = :org_id
        """),
        {"org_id": org_id}
    )
    r_row = resources.mappings().first()

    # Finding stats
    findings = await db.execute(
        text("""
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high
            FROM gcp_findings WHERE org_id = :org_id AND status = 'open'
        """),
        {"org_id": org_id}
    )
    f_row = findings.mappings().first()

    return {
        "resources": {
            "total": r_row["total"] if r_row else 0,
            "encrypted": r_row["encrypted"] if r_row else 0,
            "public": r_row["public"] if r_row else 0,
        },
        "findings": {
            "total": f_row["total"] if f_row else 0,
            "critical": f_row["critical"] if f_row else 0,
            "high": f_row["high"] if f_row else 0,
        }
    }


# ── CSPM-engine bridge ───────────────────────────────────────────────────────

async def _run_background_scan(org_id: str, connection_id: str) -> None:
    """Run a full GCP CSPM scan for one connection. Reused by /cspm-scan and
    the unified CSPM+DSPM auto-loop in main.py."""
    from backend.database import AsyncSessionLocal as _ASL
    from backend.services.cspm import ScanContext, run_scan, write_findings
    from backend.services.cspm.collectors.gcp import GcpCollectorConfig, make_gcp_collector
    from backend.services.cspm.plugins.gcp import GCP_PLUGINS
    from backend.services.cspm.sink import mark_resolved, write_scan_report

    try:
        async with _ASL() as db:
            row = await db.execute(
                text("""
                    SELECT id, project_id, service_account_json_enc
                    FROM gcp_connections
                    WHERE id = CAST(:id AS UUID) AND org_id = CAST(:org AS UUID)
                """),
                {"id": connection_id, "org": org_id},
            )
            mapping = row.mappings().first()
            if not mapping:
                logger.warning(f"GCP scan: connection {connection_id} not found")
                return

            sa_json = _decrypt(mapping["service_account_json_enc"])
            project = mapping["project_id"]

            cfg = GcpCollectorConfig(project_id=project, service_account_json=sa_json)
            ctx = ScanContext(
                org_id=org_id, connection_id=str(mapping["id"]), cloud="gcp",
            )
            report = await run_scan(
                cloud="gcp",
                collector=make_gcp_collector(cfg),
                plugins=GCP_PLUGINS,
                ctx=ctx,
            )
            await write_findings(db, org_id, str(mapping["id"]), report.findings)
            seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
            await mark_resolved(db, org_id, "gcp", seen)
            await write_scan_report(db, report)
            await db.execute(
                text("UPDATE gcp_connections SET last_scan_at = NOW() WHERE id = CAST(:id AS UUID)"),
                {"id": str(mapping["id"])},
            )
            await db.commit()
            logger.info(
                f"GCP CSPM scan complete: org={org_id} conn={connection_id} "
                f"findings={len(report.findings)} sev={report.severity_counts}"
            )
    except Exception as exc:
        logger.exception(f"GCP CSPM background scan failed: {exc}")


@router.post("/cspm-scan/{connection_id}")
async def gcp_cspm_scan(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run the unified CSPM engine against this GCP connection."""
    org_id = str(current_user.org_id)
    # Verify the connection exists + belongs to the caller before spawning.
    row = await db.execute(
        text("SELECT id FROM gcp_connections WHERE id = :id AND org_id = :org_id"),
        {"id": connection_id, "org_id": org_id},
    )
    if not row.first():
        raise HTTPException(status_code=404, detail="Connection not found")

    import asyncio as _asyncio
    _asyncio.create_task(_run_background_scan(org_id, connection_id))
    return {"success": True, "message": "GCP CSPM scan started"}
