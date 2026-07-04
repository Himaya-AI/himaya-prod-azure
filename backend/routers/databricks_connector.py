"""
Helios Databricks Connector Router — manages Databricks workspace integrations and security scanning.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text, bindparam
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/databricks", tags=["databricks"])


# ── Request/Response Models ───────────────────────────────────────────────────

class DatabricksConnectRequest(BaseModel):
    workspace_url: str = Field(..., min_length=10)
    access_token: str = Field(..., min_length=20)
    name: str = Field(default="Databricks Workspace")


class DatabricksConnectionResponse(BaseModel):
    id: str
    name: str
    workspace_url: str
    status: str
    created_at: Optional[str]
    last_scan_at: Optional[str]


# ── Table Creation ────────────────────────────────────────────────────────────

async def ensure_databricks_tables(db: AsyncSession):
    """Create Databricks connector tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS databricks_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            workspace_url VARCHAR(500),
            access_token_enc TEXT,
            workspace_id VARCHAR(100),
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, workspace_url)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS databricks_resources (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES databricks_connections(id) ON DELETE CASCADE,
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_path VARCHAR(1000),
            name VARCHAR(255),
            created_by VARCHAR(255),
            created_at TIMESTAMPTZ,
            last_modified TIMESTAMPTZ,
            language VARCHAR(50),
            cluster_id VARCHAR(255),
            is_running BOOLEAN DEFAULT FALSE,
            has_secrets BOOLEAN DEFAULT FALSE,
            metadata JSONB,
            scanned_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, resource_type, resource_id)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS databricks_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES databricks_connections(id) ON DELETE CASCADE,
            finding_id VARCHAR(255),
            severity VARCHAR(20),
            category VARCHAR(50),
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_path VARCHAR(1000),
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
        CREATE INDEX IF NOT EXISTS ix_databricks_resources_org_id ON databricks_resources(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_databricks_findings_org_id ON databricks_findings(org_id)
    """))
    
    await db.commit()


# ── Encryption helpers ────────────────────────────────────────────────────────

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


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/connect")
async def connect_databricks(
    request: DatabricksConnectRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect a Databricks workspace using personal access token.
    Tests the connection and stores encrypted credentials.
    """
    from backend.services.databricks_security_service import DatabricksSecurityService
    
    await ensure_databricks_tables(db)
    org_id = str(current_user.org_id)

    # Normalize workspace URL
    workspace_url = request.workspace_url.rstrip('/')
    if not workspace_url.startswith('https://'):
        workspace_url = f"https://{workspace_url}"

    # Test the connection
    service = DatabricksSecurityService(
        workspace_url=workspace_url,
        access_token=request.access_token,
    )
    
    test_result = await service.test_connection()
    if not test_result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to Databricks: {test_result.get('error', 'Unknown error')}"
        )

    # Encrypt credentials
    enc_token = _encrypt(request.access_token)

    # Check if connection already exists
    existing = await db.execute(
        text("SELECT id FROM databricks_connections WHERE org_id = :org_id AND workspace_url = :url"),
        {"org_id": org_id, "url": workspace_url}
    )
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This Databricks workspace is already connected.")

    # Insert new connection
    connection_id = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO databricks_connections
                (id, org_id, name, workspace_url, access_token_enc, workspace_id, status)
            VALUES
                (:id, :org_id, :name, :workspace_url, :token_enc, :workspace_id, 'active')
        """),
        {
            "id": connection_id,
            "org_id": org_id,
            "name": request.name,
            "workspace_url": workspace_url,
            "token_enc": enc_token,
            "workspace_id": test_result.get("workspace_id"),
        }
    )
    await db.commit()

    return {
        "success": True,
        "connection_id": connection_id,
        "workspace_url": workspace_url,
        "message": "Databricks workspace connected successfully.",
    }


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all Databricks connections for the organization."""
    await ensure_databricks_tables(db)
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, name, workspace_url, status, created_at, last_scan_at
            FROM databricks_connections
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
            "workspace_url": row["workspace_url"],
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
    """Delete a Databricks connection and all associated data."""
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("SELECT id FROM databricks_connections WHERE id = :id AND org_id = :org_id"),
        {"id": connection_id, "org_id": org_id}
    )
    if not result.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")

    await db.execute(text("DELETE FROM databricks_findings WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM databricks_resources WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM databricks_connections WHERE id = :id"), {"id": connection_id})
    await db.commit()

    return {"success": True, "message": "Databricks connection deleted"}


@router.post("/scan/{connection_id}")
async def trigger_scan(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a Databricks security scan for a connection."""
    from backend.services.databricks_security_service import DatabricksSecurityService
    
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, workspace_url, access_token_enc
            FROM databricks_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")

    token = _decrypt(row["access_token_enc"])

    service = DatabricksSecurityService(
        workspace_url=row["workspace_url"],
        access_token=token,
    )
    
    scan_result = await service.scan_all()

    # Store resources
    for resource in scan_result.get("resources", []):
        await db.execute(
            text("""
                INSERT INTO databricks_resources
                    (org_id, connection_id, resource_type, resource_id, resource_path,
                     name, created_by, created_at, last_modified, language,
                     cluster_id, is_running, has_secrets, metadata, scanned_at)
                VALUES
                    (:org_id, :conn_id, :resource_type, :resource_id, :resource_path,
                     :name, :created_by, :created_at, :last_modified, :language,
                     :cluster_id, :is_running, :has_secrets, :metadata, NOW())
                ON CONFLICT (org_id, resource_type, resource_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    last_modified = EXCLUDED.last_modified,
                    is_running = EXCLUDED.is_running,
                    has_secrets = EXCLUDED.has_secrets,
                    -- Preserve DLP keys written by the classifier between scans.
                    metadata = EXCLUDED.metadata || COALESCE(
                        (SELECT jsonb_object_agg(key, value)
                         FROM jsonb_each(databricks_resources.metadata)
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
                "resource_path": resource.get("resource_path"),
                "name": resource["name"],
                "created_by": resource.get("created_by"),
                "created_at": resource.get("created_at"),
                "last_modified": resource.get("last_modified"),
                "language": resource.get("language"),
                "cluster_id": resource.get("cluster_id"),
                "is_running": resource.get("is_running", False),
                "has_secrets": resource.get("has_secrets", False),
                "metadata": json.dumps(resource.get("metadata", {})),
            }
        )

    # Store findings
    for finding in scan_result.get("findings", []):
        await db.execute(
            text("""
                INSERT INTO databricks_findings
                    (org_id, connection_id, finding_id, severity, category,
                     resource_type, resource_id, resource_path,
                     title, description, recommendation, detected_at, metadata)
                VALUES
                    (:org_id, :conn_id, :finding_id, :severity, :category,
                     :resource_type, :resource_id, :resource_path,
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
                "resource_path": finding.get("resource_path"),
                "title": finding["title"],
                "description": finding["description"],
                "recommendation": finding["recommendation"],
                "detected_at": finding.get("detected_at"),
                "metadata": json.dumps(finding.get("metadata", {})),
            }
        )

    await db.execute(
        text("UPDATE databricks_connections SET last_scan_at = NOW() WHERE id = :id"),
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
    """Get Databricks resource and finding statistics."""
    await ensure_databricks_tables(db)
    org_id = str(current_user.org_id)

    resources = await db.execute(
        text("""
            SELECT 
                COUNT(*) FILTER (WHERE resource_type = 'notebook') as notebooks,
                COUNT(*) FILTER (WHERE resource_type = 'cluster') as clusters,
                COUNT(*) FILTER (WHERE has_secrets) as secrets
            FROM databricks_resources WHERE org_id = :org_id
        """),
        {"org_id": org_id}
    )
    r_row = resources.mappings().first()

    findings = await db.execute(
        text("SELECT COUNT(*) as total FROM databricks_findings WHERE org_id = :org_id AND status = 'open'"),
        {"org_id": org_id}
    )
    f_row = findings.mappings().first()

    return {
        "notebooks": r_row["notebooks"] if r_row else 0,
        "clusters": r_row["clusters"] if r_row else 0,
        "secrets": r_row["secrets"] if r_row else 0,
        "findings": f_row["total"] if f_row else 0,
    }


# ── Background Worker ─────────────────────────────────────────────────────────

DATABRICKS_SCAN_INTERVAL_SECONDS = 600  # 10 minutes
DATABRICKS_INITIAL_DELAY_SECONDS = 60  # 1 minute delay on startup

async def _run_databricks_auto_scan():
    """Background task that scans all Databricks connections periodically."""
    import asyncio
    from backend.database import AsyncSessionLocal
    from backend.services.databricks_security_service import DatabricksSecurityService
    
    # Initial delay to let other services start
    await asyncio.sleep(DATABRICKS_INITIAL_DELAY_SECONDS)
    
    while True:
        try:
            async with AsyncSessionLocal() as db:
                # Find all active Databricks connections
                result = await db.execute(text("""
                    SELECT id, org_id, workspace_url, access_token_enc
                    FROM databricks_connections
                    WHERE status = 'active'
                """))
                connections = result.mappings().all()
                
                if not connections:
                    logger.info("databricks_auto_scan: no active connections found")
                    continue
                
                logger.info(f"databricks_auto_scan: found {len(connections)} active connection(s)")
                
                for conn in connections:
                    try:
                        org_id = str(conn["org_id"])
                        connection_id = str(conn["id"])
                        workspace_url = conn["workspace_url"]
                        access_token = _decrypt(conn["access_token_enc"])
                        
                        service = DatabricksSecurityService(
                            workspace_url=workspace_url,
                            access_token=access_token,
                        )
                        scan_result = await service.scan_all()
                        
                        # Store resources using parameterized query
                        for resource in scan_result.get("resources", []):
                            metadata_json = json.dumps(resource.get("metadata", {}))
                            await db.execute(
                                text("""
                                    INSERT INTO databricks_resources 
                                        (id, org_id, connection_id, resource_type, resource_id, resource_path,
                                         name, created_by, cluster_id, is_running, has_secrets, metadata, scanned_at)
                                    VALUES 
                                        (gen_random_uuid(), :org_id, :conn_id, :resource_type, :resource_id, :resource_path,
                                         :name, :created_by, :cluster_id, :is_running, :has_secrets, :metadata, NOW())
                                    ON CONFLICT (org_id, resource_type, resource_id) DO UPDATE SET
                                        name = EXCLUDED.name,
                                        resource_path = EXCLUDED.resource_path,
                                        is_running = EXCLUDED.is_running,
                                        has_secrets = EXCLUDED.has_secrets,
                                        -- Preserve DLP keys written by the classifier between scans.
                                        metadata = EXCLUDED.metadata || COALESCE(
                                            (SELECT jsonb_object_agg(key, value)
                                             FROM jsonb_each(databricks_resources.metadata)
                                             WHERE key IN ('dlp_classified','dlp_categories','dlp_risk_level','ai_categories')),
                                            '{}'::jsonb
                                        ),
                                        scanned_at = NOW()
                                """).bindparams(bindparam('metadata', type_=JSONB)),
                                {
                                    "org_id": org_id,
                                    "conn_id": connection_id,
                                    "resource_type": resource.get("resource_type"),
                                    "resource_id": resource.get("resource_id"),
                                    "resource_path": resource.get("resource_path"),
                                    "name": resource.get("name"),
                                    "created_by": resource.get("created_by"),
                                    "cluster_id": resource.get("cluster_id"),
                                    "is_running": resource.get("is_running", False),
                                    "has_secrets": resource.get("has_secrets", False),
                                    "metadata": resource.get("metadata", {}),
                                }
                            )
                        
                        # Store findings
                        for finding in scan_result.get("findings", []):
                            finding_id = finding.get("finding_id") or f"{finding.get('finding_type', 'unknown')}-{finding.get('resource_id', '')}"
                            await db.execute(
                                text("""
                                    INSERT INTO databricks_findings
                                        (id, org_id, connection_id, finding_id, severity, category,
                                         resource_type, resource_id, resource_path, title, description,
                                         recommendation, status, detected_at, metadata)
                                    VALUES
                                        (gen_random_uuid(), :org_id, :conn_id, :finding_id, :severity, :category,
                                         :resource_type, :resource_id, :resource_path, :title, :description,
                                         :recommendation, 'open', NOW(), :metadata)
                                    ON CONFLICT (org_id, finding_id) DO UPDATE SET
                                        severity = EXCLUDED.severity,
                                        title = EXCLUDED.title,
                                        description = EXCLUDED.description,
                                        recommendation = EXCLUDED.recommendation,
                                        metadata = EXCLUDED.metadata,
                                        detected_at = NOW()
                                """).bindparams(bindparam('metadata', type_=JSONB)),
                                {
                                    "org_id": org_id,
                                    "conn_id": connection_id,
                                    "finding_id": finding_id[:255],
                                    "severity": finding.get("severity", "medium"),
                                    "category": finding.get("category") or finding.get("finding_type", "security"),
                                    "resource_type": finding.get("resource_type"),
                                    "resource_id": finding.get("resource_id"),
                                    "resource_path": finding.get("resource_path"),
                                    "title": finding.get("title"),
                                    "description": finding.get("description"),
                                    "recommendation": finding.get("remediation") or finding.get("recommendation"),
                                    "metadata": finding.get("metadata", {}),
                                }
                            )
                        
                        await db.execute(
                            text("UPDATE databricks_connections SET last_scan_at = NOW() WHERE id = :id"),
                            {"id": connection_id}
                        )
                        await db.commit()
                        
                        logger.info(f"databricks_auto_scan: completed scan for connection {connection_id}, "
                                    f"resources={len(scan_result.get('resources', []))}, "
                                    f"findings={len(scan_result.get('findings', []))}")
                        
                    except Exception as conn_exc:
                        logger.error(f"databricks_auto_scan: error scanning connection {conn.get('id')}: {conn_exc}")
                        try:
                            await db.rollback()
                        except Exception:
                            pass
                        
        except Exception as exc:
            logger.error(f"databricks_auto_scan: error: {exc}")
        
        # Wait before next scan cycle
        await asyncio.sleep(DATABRICKS_SCAN_INTERVAL_SECONDS)


def start_databricks_background_worker():
    """Start the Databricks background scanning worker."""
    import asyncio
    asyncio.create_task(_run_databricks_auto_scan())
    logger.info("Databricks background scanner started")


async def _seed_databricks_test_data_background(org_id: str, workspace_url: str, token: str):
    """Background task to seed test data and trigger scan."""
    from backend.services.databricks_security_service import DatabricksSecurityService
    
    try:
        service = DatabricksSecurityService(
            workspace_url=workspace_url,
            access_token=token,
        )
        
        # Seed test resources
        result = await service.seed_test_resources()
        logger.info(f"databricks_seed: created {len(result.get('created', []))} test resources for org {org_id}")
        
        # Trigger immediate scan
        scan_result = await service.scan_all()
        logger.info(f"databricks_seed: scan found {scan_result.get('stats', {}).get('total_findings', 0)} findings")
        
    except Exception as e:
        logger.error(f"databricks_seed: error for org {org_id}: {e}")


@router.post("/seed-test-data")
async def seed_test_data(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create test resources in the connected Databricks workspace for demo/testing.
    Creates notebooks with embedded secrets, misconfigured clusters, etc.
    Runs in background to avoid timeout - check scanner logs for results.
    """
    await ensure_databricks_tables(db)
    org_id = str(current_user.org_id)
    
    # Get the first active connection for this org
    result = await db.execute(
        text("""
            SELECT id, workspace_url, access_token_enc
            FROM databricks_connections
            WHERE org_id = :org_id AND status = 'active'
            LIMIT 1
        """),
        {"org_id": org_id}
    )
    conn = result.mappings().first()
    
    if not conn:
        raise HTTPException(status_code=404, detail="No active Databricks connection found. Connect a workspace first.")
    
    # Decrypt token
    token = _decrypt(conn["access_token_enc"])
    
    # Run seeding in background to avoid timeout
    import asyncio
    asyncio.create_task(_seed_databricks_test_data_background(
        org_id, conn["workspace_url"], token
    ))
    
    return {
        "status": "started",
        "message": "Test data seeding started in background. Check the Databricks scanner logs for results. The scanner will pick up new resources within 10 minutes.",
        "workspace_url": conn["workspace_url"],
    }
