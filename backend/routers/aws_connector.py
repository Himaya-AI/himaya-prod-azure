"""
Helios AWS Connector Router — manages AWS integrations and security scanning.
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
router = APIRouter(prefix="/api/aws", tags=["aws"])


# Tag keys we recognise as an owner signal, in priority order. Customer tag
# hygiene varies wildly so we accept multiple common conventions.
_OWNER_TAG_KEYS = (
    "Owner", "owner", "OWNER",
    "OwnerEmail", "owner_email", "ownerEmail",
    "Email", "email",
    "Contact", "contact",
    "Maintainer", "maintainer",
    "CreatedBy", "created_by", "createdBy",
    "User", "user",
    "Team", "team",
)


def _enrich_resource_metadata(resource: dict) -> dict:
    """Derive owner from tags and copy useful AWS metadata so the DSPM Data
    Inventory has data to show even when CloudTrail lookups are skipped.

    Returns a metadata dict ready to be json.dumps'd into aws_resources.metadata.
    Idempotent and tolerant to missing keys.
    """
    meta = dict(resource.get("metadata") or {})
    tags = resource.get("tags") or {}

    # Owner: prefer existing scanner-provided owner/created_by, else tag scan.
    if not meta.get("owner") and not meta.get("created_by") and not meta.get("launched_by"):
        for key in _OWNER_TAG_KEYS:
            if isinstance(tags, dict) and tags.get(key):
                meta["owner"] = str(tags[key])[:200]
                meta["owner_source"] = f"tag:{key}"
                break

    # Surface a few stable fields for the DSPM analyst view.
    if resource.get("resource_type") and "resource_type" not in meta:
        meta["resource_type"] = resource["resource_type"]
    if resource.get("region") and "region" not in meta:
        meta["region"] = resource["region"]
    if resource.get("encryption_type") and "encryption_type" not in meta:
        meta["encryption_type"] = resource["encryption_type"]
    if resource.get("public_access") and "public_access_flag" not in meta:
        # Distinct key so we don't collide with the boolean column.
        meta["public_access_flag"] = True

    # Tag environment / classification hints (common in customer setups).
    if isinstance(tags, dict):
        for src, dst in (
            ("Environment", "environment"),
            ("environment", "environment"),
            ("Env", "environment"),
            ("DataClassification", "data_classification"),
            ("Classification", "data_classification"),
            ("Confidentiality", "data_classification"),
            ("CostCenter", "cost_center"),
            ("cost_center", "cost_center"),
            ("Project", "project"),
            ("project", "project"),
            ("Application", "application"),
            ("app", "application"),
        ):
            if tags.get(src) and dst not in meta:
                meta[dst] = str(tags[src])[:120]

    return meta


# ── Request/Response Models ───────────────────────────────────────────────────

class AWSConnectRequest(BaseModel):
    access_key_id: str = Field(..., min_length=16, max_length=128)
    secret_access_key: str = Field(..., min_length=20)
    default_region: str = Field(default="us-east-1")
    name: str = Field(default="AWS Account")
    scan_regions: list[str] = Field(default_factory=lambda: ["us-east-1", "us-west-2", "eu-west-1"])


class AWSConnectionResponse(BaseModel):
    id: str
    name: str
    account_id: Optional[str]
    arn: Optional[str]
    status: str
    default_region: str
    scan_regions: list[str]
    created_at: str
    last_scan_at: Optional[str]


class AWSScanStats(BaseModel):
    total_resources: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    by_resource_type: dict
    by_finding_category: dict


# ── Table Creation ────────────────────────────────────────────────────────────

async def ensure_aws_tables(db: AsyncSession):
    """Create AWS connector tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS aws_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            access_key_id_enc VARCHAR(500),
            secret_access_key_enc VARCHAR(500),
            account_id VARCHAR(50),
            arn VARCHAR(500),
            default_region VARCHAR(50),
            scan_regions TEXT[],
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, access_key_id_enc)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS aws_resources (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES aws_connections(id) ON DELETE CASCADE,
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_arn VARCHAR(500),
            name VARCHAR(255),
            region VARCHAR(50),
            size_bytes BIGINT,
            created_at TIMESTAMPTZ,
            last_modified TIMESTAMPTZ,
            encryption_enabled BOOLEAN DEFAULT FALSE,
            encryption_type VARCHAR(50),
            public_access BOOLEAN DEFAULT FALSE,
            tags JSONB,
            metadata JSONB,
            scanned_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, resource_arn)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS aws_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES aws_connections(id) ON DELETE CASCADE,
            finding_id VARCHAR(255),
            severity VARCHAR(20),
            category VARCHAR(50),
            resource_type VARCHAR(50),
            resource_id VARCHAR(255),
            resource_arn VARCHAR(500),
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
        CREATE INDEX IF NOT EXISTS ix_aws_resources_org_id ON aws_resources(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_aws_findings_org_id ON aws_findings(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_aws_findings_severity ON aws_findings(severity)
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
async def connect_aws(
    request: AWSConnectRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect an AWS account using access key credentials.
    Tests the connection and stores encrypted credentials.
    """
    from backend.services.aws_security_service import AWSSecurityService
    
    await ensure_aws_tables(db)
    org_id = str(current_user.org_id)

    # Test the connection first
    service = AWSSecurityService(
        access_key_id=request.access_key_id,
        secret_access_key=request.secret_access_key,
        region=request.default_region,
    )
    
    test_result = await service.test_connection()
    if not test_result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to AWS: {test_result.get('error', 'Unknown error')}"
        )

    # Encrypt credentials
    enc_access_key = _encrypt(request.access_key_id)
    enc_secret_key = _encrypt(request.secret_access_key)

    # Check if connection already exists
    existing = await db.execute(
        text("SELECT id FROM aws_connections WHERE org_id = :org_id AND access_key_id_enc = :key_enc"),
        {"org_id": org_id, "key_enc": enc_access_key}
    )
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This AWS account is already connected.")

    # Insert new connection
    connection_id = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO aws_connections
                (id, org_id, name, access_key_id_enc, secret_access_key_enc,
                 account_id, arn, default_region, scan_regions, status)
            VALUES
                (:id, :org_id, :name, :access_key_enc, :secret_key_enc,
                 :account_id, :arn, :default_region, :scan_regions, 'active')
        """),
        {
            "id": connection_id,
            "org_id": org_id,
            "name": request.name,
            "access_key_enc": enc_access_key,
            "secret_key_enc": enc_secret_key,
            "account_id": test_result.get("account_id"),
            "arn": test_result.get("arn"),
            "default_region": request.default_region,
            "scan_regions": request.scan_regions,
        }
    )
    await db.commit()

    return {
        "success": True,
        "connection_id": connection_id,
        "account_id": test_result.get("account_id"),
        "arn": test_result.get("arn"),
        "message": "AWS account connected successfully. Starting initial scan...",
    }


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all AWS connections for the organization."""
    await ensure_aws_tables(db)
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, name, account_id, arn, default_region, scan_regions,
                   status, created_at, last_scan_at
            FROM aws_connections
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
            "account_id": row["account_id"],
            "arn": row["arn"],
            "default_region": row["default_region"],
            "scan_regions": row["scan_regions"] or [],
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
    """Delete an AWS connection and all associated data."""
    org_id = str(current_user.org_id)

    # Verify ownership
    result = await db.execute(
        text("SELECT id FROM aws_connections WHERE id = :id AND org_id = :org_id"),
        {"id": connection_id, "org_id": org_id}
    )
    if not result.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")

    # Delete associated data
    await db.execute(
        text("DELETE FROM aws_findings WHERE connection_id = :id"),
        {"id": connection_id}
    )
    await db.execute(
        text("DELETE FROM aws_resources WHERE connection_id = :id"),
        {"id": connection_id}
    )
    await db.execute(
        text("DELETE FROM aws_connections WHERE id = :id"),
        {"id": connection_id}
    )
    await db.commit()

    return {"success": True, "message": "AWS connection deleted"}


@router.post("/scan/{connection_id}")
async def trigger_scan(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an AWS security scan for a connection (runs in background)."""
    import asyncio
    from backend.services.aws_security_service import AWSSecurityService
    from backend.core.database import AsyncSessionLocal
    
    org_id = str(current_user.org_id)

    # Get connection details
    result = await db.execute(
        text("""
            SELECT id, access_key_id_enc, secret_access_key_enc, default_region, scan_regions
            FROM aws_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Decrypt credentials
    access_key = _decrypt(row["access_key_id_enc"])
    secret_key = _decrypt(row["secret_access_key_enc"])
    regions = row["scan_regions"] or [row["default_region"]]
    default_region = row["default_region"]

    # Launch background scan
    async def run_scan_background():
        try:
            logger.info(f"AWS background scan starting for connection {connection_id}, regions={regions}")
            service = AWSSecurityService(
                access_key_id=access_key,
                secret_access_key=secret_key,
                region=default_region,
            )
            scan_result = await service.scan_all(regions=regions)
            logger.info(f"AWS scan_all returned: {len(scan_result.get('resources', []))} resources, {len(scan_result.get('findings', []))} findings")
            
            # Save results
            async with AsyncSessionLocal() as db_bg:
                for resource in scan_result.get("resources", []):
                    await db_bg.execute(
                        text("""
                            INSERT INTO aws_resources
                                (org_id, connection_id, resource_type, resource_id, resource_arn,
                                 name, region, size_bytes, created_at, last_modified,
                                 encryption_enabled, encryption_type, public_access, tags, metadata, scanned_at)
                            VALUES
                                (:org_id, :conn_id, :resource_type, :resource_id, :resource_arn,
                                 :name, :region, :size_bytes, :created_at, :last_modified,
                                 :encryption_enabled, :encryption_type, :public_access,
                                 :tags, :metadata, NOW())
                            ON CONFLICT (org_id, resource_arn) DO UPDATE SET
                                name = EXCLUDED.name,
                                scanned_at = NOW()
                        """),
                        {
                            "org_id": org_id,
                            "conn_id": connection_id,
                            "resource_type": resource["resource_type"],
                            "resource_id": resource["resource_id"],
                            "resource_arn": resource["resource_arn"],
                            "name": resource["name"],
                            "region": resource["region"],
                            "size_bytes": resource.get("size_bytes"),
                            "created_at": resource.get("created_at"),
                            "last_modified": resource.get("last_modified"),
                            "encryption_enabled": resource.get("encryption_enabled", False),
                            "encryption_type": resource.get("encryption_type"),
                            "public_access": resource.get("public_access", False),
                            "tags": json.dumps(resource.get("tags", {})),
                            "metadata": json.dumps(_enrich_resource_metadata(resource)),
                        }
                    )
                
                for finding in scan_result.get("findings", []):
                    await db_bg.execute(
                        text("""
                            INSERT INTO aws_findings
                                (org_id, connection_id, resource_arn, finding_type, severity,
                                 title, description, recommendation, category, region, detected_at)
                            VALUES
                                (:org_id, :conn_id, :resource_arn, :finding_type, :severity,
                                 :title, :description, :recommendation, :category, :region, NOW())
                            ON CONFLICT (org_id, resource_arn, finding_type) DO UPDATE SET
                                severity = EXCLUDED.severity,
                                title = EXCLUDED.title,
                                detected_at = NOW()
                        """),
                        {
                            "org_id": org_id,
                            "conn_id": connection_id,
                            "resource_arn": finding["resource_arn"],
                            "finding_type": finding["finding_type"],
                            "severity": finding["severity"],
                            "title": finding["title"],
                            "description": finding["description"],
                            "recommendation": finding["recommendation"],
                            "category": finding["category"],
                            "region": finding.get("region"),
                        }
                    )
                
                # Update last_scan_at
                await db_bg.execute(
                    text("UPDATE aws_connections SET last_scan_at = NOW() WHERE id = :id"),
                    {"id": connection_id}
                )
                await db_bg.commit()

            logger.info(
                f"AWS legacy scan completed: "
                f"{len(scan_result.get('resources', []))} resources, "
                f"{len(scan_result.get('findings', []))} findings"
            )

            # ── Phase 2: also run the new CSPM engine ──────────────────────────────────
            # Same credentials, same regions, but writes to cspm_findings
            # so AWS findings show up in the unified cross-cloud Overview
            # alongside Azure / GCP / Oracle / GitHub.
            try:
                from backend.services.cspm import ScanContext, run_scan
                from backend.services.cspm.collectors.aws import (
                    AwsCollectorConfig, make_aws_collector,
                )
                from backend.services.cspm.plugins.aws import AWS_PLUGINS
                from backend.services.cspm.sink import (
                    mark_resolved, write_findings, write_scan_report,
                )
                cspm_cfg = AwsCollectorConfig(
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    default_region=default_region,
                    scan_regions=regions,
                )
                ctx = ScanContext(
                    org_id=org_id, connection_id=connection_id,
                    cloud="aws", regions=regions,
                )
                report = await run_scan(
                    cloud="aws",
                    collector=make_aws_collector(cspm_cfg),
                    plugins=AWS_PLUGINS,
                    ctx=ctx,
                )
                async with AsyncSessionLocal() as cspm_db:
                    await write_findings(cspm_db, org_id, connection_id, report.findings)
                    seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
                    await mark_resolved(cspm_db, org_id, "aws", seen)
                    await write_scan_report(cspm_db, report)
                logger.info(
                    f"AWS CSPM scan completed: {len(report.findings)} findings, "
                    f"sev={report.severity_counts}"
                )
            except Exception as cspm_err:
                logger.warning(
                    f"AWS CSPM scan failed (non-fatal — legacy scan still succeeded): {cspm_err}"
                )
        except Exception as e:
            import traceback
            logger.error(f"AWS background scan failed: {e}\n{traceback.format_exc()}")

    # Start background task
    asyncio.create_task(run_scan_background())
    
    return {"status": "started", "message": "AWS scan started in background", "connection_id": connection_id}


# Keep old synchronous logic for auto-scan (called internally)
async def _run_scan_sync(connection_id: str, org_id: str, db: AsyncSession):
    """Internal synchronous scan used by auto-scan."""
    from backend.services.aws_security_service import AWSSecurityService
    
    result = await db.execute(
        text("""
            SELECT id, access_key_id_enc, secret_access_key_enc, default_region, scan_regions
            FROM aws_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id}
    )
    row = result.mappings().first()
    if not row:
        return

    access_key = _decrypt(row["access_key_id_enc"])
    secret_key = _decrypt(row["secret_access_key_enc"])
    regions = row["scan_regions"] or [row["default_region"]]

    service = AWSSecurityService(
        access_key_id=access_key,
        secret_access_key=secret_key,
        region=row["default_region"],
    )
    
    scan_result = await service.scan_all(regions=regions)

    for resource in scan_result.get("resources", []):
        await db.execute(
            text("""
                INSERT INTO aws_resources
                    (org_id, connection_id, resource_type, resource_id, resource_arn,
                     name, region, size_bytes, created_at, last_modified,
                     encryption_enabled, encryption_type, public_access, tags, metadata, scanned_at)
                VALUES
                    (:org_id, :conn_id, :resource_type, :resource_id, :resource_arn,
                     :name, :region, :size_bytes, :created_at, :last_modified,
                     :encryption_enabled, :encryption_type, :public_access,
                     :tags, :metadata, NOW())
                ON CONFLICT (org_id, resource_arn) DO UPDATE SET
                    name = EXCLUDED.name,
                    size_bytes = EXCLUDED.size_bytes,
                    last_modified = EXCLUDED.last_modified,
                    encryption_enabled = EXCLUDED.encryption_enabled,
                    encryption_type = EXCLUDED.encryption_type,
                    public_access = EXCLUDED.public_access,
                    tags = EXCLUDED.tags,
                    -- Preserve DLP/AI classification keys that the DLP
                    -- worker writes between CSPM cycles. Without this the
                    -- next CSPM scan would wipe dlp_categories, etc., and
                    -- the Categories column in Data Inventory would flash
                    -- empty until the classifier caught back up.
                    metadata = EXCLUDED.metadata || COALESCE(
                        (SELECT jsonb_object_agg(key, value)
                         FROM jsonb_each(aws_resources.metadata)
                         WHERE key IN ('dlp_classified','dlp_categories',
                                       'dlp_risk_level','dlp_schema_version',
                                       'ai_categories')),
                        '{}'::jsonb
                    ),
                    scanned_at = NOW()
            """),
            {
                "org_id": org_id,
                "conn_id": connection_id,
                "resource_type": resource["resource_type"],
                "resource_id": resource["resource_id"],
                "resource_arn": resource["resource_arn"],
                "name": resource["name"],
                "region": resource["region"],
                "size_bytes": resource.get("size_bytes"),
                "created_at": resource.get("created_at"),
                "last_modified": resource.get("last_modified"),
                "encryption_enabled": resource.get("encryption_enabled", False),
                "encryption_type": resource.get("encryption_type"),
                "public_access": resource.get("public_access", False),
                "tags": json.dumps(resource.get("tags", {})),
                "metadata": json.dumps(_enrich_resource_metadata(resource)),
            }
        )

    # Store findings
    for finding in scan_result.get("findings", []):
        await db.execute(
            text("""
                INSERT INTO aws_findings
                    (org_id, connection_id, finding_id, severity, category,
                     resource_type, resource_id, resource_arn,
                     title, description, recommendation, detected_at, metadata)
                VALUES
                    (:org_id, :conn_id, :finding_id, :severity, :category,
                     :resource_type, :resource_id, :resource_arn,
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
                "resource_arn": finding["resource_arn"],
                "title": finding["title"],
                "description": finding["description"],
                "recommendation": finding["recommendation"],
                "detected_at": finding.get("detected_at"),
                "metadata": json.dumps(finding.get("metadata", {})),
            }
        )

    # Update last scan time
    await db.execute(
        text("UPDATE aws_connections SET last_scan_at = NOW() WHERE id = :id"),
        {"id": connection_id}
    )
    await db.commit()

    return {
        "success": True,
        "stats": scan_result.get("stats"),
        "scanned_at": scan_result.get("scanned_at"),
    }


@router.get("/resources")
async def list_resources(
    resource_type: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    encryption: Optional[bool] = Query(None),
    public: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List AWS resources in the data inventory."""
    await ensure_aws_tables(db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size

    where_clauses = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}

    if resource_type:
        where_clauses.append("resource_type = :resource_type")
        params["resource_type"] = resource_type
    if region:
        where_clauses.append("region = :region")
        params["region"] = region
    if encryption is not None:
        where_clauses.append("encryption_enabled = :encryption")
        params["encryption"] = encryption
    if public is not None:
        where_clauses.append("public_access = :public")
        params["public"] = public

    where_sql = " AND ".join(where_clauses)

    # Get total count
    total_result = await db.execute(
        text(f"SELECT COUNT(*) FROM aws_resources WHERE {where_sql}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")}
    )
    total = total_result.scalar() or 0

    # Get resources
    result = await db.execute(
        text(f"""
            SELECT id, resource_type, resource_id, resource_arn, name, region,
                   size_bytes, created_at, last_modified, encryption_enabled,
                   encryption_type, public_access, tags, metadata, scanned_at
            FROM aws_resources
            WHERE {where_sql}
            ORDER BY scanned_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params
    )

    resources = []
    for row in result.mappings():
        resources.append({
            "id": str(row["id"]),
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "resource_arn": row["resource_arn"],
            "name": row["name"],
            "region": row["region"],
            "size_bytes": row["size_bytes"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "last_modified": row["last_modified"].isoformat() if row["last_modified"] else None,
            "encryption_enabled": row["encryption_enabled"],
            "encryption_type": row["encryption_type"],
            "public_access": row["public_access"],
            "tags": row["tags"] or {},
            "metadata": row["metadata"] or {},
            "scanned_at": row["scanned_at"].isoformat() if row["scanned_at"] else None,
        })

    return {"resources": resources, "total": total, "page": page, "page_size": page_size}


@router.get("/findings")
async def list_findings(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List AWS security findings."""
    await ensure_aws_tables(db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size

    where_clauses = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}

    if severity:
        where_clauses.append("severity = :severity")
        params["severity"] = severity
    if category:
        where_clauses.append("category = :category")
        params["category"] = category
    if status:
        where_clauses.append("status = :status")
        params["status"] = status

    where_sql = " AND ".join(where_clauses)

    # Get total count
    total_result = await db.execute(
        text(f"SELECT COUNT(*) FROM aws_findings WHERE {where_sql}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")}
    )
    total = total_result.scalar() or 0

    # Get findings
    result = await db.execute(
        text(f"""
            SELECT id, finding_id, severity, category, resource_type, resource_id,
                   resource_arn, title, description, recommendation, status,
                   detected_at, resolved_at, metadata
            FROM aws_findings
            WHERE {where_sql}
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    ELSE 5 
                END,
                detected_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params
    )

    findings = []
    for row in result.mappings():
        findings.append({
            "id": str(row["id"]),
            "finding_id": row["finding_id"],
            "severity": row["severity"],
            "category": row["category"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "resource_arn": row["resource_arn"],
            "title": row["title"],
            "description": row["description"],
            "recommendation": row["recommendation"],
            "status": row["status"],
            "detected_at": row["detected_at"].isoformat() if row["detected_at"] else None,
            "resolved_at": row["resolved_at"].isoformat() if row["resolved_at"] else None,
            "metadata": row["metadata"] or {},
        })

    return {"findings": findings, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def get_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated AWS security stats."""
    await ensure_aws_tables(db)
    org_id = str(current_user.org_id)

    # Resource stats
    resource_result = await db.execute(
        text("""
            SELECT 
                COUNT(*) as total_resources,
                COUNT(*) FILTER (WHERE encryption_enabled = TRUE) as encrypted_resources,
                COUNT(*) FILTER (WHERE public_access = TRUE) as public_resources,
                COUNT(DISTINCT resource_type) as resource_types
            FROM aws_resources
            WHERE org_id = :org_id
        """),
        {"org_id": org_id}
    )
    resource_stats = resource_result.mappings().first()

    # Finding stats
    finding_result = await db.execute(
        text("""
            SELECT 
                COUNT(*) as total_findings,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                COUNT(*) FILTER (WHERE status = 'open') as open_findings
            FROM aws_findings
            WHERE org_id = :org_id
        """),
        {"org_id": org_id}
    )
    finding_stats = finding_result.mappings().first()

    # By resource type
    type_result = await db.execute(
        text("""
            SELECT resource_type, COUNT(*) as count
            FROM aws_resources
            WHERE org_id = :org_id
            GROUP BY resource_type
        """),
        {"org_id": org_id}
    )
    by_type = {row["resource_type"]: row["count"] for row in type_result.mappings()}

    # By category
    category_result = await db.execute(
        text("""
            SELECT category, COUNT(*) as count
            FROM aws_findings
            WHERE org_id = :org_id AND status = 'open'
            GROUP BY category
        """),
        {"org_id": org_id}
    )
    by_category = {row["category"]: row["count"] for row in category_result.mappings()}

    return {
        "resources": {
            "total": resource_stats["total_resources"] or 0,
            "encrypted": resource_stats["encrypted_resources"] or 0,
            "public": resource_stats["public_resources"] or 0,
            "resource_types": resource_stats["resource_types"] or 0,
            "by_type": by_type,
        },
        "findings": {
            "total": finding_stats["total_findings"] or 0,
            "critical": finding_stats["critical"] or 0,
            "high": finding_stats["high"] or 0,
            "medium": finding_stats["medium"] or 0,
            "low": finding_stats["low"] or 0,
            "open": finding_stats["open_findings"] or 0,
            "by_category": by_category,
        },
    }


@router.patch("/findings/{finding_id}/resolve")
async def resolve_finding(
    finding_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a finding as resolved."""
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            UPDATE aws_findings
            SET status = 'resolved', resolved_at = NOW()
            WHERE id = :id AND org_id = :org_id
            RETURNING id
        """),
        {"id": finding_id, "org_id": org_id}
    )
    
    if not result.scalar():
        raise HTTPException(status_code=404, detail="Finding not found")

    await db.commit()
    return {"success": True, "message": "Finding marked as resolved"}


# ── CSPM-engine bridge (Phase 1 retrofit) ────────────────────────────────────
# In addition to the existing AWSSecurityService scan (which populates the
# aws_resources / aws_findings tables), we expose a parallel CSPM scan that
# runs through the unified cspm engine and writes into cspm_findings. This
# lets AWS findings show up in the cross-cloud Overview / CSPM endpoints.

@router.post("/cspm-scan/{connection_id}")
async def cspm_scan(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run the unified CSPM engine against this AWS connection."""
    from backend.database import AsyncSessionLocal as _ASL
    from backend.services.cspm import ScanContext, run_scan, write_findings
    from backend.services.cspm.collectors.aws import (
        AwsCollectorConfig, make_aws_collector,
    )
    from backend.services.cspm.plugins.aws import AWS_PLUGINS
    from backend.services.cspm.sink import mark_resolved, write_scan_report

    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, access_key_id_enc, secret_access_key_enc, default_region, scan_regions
            FROM aws_connections
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": connection_id, "org_id": org_id}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")

    access_key = _decrypt(row["access_key_id_enc"])
    secret_key = _decrypt(row["secret_access_key_enc"])
    regions = row["scan_regions"] or [row["default_region"]]

    async def _run():
        try:
            cfg = AwsCollectorConfig(
                access_key_id=access_key,
                secret_access_key=secret_key,
                default_region=row["default_region"],
                scan_regions=regions,
            )
            ctx = ScanContext(
                org_id=org_id, connection_id=str(row["id"]),
                cloud="aws", regions=regions,
            )
            report = await run_scan(
                cloud="aws",
                collector=make_aws_collector(cfg),
                plugins=AWS_PLUGINS,
                ctx=ctx,
            )
            async with _ASL() as db_bg:
                await write_findings(db_bg, org_id, str(row["id"]), report.findings)
                seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
                await mark_resolved(db_bg, org_id, "aws", seen)
                await write_scan_report(db_bg, report)
            logger.info(
                f"AWS CSPM scan complete: org={org_id} findings={len(report.findings)} "
                f"sev={report.severity_counts}"
            )
        except Exception as exc:
            logger.exception(f"AWS CSPM scan failed: {exc}")

    import asyncio as _asyncio
    _asyncio.create_task(_run())
    return {"success": True, "message": "AWS CSPM scan started"}
