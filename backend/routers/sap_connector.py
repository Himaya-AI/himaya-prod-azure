"""
Himaya SAP Connector Router — manages SAP S/4HANA integrations and security scanning.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sap", tags=["sap"])


# ── Request/Response Models ───────────────────────────────────────────────────

class SAPConnectRequest(BaseModel):
    host: str = Field(..., min_length=5)
    client: str = Field(default="100", max_length=3)
    system_id: str = Field(default="", max_length=3)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    name: str = Field(default="SAP S/4HANA")


class SAPConnectionResponse(BaseModel):
    id: str
    name: str
    system_id: Optional[str]
    status: str
    created_at: Optional[str]
    last_scan_at: Optional[str]


# ── Table Creation ────────────────────────────────────────────────────────────

async def ensure_sap_tables(db: AsyncSession):
    """Create SAP connector tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sap_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            host VARCHAR(255),
            client VARCHAR(3),
            system_id VARCHAR(3),
            username_enc TEXT,
            password_enc TEXT,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, host, client)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sap_users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES sap_connections(id) ON DELETE CASCADE,
            user_id VARCHAR(50),
            user_name VARCHAR(255),
            user_type VARCHAR(50),
            email VARCHAR(255),
            department VARCHAR(255),
            last_logon TIMESTAMPTZ,
            lock_status VARCHAR(50),
            roles TEXT[],
            profiles TEXT[],
            is_privileged BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ,
            metadata JSONB,
            scanned_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, connection_id, user_id)
        )
    """))
    
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sap_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES sap_connections(id) ON DELETE CASCADE,
            finding_id VARCHAR(255),
            severity VARCHAR(20),
            category VARCHAR(50),
            finding_type VARCHAR(50),
            user_id VARCHAR(50),
            transaction_code VARCHAR(50),
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
        CREATE INDEX IF NOT EXISTS ix_sap_users_org_id ON sap_users(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_sap_findings_org_id ON sap_findings(org_id)
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
async def connect_sap(
    request: SAPConnectRequest,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect an SAP S/4HANA system using RFC credentials.
    Tests the connection and stores encrypted credentials.
    """
    from backend.services.sap_security_service import SAPSecurityService
    
    await ensure_sap_tables(db)
    org_id = str(current_user.org_id)

    # Test the connection
    service = SAPSecurityService(
        host=request.host,
        client=request.client,
        username=request.username,
        password=request.password,
    )
    
    test_result = await service.test_connection()
    if not test_result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to SAP: {test_result.get('error', 'Unknown error')}"
        )

    # Encrypt credentials
    enc_username = _encrypt(request.username)
    enc_password = _encrypt(request.password)

    # Check if connection already exists
    existing = await db.execute(
        text("SELECT id FROM sap_connections WHERE org_id = :org_id AND host = :host AND client = :client"),
        {"org_id": org_id, "host": request.host, "client": request.client}
    )
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This SAP system is already connected.")

    # Insert new connection
    connection_id = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO sap_connections
                (id, org_id, name, host, client, system_id, username_enc, password_enc, status)
            VALUES
                (:id, :org_id, :name, :host, :client, :system_id, :username_enc, :password_enc, 'active')
        """),
        {
            "id": connection_id,
            "org_id": org_id,
            "name": request.name,
            "host": request.host,
            "client": request.client,
            "system_id": request.system_id or test_result.get("system_id"),
            "username_enc": enc_username,
            "password_enc": enc_password,
        }
    )
    await db.commit()

    # Kick off the initial scan in the background so the user gets findings
    # without having to wait for the whole RFC inventory pass.
    background.add_task(_run_background_scan, org_id, connection_id)

    return {
        "success": True,
        "connection_id": connection_id,
        "system_id": request.system_id or test_result.get("system_id"),
        "message": "SAP system connected. Initial scan started.",
    }


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all SAP connections for the organization."""
    await ensure_sap_tables(db)
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("""
            SELECT id, name, system_id, status, created_at, last_scan_at
            FROM sap_connections
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
            "system_id": row["system_id"],
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
    """Delete an SAP connection and all associated data."""
    org_id = str(current_user.org_id)

    result = await db.execute(
        text("SELECT id FROM sap_connections WHERE id = :id AND org_id = :org_id"),
        {"id": connection_id, "org_id": org_id}
    )
    if not result.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")

    await db.execute(text("DELETE FROM sap_findings WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM sap_users WHERE connection_id = :id"), {"id": connection_id})
    await db.execute(text("DELETE FROM sap_connections WHERE id = :id"), {"id": connection_id})
    await db.commit()

    return {"success": True, "message": "SAP connection deleted"}


@router.post("/scan/{connection_id}")
async def trigger_scan(
    connection_id: str,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an SAP security scan for a connection (runs in background)."""
    org_id = str(current_user.org_id)
    row = await db.execute(text(
        "SELECT id FROM sap_connections "
        "WHERE id = :id AND org_id = :org_id"
    ), {"id": connection_id, "org_id": org_id})
    if not row.scalar():
        raise HTTPException(status_code=404, detail="Connection not found")
    background.add_task(_run_background_scan, org_id, connection_id)
    return {"success": True, "message": "SAP scan started in background"}


async def _run_background_scan(org_id: str, connection_id: str) -> None:
    """Run a full SAP scan for one connection and persist users + findings.

    Used by both the connect endpoint (initial scan) and the periodic
    cspm_dspm_loop worker in main.py.
    """
    from backend.services.sap_security_service import SAPSecurityService
    try:
        async with AsyncSessionLocal() as db:
            row = await db.execute(
                text("""
                    SELECT host, client, username_enc, password_enc
                    FROM sap_connections
                    WHERE id = :id AND org_id = :org_id
                """),
                {"id": connection_id, "org_id": org_id},
            )
            data = row.mappings().first()
            if not data:
                logger.warning(f"SAP scan: connection {connection_id} not found")
                return
            username = _decrypt(data["username_enc"])
            password = _decrypt(data["password_enc"])
            service = SAPSecurityService(
                host=data["host"],
                client=data["client"],
                username=username,
                password=password,
            )

        scan_result = await service.scan_all()
        users = scan_result.get("users", []) or []
        findings = scan_result.get("findings", []) or []

        async with AsyncSessionLocal() as db:
            for user in users:
                await db.execute(
                    text("""
                        INSERT INTO sap_users
                            (org_id, connection_id, user_id, user_name, user_type,
                             email, department, last_logon, lock_status, roles, profiles,
                             is_privileged, created_at, metadata, scanned_at)
                        VALUES
                            (:org_id, :conn_id, :user_id, :user_name, :user_type,
                             :email, :department, :last_logon, :lock_status, :roles, :profiles,
                             :is_privileged, :created_at, :metadata, NOW())
                        ON CONFLICT (org_id, connection_id, user_id) DO UPDATE SET
                            user_name = EXCLUDED.user_name,
                            email = EXCLUDED.email,
                            department = EXCLUDED.department,
                            last_logon = EXCLUDED.last_logon,
                            lock_status = EXCLUDED.lock_status,
                            roles = EXCLUDED.roles,
                            profiles = EXCLUDED.profiles,
                            is_privileged = EXCLUDED.is_privileged,
                            metadata = EXCLUDED.metadata,
                            scanned_at = NOW()
                    """),
                    {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "user_id": user["user_id"],
                        "user_name": user.get("user_name"),
                        "user_type": user.get("user_type"),
                        "email": user.get("email"),
                        "department": user.get("department"),
                        "last_logon": user.get("last_logon"),
                        "lock_status": user.get("lock_status"),
                        "roles": user.get("roles", []),
                        "profiles": user.get("profiles", []),
                        "is_privileged": user.get("is_privileged", False),
                        "created_at": user.get("created_at"),
                        "metadata": json.dumps(user.get("metadata", {})),
                    },
                )

            for finding in findings:
                await db.execute(
                    text("""
                        INSERT INTO sap_findings
                            (org_id, connection_id, finding_id, severity, category,
                             finding_type, user_id, transaction_code,
                             title, description, recommendation, detected_at, metadata)
                        VALUES
                            (:org_id, :conn_id, :finding_id, :severity, :category,
                             :finding_type, :user_id, :transaction_code,
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
                        "finding_type": finding.get("finding_type"),
                        "user_id": finding.get("user_id"),
                        "transaction_code": finding.get("transaction_code"),
                        "title": finding["title"],
                        "description": finding["description"],
                        "recommendation": finding["recommendation"],
                        "detected_at": finding.get("detected_at"),
                        "metadata": json.dumps(finding.get("metadata", {})),
                    },
                )

            await db.execute(
                text("UPDATE sap_connections SET last_scan_at = NOW() WHERE id = :id"),
                {"id": connection_id},
            )
            await db.commit()

        logger.info(
            f"SAP scan complete: org={org_id} conn={connection_id} "
            f"users={len(users)} findings={len(findings)}"
        )
    except Exception as exc:
        logger.exception(f"SAP background scan failed: {exc}")


@router.get("/stats")
async def get_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get SAP user and finding statistics."""
    await ensure_sap_tables(db)
    org_id = str(current_user.org_id)

    users = await db.execute(
        text("""
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE is_privileged) as privileged
            FROM sap_users WHERE org_id = :org_id
        """),
        {"org_id": org_id}
    )
    u_row = users.mappings().first()

    # Count unique transaction codes from findings
    tcodes = await db.execute(
        text("SELECT COUNT(DISTINCT transaction_code) as count FROM sap_findings WHERE org_id = :org_id"),
        {"org_id": org_id}
    )
    t_row = tcodes.mappings().first()

    # Sensitive tables accessed (from findings metadata)
    sensitive = await db.execute(
        text("SELECT COUNT(*) as count FROM sap_findings WHERE org_id = :org_id AND category = 'sensitive_table_access'"),
        {"org_id": org_id}
    )
    s_row = sensitive.mappings().first()

    findings = await db.execute(
        text("SELECT COUNT(*) as total FROM sap_findings WHERE org_id = :org_id AND status = 'open'"),
        {"org_id": org_id}
    )
    f_row = findings.mappings().first()

    return {
        "users": u_row["total"] if u_row else 0,
        "transactions": t_row["count"] if t_row else 0,
        "sensitive_tables": s_row["count"] if s_row else 0,
        "findings": f_row["total"] if f_row else 0,
    }
