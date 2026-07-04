"""
Helios Salesforce Connector — SALSA-inspired SaaS Security Posture Management

Inspired by https://github.com/cosad3s/salsa (SALesforce Scanner for Aura).
SALSA is an offensive-security tool that probes Salesforce orgs for:

  - Unauthenticated guest-user data exposure (Aura endpoints
    accessible without auth that leak sObject records).
  - Custom object exposure via REST sObjects API and SOQL.
  - SOAP API exposure under `/services/Soap/c/`.
  - Bruteforce-able record identifiers (predictable IDs).
  - Field-level permission misconfigurations that leak fields to
    guest users.
  - Permissive Apex controllers (`@AuraEnabled` endpoints
    returning sensitive data without permission checks).

This connector implements the **defensive** half: it lets a Helios
customer point at one or more of their own Salesforce orgs and run
the SALSA-style probes in a safe, read-only mode against the SAME
endpoints so we surface findings BEFORE a real attacker does.

Authentication
--------------
Two modes:
  1. Unauthenticated probe (community sites & public pages):
     - just the instance URL
     - probes Aura / sObjects / SOAP for guest-accessible records.
  2. Authenticated probe (session id / aura token / OAuth):
     - session_id or aura_token cookie
     - lets us run authenticated checks (read-only) against
       custom objects, list views, etc.

We deliberately do NOT implement SALSA's "--update" or "--create"
flags. We never write to a customer's org.

Tables
------
  salesforce_connections   one row per connected org
  salesforce_findings      open posture findings from the SSPM scan
  salesforce_objects       discovered sObjects (standard + custom)
                           and whether they were guest-accessible.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/salesforce", tags=["salesforce"])


# ── Tables ────────────────────────────────────────────────────────────────

async def ensure_salesforce_tables(db: AsyncSession) -> None:
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS salesforce_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            instance_url TEXT NOT NULL,
            auth_method VARCHAR(50) DEFAULT 'unauthenticated',  -- 'unauthenticated' | 'session' | 'aura_token'
            session_id_enc TEXT,         -- encrypted at rest; nullable for unauth
            aura_token_enc TEXT,         -- encrypted at rest; nullable for unauth
            include_custom_only BOOLEAN DEFAULT FALSE,
            allow_bruteforce_probe BOOLEAN DEFAULT FALSE,
            status VARCHAR(50) DEFAULT 'active',
            last_scanned_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, instance_url)
        )
    """))
    # Older rows may pre-date the status column — add if missing.
    await db.execute(text(
        "ALTER TABLE salesforce_connections "
        "ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active'"
    ))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS salesforce_objects (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES salesforce_connections(id) ON DELETE CASCADE,
            sobject_name VARCHAR(255) NOT NULL,
            is_custom BOOLEAN DEFAULT FALSE,
            guest_accessible BOOLEAN DEFAULT FALSE,
            via_api VARCHAR(50),         -- 'aura' | 'rest' | 'soap'
            field_count INTEGER,
            sample_record_id VARCHAR(255),
            metadata JSONB,
            discovered_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, connection_id, sobject_name)
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS salesforce_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID REFERENCES salesforce_connections(id) ON DELETE CASCADE,
            finding_id VARCHAR(255),
            severity VARCHAR(20),
            category VARCHAR(50),
            sobject_name VARCHAR(255),
            title VARCHAR(500),
            description TEXT,
            recommendation TEXT,
            status VARCHAR(50) DEFAULT 'open',
            detected_at TIMESTAMPTZ DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            metadata JSONB,
            UNIQUE (org_id, finding_id)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_sf_findings_org_id ON salesforce_findings(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_sf_objects_org_id ON salesforce_objects(org_id)"
    ))
    await db.commit()


# ── Pydantic models ───────────────────────────────────────────────────────

class SalesforceConnectRequest(BaseModel):
    name: str = Field(default="Salesforce Org")
    instance_url: str = Field(..., min_length=8, description="e.g. https://acme.lightning.force.com")
    auth_method: str = Field(default="unauthenticated", pattern="^(unauthenticated|session|aura_token)$")
    session_id: Optional[str] = Field(default=None)
    aura_token: Optional[str] = Field(default=None)
    include_custom_only: bool = Field(default=False)
    allow_bruteforce_probe: bool = Field(default=False)


class SalesforceConnectionResponse(BaseModel):
    id: str
    name: str
    instance_url: str
    auth_method: str
    include_custom_only: bool
    allow_bruteforce_probe: bool
    last_scanned_at: Optional[datetime]
    created_at: datetime


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("/connections", response_model=list[SalesforceConnectionResponse])
async def list_connections(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await ensure_salesforce_tables(db)
    rows = (await db.execute(text("""
        SELECT id::text, name, instance_url, auth_method,
               include_custom_only, allow_bruteforce_probe,
               last_scanned_at, created_at
        FROM salesforce_connections
        WHERE org_id = CAST(:oid AS UUID)
        ORDER BY created_at DESC
    """), {"oid": str(user.org_id)})).mappings().all()
    return [SalesforceConnectionResponse(**r) for r in rows]


@router.post("/connect", response_model=SalesforceConnectionResponse)
async def connect(
    req: SalesforceConnectRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await ensure_salesforce_tables(db)
    instance_url = req.instance_url.rstrip("/")
    if not re.match(r"^https?://", instance_url):
        raise HTTPException(400, detail="instance_url must start with http(s)://")

    # Quick reachability probe so a broken URL is surfaced immediately.
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
            r = await c.get(instance_url)
            if r.status_code >= 500:
                raise HTTPException(400, detail=f"Instance URL returned HTTP {r.status_code}")
    except httpx.HTTPError as exc:
        raise HTTPException(400, detail=f"Instance URL unreachable: {exc}")

    conn_id = uuid.uuid4()
    await db.execute(text("""
        INSERT INTO salesforce_connections
            (id, org_id, name, instance_url, auth_method,
             session_id_enc, aura_token_enc,
             include_custom_only, allow_bruteforce_probe, created_at)
        VALUES
            (:id, CAST(:oid AS UUID), :name, :url, :auth,
             :sid, :tok, :custom, :bf, NOW())
        ON CONFLICT (org_id, instance_url) DO UPDATE
          SET name = EXCLUDED.name,
              auth_method = EXCLUDED.auth_method,
              session_id_enc = EXCLUDED.session_id_enc,
              aura_token_enc = EXCLUDED.aura_token_enc,
              include_custom_only = EXCLUDED.include_custom_only,
              allow_bruteforce_probe = EXCLUDED.allow_bruteforce_probe
    """), {
        "id": conn_id, "oid": str(user.org_id),
        "name": req.name, "url": instance_url,
        "auth": req.auth_method,
        # NOTE: secrets are stored as-is in this first cut. They are
        # short-lived session credentials that the customer themselves
        # provided. A future PR can wrap them in app-layer KMS.
        "sid": req.session_id,
        "tok": req.aura_token,
        "custom": req.include_custom_only,
        "bf": req.allow_bruteforce_probe,
    })
    await db.commit()

    # Kick the first background scan so the UI shows something quickly.
    background_tasks.add_task(_run_background_scan, str(conn_id))

    row = (await db.execute(text("""
        SELECT id::text, name, instance_url, auth_method,
               include_custom_only, allow_bruteforce_probe,
               last_scanned_at, created_at
        FROM salesforce_connections
        WHERE id = :id
    """), {"id": str(conn_id)})).mappings().first()
    return SalesforceConnectionResponse(**row)


@router.delete("/connections/{conn_id}")
async def delete_connection(
    conn_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await db.execute(text("""
        DELETE FROM salesforce_connections
        WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:oid AS UUID)
    """), {"cid": conn_id, "oid": str(user.org_id)})
    await db.commit()
    return {"ok": True}


@router.post("/scan/{conn_id}")
async def trigger_scan(
    conn_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    row = (await db.execute(text("""
        SELECT id FROM salesforce_connections
        WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:oid AS UUID)
    """), {"cid": conn_id, "oid": str(user.org_id)})).first()
    if not row:
        raise HTTPException(404, detail="connection not found")
    background_tasks.add_task(_run_background_scan, conn_id)
    return {"ok": True, "queued": True}


@router.get("/findings")
async def list_findings(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
    limit: int = 100,
    status: Optional[str] = None,
):
    await ensure_salesforce_tables(db)
    where = "WHERE org_id = CAST(:oid AS UUID)"
    params: dict = {"oid": str(user.org_id), "lim": limit}
    if status:
        where += " AND status = :st"
        params["st"] = status
    rows = (await db.execute(text(f"""
        SELECT id::text, finding_id, severity, category, sobject_name,
               title, description, recommendation, status,
               detected_at, metadata
        FROM salesforce_findings
        {where}
        ORDER BY detected_at DESC LIMIT :lim
    """), params)).mappings().all()
    return [dict(r) for r in rows]


@router.get("/objects")
async def list_objects(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
    limit: int = 500,
):
    await ensure_salesforce_tables(db)
    rows = (await db.execute(text("""
        SELECT id::text, sobject_name, is_custom, guest_accessible, via_api,
               field_count, sample_record_id, discovered_at
        FROM salesforce_objects
        WHERE org_id = CAST(:oid AS UUID)
        ORDER BY guest_accessible DESC, sobject_name ASC LIMIT :lim
    """), {"oid": str(user.org_id), "lim": limit})).mappings().all()
    return [dict(r) for r in rows]


# ── Background scan ───────────────────────────────────────────────────────

async def _run_background_scan(org_id: str | None = None, connection_id: str | None = None) -> None:
    """Run the SALSA-style probe against one connection.

    Signature mirrors the other CSPM connectors (org_id, connection_id) so the
    main.py `_connector_cspm` dispatcher can call it uniformly. The scanner
    itself only needs `connection_id` (org_id is read from the row) so we
    accept org_id as a positional arg and ignore it. Also supports the
    BackgroundTasks single-arg call from POST /connect.
    """
    # Backwards compat: when called from BackgroundTasks with a single
    # positional connection_id (str), main flow looks like
    # `background_tasks.add_task(_run_background_scan, str(conn_id))`.
    # In that case `org_id` is actually the connection_id.
    if connection_id is None and org_id is not None:
        connection_id = org_id
    if not connection_id:
        return
    try:
        from backend.services.salesforce_scanner import scan_salesforce_connection
        async with AsyncSessionLocal() as db:
            await ensure_salesforce_tables(db)
            await scan_salesforce_connection(connection_id, db)
    except Exception as exc:
        logger.warning(f"salesforce_connector: scan {connection_id} failed: {exc}", exc_info=True)
