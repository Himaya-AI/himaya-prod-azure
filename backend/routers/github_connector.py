"""
Himaya GitHub Connector Router.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user
from backend.services.cspm import ScanContext, ensure_cspm_tables, run_scan, write_findings
from backend.services.cspm.collectors.github import (
    GitHubCollectorConfig,
    make_github_collector,
)
from backend.services.cspm.plugins.github import GITHUB_PLUGINS
from backend.services.cspm.sink import mark_resolved, write_scan_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/github", tags=["github"])


# ── Models ───────────────────────────────────────────────────────────────────

class GitHubConnectRequest(BaseModel):
    name: str = Field(default="GitHub Org")
    token: str = Field(..., min_length=20, description="Fine-grained PAT or classic PAT with admin:org, repo, read:org scopes.")
    org: str = Field(..., min_length=1)
    max_repos: int = Field(default=200, ge=1, le=2000)


# ── Tables ───────────────────────────────────────────────────────────────────

async def ensure_github_tables(db: AsyncSession):
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS github_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            token_enc TEXT NOT NULL,
            gh_org VARCHAR(255) NOT NULL,
            max_repos INTEGER DEFAULT 200,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            UNIQUE (org_id, gh_org)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_github_connections_org ON github_connections(org_id)"
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
async def connect_github(
    request: GitHubConnectRequest,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_github_tables(db)
    org_id = str(current_user.org_id)

    # Test token + org access
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://api.github.com/orgs/{request.org}",
                headers={
                    "Authorization": f"Bearer {request.token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            if r.status_code == 404:
                raise HTTPException(status_code=400, detail=f"GitHub org '{request.org}' not found or token has no access.")
            if r.status_code == 401:
                raise HTTPException(status_code=400, detail="GitHub token is invalid.")
            if r.status_code >= 400:
                raise HTTPException(status_code=400, detail=f"GitHub API error: HTTP {r.status_code}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"GitHub connection test failed: {exc}")

    existing = await db.execute(text(
        "SELECT id FROM github_connections WHERE org_id = CAST(:org AS UUID) AND gh_org = :gho"
    ), {"org": org_id, "gho": request.org})
    if existing.scalar():
        raise HTTPException(status_code=409, detail="This GitHub org is already connected.")

    cid = str(uuid.uuid4())
    await db.execute(text("""
        INSERT INTO github_connections (id, org_id, name, token_enc, gh_org, max_repos, status)
        VALUES (CAST(:id AS UUID), CAST(:org AS UUID), :name, :tok, :gho, :mr, 'active')
    """), {
        "id": cid, "org": org_id, "name": request.name,
        "tok": _encrypt(request.token), "gho": request.org, "mr": request.max_repos,
    })
    await db.commit()

    background.add_task(_run_background_scan, org_id, cid)
    return {"success": True, "connection_id": cid, "message": "GitHub org connected. Initial scan started."}


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_github_tables(db)
    org_id = str(current_user.org_id)
    rows = await db.execute(text("""
        SELECT id, name, gh_org, max_repos, status, created_at, last_scan_at
        FROM github_connections WHERE org_id = CAST(:org AS UUID)
        ORDER BY created_at DESC
    """), {"org": org_id})
    return [
        {
            "id": str(r[0]), "name": r[1], "org": r[2], "max_repos": r[3],
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
        "DELETE FROM github_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
        "SELECT id FROM github_connections WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
    await ensure_github_tables(db)
    org_id = str(current_user.org_id)
    sev = await db.execute(text("""
        SELECT severity, COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'github' AND resolved_at IS NULL
        GROUP BY severity
    """), {"org": org_id})
    sc = {s: int(n) for s, n in sev.fetchall()}
    total = await db.execute(text("""
        SELECT COUNT(*) FROM cspm_findings
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'github' AND resolved_at IS NULL
    """), {"org": org_id})
    last = await db.execute(text("""
        SELECT MAX(finished_at) FROM cspm_scans
        WHERE org_id = CAST(:org AS UUID) AND cloud = 'github'
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
    await ensure_github_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)", "cloud = 'github'"]
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
                SELECT token_enc, gh_org, max_repos
                FROM github_connections
                WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
            """), {"cid": connection_id, "org": org_id})
            data = row.first()
            if not data:
                return
            token_enc, gh_org, max_repos = data
            token = _decrypt(token_enc)
            cfg = GitHubCollectorConfig(token=token, org=gh_org, max_repos=max_repos)

            ctx = ScanContext(
                org_id=org_id, connection_id=connection_id, cloud="github",
                settings={"org": gh_org},
            )
            report = await run_scan(
                cloud="github",
                collector=make_github_collector(cfg),
                plugins=GITHUB_PLUGINS,
                ctx=ctx,
            )
            await write_findings(db, org_id, connection_id, report.findings)
            seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
            await mark_resolved(db, org_id, "github", seen)
            await write_scan_report(db, report)
            await db.execute(text(
                "UPDATE github_connections SET last_scan_at = NOW() WHERE id = CAST(:cid AS UUID)"
            ), {"cid": connection_id})
            await db.commit()
            logger.info(
                f"GitHub scan complete: org={org_id} conn={connection_id} "
                f"findings={len(report.findings)} sev={report.severity_counts}"
            )
    except Exception as exc:
        logger.exception(f"GitHub background scan failed: {exc}")
