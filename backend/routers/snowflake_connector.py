"""
Himaya Snowflake Connector Router — manages Snowflake account integrations and
SSPM scanning against the CIS Snowflake Foundations Benchmark v1.0.0.

Auth options:
  - Password (account + user + password [+ role])
  - Key pair (account + user + private_key_pem [+ passphrase] [+ role])
"""
from __future__ import annotations

import asyncio
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

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/snowflake", tags=["snowflake"])


# ── Models ───────────────────────────────────────────────────────────────────

class SnowflakeConnectRequest(BaseModel):
    name: str = Field(default="Snowflake Account")
    account: str = Field(..., min_length=3, description="Snowflake account identifier, e.g. xy12345.us-east-1")
    user: str = Field(..., min_length=1)
    role: str = Field(default="ACCOUNTADMIN")
    warehouse: Optional[str] = Field(default=None)
    # Exactly one of these two must be supplied
    password: Optional[str] = Field(default=None, min_length=1)
    private_key_pem: Optional[str] = Field(default=None, min_length=20)
    private_key_passphrase: Optional[str] = Field(default=None)


class SnowflakeConnectionResponse(BaseModel):
    id: str
    name: str
    account: str
    user: str
    role: str
    auth_method: str
    status: str
    created_at: Optional[str]
    last_scan_at: Optional[str]


# ── Table setup ───────────────────────────────────────────────────────────────

async def ensure_snowflake_tables(db: AsyncSession):
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS snowflake_connections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255),
            account VARCHAR(255) NOT NULL,
            sf_user VARCHAR(255) NOT NULL,
            sf_role VARCHAR(255) NOT NULL DEFAULT 'ACCOUNTADMIN',
            warehouse VARCHAR(255),
            auth_method VARCHAR(20) NOT NULL,  -- 'password' or 'keypair'
            password_enc TEXT,
            private_key_enc TEXT,
            private_key_passphrase_enc TEXT,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_scan_at TIMESTAMPTZ,
            last_score NUMERIC(5,2),
            last_grade VARCHAR(2),
            UNIQUE (org_id, account, sf_user)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_snowflake_connections_org "
        "ON snowflake_connections(org_id)"
    ))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS snowflake_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID NOT NULL REFERENCES snowflake_connections(id) ON DELETE CASCADE,
            rule_id VARCHAR(64) NOT NULL,
            title VARCHAR(500),
            status VARCHAR(20),       -- PASS / FAIL / WARN / SKIP / ERROR
            severity VARCHAR(20),     -- CRITICAL / HIGH / MEDIUM / LOW / INFO
            category VARCHAR(64),     -- IAM / MON / NET / DP
            cis_ref VARCHAR(32),
            profile_level INT,
            description TEXT,
            remediation TEXT,
            evidence TEXT,
            compliance JSONB,
            first_seen_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            UNIQUE (org_id, connection_id, rule_id)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_snowflake_findings_org "
        "ON snowflake_findings(org_id)"
    ))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS snowflake_scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID NOT NULL REFERENCES snowflake_connections(id) ON DELETE CASCADE,
            started_at TIMESTAMPTZ DEFAULT NOW(),
            finished_at TIMESTAMPTZ,
            status VARCHAR(20) DEFAULT 'running',
            score NUMERIC(5,2),
            grade VARCHAR(2),
            findings_total INT DEFAULT 0,
            findings_pass INT DEFAULT 0,
            findings_fail INT DEFAULT 0,
            findings_warn INT DEFAULT 0,
            error TEXT
        )
    """))
    await db.commit()


# ── Encryption helpers (reuse Fernet from onboarding) ────────────────────────

def _encrypt(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().encrypt(value.encode()).decode()
    except Exception:
        return value


def _decrypt(enc: Optional[str]) -> Optional[str]:
    if enc is None:
        return None
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return enc


# ── Credential verification ──────────────────────────────────────────────────

def _verify_creds_sync(req: SnowflakeConnectRequest) -> tuple[bool, Optional[str]]:
    """
    Try to open a Snowflake connection and run a trivial query.
    Runs in a thread because snowflake-connector-python is sync.
    """
    try:
        from backend.services.snowflake_scanner import SnowflakeClient
    except ImportError:
        return False, "snowflake-connector-python is not installed on the server."

    try:
        client = SnowflakeClient(
            account=req.account,
            user=req.user,
            password=req.password,
            role=req.role,
            warehouse=req.warehouse,
            private_key_pem=req.private_key_pem,
            private_key_passphrase=req.private_key_passphrase,
        )
        client.connect()
        client.query_scalar("SELECT CURRENT_ACCOUNT()")
        client.close()
        return True, None
    except Exception as exc:
        return False, str(exc)[:400]


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/connect")
async def connect_snowflake(
    request: SnowflakeConnectRequest,
    background: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify Snowflake credentials, store the connection, kick off initial scan."""
    await ensure_snowflake_tables(db)
    org_id = str(current_user.org_id)

    if not request.password and not request.private_key_pem:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'password' or 'private_key_pem' to authenticate.",
        )
    auth_method = "keypair" if request.private_key_pem else "password"

    # Verify creds (snowflake-connector-python is sync, run in thread)
    ok, err = await asyncio.to_thread(_verify_creds_sync, request)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail=(
                "Could not authenticate to Snowflake. "
                "Check the account identifier (e.g. xy12345.us-east-1), user, "
                f"role, and credentials. Snowflake error: {err}"
            ),
        )

    # Dedup
    existing = await db.execute(
        text(
            "SELECT id FROM snowflake_connections "
            "WHERE org_id = CAST(:org AS UUID) "
            "AND account = :acct AND sf_user = :usr"
        ),
        {"org": org_id, "acct": request.account, "usr": request.user},
    )
    if existing.scalar():
        raise HTTPException(
            status_code=409,
            detail="A Snowflake connection for this account + user already exists.",
        )

    cid = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO snowflake_connections
                (id, org_id, name, account, sf_user, sf_role, warehouse,
                 auth_method, password_enc, private_key_enc,
                 private_key_passphrase_enc, status)
            VALUES
                (CAST(:id AS UUID), CAST(:org AS UUID), :name, :acct, :usr,
                 :role, :wh, :auth, :pwd, :pk, :pkp, 'active')
        """),
        {
            "id": cid, "org": org_id, "name": request.name,
            "acct": request.account, "usr": request.user,
            "role": request.role, "wh": request.warehouse,
            "auth": auth_method,
            "pwd": _encrypt(request.password),
            "pk": _encrypt(request.private_key_pem),
            "pkp": _encrypt(request.private_key_passphrase),
        },
    )
    await db.commit()

    background.add_task(_run_background_scan, org_id, cid)

    return {
        "success": True,
        "connection_id": cid,
        "account": request.account,
        "user": request.user,
        "auth_method": auth_method,
        "message": "Snowflake account connected. Initial scan started.",
    }


@router.get("/connections")
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_snowflake_tables(db)
    org_id = str(current_user.org_id)
    rows = await db.execute(text("""
        SELECT id, name, account, sf_user, sf_role, auth_method, status,
               created_at, last_scan_at, last_score, last_grade
        FROM snowflake_connections
        WHERE org_id = CAST(:org AS UUID)
        ORDER BY created_at DESC
    """), {"org": org_id})
    out = []
    for r in rows.fetchall():
        out.append({
            "id": str(r[0]),
            "name": r[1] or "Snowflake Account",
            "account": r[2],
            "user": r[3],
            "role": r[4],
            "auth_method": r[5],
            "status": r[6],
            "created_at": r[7].isoformat() if r[7] else None,
            "last_scan_at": r[8].isoformat() if r[8] else None,
            "last_score": float(r[9]) if r[9] is not None else None,
            "last_grade": r[10],
        })
    # Frontend likes a {connections: [...]} envelope for some panels and the raw
    # list for others. Return both to keep both call sites happy.
    return {"connections": out}


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = str(current_user.org_id)
    await db.execute(text(
        "DELETE FROM snowflake_connections "
        "WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
        "SELECT id FROM snowflake_connections "
        "WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)"
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
    """Return SSPM stats for the org's Snowflake findings."""
    await ensure_snowflake_tables(db)
    org_id = str(current_user.org_id)

    sev_row = await db.execute(text("""
        SELECT severity, COUNT(*) FROM snowflake_findings
        WHERE org_id = CAST(:org AS UUID)
        AND status IN ('FAIL', 'WARN')
        AND resolved_at IS NULL
        GROUP BY severity
    """), {"org": org_id})
    sev_counts = {sev: int(cnt) for sev, cnt in sev_row.fetchall()}

    cat_row = await db.execute(text("""
        SELECT category, COUNT(*) FROM snowflake_findings
        WHERE org_id = CAST(:org AS UUID)
        AND status IN ('FAIL', 'WARN')
        AND resolved_at IS NULL
        GROUP BY category
    """), {"org": org_id})
    by_category = {c: int(n) for c, n in cat_row.fetchall()}

    total_row = await db.execute(text("""
        SELECT COUNT(*) FROM snowflake_findings
        WHERE org_id = CAST(:org AS UUID)
        AND status IN ('FAIL', 'WARN')
        AND resolved_at IS NULL
    """), {"org": org_id})
    total = int(total_row.scalar() or 0)

    avg_row = await db.execute(text("""
        SELECT AVG(last_score), COUNT(*)
        FROM snowflake_connections
        WHERE org_id = CAST(:org AS UUID) AND last_score IS NOT NULL
    """), {"org": org_id})
    avg_score, _ = avg_row.fetchone() or (None, 0)

    last_scan_row = await db.execute(text("""
        SELECT MAX(finished_at) FROM snowflake_scans
        WHERE org_id = CAST(:org AS UUID)
    """), {"org": org_id})
    last_scan = last_scan_row.scalar()

    return {
        "total_findings": total,
        "critical_findings": sev_counts.get("CRITICAL", 0),
        "high_findings": sev_counts.get("HIGH", 0),
        "medium_findings": sev_counts.get("MEDIUM", 0),
        "low_findings": sev_counts.get("LOW", 0),
        "by_category": by_category,
        "average_score": float(avg_score) if avg_score is not None else None,
        "last_scan_at": last_scan.isoformat() if last_scan else None,
    }


@router.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await ensure_snowflake_tables(db)
    org_id = str(current_user.org_id)
    where = ["org_id = CAST(:org AS UUID)"]
    params: dict = {"org": org_id, "lim": min(limit, 500)}
    if severity:
        where.append("severity = :sev")
        params["sev"] = severity.upper()
    if status == "open":
        where.append("resolved_at IS NULL")
        where.append("status IN ('FAIL', 'WARN')")
    elif status == "resolved":
        where.append("resolved_at IS NOT NULL")
    sql = f"""
        SELECT id, rule_id, title, status, severity, category, cis_ref,
               profile_level, description, remediation, evidence, compliance,
               first_seen_at, last_seen_at, resolved_at
        FROM snowflake_findings
        WHERE {' AND '.join(where)}
        ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
            last_seen_at DESC
        LIMIT :lim
    """
    rows = await db.execute(text(sql), params)
    return [
        {
            "id": str(r[0]),
            "rule_id": r[1],
            "title": r[2],
            "status": r[3],
            "severity": r[4],
            "category": r[5],
            "cis_ref": r[6],
            "profile_level": r[7],
            "description": r[8],
            "remediation": r[9],
            "evidence": r[10],
            "compliance": r[11] if isinstance(r[11], dict) else (
                json.loads(r[11]) if r[11] else {}
            ),
            "first_seen_at": r[12].isoformat() if r[12] else None,
            "last_seen_at": r[13].isoformat() if r[13] else None,
            "resolved_at": r[14].isoformat() if r[14] else None,
        }
        for r in rows.fetchall()
    ]


# ── Background scan helper ────────────────────────────────────────────────────

def _category_from_rule_id(rule_id: str) -> str:
    # SF-IAM-001 -> IAM, SF-MON-002 -> MON, etc.
    parts = (rule_id or "").split("-")
    return parts[1] if len(parts) >= 2 else "OTHER"


def _scan_sync(
    account: str, user: str, role: str, warehouse: Optional[str],
    auth_method: str, password: Optional[str],
    private_key_pem: Optional[str], private_key_passphrase: Optional[str],
) -> dict:
    """Run the vendored scanner. Sync — call from a worker thread."""
    from backend.services.snowflake_scanner import (
        SnowflakeClient, SnowflakeScanner, compute_score,
    )
    client = SnowflakeClient(
        account=account, user=user, password=password, role=role,
        warehouse=warehouse,
        private_key_pem=private_key_pem,
        private_key_passphrase=private_key_passphrase,
    )
    client.connect()
    try:
        scanner = SnowflakeScanner(client, verbose=False)
        scanner.run_all()
        findings = [f.to_dict() for f in scanner.findings]
        score = compute_score(scanner.findings)
        return {"findings": findings, "score": score}
    finally:
        client.close()


async def _run_background_scan(org_id: str, connection_id: str) -> None:
    """Run a full Snowflake SSPM scan for one connection."""
    scan_id = str(uuid.uuid4())
    try:
        async with AsyncSessionLocal() as db:
            row = await db.execute(text("""
                SELECT account, sf_user, sf_role, warehouse, auth_method,
                       password_enc, private_key_enc, private_key_passphrase_enc
                FROM snowflake_connections
                WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
            """), {"cid": connection_id, "org": org_id})
            data = row.first()
            if not data:
                logger.warning(f"Snowflake scan: connection {connection_id} not found")
                return
            (acct, usr, role, wh, auth_method, pwd_enc, pk_enc, pkp_enc) = data

            await db.execute(text("""
                INSERT INTO snowflake_scans (id, org_id, connection_id, status)
                VALUES (CAST(:id AS UUID), CAST(:org AS UUID),
                        CAST(:cid AS UUID), 'running')
            """), {"id": scan_id, "org": org_id, "cid": connection_id})
            await db.commit()

        # Run the scanner off the event loop
        result = await asyncio.to_thread(
            _scan_sync,
            acct, usr, role, wh, auth_method,
            _decrypt(pwd_enc), _decrypt(pk_enc), _decrypt(pkp_enc),
        )
        findings = result["findings"]
        score_data = result["score"]
        score = score_data.get("score")
        grade = score_data.get("grade")

        # Persist findings (upsert) + close stale ones
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            seen_rule_ids: list[str] = []
            counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0, "ERROR": 0}
            for f in findings:
                rule_id = f.get("rule_id")
                if not rule_id:
                    continue
                seen_rule_ids.append(rule_id)
                status_v = (f.get("status") or "").upper()
                counts[status_v] = counts.get(status_v, 0) + 1
                category = _category_from_rule_id(rule_id)
                compliance = f.get("compliance") or {}
                # Resolved logic: PASS counts as resolved; FAIL/WARN/ERROR are open
                resolved_at = now if status_v == "PASS" else None
                await db.execute(text("""
                    INSERT INTO snowflake_findings
                        (org_id, connection_id, rule_id, title, status, severity,
                         category, cis_ref, profile_level, description, remediation,
                         evidence, compliance, first_seen_at, last_seen_at, resolved_at)
                    VALUES
                        (CAST(:org AS UUID), CAST(:cid AS UUID), :rid, :title,
                         :status, :sev, :cat, :cis, :pl, :desc, :rem, :evi,
                         CAST(:comp AS JSONB), :now, :now, :resolved)
                    ON CONFLICT (org_id, connection_id, rule_id) DO UPDATE SET
                        title = EXCLUDED.title,
                        status = EXCLUDED.status,
                        severity = EXCLUDED.severity,
                        category = EXCLUDED.category,
                        cis_ref = EXCLUDED.cis_ref,
                        profile_level = EXCLUDED.profile_level,
                        description = EXCLUDED.description,
                        remediation = EXCLUDED.remediation,
                        evidence = EXCLUDED.evidence,
                        compliance = EXCLUDED.compliance,
                        last_seen_at = EXCLUDED.last_seen_at,
                        resolved_at = EXCLUDED.resolved_at
                """), {
                    "org": org_id, "cid": connection_id, "rid": rule_id,
                    "title": (f.get("title") or "")[:500],
                    "status": status_v, "sev": (f.get("severity") or "INFO").upper(),
                    "cat": category, "cis": f.get("cis_ref") or "",
                    "pl": int(f.get("profile_level") or 1),
                    "desc": f.get("description") or "",
                    "rem": f.get("remediation") or "",
                    "evi": f.get("evidence") or "",
                    "comp": json.dumps(compliance),
                    "now": now,
                    "resolved": resolved_at,
                })

            # Any rule that wasn't seen this scan but was previously open:
            # mark as resolved (config drift back to compliant, or rule retired).
            if seen_rule_ids:
                await db.execute(text("""
                    UPDATE snowflake_findings
                    SET resolved_at = :now
                    WHERE org_id = CAST(:org AS UUID)
                    AND connection_id = CAST(:cid AS UUID)
                    AND resolved_at IS NULL
                    AND rule_id != ALL(:rules)
                """), {
                    "org": org_id, "cid": connection_id,
                    "now": now, "rules": seen_rule_ids,
                })

            await db.execute(text("""
                UPDATE snowflake_scans
                SET finished_at = :now, status = 'completed',
                    score = :score, grade = :grade,
                    findings_total = :total, findings_pass = :p,
                    findings_fail = :f, findings_warn = :w
                WHERE id = CAST(:id AS UUID)
            """), {
                "id": scan_id, "now": now,
                "score": float(score) if score is not None else None,
                "grade": grade,
                "total": len(findings),
                "p": counts.get("PASS", 0),
                "f": counts.get("FAIL", 0),
                "w": counts.get("WARN", 0),
            })

            await db.execute(text("""
                UPDATE snowflake_connections
                SET last_scan_at = :now, last_score = :score, last_grade = :grade
                WHERE id = CAST(:cid AS UUID)
            """), {
                "cid": connection_id, "now": now,
                "score": float(score) if score is not None else None,
                "grade": grade,
            })
            await db.commit()

        logger.info(
            f"Snowflake scan complete: org={org_id} conn={connection_id} "
            f"findings={len(findings)} score={score} grade={grade}"
        )

    except Exception as exc:
        logger.exception(f"Snowflake background scan failed: {exc}")
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("""
                    UPDATE snowflake_scans
                    SET finished_at = NOW(), status = 'failed', error = :err
                    WHERE id = CAST(:id AS UUID)
                """), {"id": scan_id, "err": str(exc)[:500]})
                await db.commit()
        except Exception:
            pass
