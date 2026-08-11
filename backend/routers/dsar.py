"""
Data Subject Access Request (DSAR) + column-classification browse — enterprise tier.

Built on the column-level classified inventory (`column_classifications`) produced
by the PII discovery scanners. Delivers three capabilities the sovereignty story
was missing versus BigID:

  1. **Classification browse with evidence/lineage** — every classified column with
     its detector, confidence, redacted sample evidence, and source→schema→table
     →column lineage for auditor defensibility.
  2. **DSAR workflow** — create an access/erasure/rectification/portability request
     for a data subject, auto-build a cross-system *data map* of where that subject's
     PII categories live, and track the request lifecycle. For erasure we generate
     suggested per-system remediation SQL (never auto-executed).
  3. **Scan triggers** — kick off per-column classification for Snowflake / SAP.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user
from backend.routers.data_sovereignty import _require_enterprise
from backend.services.pii_discovery_scan import ensure_classification_tables

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dsar", tags=["dsar"])


# ── Table setup ──────────────────────────────────────────────────────────────

async def ensure_dsar_tables(db: AsyncSession) -> None:
    await ensure_classification_tables(db)
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dsar_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            subject_name VARCHAR(255),
            subject_email VARCHAR(255),
            subject_identifiers JSONB DEFAULT '{}'::jsonb,   -- {email, phone, national_id, ...}
            request_type VARCHAR(32) NOT NULL DEFAULT 'access', -- access/erasure/rectification/portability
            status VARCHAR(32) NOT NULL DEFAULT 'open',       -- open/searching/data_mapped/completed/rejected
            legal_basis VARCHAR(128),
            due_at TIMESTAMPTZ,
            summary JSONB DEFAULT '{}'::jsonb,
            created_by VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_dsar_requests_org ON dsar_requests(org_id, created_at DESC)"
    ))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dsar_matches (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id UUID NOT NULL REFERENCES dsar_requests(id) ON DELETE CASCADE,
            org_id UUID NOT NULL,
            source VARCHAR(32),
            database_name VARCHAR(255),
            schema_name VARCHAR(255),
            table_name VARCHAR(255),
            column_name VARCHAR(255),
            data_class VARCHAR(32),
            category VARCHAR(64),
            region VARCHAR(64),
            country VARCHAR(8),
            confidence REAL,
            match_reason TEXT,
            remediation_sql TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_dsar_matches_req ON dsar_matches(request_id)"
    ))
    await db.commit()


# ── Models ────────────────────────────────────────────────────────────────────

class DSARCreate(BaseModel):
    subject_name: Optional[str] = None
    subject_email: Optional[str] = None
    subject_identifiers: dict = {}
    request_type: str = "access"
    legal_basis: Optional[str] = None


# Which PII categories are implied by each identifier the requester supplies.
_IDENTIFIER_CATEGORIES = {
    "email": ["pii_email"],
    "phone": ["pii_phone"],
    "national_id": ["pii_national_id"],
    "passport": ["pii_passport"],
    "name": ["pii_name"],
    "dob": ["pii_dob"],
}

_VALID_REQUEST_TYPES = ("access", "erasure", "rectification", "portability")


# ── Classification browse ──────────────────────────────────────────────────────

@router.get("/classifications")
async def list_classifications(
    source: Optional[str] = None,
    data_class: Optional[str] = None,
    min_confidence: float = 0.0,
    limit: int = 500,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Browse the column-level classified inventory with evidence + lineage."""
    await _require_enterprise(current_user, db)
    await ensure_dsar_tables(db)
    where = ["org_id = CAST(:oid AS UUID)", "confidence >= :minc"]
    params: dict = {"oid": str(current_user.org_id), "minc": min_confidence, "lim": min(limit, 2000)}
    if source:
        where.append("source = :src")
        params["src"] = source
    if data_class:
        where.append("data_class = :dc")
        params["dc"] = data_class
    rows = (await db.execute(text(f"""
        SELECT source, connection_id, database_name, schema_name, table_name,
               column_name, data_class, category, detector, confidence, evidence,
               region, country, last_seen_at
        FROM column_classifications
        WHERE {' AND '.join(where)}
        ORDER BY confidence DESC, last_seen_at DESC
        LIMIT :lim
    """), params)).mappings().all()
    out = []
    for r in rows:
        ev = r["evidence"] if isinstance(r["evidence"], dict) else json.loads(r["evidence"] or "{}")
        out.append({
            "source": r["source"],
            "lineage": {
                "database": r["database_name"], "schema": r["schema_name"],
                "table": r["table_name"], "column": r["column_name"],
                "path": f"{r['source']}:{r['database_name']}.{r['schema_name']}.{r['table_name']}.{r['column_name']}",
            },
            "data_class": r["data_class"], "category": r["category"],
            "detector": r["detector"], "confidence": r["confidence"],
            "evidence": ev, "region": r["region"], "country": r["country"],
            "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
        })
    return {"classifications": out, "total": len(out)}


@router.get("/classifications/summary")
async def classifications_summary(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate coverage: columns per source and per data_class."""
    await _require_enterprise(current_user, db)
    await ensure_dsar_tables(db)
    oid = str(current_user.org_id)
    by_source = (await db.execute(text("""
        SELECT source, COUNT(*) AS n, ROUND(AVG(confidence)::numeric, 3) AS avg_conf
        FROM column_classifications WHERE org_id = CAST(:oid AS UUID)
        GROUP BY source ORDER BY n DESC
    """), {"oid": oid})).mappings().all()
    by_class = (await db.execute(text("""
        SELECT data_class, COUNT(*) AS n FROM column_classifications
        WHERE org_id = CAST(:oid AS UUID) GROUP BY data_class ORDER BY n DESC
    """), {"oid": oid})).mappings().all()
    return {
        "by_source": [{"source": r["source"], "columns": int(r["n"]), "avg_confidence": float(r["avg_conf"] or 0)} for r in by_source],
        "by_data_class": [{"data_class": r["data_class"], "columns": int(r["n"])} for r in by_class],
        "total_columns": sum(int(r["n"]) for r in by_source),
    }


# ── Scan triggers ──────────────────────────────────────────────────────────────

@router.post("/scan/snowflake/{connection_id}")
async def scan_snowflake(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a real per-column PII scan for a Snowflake connection (background)."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    async def _run():
        from backend.services.pii_discovery_scan import scan_snowflake_columns
        try:
            async with AsyncSessionLocal() as bg:
                res = await scan_snowflake_columns(bg, org_id, connection_id)
            logger.info(f"dsar: snowflake column scan done org={org_id}: {res}")
        except Exception as exc:
            logger.exception(f"dsar: snowflake column scan failed: {exc}")

    import asyncio
    asyncio.create_task(_run())
    return {"ok": True, "message": "Snowflake per-column classification started."}


@router.post("/scan/sap/{connection_id}")
async def scan_sap(
    connection_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Classify the documented SAP data-dictionary PII/finance columns."""
    await _require_enterprise(current_user, db)
    from backend.services.pii_discovery_scan import classify_sap_catalog
    res = await classify_sap_catalog(db, str(current_user.org_id), connection_id)
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("error", "scan failed"))
    return res


# ── DSAR workflow ──────────────────────────────────────────────────────────────

def _erasure_sql(source: str, db_name: str, schema: str, table: str, column: str,
                 identifiers: dict) -> Optional[str]:
    """Best-effort suggested remediation SQL for erasure. Never auto-executed."""
    key_col = None
    key_val = None
    if identifiers.get("email"):
        key_col, key_val = "EMAIL", identifiers["email"]
    elif identifiers.get("national_id"):
        key_col, key_val = "NATIONAL_ID", identifiers["national_id"]
    elif identifiers.get("phone"):
        key_col, key_val = "PHONE", identifiers["phone"]
    where = f"{key_col} = '{key_val}'" if key_col else "<subject key column> = '<value>'"
    fq = f'"{db_name}"."{schema}"."{table}"' if source == "snowflake" else f"{schema}.{table}"
    return f"UPDATE {fq} SET \"{column}\" = NULL WHERE {where};  -- review before running"


async def _build_data_map(db: AsyncSession, org_id: str, request_id: str,
                          request_type: str, identifiers: dict) -> list[dict]:
    """Locate where the subject's PII categories live across all classified sources.

    We match on PII *categories* implied by the identifiers the requester supplied
    (e.g. an email → all pii_email columns), plus every pii_name column. This is a
    privacy-preserving data map: we point to columns/tables/systems, we do not read
    or store the subject's raw values.
    """
    wanted: set[str] = set()
    for key, val in (identifiers or {}).items():
        if val:
            wanted.update(_IDENTIFIER_CATEGORIES.get(key, []))
    # Always include name/contact categories as they anchor a person.
    wanted.update(["pii_name", "pii_email", "pii_phone", "pii_national_id"])

    rows = (await db.execute(text("""
        SELECT source, database_name, schema_name, table_name, column_name,
               data_class, category, region, country, confidence
        FROM column_classifications
        WHERE org_id = CAST(:oid AS UUID) AND category = ANY(:cats)
        ORDER BY source, table_name
    """), {"oid": org_id, "cats": list(wanted)})).mappings().all()

    matches = []
    for r in rows:
        remediation = None
        if request_type == "erasure":
            remediation = _erasure_sql(r["source"], r["database_name"], r["schema_name"],
                                       r["table_name"], r["column_name"], identifiers)
        reason = f"{r['category']} column likely holds this subject's data"
        await db.execute(text("""
            INSERT INTO dsar_matches
                (request_id, org_id, source, database_name, schema_name, table_name,
                 column_name, data_class, category, region, country, confidence,
                 match_reason, remediation_sql)
            VALUES
                (CAST(:rid AS UUID), CAST(:oid AS UUID), :src, :db, :sc, :tbl,
                 :col, :dc, :cat, :region, :country, :conf, :reason, :rem)
        """), {
            "rid": request_id, "oid": org_id, "src": r["source"],
            "db": r["database_name"], "sc": r["schema_name"], "tbl": r["table_name"],
            "col": r["column_name"], "dc": r["data_class"], "cat": r["category"],
            "region": r["region"], "country": r["country"], "conf": r["confidence"],
            "reason": reason, "rem": remediation,
        })
        matches.append({
            "source": r["source"],
            "path": f"{r['source']}:{r['database_name']}.{r['schema_name']}.{r['table_name']}.{r['column_name']}",
            "data_class": r["data_class"], "category": r["category"],
            "region": r["region"], "country": r["country"],
            "confidence": r["confidence"], "remediation_sql": remediation,
        })
    return matches


@router.post("/requests")
async def create_dsar(
    body: DSARCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a DSAR and auto-build the cross-system data map."""
    await _require_enterprise(current_user, db)
    await ensure_dsar_tables(db)
    if body.request_type not in _VALID_REQUEST_TYPES:
        raise HTTPException(status_code=400, detail=f"request_type must be one of {_VALID_REQUEST_TYPES}")
    org_id = str(current_user.org_id)
    rid = str(uuid.uuid4())

    identifiers = dict(body.subject_identifiers or {})
    if body.subject_email and "email" not in identifiers:
        identifiers["email"] = body.subject_email

    # GDPR/PDPL response clock: 30 days.
    from datetime import timedelta
    due = datetime.now(timezone.utc) + timedelta(days=30)

    await db.execute(text("""
        INSERT INTO dsar_requests
            (id, org_id, subject_name, subject_email, subject_identifiers,
             request_type, status, legal_basis, due_at, created_by, created_at)
        VALUES
            (CAST(:id AS UUID), CAST(:oid AS UUID), :name, :email, CAST(:ids AS JSONB),
             :rtype, 'searching', :legal, :due, :actor, NOW())
    """), {
        "id": rid, "oid": org_id, "name": body.subject_name, "email": body.subject_email,
        "ids": json.dumps(identifiers), "rtype": body.request_type,
        "legal": body.legal_basis, "due": due,
        "actor": getattr(current_user, "email", None),
    })

    matches = await _build_data_map(db, org_id, rid, body.request_type, identifiers)

    # Summarize the data map.
    by_source: dict[str, int] = {}
    by_country: dict[str, int] = {}
    for m in matches:
        by_source[m["source"]] = by_source.get(m["source"], 0) + 1
        c = m["country"] or "unknown"
        by_country[c] = by_country.get(c, 0) + 1
    summary = {
        "total_matches": len(matches),
        "systems": sorted(by_source.keys()),
        "by_source": by_source,
        "by_country": by_country,
    }
    await db.execute(text("""
        UPDATE dsar_requests SET summary = CAST(:s AS JSONB), status = 'data_mapped'
        WHERE id = CAST(:id AS UUID)
    """), {"s": json.dumps(summary), "id": rid})
    await db.commit()

    return {
        "ok": True, "request_id": rid, "status": "data_mapped",
        "due_at": due.isoformat(), "summary": summary, "matches": matches,
    }


@router.get("/requests")
async def list_dsar(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    await ensure_dsar_tables(db)
    rows = (await db.execute(text("""
        SELECT id, subject_name, subject_email, request_type, status, legal_basis,
               due_at, summary, created_by, created_at, completed_at
        FROM dsar_requests WHERE org_id = CAST(:oid AS UUID)
        ORDER BY created_at DESC LIMIT 200
    """), {"oid": str(current_user.org_id)})).mappings().all()
    out = []
    for r in rows:
        summ = r["summary"] if isinstance(r["summary"], dict) else json.loads(r["summary"] or "{}")
        out.append({
            "id": str(r["id"]), "subject_name": r["subject_name"],
            "subject_email": r["subject_email"], "request_type": r["request_type"],
            "status": r["status"], "legal_basis": r["legal_basis"],
            "due_at": r["due_at"].isoformat() if r["due_at"] else None,
            "summary": summ, "created_by": r["created_by"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
        })
    return {"requests": out, "total": len(out)}


@router.get("/requests/{request_id}")
async def get_dsar(
    request_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    await ensure_dsar_tables(db)
    oid = str(current_user.org_id)
    req = (await db.execute(text("""
        SELECT id, subject_name, subject_email, subject_identifiers, request_type,
               status, legal_basis, due_at, summary, created_by, created_at, completed_at
        FROM dsar_requests WHERE id = CAST(:id AS UUID) AND org_id = CAST(:oid AS UUID)
    """), {"id": request_id, "oid": oid})).mappings().first()
    if not req:
        raise HTTPException(status_code=404, detail="DSAR not found")
    matches = (await db.execute(text("""
        SELECT source, database_name, schema_name, table_name, column_name,
               data_class, category, region, country, confidence, match_reason, remediation_sql
        FROM dsar_matches WHERE request_id = CAST(:id AS UUID)
        ORDER BY source, table_name
    """), {"id": request_id})).mappings().all()
    summ = req["summary"] if isinstance(req["summary"], dict) else json.loads(req["summary"] or "{}")
    ids = req["subject_identifiers"] if isinstance(req["subject_identifiers"], dict) else json.loads(req["subject_identifiers"] or "{}")
    return {
        "id": str(req["id"]), "subject_name": req["subject_name"],
        "subject_email": req["subject_email"], "subject_identifiers": ids,
        "request_type": req["request_type"], "status": req["status"],
        "legal_basis": req["legal_basis"],
        "due_at": req["due_at"].isoformat() if req["due_at"] else None,
        "summary": summ, "created_at": req["created_at"].isoformat() if req["created_at"] else None,
        "completed_at": req["completed_at"].isoformat() if req["completed_at"] else None,
        "matches": [{
            "source": m["source"],
            "path": f"{m['source']}:{m['database_name']}.{m['schema_name']}.{m['table_name']}.{m['column_name']}",
            "data_class": m["data_class"], "category": m["category"],
            "region": m["region"], "country": m["country"], "confidence": m["confidence"],
            "match_reason": m["match_reason"], "remediation_sql": m["remediation_sql"],
        } for m in matches],
    }


@router.post("/requests/{request_id}/complete")
async def complete_dsar(
    request_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a DSAR complete (e.g. after fulfilling access/erasure)."""
    await _require_enterprise(current_user, db)
    res = await db.execute(text("""
        UPDATE dsar_requests SET status = 'completed', completed_at = NOW()
        WHERE id = CAST(:id AS UUID) AND org_id = CAST(:oid AS UUID)
    """), {"id": request_id, "oid": str(current_user.org_id)})
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="DSAR not found")
    await db.commit()
    return {"ok": True, "status": "completed"}
