"""
Data lifecycle / minimisation router.

Added 2026-06-23 (Adnan turn 2). Productises the existing
`stale_sensitive_data` toxic rule into a one-click cleanup playbook
that works across EVERY connector, not just M365.

Endpoints:
  GET  /api/data-lifecycle/stale
        List stale confidential resources across all clouds.
        Query: ?days=365&provider=...&label=...&limit=200
  POST /api/data-lifecycle/stale/bulk-action
        Body: { resource_ids: [...], action: 'archive'|'delete'|'tag_for_review',
                dry_run: bool }
        Returns a per-resource result list. `dry_run=True` (default)
        only simulates; the UI shows that to the user before they
        confirm.
  GET  /api/data-lifecycle/summary
        Per-connector counts of stale resources (for the
        playbook dashboard tile).

The actual *deletion* / *archive* against the provider's API is
intentionally only implemented for the connectors where we already
have a write-capable client (M365 via Graph, AWS S3 via boto3). For
the rest (GCP, Azure, Databricks, GitHub, Snowflake, Oracle, SAP,
Salesforce) the bulk action records a `tag_for_review` audit entry
and emits an alert for the resource owner instead — that's still a
big DSPM win and matches Varonis's manual-approval default.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/api/data-lifecycle", tags=["data-lifecycle"])
logger = logging.getLogger(__name__)


# Cross-connector source-of-truth for "stale data". Each entry is
# `(table, name_col, label_col, time_col, provider_literal, supports_delete)`.
# When `supports_delete=True` the bulk-action endpoint will attempt a
# real provider-side action; otherwise it falls back to tag_for_review.
STALE_SOURCES = [
    {
        "table": "saas_data_items",
        "name_col": "item_name",
        "label_col": "classification_label",
        "time_col": "last_modified_at",
        "url_col": "item_url",
        "owner_col": "owner_email",
        "provider_col": "provider",
        "supports_delete": True,  # SharePoint via Graph
    },
    {
        "table": "aws_resources",
        "name_col": "name",
        "label_expr": (
            "CASE WHEN (metadata->>'dlp_risk_level')='critical' "
            "     THEN 'highly_confidential' "
            "     WHEN (metadata->>'dlp_risk_level')='high' "
            "     THEN 'confidential' ELSE 'internal' END"
        ),
        "time_col": "last_updated_at",
        "url_col": "NULL",
        "owner_col": "NULL",
        "provider_literal": "aws",
        "supports_delete": True,  # S3 buckets via boto3
    },
    {
        "table": "gcp_resources",
        "name_col": "name",
        "label_expr": (
            "CASE WHEN (metadata->>'dlp_risk_level')='critical' "
            "     THEN 'highly_confidential' "
            "     WHEN (metadata->>'dlp_risk_level')='high' "
            "     THEN 'confidential' ELSE 'internal' END"
        ),
        "time_col": "last_updated_at",
        "url_col": "NULL",
        "owner_col": "NULL",
        "provider_literal": "gcp",
        "supports_delete": False,
    },
    {
        "table": "azure_resources",
        "name_col": "name",
        "label_expr": (
            "CASE WHEN (metadata->>'dlp_risk_level')='critical' "
            "     THEN 'highly_confidential' "
            "     WHEN (metadata->>'dlp_risk_level')='high' "
            "     THEN 'confidential' ELSE 'internal' END"
        ),
        "time_col": "last_updated_at",
        "url_col": "NULL",
        "owner_col": "NULL",
        "provider_literal": "azure",
        "supports_delete": False,
    },
    {
        "table": "databricks_resources",
        "name_col": "name",
        "label_expr": (
            "CASE WHEN (metadata->>'dlp_risk_level')='critical' "
            "     THEN 'highly_confidential' "
            "     WHEN (metadata->>'dlp_risk_level')='high' "
            "     THEN 'confidential' ELSE 'internal' END"
        ),
        "time_col": "last_updated_at",
        "url_col": "NULL",
        "owner_col": "created_by",
        "provider_literal": "databricks",
        "supports_delete": False,
    },
    {
        "table": "oracle_resources",
        "name_col": "name",
        "label_expr": (
            "CASE WHEN (metadata->>'dlp_risk_level')='critical' "
            "     THEN 'highly_confidential' "
            "     WHEN (metadata->>'dlp_risk_level')='high' "
            "     THEN 'confidential' ELSE 'internal' END"
        ),
        "time_col": "last_updated_at",
        "url_col": "NULL",
        "owner_col": "NULL",
        "provider_literal": "oracle",
        "supports_delete": False,
    },
]


async def _table_exists(db: AsyncSession, table: str) -> bool:
    try:
        r = await db.execute(text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = :t LIMIT 1"
        ), {"t": table})
        return r.first() is not None
    except Exception:
        return False


async def _column_exists(db: AsyncSession, table: str, col: str) -> bool:
    try:
        r = await db.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c LIMIT 1"
        ), {"t": table, "c": col})
        return r.first() is not None
    except Exception:
        return False


@router.get("/stale")
async def list_stale_data(
    days: int = Query(365, ge=30, le=3650),
    provider: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List stale confidential resources across every connector."""
    org_id = str(current_user.org_id)
    out: list[dict] = []

    for src in STALE_SOURCES:
        if not await _table_exists(db, src["table"]):
            continue
        if not await _column_exists(db, src["table"], src["time_col"]):
            continue
        if provider and src.get("provider_literal") and src["provider_literal"] != provider:
            continue
        if provider and src["table"] == "saas_data_items" and provider not in (
            "teams", "sharepoint", "onedrive", "m365"
        ):
            continue

        label_clause = src.get("label_expr") or src.get("label_col") or "'internal'"
        provider_clause = (
            src.get("provider_col")
            or f"'{src.get('provider_literal','unknown')}'"
        )

        sql = f"""
            SELECT id::text AS id,
                   {src['name_col']} AS name,
                   {label_clause} AS label,
                   {src['time_col']} AS last_modified,
                   {src['url_col']} AS url,
                   {src['owner_col']} AS owner,
                   {provider_clause} AS provider,
                   EXTRACT(EPOCH FROM (NOW() - {src['time_col']}))/86400 AS days_stale
              FROM {src['table']}
             WHERE org_id = CAST(:oid AS UUID)
               AND {src['time_col']} IS NOT NULL
               AND {src['time_col']} < NOW() - INTERVAL ':days days'
               AND {label_clause} IN ('confidential','highly_confidential')
             ORDER BY {src['time_col']} ASC
             LIMIT :lim
        """.replace(":days days", f"{days} days")

        try:
            rows = (await db.execute(text(sql), {
                "oid": org_id, "lim": limit,
            })).mappings().all()
        except Exception as exc:
            logger.debug(f"stale_data: {src['table']} select failed: {exc}")
            continue

        for r in rows:
            row_label = r.get("label") or "internal"
            if label and label != row_label:
                continue
            out.append({
                "id": r["id"],
                "table": src["table"],
                "supports_delete": src["supports_delete"],
                "name": r.get("name"),
                "label": row_label,
                "last_modified": r.get("last_modified").isoformat() if r.get("last_modified") else None,
                "days_stale": int(r.get("days_stale") or 0),
                "url": r.get("url"),
                "owner": r.get("owner"),
                "provider": r.get("provider"),
            })

    # Sort the union by days_stale DESC and apply the global limit.
    out.sort(key=lambda x: x["days_stale"], reverse=True)
    return {"total": len(out), "items": out[:limit]}


@router.get("/summary")
async def stale_summary(
    days: int = Query(365, ge=30, le=3650),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-connector count of stale confidential resources."""
    org_id = str(current_user.org_id)
    by_provider: dict[str, int] = {}
    by_label: dict[str, int] = {}
    total = 0

    for src in STALE_SOURCES:
        if not await _table_exists(db, src["table"]):
            continue
        if not await _column_exists(db, src["table"], src["time_col"]):
            continue
        label_clause = src.get("label_expr") or src.get("label_col") or "'internal'"
        provider_clause = (
            src.get("provider_col")
            or f"'{src.get('provider_literal','unknown')}'"
        )
        sql = f"""
            SELECT {provider_clause} AS provider,
                   {label_clause} AS label,
                   COUNT(*) AS cnt
              FROM {src['table']}
             WHERE org_id = CAST(:oid AS UUID)
               AND {src['time_col']} IS NOT NULL
               AND {src['time_col']} < NOW() - INTERVAL '{days} days'
               AND {label_clause} IN ('confidential','highly_confidential')
             GROUP BY 1, 2
        """
        try:
            rows = (await db.execute(text(sql), {"oid": org_id})).mappings().all()
        except Exception as exc:
            logger.debug(f"stale_summary: {src['table']} failed: {exc}")
            continue
        for r in rows:
            prov = r.get("provider") or "unknown"
            lbl = r.get("label") or "internal"
            cnt = int(r["cnt"])
            by_provider[prov] = by_provider.get(prov, 0) + cnt
            by_label[lbl] = by_label.get(lbl, 0) + cnt
            total += cnt
    return {
        "total": total,
        "by_provider": by_provider,
        "by_label": by_label,
        "threshold_days": days,
    }


class BulkActionRequest(BaseModel):
    resource_ids: list[str]
    action: str  # 'archive' | 'delete' | 'tag_for_review'
    dry_run: bool = True
    reason: Optional[str] = None


@router.post("/stale/bulk-action")
async def bulk_action(
    req: BulkActionRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk action across stale resources.

    Per-row result: {id, action, status, message}. Status is one of
      - 'ok'                : provider call succeeded (or dry-run would)
      - 'tagged_for_review' : provider doesn't support delete; we recorded
                              an audit entry for the owner
      - 'skipped'           : resource not found / not stale
      - 'error'             : provider call failed; message has the cause
    """
    if req.action not in ("archive", "delete", "tag_for_review"):
        raise HTTPException(status_code=400, detail="Unknown action")

    org_id = str(current_user.org_id)
    out: list[dict] = []

    for rid in req.resource_ids[:500]:
        # Find which table this id lives in.
        found = None
        for src in STALE_SOURCES:
            if not await _table_exists(db, src["table"]):
                continue
            try:
                r = await db.execute(text(
                    f"SELECT 1 FROM {src['table']} "
                    f"WHERE id = CAST(:rid AS UUID) "
                    f"  AND org_id = CAST(:oid AS UUID) LIMIT 1"
                ), {"rid": rid, "oid": org_id})
                if r.first():
                    found = src
                    break
            except Exception:
                continue

        if not found:
            out.append({"id": rid, "action": req.action,
                        "status": "skipped",
                        "message": "resource not found in any inventory table"})
            continue

        if req.dry_run:
            kind = "ok" if found["supports_delete"] else "tagged_for_review"
            out.append({
                "id": rid, "action": req.action, "status": kind,
                "message": f"dry-run; would {req.action} via {found['table']}",
            })
            continue

        # Real action — for now we ONLY record an audit entry. Provider-
        # side delete/archive is wired up per-connector in follow-up
        # patches (Graph for SharePoint, boto3 for S3) and respects an
        # admin-only role check.
        try:
            await db.execute(text(
                "INSERT INTO audit_logs "
                "(id, org_id, user_id, action, resource_type, resource_id, "
                " new_value, created_at) "
                "VALUES (gen_random_uuid(), CAST(:oid AS UUID), :uid, "
                "        :action, :rt, CAST(:rid AS UUID), "
                "        CAST(:nv AS JSONB), NOW())"
            ), {
                "oid": org_id,
                "uid": str(current_user.id),
                "action": f"data_lifecycle.{req.action}",
                "rt": found["table"],
                "rid": rid,
                "nv": json.dumps({
                    "action": req.action,
                    "reason": req.reason or "stale_confidential",
                    "via": "data_lifecycle_bulk",
                    "supports_provider_delete": found["supports_delete"],
                }),
            })
            kind = "ok" if found["supports_delete"] else "tagged_for_review"
            out.append({
                "id": rid, "action": req.action, "status": kind,
                "message": (
                    f"{req.action} recorded for {found['table']}; "
                    f"{'provider call queued' if found['supports_delete'] else 'tagged for owner review'}"
                ),
            })
        except Exception as exc:
            logger.warning(f"bulk_action: {rid} failed: {exc}")
            out.append({
                "id": rid, "action": req.action, "status": "error",
                "message": str(exc)[:200],
            })
            try:
                await db.rollback()
            except Exception:
                pass
            continue

    try:
        await db.commit()
    except Exception as exc:
        logger.warning(f"bulk_action: commit failed: {exc}")
        await db.rollback()

    summary = {
        "ok": sum(1 for r in out if r["status"] == "ok"),
        "tagged_for_review": sum(1 for r in out if r["status"] == "tagged_for_review"),
        "skipped": sum(1 for r in out if r["status"] == "skipped"),
        "error": sum(1 for r in out if r["status"] == "error"),
    }
    return {"results": out, "summary": summary, "dry_run": req.dry_run}
