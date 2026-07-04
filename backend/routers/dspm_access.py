"""
DSPM Access Intelligence
========================

Aggregates per-owner access surface across providers. Concentric/Varonis call
this "Identity-Centric DSPM" — instead of looking at resources, you look at
identities and ask: 'if this person's credential were compromised tomorrow,
what would the attacker get?'

Endpoints
---------
GET /api/dspm/access/owners
    Per-owner access surface across AWS / Databricks / GCP / SaaS:
    { total, sensitive, external, providers, last_seen }
    Top-N by exposure score = sensitive + external*3.

GET /api/dspm/access/stale-privileged
    Privileged identities (IAM users, SAP privileged users) that haven't been
    used recently — the classic 'orphaned access' problem.

GET /api/dspm/access/blast-radius/{owner_email}
    Detail view for one owner: every asset they touch + classification.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dspm/access", tags=["dspm-access"])


@router.get("/owners")
async def access_owners(
    limit: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cross-provider per-owner aggregation. One row per email."""
    org_id = str(current_user.org_id)
    # AWS — owner from tag or CloudTrail
    aws_sql = text("""
        SELECT COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by') AS owner,
               COUNT(*)                                                    AS total,
               COUNT(*) FILTER (WHERE metadata->>'dlp_risk_level' IN ('high','critical')) AS sensitive,
               COUNT(*) FILTER (WHERE public_access = TRUE)                AS external,
               'aws'                                                       AS provider,
               MAX(scanned_at)                                              AS last_seen
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
        GROUP BY 1
    """)
    saas_sql = text("""
        SELECT LOWER(owner_email) AS owner,
               COUNT(*)           AS total,
               COUNT(*) FILTER (WHERE classification_label IN ('confidential','highly_confidential','restricted')) AS sensitive,
               COUNT(*) FILTER (WHERE sharing_scope IN ('external','public')) AS external,
               provider           AS provider,
               MAX(last_scanned_at) AS last_seen
        FROM saas_data_items
        WHERE org_id = CAST(:org_id AS UUID)
        GROUP BY 1, provider
    """)
    db_sql = text("""
        SELECT LOWER(created_by) AS owner,
               COUNT(*)          AS total,
               COUNT(*) FILTER (WHERE has_secrets = TRUE) AS sensitive,
               0                 AS external,
               'databricks'      AS provider,
               MAX(scanned_at)   AS last_seen
        FROM databricks_resources
        WHERE org_id = CAST(:org_id AS UUID)
        GROUP BY 1
    """)
    gcp_sql = text("""
        SELECT COALESCE(metadata->>'owner', metadata->>'created_by') AS owner,
               COUNT(*)                                              AS total,
               COUNT(*) FILTER (WHERE metadata->>'dlp_risk_level' IN ('high','critical')) AS sensitive,
               COUNT(*) FILTER (WHERE public_access = TRUE)          AS external,
               'gcp'                                                  AS provider,
               MAX(scanned_at)                                        AS last_seen
        FROM gcp_resources
        WHERE org_id = CAST(:org_id AS UUID)
        GROUP BY 1
    """)

    rows = []
    for q in (aws_sql, saas_sql, db_sql, gcp_sql):
        try:
            r = (await db.execute(q, {"org_id": org_id})).mappings().all()
            rows.extend(r)
        except Exception as exc:
            logger.debug(f"access_owners: source skipped: {exc}")

    # Roll up by owner across providers.
    by_owner: dict[str, dict] = {}
    for r in rows:
        owner = (r.get("owner") or "").strip().lower()
        if not owner or owner in ("none", "null"):
            owner = "(unowned)"
        cur = by_owner.setdefault(owner, {
            "owner": owner,
            "total": 0,
            "sensitive": 0,
            "external": 0,
            "providers": {},
            "last_seen": None,
        })
        cur["total"] += r["total"]
        cur["sensitive"] += r["sensitive"]
        cur["external"] += r["external"]
        cur["providers"][r["provider"]] = cur["providers"].get(r["provider"], 0) + r["total"]
        ls = r["last_seen"]
        if ls and (not cur["last_seen"] or ls > cur["last_seen"]):
            cur["last_seen"] = ls

    items = []
    for cur in by_owner.values():
        score = cur["sensitive"] + cur["external"] * 3
        items.append({
            "owner": cur["owner"],
            "total": cur["total"],
            "sensitive": cur["sensitive"],
            "external": cur["external"],
            "providers": cur["providers"],
            "provider_count": len(cur["providers"]),
            "last_seen": cur["last_seen"].isoformat() if cur["last_seen"] else None,
            "exposure_score": score,
        })
    items.sort(key=lambda x: x["exposure_score"], reverse=True)
    return {"items": items[:limit], "total_owners": len(items)}


@router.get("/stale-privileged")
async def stale_privileged(
    days: int = Query(90, ge=7, le=365),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Privileged identities not used in N days."""
    org_id = str(current_user.org_id)
    items = []

    # SAP privileged users
    try:
        rows = (await db.execute(text("""
            SELECT user_id, user_name, email, department, last_logon,
                   roles, profiles
            FROM sap_users
            WHERE org_id = CAST(:org_id AS UUID)
              AND is_privileged = TRUE
              AND (last_logon IS NULL OR last_logon < NOW() - (:days || ' days')::interval)
            LIMIT 200
        """), {"org_id": org_id, "days": days})).mappings().all()
        for r in rows:
            items.append({
                "source": "sap",
                "identity": r["user_name"] or r["user_id"],
                "email": r["email"],
                "department": r["department"],
                "last_seen": r["last_logon"].isoformat() if r["last_logon"] else None,
                "privilege": ", ".join((r["roles"] or [])[:3]),
            })
    except Exception as exc:
        logger.debug(f"stale_privileged: sap skipped: {exc}")

    # AWS IAM users — admin-tagged (best-effort via metadata.policy_arns)
    try:
        rows = (await db.execute(text("""
            SELECT id::text, name, resource_arn, metadata->>'console_access' AS console_access,
                   metadata->>'mfa_enabled' AS mfa_enabled,
                   metadata->>'last_used' AS last_used,
                   metadata->>'days_since_used' AS days_since_used
            FROM aws_resources
            WHERE org_id = CAST(:org_id AS UUID)
              AND resource_type = 'iam_user'
              AND (metadata->>'days_since_used' IS NULL
                   OR (metadata->>'days_since_used')::int >= :days)
            LIMIT 200
        """), {"org_id": org_id, "days": days})).mappings().all()
        for r in rows:
            items.append({
                "source": "aws_iam",
                "identity": r["name"],
                "email": None,
                "department": None,
                "last_seen": r["last_used"],
                "privilege": f"console={r['console_access']} mfa={r['mfa_enabled']}",
            })
    except Exception as exc:
        logger.debug(f"stale_privileged: aws skipped: {exc}")

    return {"items": items, "total": len(items), "stale_days_threshold": days}


@router.get("/blast-radius/{owner_email}")
async def blast_radius(
    owner_email: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-owner asset list across providers, sorted by sensitivity."""
    org_id = str(current_user.org_id)
    owner = owner_email.strip().lower()
    results: list[dict] = []
    try:
        rows = (await db.execute(text("""
            SELECT id::text, item_name AS name, provider, item_type AS type,
                   sharing_scope AS sharing, classification_label AS label,
                   classification_categories AS categories,
                   last_modified_at AS modified, last_scanned_at AS scanned
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND LOWER(owner_email) = :owner
            ORDER BY last_modified_at DESC NULLS LAST
            LIMIT 200
        """), {"org_id": org_id, "owner": owner})).mappings().all()
        results.extend(dict(r) for r in rows)
    except Exception as exc:
        logger.debug(f"blast_radius: saas skipped: {exc}")
    try:
        rows = (await db.execute(text("""
            SELECT id::text, name, 'aws' AS provider, resource_type AS type,
                   CASE WHEN public_access THEN 'public' ELSE 'private' END AS sharing,
                   metadata->>'dlp_risk_level' AS label,
                   metadata->'dlp_categories' AS categories,
                   last_modified AS modified, scanned_at AS scanned
            FROM aws_resources
            WHERE org_id = CAST(:org_id AS UUID)
              AND LOWER(COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by')) = :owner
            ORDER BY last_modified DESC NULLS LAST
            LIMIT 200
        """), {"org_id": org_id, "owner": owner})).mappings().all()
        results.extend(dict(r) for r in rows)
    except Exception as exc:
        logger.debug(f"blast_radius: aws skipped: {exc}")
    try:
        rows = (await db.execute(text("""
            SELECT id::text, name, 'databricks' AS provider, resource_type AS type,
                   'org' AS sharing,
                   metadata->>'dlp_risk_level' AS label,
                   metadata->'dlp_categories' AS categories,
                   last_modified AS modified, scanned_at AS scanned
            FROM databricks_resources
            WHERE org_id = CAST(:org_id AS UUID)
              AND LOWER(created_by) = :owner
            ORDER BY last_modified DESC NULLS LAST
            LIMIT 200
        """), {"org_id": org_id, "owner": owner})).mappings().all()
        results.extend(dict(r) for r in rows)
    except Exception as exc:
        logger.debug(f"blast_radius: databricks skipped: {exc}")

    # Stamp ISO timestamps
    for r in results:
        if r.get("modified") and hasattr(r["modified"], "isoformat"):
            r["modified"] = r["modified"].isoformat()
        if r.get("scanned") and hasattr(r["scanned"], "isoformat"):
            r["scanned"] = r["scanned"].isoformat()
    return {"owner": owner, "items": results, "total": len(results)}
