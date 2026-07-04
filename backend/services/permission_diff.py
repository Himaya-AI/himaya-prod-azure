"""
Permission diff / ACL change tracker.

Added 2026-06-23 (Adnan turn 2). For every connector inventory table
we snapshot the access-relevant subset of each row's fields daily,
then compute a diff against the previous snapshot.

Output: list of dicts you can render in a "What changed in your access
posture today?" panel, with severity + rollback hints.

Schema (created on first run):

  permission_snapshots (
    id            UUID PK
    org_id        UUID
    table_name    TEXT       -- 'saas_data_items' | 'aws_resources' | ...
    resource_id   TEXT       -- string-cast of the row's PK
    snapshot_at   TIMESTAMPTZ
    snapshot      JSONB      -- canonical ACL subset
    PRIMARY KEY (id),
    INDEX (org_id, table_name, resource_id, snapshot_at DESC)
  )

The canonical ACL subset for each connector is intentionally small:

  M365 saas_data_items   :: { sharing_scope, classification_label }
  AWS aws_resources      :: { public_access, encryption_enabled,
                               metadata.policy_external,
                               metadata.bucket_acl_summary }
  GCP gcp_resources      :: { public_access, encryption_enabled }
  Azure azure_resources  :: { public_access, encryption_enabled }
  Databricks resources   :: { is_public, has_secrets }
  Oracle resources       :: { public_access, encryption_enabled }
  GitHub findings        :: { severity, category }  (best-effort)

A "diff" record looks like:

  {
    "resource_id": "...",
    "table": "aws_resources",
    "name": "customer-data-bucket",
    "field": "public_access",
    "before": false, "after": true,
    "severity": "critical",          # derived from field + delta direction
    "rollback_hint": "aws s3api put-public-access-block --bucket ...",
    "snapshot_at": ISO,
  }

Public API:
  - ensure_table(db)
  - snapshot_all(db, org_id)          -> int (rows written)
  - compute_diff(db, org_id, since)   -> list[dict]
  - run_and_alert(db, org_id)         -> int (alerts inserted)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── Schema bootstrap ─────────────────────────────────────────────────

async def ensure_table(db: AsyncSession) -> None:
    """Create the snapshot table on first use. Idempotent."""
    try:
        await db.execute(text(
            "CREATE TABLE IF NOT EXISTS permission_snapshots ("
            "  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "  org_id UUID NOT NULL,"
            "  table_name TEXT NOT NULL,"
            "  resource_id TEXT NOT NULL,"
            "  resource_name TEXT,"
            "  snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
            "  snapshot JSONB NOT NULL"
            ")"
        ))
        await db.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_perm_snap_lookup "
            "  ON permission_snapshots(org_id, table_name, resource_id, snapshot_at DESC)"
        ))
        await db.commit()
    except Exception as exc:
        logger.warning(f"permission_diff.ensure_table failed: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass


# ── Source map ───────────────────────────────────────────────────────
# Each entry describes how to extract a stable ACL subset from a
# connector's inventory table.

SOURCES: list[dict[str, Any]] = [
    {
        "table": "saas_data_items",
        "id_col": "id",
        "name_col": "item_name",
        "fields": {
            "sharing_scope":        "sharing_scope",
            "classification_label": "classification_label",
        },
        "watch": ["sharing_scope"],  # only diff these
    },
    {
        "table": "aws_resources",
        "id_col": "id",
        "name_col": "name",
        "fields": {
            "public_access":      "public_access",
            "encryption_enabled": "encryption_enabled",
            "resource_type":      "resource_type",
        },
        "watch": ["public_access", "encryption_enabled"],
    },
    {
        "table": "gcp_resources",
        "id_col": "id",
        "name_col": "name",
        "fields": {
            "public_access":      "public_access",
            "encryption_enabled": "encryption_enabled",
            "resource_type":      "resource_type",
        },
        "watch": ["public_access", "encryption_enabled"],
    },
    {
        "table": "azure_resources",
        "id_col": "id",
        "name_col": "name",
        "fields": {
            "public_access":      "public_access",
            "encryption_enabled": "encryption_enabled",
            "resource_type":      "resource_type",
        },
        "watch": ["public_access", "encryption_enabled"],
    },
    {
        "table": "databricks_resources",
        "id_col": "id",
        "name_col": "name",
        "fields": {
            "is_public":   "is_public",
            "has_secrets": "has_secrets",
        },
        "watch": ["is_public", "has_secrets"],
    },
    {
        "table": "oracle_resources",
        "id_col": "id",
        "name_col": "name",
        "fields": {
            "public_access":      "public_access",
            "encryption_enabled": "encryption_enabled",
        },
        "watch": ["public_access", "encryption_enabled"],
    },
]


# Severity rules per (field, before, after). Default is "medium".
SEVERITY_RULES = {
    ("public_access",      False, True): "critical",
    ("public_access",      True, False): "low",       # tightened — good
    ("is_public",          False, True): "critical",
    ("is_public",          True, False): "low",
    ("encryption_enabled", True, False): "high",       # turning encryption OFF
    ("encryption_enabled", False, True): "low",
    ("sharing_scope",      "private", "public"):   "critical",
    ("sharing_scope",      "private", "external"): "high",
    ("sharing_scope",      "org",     "public"):   "critical",
    ("sharing_scope",      "org",     "external"): "high",
    ("sharing_scope",      "external","public"):   "high",
    ("sharing_scope",      "public",  "private"):  "low",
    ("sharing_scope",      "external","private"):  "low",
    ("has_secrets",        False, True): "high",
}


def _severity_for(field: str, before: Any, after: Any) -> str:
    return SEVERITY_RULES.get((field, before, after), "medium")


def _rollback_hint(table: str, field: str, name: str, after: Any) -> str:
    if table == "aws_resources" and field == "public_access" and after:
        return (
            f"aws s3api put-public-access-block --bucket {name} "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )
    if table == "aws_resources" and field == "encryption_enabled" and after is False:
        return (
            f"aws s3api put-bucket-encryption --bucket {name} "
            "--server-side-encryption-configuration "
            "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
            "{\"SSEAlgorithm\":\"AES256\"}}]}'"
        )
    if table == "saas_data_items" and field == "sharing_scope":
        return (
            f"Open '{name}' in SharePoint/OneDrive → Share → "
            "Manage access → remove anyone-link / external grants."
        )
    if table == "gcp_resources" and field == "public_access" and after:
        return f"gcloud storage buckets update gs://{name} --no-public-access-prevention"
    if table == "azure_resources" and field == "public_access" and after:
        return (
            f"az storage account update --name {name} "
            "--allow-blob-public-access false"
        )
    if table == "databricks_resources" and field == "is_public" and after:
        return f"Open the Databricks workspace and revoke 'Workspace' access for '{name}'."
    return f"Review {field} change on {name}."


# ── Snapshot ─────────────────────────────────────────────────────────

async def _table_exists(db: AsyncSession, table: str) -> bool:
    r = await db.execute(text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t LIMIT 1"
    ), {"t": table})
    return r.first() is not None


async def _columns(db: AsyncSession, table: str) -> set[str]:
    r = await db.execute(text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = :t"
    ), {"t": table})
    return {row[0] for row in r.fetchall()}


async def snapshot_all(db: AsyncSession, org_id: str) -> int:
    """Write a snapshot row for every inventory record."""
    await ensure_table(db)
    written = 0
    for src in SOURCES:
        if not await _table_exists(db, src["table"]):
            continue
        cols = await _columns(db, src["table"])
        # Only select fields that exist on this table.
        usable = {k: v for k, v in src["fields"].items() if v in cols}
        if not usable:
            continue
        select_parts = [
            f"{src['id_col']}::text AS _id",
            f"{src['name_col']} AS _name",
        ] + [f"{col} AS \"{k}\"" for k, col in usable.items()]
        sql = (
            f"SELECT {', '.join(select_parts)} FROM {src['table']} "
            f"WHERE org_id = CAST(:oid AS UUID) LIMIT 5000"
        )
        try:
            rows = (await db.execute(text(sql), {"oid": org_id})).mappings().all()
        except Exception as exc:
            logger.debug(f"snapshot: {src['table']} select failed: {exc}")
            continue
        for r in rows:
            snap = {k: r.get(k) for k in usable}
            try:
                await db.execute(text(
                    "INSERT INTO permission_snapshots "
                    "(org_id, table_name, resource_id, resource_name, snapshot) "
                    "VALUES (CAST(:oid AS UUID), :t, :rid, :rn, CAST(:s AS JSONB))"
                ), {
                    "oid": org_id, "t": src["table"],
                    "rid": r["_id"], "rn": (r.get("_name") or "")[:240],
                    "s": json.dumps(snap, default=str),
                })
                written += 1
            except Exception as exc:
                logger.debug(f"snapshot insert {src['table']}/{r['_id']}: {exc}")
                try:
                    await db.rollback()
                except Exception:
                    pass
                continue
        try:
            await db.commit()
        except Exception:
            await db.rollback()
    return written


# ── Diff ─────────────────────────────────────────────────────────────

async def compute_diff(
    db: AsyncSession,
    org_id: str,
    *,
    since_hours: int = 24,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Compute permission-changes for the last `since_hours` hours.

    For each resource we take the most recent snapshot AT OR AFTER
    `since` and compare it against the most recent snapshot BEFORE
    `since`. If they differ in any `watch` field, we emit a diff
    record per changed field.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    diffs: list[dict[str, Any]] = []
    for src in SOURCES:
        try:
            sql = text("""
                WITH latest AS (
                  SELECT DISTINCT ON (resource_id)
                         resource_id, resource_name, snapshot, snapshot_at
                    FROM permission_snapshots
                   WHERE org_id = CAST(:oid AS UUID)
                     AND table_name = :t
                     AND snapshot_at >= :since
                   ORDER BY resource_id, snapshot_at DESC
                ),
                prior AS (
                  SELECT DISTINCT ON (resource_id)
                         resource_id, snapshot, snapshot_at
                    FROM permission_snapshots
                   WHERE org_id = CAST(:oid AS UUID)
                     AND table_name = :t
                     AND snapshot_at < :since
                   ORDER BY resource_id, snapshot_at DESC
                )
                SELECT l.resource_id, l.resource_name,
                       l.snapshot AS new_snap, p.snapshot AS old_snap,
                       l.snapshot_at AS new_at
                  FROM latest l
                  JOIN prior  p USING (resource_id)
                 WHERE l.snapshot <> p.snapshot
                 LIMIT :lim
            """)
            rows = (await db.execute(sql, {
                "oid": org_id, "t": src["table"],
                "since": since, "lim": limit,
            })).mappings().all()
        except Exception as exc:
            logger.debug(f"compute_diff: {src['table']} failed: {exc}")
            continue

        for r in rows:
            new_snap = r["new_snap"] or {}
            old_snap = r["old_snap"] or {}
            if isinstance(new_snap, str):
                try: new_snap = json.loads(new_snap)
                except Exception: new_snap = {}
            if isinstance(old_snap, str):
                try: old_snap = json.loads(old_snap)
                except Exception: old_snap = {}
            for field in src["watch"]:
                before = old_snap.get(field)
                after = new_snap.get(field)
                if before == after:
                    continue
                diffs.append({
                    "resource_id": r["resource_id"],
                    "table": src["table"],
                    "name": r.get("resource_name"),
                    "field": field,
                    "before": before,
                    "after": after,
                    "severity": _severity_for(field, before, after),
                    "rollback_hint": _rollback_hint(
                        src["table"], field, r.get("resource_name") or "", after
                    ),
                    "snapshot_at": (
                        r["new_at"].isoformat() if r.get("new_at") else None
                    ),
                })

    # Sort: critical first, then high, then medium, then low.
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    diffs.sort(key=lambda d: sev_order.get(d["severity"], 5))
    return diffs


# ── Alert sink ───────────────────────────────────────────────────────

async def _alert_pref_enabled(db: AsyncSession, org_id: str, key: str) -> bool:
    try:
        r = (await db.execute(text(
            "SELECT org_metadata FROM organizations WHERE id = CAST(:oid AS UUID)"
        ), {"oid": org_id})).first()
        if not r:
            return True
        meta = r[0]
        if isinstance(meta, str):
            try: meta = json.loads(meta)
            except Exception: meta = {}
        prefs = (meta or {}).get("alert_prefs") or {}
        v = prefs.get(key)
        return bool(v) if v is not None else True
    except Exception:
        return True


async def run_and_alert(db: AsyncSession, org_id: str) -> int:
    """Snapshot, diff, and push CRITICAL+HIGH diffs into saas_alerts."""
    await snapshot_all(db, org_id)
    diffs = await compute_diff(db, org_id, since_hours=24)
    if not diffs:
        return 0
    if not await _alert_pref_enabled(db, org_id, "saas_posture_drift"):
        return 0

    inserted = 0
    for d in diffs:
        if d["severity"] not in ("critical", "high"):
            continue
        try:
            existing = (await db.execute(text(
                "SELECT 1 FROM saas_alerts "
                "WHERE org_id = CAST(:oid AS UUID) "
                "  AND alert_type = 'PERMISSION_DIFF' "
                "  AND resource_id = :rid "
                "  AND status = 'open' "
                "  AND raw_data->>'field' = :f "
                "LIMIT 1"
            ), {"oid": org_id, "rid": d["resource_id"], "f": d["field"]})).first()
            if existing:
                continue
            await db.execute(text(
                "INSERT INTO saas_alerts "
                "(id, org_id, provider, alert_type, severity, title, "
                " description, resource_id, resource_name, status, "
                " raw_data, created_at) "
                "VALUES (gen_random_uuid(), CAST(:oid AS UUID), :prov, "
                "        'PERMISSION_DIFF', :sev, :title, :desc, :rid, "
                "        :rname, 'open', CAST(:raw AS JSONB), NOW())"
            ), {
                "oid": org_id,
                "prov": d["table"].replace("_resources", "").replace("saas_data_items", "m365"),
                "sev": d["severity"],
                "title": (
                    f"Access tightening: {d['name']} "
                    f"{d['field']} changed {d['before']!r} \u2192 {d['after']!r}"
                )[:240] if d["severity"] == "low" else (
                    f"Access loosened: {d['name']} "
                    f"{d['field']} changed {d['before']!r} \u2192 {d['after']!r}"
                )[:240],
                "desc": (
                    f"{d['table']} '{d['name']}' had its {d['field']} change "
                    f"from {d['before']!r} to {d['after']!r}. "
                    f"Rollback: {d['rollback_hint']}"
                ),
                "rid": d["resource_id"],
                "rname": (d["name"] or "")[:240],
                "raw": json.dumps(d, default=str),
            })
            inserted += 1
        except Exception as exc:
            logger.warning(f"permission_diff alert insert failed: {exc}")
            try: await db.rollback()
            except Exception: pass
            continue
    try:
        await db.commit()
    except Exception:
        await db.rollback()
    return inserted
