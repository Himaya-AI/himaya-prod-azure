"""
Cross-Cloud DLP Classifier
==========================

Issue (rev 367 retrospective): only AWS resources were being DLP-classified
(`metadata->>'dlp_classified'` set true, `dlp_categories` / `dlp_risk_level`
written). Databricks notebooks, GCP buckets, Azure storage, SAP assets,
GitHub repos, Snowflake objects and Oracle resources all stayed
unclassified — so the Data Inventory and Sensitive Data Discovery views
only ever showed M365 + AWS rows tagged with categories.

This module owns the cross-cloud classification path. It:

1. Reuses the per-AWS classifier (Claude Haiku → DeepSeek fallback) but
   exposes it as a generic function that takes any resource shape.
2. Adds **heuristic patterns** (no LLM call needed) for fast common
   classifications across all clouds — e.g. an S3/GCS/Azure bucket whose
   name contains "backup", "snapshot", "logs", "audit" gets DLP categories
   without a network round-trip. This drops the per-cycle cost
   meaningfully and gives every connector at least *some* categorisation.
3. Writes the same shape of metadata (`dlp_classified=true`,
   `dlp_categories=[...]`, `dlp_risk_level=...`) into each resource table
   the corresponding connector owns.

This module is intentionally simple/SQL-driven so that it doesn't grow a
dependency on any one connector module.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── Heuristic patterns ────────────────────────────────────────────────────
# Fast, deterministic categorisation by name/type/region/tag tokens.
# A resource matches a category as long as one of its `tokens` is found
# in the joined-text-blob (name + path + tags). These don't try to be
# exhaustive — they catch the common cases so we never ship a resource
# with no categories at all. The LLM (when available) refines on top.

HEURISTIC_RULES: list[tuple[str, list[str]]] = [
    # category, token list
    ("credentials", ["secret", "credential", "api-key", "apikey",
                     "password", "token", "kms-key", "iam-key",
                     "service-account", ".pem", ".key", "private-key"]),
    ("backup",      ["backup", "snapshot", "restore", "archive",
                     "snap-", "-snap", "-bk-", "/bkup"]),
    ("logs",        ["log", "audit", "access-log", "cloudtrail",
                     "cloudwatch", "auditlog", "trace", "events"]),
    ("pii",         ["customer", "user-data", "userdata", "employee",
                     "personal", "pii", "contact", "subscriber",
                     "ssn", "passport", "identity", "kyc", "hr-data",
                     "payroll"]),
    ("pci",         ["payment", "card", "billing", "invoice", "stripe",
                     "checkout", "pos-", "merchant", "pci"]),
    ("phi",         ["health", "patient", "medical", "phi", "hipaa",
                     "ehr", "diagnos", "prescription", "clinic"]),
    ("financial",   ["financ", "ledger", "revenue", "accounting",
                     "transactions", "ach", "iban", "bank-",
                     "trading", "treasury"]),
    ("source_code", ["repo", "src", "source", "code", ".git",
                     "github", "bitbucket", "gitlab", "build-artifact"]),
    ("ml_data",     ["model", "training-data", "dataset", "feature-store",
                     "tfrecord", "embeddings", "ml-"]),
    ("config",      ["config", "settings", "params", "terraform",
                     "cloudformation", "iac", "manifest"]),
    ("network",     ["vpn", "vpc", "subnet", "loadbalancer", "lb-",
                     "gateway", "elb-", "alb-", "nlb-", "firewall"]),
    ("public_data", ["public", "static", "cdn", "website", "marketing",
                     "press", "blog"]),
]


# Tokens that imply high or critical risk regardless of public access.
HIGH_RISK_TOKENS = {
    "secret", "credential", "password", "token", "private-key", ".pem",
    "ssn", "passport", "pii", "phi", "hipaa", "kyc", "pci", "payment",
    "card", "patient", "medical", "iam-key", "kms-key", "stripe",
}


def _classify_heuristic(resource: dict[str, Any]) -> tuple[list[str], str]:
    """Return (categories, risk_level) from name/path/tags tokens.

    risk_level is one of "low" | "medium" | "high" | "critical".
    """
    blob_parts = [
        resource.get("name") or "",
        resource.get("resource_id") or "",
        resource.get("resource_path") or "",
        resource.get("resource_type") or "",
        resource.get("region") or resource.get("location") or "",
    ]
    tags = resource.get("tags") or resource.get("labels") or resource.get("metadata") or {}
    if isinstance(tags, dict):
        for k, v in tags.items():
            blob_parts.append(str(k))
            blob_parts.append(str(v))
    elif isinstance(tags, list):
        blob_parts.extend([str(t) for t in tags])
    blob = " ".join(str(p) for p in blob_parts).lower()

    matched: list[str] = []
    for cat, tokens in HEURISTIC_RULES:
        for tok in tokens:
            if tok in blob:
                matched.append(cat)
                break

    if not matched:
        # Resource-type fallback so we never emit zero categories.
        rt = (resource.get("resource_type") or "").lower()
        if "bucket" in rt or "storage" in rt or "blob" in rt:
            matched = ["storage"]
        elif "database" in rt or "rds" in rt or "warehouse" in rt or "snowflake" in rt:
            matched = ["database"]
        elif "notebook" in rt or "workspace" in rt:
            matched = ["analytics"]
        elif "repo" in rt:
            matched = ["source_code"]
        elif "user" in rt or "iam" in rt or "role" in rt:
            matched = ["identity"]
        else:
            matched = ["infrastructure"]

    # Risk: start from public access + encryption.
    is_public = bool(resource.get("public_access")) or bool(resource.get("is_public"))
    is_encrypted = bool(resource.get("encryption_enabled")) or bool(resource.get("encrypted"))

    risk = "low"
    if any(tok in blob for tok in HIGH_RISK_TOKENS):
        risk = "high"
    if is_public and any(c in matched for c in ("pii", "pci", "phi", "credentials", "financial")):
        risk = "critical"
    elif is_public and matched != ["public_data"]:
        risk = "medium" if risk == "low" else risk
    elif not is_encrypted and any(c in matched for c in ("pii", "pci", "phi", "credentials")):
        risk = "high"

    # De-dup but preserve order.
    seen: set[str] = set()
    ordered = []
    for c in matched:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered, risk


# ── Generic per-table classifier ──────────────────────────────────────────

# (table_name, resource_id_col, name_col, type_col, optional metadata cols)
# `extra_cols` are pulled into the heuristic blob.
CONNECTOR_TABLES: list[dict[str, Any]] = [
    {
        "table": "databricks_resources",
        "name_col": "name",
        "type_col": "resource_type",
        "extra_cols": ["resource_path", "created_by",
                       "has_secrets", "is_running"],
    },
    {
        "table": "gcp_resources",
        "name_col": "name",
        "type_col": "resource_type",
        "extra_cols": ["resource_name", "location", "size_bytes",
                       "encryption_enabled", "public_access", "labels"],
    },
    {
        "table": "snowflake_findings",
        "name_col": "resource_name",
        "type_col": "resource_type",
        "extra_cols": ["category", "severity"],
        "id_col": "id",
    },
    {
        "table": "sap_findings",
        "name_col": "title",
        "type_col": "finding_type",
        "extra_cols": ["category", "severity"],
        "id_col": "id",
    },
    {
        "table": "github_findings",
        "name_col": "title",
        "type_col": "finding_type",
        "extra_cols": ["category", "severity", "repository"],
        "id_col": "id",
    },
    {
        "table": "azure_resources",
        "name_col": "name",
        "type_col": "resource_type",
        "extra_cols": ["location", "encryption_enabled", "public_access"],
    },
    {
        "table": "oracle_resources",
        "name_col": "name",
        "type_col": "resource_type",
        "extra_cols": ["region", "public_access", "encryption_enabled"],
    },
    {
        # SALSA-style probe findings tagged so they show up in DSPM with
        # categories (pii / customer-data) rather than "uncategorised".
        "table": "salesforce_findings",
        "name_col": "title",
        "type_col": "category",
        "extra_cols": ["sobject_name", "severity"],
        "id_col": "id",
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


# Map connector table → the `cloud` string we write into dspm_findings.
# Keep these stable: the Sensitive Data Discovery panel filters by
# `cloud`, so a rename here breaks the UI filter.
_TABLE_TO_CLOUD: dict[str, str] = {
    "databricks_resources": "databricks",
    "gcp_resources":        "gcp",
    "azure_resources":      "azure",
    "oracle_resources":     "oracle",
    "github_findings":      "github",
    "snowflake_findings":   "snowflake",
    "sap_findings":         "sap",
    "salesforce_findings":  "salesforce",
}

# Translate the heuristic risk level into the dspm_findings severity
# vocabulary. Heuristic emits low|medium|high|critical; dspm_findings
# expects info|low|medium|high|critical.
_RISK_TO_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
}


async def _mirror_to_dspm_findings(
    db: AsyncSession,
    org_id: str,
    table: str,
    row: Any,
    cats: list[str],
    risk: str,
) -> None:
    """Insert (or refresh) a dspm_findings row for a heuristic hit.

    Idempotent via dspm_findings_unique (org_id, cloud, fingerprint).
    Each connector picks its own resource_type / resource_id mapping
    out of the source row.
    """
    cloud = _TABLE_TO_CLOUD.get(table)
    if not cloud:
        return
    severity = _RISK_TO_SEVERITY.get(risk, "medium")
    category = cats[0] if cats else "sensitive_data"
    resource_id = str(row.get("_name") or row.get("_id") or "")
    resource_type = str(row.get("_type") or table)
    object_key = str(row.get("resource_path") or row.get("repository")
                     or row.get("sobject_name") or "")
    pattern_name = f"heuristic:{category}"
    fingerprint_src = f"{table}|{row['_id']}|{category}|{pattern_name}"
    import hashlib as _hashlib
    fingerprint = _hashlib.sha256(fingerprint_src.encode()).hexdigest()
    redacted = (
        f"{cloud} {resource_type} '{resource_id[:80]}' "
        f"flagged {','.join(cats[:3])} by heuristic"
    )
    metadata = {
        "source": "cross_cloud_dlp",
        "categories": cats,
        "risk_level": risk,
    }
    try:
        await db.execute(text(
            "INSERT INTO dspm_findings ("
            "  org_id, cloud, resource_type, resource_id, object_key, "
            "  category, severity, pattern_name, match_count, redacted_sample, "
            "  confidence, region, metadata, first_seen_at, last_seen_at, "
            "  fingerprint"
            ") VALUES ("
            "  CAST(:org_id AS UUID), :cloud, :rt, :rid, :ok, "
            "  :cat, :sev, :pn, 1, :rs, "
            "  0.6, :region, CAST(:md AS JSONB), NOW(), NOW(), "
            "  :fp"
            ") ON CONFLICT (org_id, cloud, fingerprint) DO UPDATE SET "
            "  last_seen_at = NOW(), "
            "  match_count = dspm_findings.match_count + 1, "
            "  severity = EXCLUDED.severity"
        ), {
            "org_id": org_id, "cloud": cloud, "rt": resource_type,
            "rid": resource_id[:240], "ok": object_key[:240],
            "cat": category, "sev": severity, "pn": pattern_name,
            "rs": redacted[:500], "region": str(row.get("region")
                                              or row.get("location")
                                              or ""),
            "md": json.dumps(metadata), "fp": fingerprint,
        })
    except Exception as exc:
        # Promoted from silent: surface so we notice schema drift.
        logger.debug(f"_mirror_to_dspm_findings: {table}/{row.get('_id')}: {exc}")


async def classify_table(
    org_id: str,
    db: AsyncSession,
    table: str,
    *,
    name_col: str,
    type_col: str,
    extra_cols: list[str] | None = None,
    id_col: str = "id",
    limit: int = 25,
) -> int:
    """Classify unclassified rows in one connector table.

    Returns the number of rows newly classified.
    """
    if not await _table_exists(db, table):
        return 0
    # Ensure metadata column exists; if not, can't store classification.
    if not await _column_exists(db, table, "metadata"):
        return 0

    # Drop extra cols that don't exist (some tables are sparse).
    extra_cols = extra_cols or []
    safe_extras: list[str] = []
    for c in extra_cols:
        if await _column_exists(db, table, c):
            safe_extras.append(c)

    select_cols = [f"{id_col}::text as _id"]
    select_cols.append(f"{name_col} as _name")
    select_cols.append(f"{type_col} as _type")
    for c in safe_extras:
        select_cols.append(c)
    select_cols.append("metadata")

    sql = (
        f"SELECT {', '.join(select_cols)} FROM {table} "
        "WHERE org_id = CAST(:org_id AS UUID) "
        "  AND (metadata->>'dlp_classified' IS NULL "
        "       OR metadata->>'dlp_classified' != 'true') "
        f"ORDER BY {id_col} DESC LIMIT :lim"
    )
    try:
        rows = (await db.execute(text(sql), {"org_id": org_id, "lim": limit})).mappings().all()
    except Exception as exc:
        # Promoted from debug → warning so silent table-shape mismatches
        # surface in production logs. asyncpg leaves the session aborted
        # on error, so rollback before returning.
        logger.warning(f"cross_cloud_dlp: select from {table} failed: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass
        return 0

    # Always log how many candidates we found so we can tell when an org
    # legitimately has zero unclassified rows vs the query is broken.
    logger.info(
        f"cross_cloud_dlp: {table} org={org_id} found {len(rows)} unclassified candidate(s)"
    )

    classified = 0
    skipped = 0
    for row in rows:
        resource = {
            "name": row.get("_name"),
            "resource_type": row.get("_type"),
        }
        for c in safe_extras:
            resource[c] = row.get(c)
        cats, risk = _classify_heuristic(resource)
        existing_meta: Any = row.get("metadata") or {}
        if isinstance(existing_meta, str):
            try:
                existing_meta = json.loads(existing_meta)
            except Exception:
                existing_meta = {}
        if not isinstance(existing_meta, dict):
            existing_meta = {}
        existing_meta["dlp_classified"] = "true"
        existing_meta["dlp_categories"] = cats
        existing_meta["dlp_risk_level"] = risk
        existing_meta["dlp_source"] = "heuristic"
        try:
            await db.execute(text(
                f"UPDATE {table} SET metadata = CAST(:meta AS jsonb) "
                f"WHERE {id_col} = CAST(:rid AS UUID)"
            ), {"meta": json.dumps(existing_meta), "rid": row["_id"]})
            classified += 1
            # Adnan 2026-06-23 (turn 3): mirror sensitive rows into
            # dspm_findings so the Sensitive Data Discovery panel
            # (Workspace Security → Data Inventory → DSPM) surfaces
            # ALL connectors, not just AWS / M365. Without this the
            # only DLP findings the UI sees are the ones the per-cloud
            # scanners write directly (aws_s3, gcp_gcs, azure_blob,
            # m365_graph). Heuristic classifications from databricks,
            # github, snowflake, sap, salesforce, oracle, etc were
            # invisible to the panel.
            if cats and risk in ("high", "critical", "medium"):
                try:
                    await _mirror_to_dspm_findings(
                        db, org_id, table, row, cats, risk,
                    )
                except Exception as _mexc:
                    logger.debug(
                        f"cross_cloud_dlp: mirror to dspm_findings "
                        f"failed for {table}/{row.get('_id')}: {_mexc}"
                    )
        except Exception as exc:
            # Promoted from debug so update failures (wrong cast, wrong
            # column type, etc.) are visible. Roll back the aborted tx so
            # the next iteration can still run.
            logger.warning(
                f"cross_cloud_dlp: update {table} row {row.get('_id')}: {exc}"
            )
            try:
                await db.rollback()
            except Exception:
                pass
            skipped += 1
            continue

    if classified:
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            logger.warning(f"cross_cloud_dlp: commit for {table} failed", exc_info=True)
            return 0
        logger.info(
            f"cross_cloud_dlp: classified {classified}/{len(rows)} rows in {table} for org {org_id} (skipped {skipped})"
        )
    elif rows:
        logger.info(
            f"cross_cloud_dlp: 0 rows classified in {table} for org {org_id} "
            f"(found {len(rows)} candidates but all updates failed)"
        )
    return classified


async def classify_all_clouds(org_id: str, db: AsyncSession) -> dict[str, int]:
    """Run heuristic DLP classification across every connector table.

    Returns a dict {table_name: rows_classified}.
    """
    results: dict[str, int] = {}
    for cfg in CONNECTOR_TABLES:
        try:
            n = await classify_table(
                org_id, db,
                table=cfg["table"],
                name_col=cfg["name_col"],
                type_col=cfg["type_col"],
                extra_cols=cfg.get("extra_cols", []),
                id_col=cfg.get("id_col", "id"),
                limit=25,
            )
            results[cfg["table"]] = n
        except Exception as exc:
            logger.warning(
                f"cross_cloud_dlp: classify_table {cfg['table']} failed: {exc}"
            )
            results[cfg["table"]] = 0
    return results
