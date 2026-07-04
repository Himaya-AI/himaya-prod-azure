"""
Toxic Combinations DSPM Engine
==============================

Detects compound risk: situations where two or more individually-tolerable
facts compose into a critical exposure. Concentric AI and Varonis ship this
under names like "Toxic Combinations" or "Blast-Radius Findings" — the value
prop is that an admin staring at a 5,000-finding queue has no chance, but
five "S3 bucket is public AND contains PII AND has external readers" alerts
they can act on today.

Approach
--------
- Rule-driven, not ML. Each rule is a pure SQL query against the existing
  resource + finding + classification tables; if it returns rows, those are
  toxic combinations to surface.
- Runs on the same 5-minute cadence as the CSPM/DSPM loop so newly-classified
  resources show up quickly.
- Writes into `toxic_combinations` (own table) and mirrors a row into
  `saas_alerts` so the existing Workspace Security > Alerts UI surfaces it
  without any frontend work.
- Idempotent: ON CONFLICT (org_id, rule_id, fingerprint) DO UPDATE keeps
  state across cycles and lets us "close" alerts that no longer hit.

Rule Catalogue (v1)
-------------------
- public_pii_bucket          public S3 bucket where DLP found PII categories
- unencrypted_confidential   resource flagged confidential with encryption off
- public_admin_role          admin IAM role with public trust relationship
- shadow_data_external       SaaS file shared externally + sensitive label
- stale_privileged_user      privileged user that hasn't logged in 90d
- public_db_with_data        publicly-reachable RDS/database instance
- production_unencrypted     resource tagged prod/production but encryption off
- secret_in_public_notebook  Databricks notebook with secrets + public share
- cross_provider_exposure    same owner has public assets on multiple clouds
- unowned_high_risk          high/critical risk resource without an owner tag

Author: Pikachu, 2026-06-20
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def _json_dumps_safe(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return "{}"

logger = logging.getLogger(__name__)


# ── Schema bootstrap ──────────────────────────────────────────────────────────

# asyncpg cannot pass multi-statement DDL through a prepared statement, so we
# split into one statement per execute() call. All are CREATE IF NOT EXISTS
# so calling on every cycle is a cheap no-op.
TOXIC_COMBINATIONS_DDL_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS toxic_combinations (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id        UUID NOT NULL,
        rule_id       TEXT NOT NULL,
        severity      TEXT NOT NULL,
        title         TEXT NOT NULL,
        description   TEXT NOT NULL,
        resources     JSONB NOT NULL DEFAULT '[]'::jsonb,
        fingerprint   TEXT NOT NULL,
        factors       JSONB NOT NULL DEFAULT '[]'::jsonb,
        status        TEXT NOT NULL DEFAULT 'open',
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        resolved_at   TIMESTAMPTZ,
        metadata      JSONB DEFAULT '{}'::jsonb,
        UNIQUE (org_id, rule_id, fingerprint)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_toxic_combinations_org_status ON toxic_combinations (org_id, status)",
    "CREATE INDEX IF NOT EXISTS ix_toxic_combinations_org_severity ON toxic_combinations (org_id, severity)",
    "CREATE INDEX IF NOT EXISTS ix_toxic_combinations_last_seen ON toxic_combinations (org_id, last_seen_at DESC)",
)


async def ensure_schema(db: AsyncSession) -> None:
    """Idempotent DDL — safe to call on every cycle, no-op once installed."""
    for stmt in TOXIC_COMBINATIONS_DDL_STATEMENTS:
        await db.execute(text(stmt))
    await db.commit()


# ── Rule model ────────────────────────────────────────────────────────────────

@dataclass
class ToxicMatch:
    """One concrete toxic combination instance detected by a rule."""
    rule_id: str
    severity: str
    title: str
    description: str
    resources: list[dict]
    factors: list[str]
    primary_keys: list[str] = field(default_factory=list)   # for fingerprint
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        # Sort so order-insensitive across cycles.
        joined = "|".join(sorted(self.primary_keys)) or self.rule_id
        return hashlib.sha256(f"{self.rule_id}::{joined}".encode()).hexdigest()[:32]


@dataclass
class ToxicRule:
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool = True


# ── Rule definitions ─────────────────────────────────────────────────────────
# Each rule is a pure async function: async def rule(org_id, db) -> list[ToxicMatch]
# Keep them lean and SQL-driven where possible; fall back to Python only when
# the matrix is too gnarly to express in one query.

async def _rule_public_pii_bucket(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Public S3/GCS bucket whose DLP classifier tagged it with PII categories."""
    sql = text("""
        SELECT id::text, name, resource_arn, region, public_access,
               metadata->>'dlp_risk_level' as risk_level,
               metadata->'dlp_categories' as cats,
               COALESCE(metadata->>'owner', metadata->>'created_by') as owner
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND resource_type = 's3_bucket'
          AND public_access = TRUE
          AND metadata->>'dlp_classified' = 'true'
          AND metadata->'dlp_categories' ?| ARRAY['pii','pci','phi','financial','credentials','secrets']
        UNION ALL
        SELECT id::text, name, NULL as resource_arn, location as region, public_access,
               metadata->>'dlp_risk_level' as risk_level,
               metadata->'dlp_categories' as cats,
               COALESCE(metadata->>'owner', metadata->>'created_by') as owner
        FROM gcp_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND resource_type IN ('storage_bucket','gcs_bucket')
          AND public_access = TRUE
          AND metadata->>'dlp_classified' = 'true'
          AND metadata->'dlp_categories' ?| ARRAY['pii','pci','phi','financial','credentials','secrets']
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        cats = r["cats"] if isinstance(r["cats"], list) else []
        matches.append(ToxicMatch(
            rule_id="public_pii_bucket",
            severity="critical",
            title=f"Public bucket with sensitive data: {r['name']}",
            description=(
                f"Bucket '{r['name']}' is publicly accessible and DLP classified "
                f"it as containing {', '.join(cats[:3]) if cats else 'sensitive data'}. "
                f"Anyone on the internet can read this data."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "arn": r["resource_arn"],
                "region": r["region"],
                "owner": r["owner"],
            }],
            factors=[
                "Public access enabled",
                f"Contains: {', '.join(cats[:5])}" if cats else "Contains sensitive data",
                f"Risk level: {r['risk_level']}" if r["risk_level"] else "",
            ],
            primary_keys=[r["id"]],
            metadata={"categories": cats, "owner": r["owner"]},
        ))
    return matches


async def _rule_unencrypted_confidential(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Resource flagged confidential by DLP but encryption is off."""
    sql = text("""
        SELECT id::text, resource_type, name, region, public_access,
               metadata->'dlp_categories' as cats,
               COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by') as owner,
               'aws' as cloud
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND encryption_enabled = FALSE
          AND metadata->>'dlp_risk_level' IN ('high','critical')
          AND metadata->>'dlp_classified' = 'true'
        LIMIT 50
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        cats = r["cats"] if isinstance(r["cats"], list) else []
        matches.append(ToxicMatch(
            rule_id="unencrypted_confidential",
            severity="high",
            title=f"Unencrypted {r['resource_type']} flagged confidential: {r['name']}",
            description=(
                f"{r['resource_type']} '{r['name']}' in {r['region']} has encryption "
                f"disabled, yet DLP classified it as containing "
                f"{', '.join(cats[:3]) if cats else 'sensitive content'}. "
                f"A snapshot or breach would leak the data at rest."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "type": r["resource_type"],
                "region": r["region"],
                "owner": r["owner"],
                "cloud": r["cloud"],
            }],
            factors=[
                "Encryption at rest: disabled",
                f"DLP classification: {', '.join(cats[:3])}" if cats else "DLP classification: sensitive",
                "Public access" if r["public_access"] else "Private",
            ],
            primary_keys=[r["id"]],
            metadata={"categories": cats},
        ))
    return matches


async def _rule_public_db_with_data(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Database (RDS) instance reachable from the internet."""
    sql = text("""
        SELECT id::text, name, region, encryption_enabled,
               metadata->>'engine' as engine,
               metadata->>'endpoint' as endpoint,
               COALESCE(metadata->>'owner', metadata->>'created_by') as owner
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND resource_type = 'rds_instance'
          AND public_access = TRUE
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        sev = "critical" if not r["encryption_enabled"] else "high"
        matches.append(ToxicMatch(
            rule_id="public_db_with_data",
            severity=sev,
            title=f"Public database: {r['name']} ({r['engine'] or 'rds'})",
            description=(
                f"RDS instance '{r['name']}' is publicly accessible"
                + (" and has encryption disabled" if not r["encryption_enabled"] else "")
                + f". Endpoint: {r['endpoint'] or 'n/a'}. "
                f"Restrict to a VPC security group; databases should never face the internet."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "region": r["region"],
                "engine": r["engine"],
                "owner": r["owner"],
            }],
            factors=[
                "Publicly accessible",
                f"Engine: {r['engine']}" if r["engine"] else "Database instance",
                "Encryption: disabled" if not r["encryption_enabled"] else "Encryption: enabled",
            ],
            primary_keys=[r["id"]],
        ))
    return matches


async def _rule_production_unencrypted(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Resource tagged prod/production but encryption disabled."""
    sql = text("""
        SELECT id::text, resource_type, name, region,
               metadata->>'environment' as env,
               COALESCE(metadata->>'owner', metadata->>'created_by') as owner
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND encryption_enabled = FALSE
          AND LOWER(COALESCE(metadata->>'environment','')) IN ('prod','production','prd','live')
        LIMIT 100
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        matches.append(ToxicMatch(
            rule_id="production_unencrypted",
            severity="high",
            title=f"Production resource without encryption: {r['name']}",
            description=(
                f"{r['resource_type']} '{r['name']}' carries an environment tag of "
                f"'{r['env']}' but has encryption disabled. Production data at rest "
                f"is a top-of-funnel compliance failure (PCI/HIPAA/SOC2)."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "type": r["resource_type"],
                "region": r["region"],
                "environment": r["env"],
                "owner": r["owner"],
            }],
            factors=[
                f"Environment: {r['env']}",
                "Encryption at rest: disabled",
            ],
            primary_keys=[r["id"]],
        ))
    return matches


async def _rule_unowned_high_risk(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """High/critical risk resource with no owner identified — nobody to remediate it."""
    sql = text("""
        SELECT id::text, resource_type, name, region,
               metadata->>'dlp_risk_level' as risk_level,
               metadata->'dlp_categories' as cats
        FROM aws_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND metadata->>'dlp_risk_level' IN ('high','critical')
          AND metadata->>'dlp_classified' = 'true'
          AND COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by') IS NULL
        LIMIT 50
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        cats = r["cats"] if isinstance(r["cats"], list) else []
        matches.append(ToxicMatch(
            rule_id="unowned_high_risk",
            severity="medium",
            title=f"Unowned high-risk resource: {r['name']}",
            description=(
                f"{r['resource_type']} '{r['name']}' is classified as "
                f"{r['risk_level']} risk ({', '.join(cats[:3]) if cats else 'sensitive'}) "
                f"but has no owner / CreatedBy / Owner tag. Without an owner there is "
                f"nobody to triage when an alert fires."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "type": r["resource_type"],
                "region": r["region"],
            }],
            factors=[
                f"Risk level: {r['risk_level']}",
                "No owner tag",
                f"Categories: {', '.join(cats[:3])}" if cats else "Sensitive content",
            ],
            primary_keys=[r["id"]],
        ))
    return matches


async def _rule_shadow_data_external(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """SaaS file shared externally / publicly that DLP classified as sensitive."""
    sql = text("""
        SELECT id::text, item_name, provider, item_type, sharing_scope,
               owner_email, classification_label, classification_categories
        FROM saas_data_items
        WHERE org_id = CAST(:org_id AS UUID)
          AND sharing_scope IN ('external','public')
          AND classification_label IN ('confidential','highly_confidential','restricted')
        LIMIT 100
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        cats = r["classification_categories"] or []
        if isinstance(cats, str):
            try:
                cats = json.loads(cats)
            except Exception:
                cats = []
        matches.append(ToxicMatch(
            rule_id="shadow_data_external",
            severity="high" if r["sharing_scope"] == "public" else "medium",
            title=f"Sensitive {r['item_type']} shared externally: {r['item_name']}",
            description=(
                f"'{r['item_name']}' on {r['provider']} is shared "
                f"{r['sharing_scope']} and classified {r['classification_label']}. "
                f"Owner: {r['owner_email'] or 'unknown'}."
            ),
            resources=[{
                "id": r["id"],
                "name": r["item_name"],
                "provider": r["provider"],
                "type": r["item_type"],
                "owner": r["owner_email"],
                "sharing": r["sharing_scope"],
            }],
            factors=[
                f"Sharing: {r['sharing_scope']}",
                f"Classification: {r['classification_label']}",
                f"Categories: {', '.join(cats[:3])}" if cats else "",
            ],
            primary_keys=[r["id"]],
        ))
    return matches


async def _rule_secret_in_public_notebook(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Databricks notebook containing secrets, with broader-than-private sharing."""
    sql = text("""
        SELECT id::text, name, resource_path, created_by, has_secrets,
               metadata->'dlp_categories' as cats
        FROM databricks_resources
        WHERE org_id = CAST(:org_id AS UUID)
          AND resource_type = 'notebook'
          AND has_secrets = TRUE
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        cats = r["cats"] if isinstance(r["cats"], list) else []
        matches.append(ToxicMatch(
            rule_id="secret_in_public_notebook",
            severity="high",
            title=f"Databricks notebook with secrets: {r['name']}",
            description=(
                f"Notebook '{r['name']}' at {r['resource_path']} contains hardcoded "
                f"secrets. Rotate them and move into Databricks secret scopes."
            ),
            resources=[{
                "id": r["id"],
                "name": r["name"],
                "path": r["resource_path"],
                "owner": r["created_by"],
            }],
            factors=[
                "Hardcoded secrets detected",
                f"DLP categories: {', '.join(cats[:3])}" if cats else "",
            ],
            primary_keys=[r["id"]],
        ))
    return matches


async def _rule_cross_provider_exposure(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Same owner has public resources across multiple cloud providers — blast radius."""
    sql = text("""
        WITH owners_aws AS (
          SELECT COALESCE(metadata->>'owner', metadata->>'created_by') as owner, COUNT(*) as n
          FROM aws_resources
          WHERE org_id = CAST(:org_id AS UUID) AND public_access = TRUE
          GROUP BY 1
        ),
        owners_gcp AS (
          SELECT COALESCE(metadata->>'owner', metadata->>'created_by') as owner, COUNT(*) as n
          FROM gcp_resources
          WHERE org_id = CAST(:org_id AS UUID) AND public_access = TRUE
          GROUP BY 1
        ),
        owners_saas AS (
          SELECT owner_email as owner, COUNT(*) as n
          FROM saas_data_items
          WHERE org_id = CAST(:org_id AS UUID) AND sharing_scope IN ('external','public')
          GROUP BY 1
        )
        SELECT
          a.owner,
          a.n AS aws_n,
          COALESCE(g.n, 0) AS gcp_n,
          COALESCE(s.n, 0) AS saas_n
        FROM owners_aws a
        LEFT JOIN owners_gcp  g ON g.owner  = a.owner
        LEFT JOIN owners_saas s ON s.owner  = a.owner
        WHERE a.owner IS NOT NULL
          AND ((COALESCE(g.n,0) > 0) OR (COALESCE(s.n,0) > 0))
        LIMIT 50
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches = []
    for r in rows:
        total = r["aws_n"] + r["gcp_n"] + r["saas_n"]
        matches.append(ToxicMatch(
            rule_id="cross_provider_exposure",
            severity="high",
            title=f"Cross-cloud public exposure by {r['owner']}",
            description=(
                f"{r['owner']} owns {total} publicly-exposed assets across "
                f"AWS({r['aws_n']}) GCP({r['gcp_n']}) SaaS({r['saas_n']}). "
                f"A single credential compromise has multi-cloud blast radius."
            ),
            resources=[{"owner": r["owner"], "aws": r["aws_n"], "gcp": r["gcp_n"], "saas": r["saas_n"]}],
            factors=[
                f"AWS public: {r['aws_n']}",
                f"GCP public: {r['gcp_n']}",
                f"SaaS shared externally: {r['saas_n']}",
            ],
            primary_keys=[f"owner:{r['owner']}"],
        ))
    return matches


# ── Salesforce SSPM rules ─────────────────────────────────────────────────
# Adnan 2026-06-22: with the SALSA-inspired connector landed in rev 368,
# Salesforce orgs now emit `salesforce_findings` + `salesforce_objects`.
# These rules turn the most damaging findings into top-of-queue toxic
# combinations so they jump the Workspace Security > Alerts UI.

async def _rule_salesforce_guest_custom_object(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Custom (*__c) sObject readable by an unauthenticated guest.

    Almost always indicates customer/business data that was not meant
    to be public.
    """
    try:
        sql = text("""
            SELECT id::text, sobject_name, sample_record_id, discovered_at,
                   connection_id::text
            FROM salesforce_objects
            WHERE org_id = CAST(:org_id AS UUID)
              AND guest_accessible = TRUE
              AND is_custom = TRUE
            ORDER BY discovered_at DESC
            LIMIT 50
        """)
        rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    except Exception:
        return []
    matches = []
    for r in rows:
        matches.append(ToxicMatch(
            rule_id="salesforce_guest_custom_object",
            severity="critical",
            title=f"Salesforce: custom object {r['sobject_name']} readable as guest",
            description=(
                f"The Aura controller for sObject {r['sobject_name']} returns "
                f"record id {r['sample_record_id'] or '?'} without authentication. "
                f"Custom objects (*__c) almost always contain customer or business "
                f"data — SALSA-style enumeration would dump every record."
            ),
            resources=[{
                "id": r["id"],
                "name": r["sobject_name"],
                "provider": "salesforce",
                "cloud": "salesforce",
                "connection_id": r["connection_id"],
            }],
            factors=[
                "Guest user can read records",
                "Custom object (*__c)",
                f"Sample record id: {r['sample_record_id'] or 'unknown'}",
            ],
            primary_keys=[f"sfdc:{r['connection_id']}:{r['sobject_name']}"],
            metadata={"sobject": r["sobject_name"]},
        ))
    return matches


async def _rule_salesforce_guest_pii_object(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Standard high-PII sObject (User, Contact, Account, Lead) readable as guest."""
    try:
        sql = text("""
            SELECT id::text, sobject_name, sample_record_id, connection_id::text
            FROM salesforce_objects
            WHERE org_id = CAST(:org_id AS UUID)
              AND guest_accessible = TRUE
              AND sobject_name IN ('User','Contact','Account','Lead','Order','Case','EmailMessage')
            LIMIT 50
        """)
        rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    except Exception:
        return []
    matches = []
    for r in rows:
        matches.append(ToxicMatch(
            rule_id="salesforce_guest_pii_object",
            severity="critical",
            title=f"Salesforce: PII sObject {r['sobject_name']} readable as guest",
            description=(
                f"Standard sObject {r['sobject_name']} (contains personal/customer data) "
                f"returns record id {r['sample_record_id'] or '?'} without authentication. "
                f"This violates GDPR / CCPA / NESA controls on personal data access."
            ),
            resources=[{
                "id": r["id"],
                "name": r["sobject_name"],
                "provider": "salesforce",
                "cloud": "salesforce",
                "connection_id": r["connection_id"],
            }],
            factors=[
                "Guest user can read records",
                "Standard PII-bearing object",
                f"Sample record id: {r['sample_record_id'] or 'unknown'}",
            ],
            primary_keys=[f"sfdc-pii:{r['connection_id']}:{r['sobject_name']}"],
            metadata={"sobject": r["sobject_name"]},
        ))
    return matches


async def _rule_salesforce_api_anonymous_enum(org_id: str, db: AsyncSession) -> list[ToxicMatch]:
    """Anonymous REST sObjects enumeration or SOAP API reachable as guest."""
    try:
        sql = text("""
            SELECT id::text, finding_id, severity, title, description,
                   connection_id::text, metadata, sobject_name
            FROM salesforce_findings
            WHERE org_id = CAST(:org_id AS UUID)
              AND status = 'open'
              AND finding_id LIKE 'sf-api-%'
            LIMIT 25
        """)
        rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    except Exception:
        return []
    matches = []
    for r in rows:
        matches.append(ToxicMatch(
            rule_id="salesforce_api_anonymous_enum",
            severity=r["severity"] if r["severity"] in ("critical", "high") else "high",
            title=f"Salesforce: {r['title']}",
            description=r["description"] or "Anonymous Salesforce API endpoint reachable.",
            resources=[{
                "id": r["id"],
                "name": r["sobject_name"] or r["finding_id"],
                "provider": "salesforce",
                "cloud": "salesforce",
                "connection_id": r["connection_id"],
            }],
            factors=[
                "Anonymous API endpoint reachable",
                f"Finding: {r['finding_id']}",
            ],
            primary_keys=[f"sfdc-api:{r['finding_id']}"],
        ))
    return matches


# ── Rev 374: SharePoint + Teams + data-lifecycle rules ──────────────────────

async def _rule_sharepoint_anyone_link_sensitive(
    org_id: str, db: AsyncSession
) -> list[ToxicMatch]:
    """SharePoint/OneDrive file with confidential classification AND a public
    or external sharing scope. This is the single biggest accidental-leak
    vector inside M365 — someone clicks "Anyone with the link" on a doc
    that contains PII or credentials.
    """
    sql = text("""
        SELECT id::text, provider, item_id, item_name, item_url,
               owner_email, classification_label, classification_categories,
               sharing_scope, last_modified_at
          FROM saas_data_items
         WHERE org_id = CAST(:org_id AS UUID)
           AND provider IN ('sharepoint','onedrive','teams')
           AND classification_label IN ('confidential','highly_confidential')
           AND sharing_scope IN ('public','external')
         ORDER BY
           CASE WHEN classification_label = 'highly_confidential' THEN 0 ELSE 1 END,
           last_modified_at DESC NULLS LAST
         LIMIT 50
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches: list[ToxicMatch] = []
    for r in rows:
        cats = r["classification_categories"] or []
        sev = "critical" if r["classification_label"] == "highly_confidential" else "high"
        scope_label = "Anyone with the link" if r["sharing_scope"] == "public" else "External user(s)"
        matches.append(ToxicMatch(
            rule_id="sharepoint_anyone_link_sensitive",
            severity=sev,
            title=f"{r['provider'].title()}: confidential file shared externally — {r['item_name']}",
            description=(
                f"'{r['item_name']}' is classified {r['classification_label'].replace('_',' ')}"
                + (f" ({', '.join(cats[:3])})" if cats else "")
                + f" and is shared via '{scope_label}'. Anyone with the URL"
                + (" can open it without signing in." if r["sharing_scope"] == "public"
                   else " external to the org can access it.")
            ),
            resources=[{
                "id": r["id"],
                "name": r["item_name"],
                "url": r["item_url"],
                "owner": r["owner_email"],
                "provider": r["provider"],
                "cloud": "m365",
            }],
            factors=[
                f"Sharing scope: {r['sharing_scope']}",
                f"Classification: {r['classification_label']}",
                f"Categories: {', '.join(cats[:3])}" if cats else "Sensitive categories present",
                f"Owner: {r['owner_email']}" if r["owner_email"] else "Owner unknown",
            ],
            primary_keys=[r["id"]],
            metadata={
                "categories": cats,
                "sharing_scope": r["sharing_scope"],
                "owner_email": r["owner_email"],
            },
        ))
    return matches


async def _rule_stale_sensitive_data(
    org_id: str, db: AsyncSession
) -> list[ToxicMatch]:
    """Confidential or highly_confidential data not touched in 365+ days.
    Classic data-lifecycle / minimisation finding — most regulatory regimes
    (GDPR, PDPL, HIPAA retention) require justification for keeping
    sensitive data past business need.
    """
    sql = text("""
        SELECT id::text, provider, item_name, item_url, owner_email,
               classification_label, classification_categories,
               last_modified_at,
               EXTRACT(EPOCH FROM (NOW() - last_modified_at))/86400 AS days_stale
          FROM saas_data_items
         WHERE org_id = CAST(:org_id AS UUID)
           AND classification_label IN ('confidential','highly_confidential')
           AND last_modified_at IS NOT NULL
           AND last_modified_at < NOW() - INTERVAL '365 days'
         ORDER BY last_modified_at ASC
         LIMIT 50
    """)
    rows = (await db.execute(sql, {"org_id": org_id})).mappings().all()
    matches: list[ToxicMatch] = []
    for r in rows:
        cats = r["classification_categories"] or []
        days = int(r["days_stale"] or 0)
        sev = "high" if r["classification_label"] == "highly_confidential" else "medium"
        matches.append(ToxicMatch(
            rule_id="stale_sensitive_data",
            severity=sev,
            title=f"Stale sensitive file ({days}d untouched): {r['item_name']}",
            description=(
                f"'{r['item_name']}' on {r['provider']} is classified "
                f"{r['classification_label'].replace('_',' ')}"
                + (f" ({', '.join(cats[:3])})" if cats else "")
                + f" and has not been modified in {days} days. "
                f"Review retention need or archive/delete to reduce blast radius."
            ),
            resources=[{
                "id": r["id"],
                "name": r["item_name"],
                "url": r["item_url"],
                "owner": r["owner_email"],
                "provider": r["provider"],
                "cloud": "m365" if r["provider"] in ("sharepoint","onedrive","teams") else r["provider"],
            }],
            factors=[
                f"Days since modified: {days}",
                f"Classification: {r['classification_label']}",
                f"Categories: {', '.join(cats[:3])}" if cats else "Sensitive",
                f"Owner: {r['owner_email']}" if r["owner_email"] else "Owner unknown",
            ],
            primary_keys=[r["id"]],
            metadata={
                "days_stale": days,
                "categories": cats,
                "owner_email": r["owner_email"],
            },
        ))
    return matches


async def _rule_external_owner_confidential(
    org_id: str, db: AsyncSession
) -> list[ToxicMatch]:
    """Confidential file whose owner_email is outside the org's primary
    domain set (looks like an external guest owns sensitive data).
    Bounded to top 30 hits.
    """
    try:
        # Get the org's primary domains from users + integrations table.
        domains_sql = text("""
            SELECT DISTINCT lower(split_part(email,'@',2)) AS d
              FROM users
             WHERE org_id = CAST(:org_id AS UUID)
               AND email IS NOT NULL AND email <> ''
        """)
        rows = (await db.execute(domains_sql, {"org_id": org_id})).mappings().all()
        domains = [r["d"] for r in rows if r["d"]]
        if not domains:
            return []
    except Exception:
        return []
    sql = text("""
        SELECT id::text, provider, item_name, item_url, owner_email,
               classification_label, classification_categories,
               sharing_scope, last_modified_at
          FROM saas_data_items
         WHERE org_id = CAST(:org_id AS UUID)
           AND provider IN ('sharepoint','onedrive','teams')
           AND classification_label IN ('confidential','highly_confidential')
           AND owner_email IS NOT NULL
           AND owner_email <> ''
           AND lower(split_part(owner_email,'@',2)) <> ALL(:domains)
         ORDER BY last_modified_at DESC NULLS LAST
         LIMIT 30
    """)
    rows = (await db.execute(sql, {"org_id": org_id, "domains": domains})).mappings().all()
    matches: list[ToxicMatch] = []
    for r in rows:
        cats = r["classification_categories"] or []
        sev = "critical" if r["classification_label"] == "highly_confidential" else "high"
        matches.append(ToxicMatch(
            rule_id="external_owner_confidential",
            severity=sev,
            title=f"External user owns confidential file: {r['item_name']}",
            description=(
                f"'{r['item_name']}' is classified {r['classification_label'].replace('_',' ')}"
                + (f" ({', '.join(cats[:3])})" if cats else "")
                + f" but its owner '{r['owner_email']}' is outside the org's known domains. "
                f"Guests holding sensitive data is a common insider/leak risk."
            ),
            resources=[{
                "id": r["id"],
                "name": r["item_name"],
                "url": r["item_url"],
                "owner": r["owner_email"],
                "provider": r["provider"],
                "cloud": "m365",
            }],
            factors=[
                f"Owner outside org domains: {r['owner_email']}",
                f"Classification: {r['classification_label']}",
                f"Sharing scope: {r['sharing_scope'] or 'unknown'}",
            ],
            primary_keys=[r["id"]],
            metadata={
                "owner_email": r["owner_email"],
                "categories": cats,
            },
        ))
    return matches


# Rule registry — order matters for deterministic ordering in UI.
RULES: list[tuple[ToxicRule, Any]] = [
    (ToxicRule("public_pii_bucket",         "Public bucket with sensitive data",
               "Combines public access with PII/PCI/PHI classification.", "critical"),
     _rule_public_pii_bucket),
    (ToxicRule("public_db_with_data",       "Public database",
               "Database engine reachable from the public internet.", "critical"),
     _rule_public_db_with_data),
    (ToxicRule("unencrypted_confidential",  "Unencrypted confidential resource",
               "Confidential data at rest with encryption off.", "high"),
     _rule_unencrypted_confidential),
    (ToxicRule("production_unencrypted",    "Production resource without encryption",
               "Resource tagged production with encryption disabled.", "high"),
     _rule_production_unencrypted),
    (ToxicRule("secret_in_public_notebook", "Databricks notebook contains secrets",
               "Hardcoded secrets in collaborative notebook.", "high"),
     _rule_secret_in_public_notebook),
    (ToxicRule("shadow_data_external",      "Sensitive file shared externally",
               "Confidential SaaS file with external / public share.", "high"),
     _rule_shadow_data_external),
    (ToxicRule("cross_provider_exposure",   "Cross-cloud blast radius",
               "Single owner with public assets across multiple providers.", "high"),
     _rule_cross_provider_exposure),
    (ToxicRule("unowned_high_risk",         "High-risk resource without owner",
               "No one assigned to triage when this fires.", "medium"),
     _rule_unowned_high_risk),
    (ToxicRule("salesforce_guest_custom_object", "Salesforce: guest-readable custom object",
               "Custom (*__c) sObject readable by an unauthenticated guest user.", "critical"),
     _rule_salesforce_guest_custom_object),
    (ToxicRule("salesforce_guest_pii_object", "Salesforce: guest-readable PII object",
               "Standard PII-bearing object (User/Contact/Account/Lead) reachable as guest.", "critical"),
     _rule_salesforce_guest_pii_object),
    (ToxicRule("salesforce_api_anonymous_enum", "Salesforce: anonymous API enumeration",
               "Anonymous REST sObjects / SOAP Partner API reachable on the instance.", "high"),
     _rule_salesforce_api_anonymous_enum),
    # ── Rev 374 ──
    (ToxicRule("sharepoint_anyone_link_sensitive",
               "SharePoint/OneDrive: confidential file shared externally",
               "Confidential or highly_confidential M365 file with public / external sharing scope.",
               "critical"),
     _rule_sharepoint_anyone_link_sensitive),
    (ToxicRule("external_owner_confidential",
               "External user owns confidential M365 file",
               "M365 SaaS file is owned by an email outside the org's known domains.",
               "high"),
     _rule_external_owner_confidential),
    (ToxicRule("stale_sensitive_data",
               "Stale sensitive data (365d+ untouched)",
               "Confidential data that hasn't been modified for over a year — retention/minimisation risk.",
               "medium"),
     _rule_stale_sensitive_data),
]


# ── Engine ───────────────────────────────────────────────────────────────────

async def run_for_org(org_id: str, db: AsyncSession) -> dict[str, Any]:
    """Run every enabled rule for one org, upsert into toxic_combinations, and
    mirror open critical/high entries into saas_alerts so the existing alerts
    UI surfaces them. Returns a small summary for logging."""
    await ensure_schema(db)

    all_matches: list[ToxicMatch] = []
    rule_counts: dict[str, int] = {}

    for rule, fn in RULES:
        if not rule.enabled:
            continue
        try:
            ms = await fn(org_id, db)
            rule_counts[rule.rule_id] = len(ms)
            all_matches.extend(ms)
        except Exception as exc:
            logger.warning(f"toxic: rule {rule.rule_id} failed for org {org_id}: {exc}")
            rule_counts[rule.rule_id] = -1  # -1 marker = errored

    upserted = 0
    for m in all_matches:
        try:
            await db.execute(text("""
                INSERT INTO toxic_combinations
                    (org_id, rule_id, severity, title, description,
                     resources, fingerprint, factors, status, first_seen_at, last_seen_at, metadata)
                VALUES
                    (CAST(:org_id AS UUID), :rule_id, :severity, :title, :description,
                     CAST(:resources AS jsonb), :fingerprint, CAST(:factors AS jsonb), 'open', NOW(), NOW(),
                     CAST(:metadata AS jsonb))
                ON CONFLICT (org_id, rule_id, fingerprint) DO UPDATE SET
                    severity      = EXCLUDED.severity,
                    title         = EXCLUDED.title,
                    description   = EXCLUDED.description,
                    resources     = EXCLUDED.resources,
                    factors       = EXCLUDED.factors,
                    last_seen_at  = NOW(),
                    -- Only re-open if we had marked it resolved.
                    status        = CASE WHEN toxic_combinations.status = 'resolved' THEN 'open'
                                         ELSE toxic_combinations.status END
            """), {
                "org_id": org_id,
                "rule_id": m.rule_id,
                "severity": m.severity,
                "title": m.title[:500],
                "description": m.description[:2000],
                "resources": json.dumps(m.resources),
                "fingerprint": m.fingerprint,
                "factors": json.dumps([f for f in m.factors if f]),
                "metadata": json.dumps(m.metadata or {}),
            })
            upserted += 1
        except Exception as exc:
            logger.warning(f"toxic: upsert failed rule={m.rule_id}: {exc}")

    # Auto-resolve: any open combination we didn't see this cycle. Only sweep
    # rules that actually ran (rule_counts >= 0). Cycle window = 30 min so a
    # transient rule failure doesn't flap.
    seen_fps_by_rule: dict[str, set[str]] = {}
    for m in all_matches:
        seen_fps_by_rule.setdefault(m.rule_id, set()).add(m.fingerprint)

    swept = 0
    for rule, _ in RULES:
        if rule_counts.get(rule.rule_id, -1) < 0:
            continue
        seen = list(seen_fps_by_rule.get(rule.rule_id, set()))
        try:
            result = await db.execute(text(f"""
                UPDATE toxic_combinations
                SET status = 'resolved', resolved_at = NOW()
                WHERE org_id   = CAST(:org_id AS UUID)
                  AND rule_id  = :rule_id
                  AND status   = 'open'
                  AND last_seen_at < NOW() - INTERVAL '30 minutes'
                  {"AND fingerprint <> ALL(CAST(:seen AS text[]))" if seen else ""}
            """), {"org_id": org_id, "rule_id": rule.rule_id, **({"seen": seen} if seen else {})})
            swept += result.rowcount or 0
        except Exception as exc:
            logger.debug(f"toxic: sweep failed rule={rule.rule_id}: {exc}")

    # Commit toxic_combinations writes FIRST. The saas_alerts mirror runs in
    # its own transaction so any constraint mismatch there (e.g. the
    # ON CONFLICT clause referencing a UNIQUE we don't actually have)
    # cannot poison the toxic_combinations writes via asyncpg's failed-tx
    # semantics.
    await db.commit()

    # Mirror open critical/high entries into saas_alerts. Best-effort: skip
    # rows that already exist for this org+title+resource and avoid relying
    # on an ON CONFLICT clause whose underlying UNIQUE may not exist.
    alert_mirrored = 0
    # Recommended next-step text per rule — surfaced as posture_result.remediation
    # so the AlertDetailPanel side-pane shows a concrete "do this".
    _REMEDIATION_BY_RULE = {
        "public_pii_bucket":            "Remove public ACLs / bucket policy and enable Block Public Access. Rotate any keys that ever touched the bucket.",
        "public_db_with_data":          "Move database into private subnets and require IAM auth or strong creds. Audit recent connections.",
        "unencrypted_confidential":     "Enable encryption at rest (KMS/CMK). Re-key existing data and rotate keys.",
        "production_unencrypted":       "Enable encryption at rest for the production resource and verify backups are encrypted.",
        "secret_in_public_notebook":    "Move secrets to a vault, revoke the exposed secret, and rotate downstream credentials.",
        "shadow_data_external":         "Remove external sharing on the resource or move the data into a sanctioned location.",
        "cross_provider_exposure":      "Audit and revoke the cross-cloud trust/role until business owner is identified.",
        "unowned_high_risk":            "Assign an owner tag (Owner / OwnerEmail) and route to that owner for review.",
        "salesforce_guest_custom_object": "Open Salesforce Setup → Sites → Guest User Profile and remove Read access from this custom object. Audit CRUD/FLS and re-run the Helios scan.",
        "salesforce_guest_pii_object": "Restrict guest user access to this standard object in Setup → Profiles → Site Guest User. Review sharing rules and field-level security.",
        "salesforce_api_anonymous_enum": "In Setup → Session Settings restrict API access for guest users. Disable Partner SOAP if not used. Block /services/data and /services/Soap from the guest profile.",
    }
    for m in all_matches:
        if m.severity not in ("critical", "high"):
            continue
        provider = (m.resources[0] if m.resources else {}).get("cloud") or \
                   (m.resources[0] if m.resources else {}).get("provider") or \
                   "platform"
        resource_name = (m.resources[0] if m.resources else {}).get("name") or m.rule_id
        title = m.title[:300]
        desc = m.description[:1000]
        resource = str(resource_name)[:300]
        # Build a posture_result blob the existing AlertDetailPanel
        # renders (posture_risk + findings list + remediation). Each
        # finding is one row of "why this fired" — owner, public access,
        # encryption state, the DLP categories, etc. — pulled from the
        # rule's factors list. The frontend AlertDetailPanel already
        # knows how to render alert.posture_result.findings/remediation.
        findings_list = [f for f in (m.factors or []) if f]
        # Always include the rule_id so an analyst can correlate quickly.
        findings_list = findings_list + [f"Rule: {m.rule_id}"]
        # Include resource provenance (cloud + region + owner if known).
        primary = (m.resources[0] if m.resources else {}) or {}
        if primary.get("region"):
            findings_list.append(f"Region: {primary['region']}")
        if primary.get("owner"):
            findings_list.append(f"Owner: {primary['owner']}")
        else:
            findings_list.append("Owner: unassigned")
        posture_blob = {
            "posture_risk": m.severity,
            "findings": findings_list[:12],
            "remediation": _REMEDIATION_BY_RULE.get(
                m.rule_id,
                "Review the affected resource, restrict access, encrypt at rest, and assign an owner.",
            ),
            "rule_id": m.rule_id,
            "resources": [
                {
                    "name": (r or {}).get("name"),
                    "id": (r or {}).get("id"),
                    "region": (r or {}).get("region"),
                    "cloud": (r or {}).get("cloud") or (r or {}).get("provider"),
                }
                for r in (m.resources or [])[:5]
            ],
        }
        try:
            exists = (await db.execute(text(
                "SELECT 1 FROM saas_alerts "
                "WHERE org_id = CAST(:org_id AS UUID) "
                "  AND title = :title "
                "  AND COALESCE(resource_name,'') = COALESCE(:resource,'') "
                "LIMIT 1"
            ), {"org_id": org_id, "title": title, "resource": resource})).scalar()
            if exists:
                # Refresh timestamp + severity + posture_result for the existing row
                # so an analyst always sees the latest "why" without re-creating rows.
                await db.execute(text(
                    "UPDATE saas_alerts SET severity = :sev, description = :desc, "
                    "       posture_result = CAST(:posture AS jsonb), created_at = NOW() "
                    "WHERE org_id = CAST(:org_id AS UUID) "
                    "  AND title = :title "
                    "  AND COALESCE(resource_name,'') = COALESCE(:resource,'')"
                ), {"org_id": org_id, "sev": m.severity, "desc": desc,
                    "title": title, "resource": resource,
                    "posture": _json_dumps_safe(posture_blob)})
            else:
                await db.execute(text("""
                    INSERT INTO saas_alerts
                        (id, org_id, provider, alert_type, severity, title, description,
                         resource_name, status, posture_result, created_at)
                    VALUES
                        (gen_random_uuid(), CAST(:org_id AS UUID), :provider,
                         'toxic_combination', :severity, :title, :desc, :resource, 'open',
                         CAST(:posture AS jsonb), NOW())
                """), {
                    "org_id": org_id, "provider": provider,
                    "severity": m.severity, "title": title,
                    "desc": desc, "resource": resource,
                    "posture": _json_dumps_safe(posture_blob),
                })
            await db.commit()
            alert_mirrored += 1
        except Exception as exc:
            # Roll back this one row, keep going.
            try:
                await db.rollback()
            except Exception:
                pass
            logger.debug(f"toxic: alert mirror failed for rule={m.rule_id}: {exc}")

    # Sanity self-check: how many rows actually persisted for this org?
    try:
        persisted = (await db.execute(text(
            "SELECT COUNT(*) FROM toxic_combinations WHERE org_id = CAST(:org_id AS UUID)"
        ), {"org_id": org_id})).scalar() or 0
    except Exception as _pc:
        persisted = -1
    try:
        total_rows = (await db.execute(text(
            "SELECT COUNT(*) FROM toxic_combinations"
        ))).scalar() or 0
    except Exception:
        total_rows = -1
    try:
        table_exists = (await db.execute(text(
            "SELECT to_regclass('public.toxic_combinations')::text"
        ))).scalar()
    except Exception:
        table_exists = None

    summary = {
        "org_id": org_id,
        "matches": len(all_matches),
        "upserted": upserted,
        "persisted": persisted,
        "total_rows": total_rows,
        "table_exists": table_exists,
        "swept": swept,
        "alert_mirrored": alert_mirrored,
        "rule_counts": rule_counts,
    }
    logger.info(f"toxic: org={org_id} {summary}")
    return summary


async def get_rules() -> list[dict]:
    """Return the rule catalogue for the UI / API."""
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "enabled": r.enabled,
        }
        for r, _ in RULES
    ]
