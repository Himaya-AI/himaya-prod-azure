"""
Azure resource indexer + Claude-driven data classifier.

Background
----------
The Azure CSPM scan (`azure_connector._run_background_scan`) evaluates plugins
and writes `cspm_findings`, but it historically never populated an
`azure_resources` inventory table. Every other cloud connector (AWS, GCP,
Databricks, Oracle, …) persists its enumerated resources into a
`<cloud>_resources` table which the Data Inventory, Sensitive Data Discovery,
cross-cloud DLP, toxic-combinations, permission-diff and data-lifecycle views
all read from. Azure had no such table, so:

  * the UI showed **zero Azure resources enumerated**, and
  * the cross-cloud DLP classifier had nothing to classify for Azure.

This module closes that gap. After a scan it:

  1. Ensures the `azure_resources` table exists (schema aligned with the other
     `*_resources` tables that downstream consumers expect).
  2. Extracts resources from the collector's `ScanContext` cache (storage
     accounts, key vaults, VMs, disks, SQL servers, NSGs, public IPs, app
     services).
  3. Classifies each resource with the **dlp-classifier service** — connector
     data classification is service-driven — falling back to the deterministic
     heuristic classifier only when the service is unavailable or errors.
  4. Upserts rows into `azure_resources` with
     `dlp_classified` / `dlp_categories` / `dlp_risk_level` / `dlp_source`
     metadata (same shape the rest of the platform reads).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Cap how many resources we ship to the classifier per scan to bound
# cost/latency (one HTTP call per resource, run with bounded concurrency).
_MAX_CLASSIFY = 400

# (cache service key, normalised resource_type) pairs to extract from the scan.
_SERVICE_MAP: list[tuple[str, str]] = [
    ("storageAccounts", "storage_account"),
    ("vaults", "key_vault"),
    ("virtualMachines", "virtual_machine"),
    ("disks", "managed_disk"),
    ("sqlServers", "sql_server"),
    ("networkSecurityGroups", "network_security_group"),
    ("publicIPAddresses", "public_ip"),
    ("webApps", "app_service"),
    ("containerApps", "container_app"),
    ("containerRegistries", "container_registry"),
    ("communicationServices", "communication_service"),
    ("redis", "redis_cache"),
    ("cdnProfiles", "cdn_profile"),
    ("logAnalyticsWorkspaces", "log_analytics_workspace"),
    ("managedIdentities", "managed_identity"),
    ("postgresServers", "postgres_server"),
    ("serviceBusNamespaces", "service_bus_namespace"),
]


async def ensure_azure_resources_table(db: AsyncSession) -> None:
    """Create the azure_resources inventory table if it does not yet exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS azure_resources (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            connection_id UUID,
            resource_id TEXT NOT NULL,
            name VARCHAR(512),
            resource_type VARCHAR(128),
            location VARCHAR(64),
            public_access BOOLEAN DEFAULT FALSE,
            encryption_enabled BOOLEAN DEFAULT TRUE,
            metadata JSONB DEFAULT '{}'::jsonb,
            scanned_at TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, resource_id)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_azure_resources_org ON azure_resources(org_id)"
    ))
    await db.commit()


def _derive_security_flags(resource_type: str, props: dict) -> tuple[bool, bool]:
    """Return (public_access, encryption_enabled) for a resource type."""
    public_access = False
    encryption_enabled = True
    try:
        if resource_type == "storage_account":
            public_access = bool(props.get("allowBlobPublicAccess"))
            enc = ((props.get("encryption") or {}).get("services") or {}).get("blob") or {}
            encryption_enabled = bool(enc.get("enabled", True))
        elif resource_type == "public_ip":
            public_access = True
        elif resource_type == "app_service":
            # Web apps are internet-facing unless access restrictions are set.
            public_access = not bool(props.get("privateEndpointConnections"))
        elif resource_type == "container_app":
            # Container apps are internet-facing unless ingress is disabled.
            ingress = props.get("configuration", {}).get("ingress") or {}
            public_access = ingress.get("external", True) and ingress.get("targetPort") is not None
        elif resource_type == "managed_disk":
            encryption_enabled = bool((props.get("encryption") or {}).get("type"))
        elif resource_type == "key_vault":
            acls = props.get("networkAcls") or {}
            public_access = (acls.get("defaultAction") or "Allow").lower() == "allow"
        elif resource_type == "sql_server":
            public_access = (props.get("publicNetworkAccess") or "Enabled").lower() == "enabled"
        elif resource_type == "postgres_server":
            public_access = (props.get("network", {}).get("publicNetworkAccess") or "Enabled").lower() == "enabled"
        elif resource_type == "redis_cache":
            public_access = (props.get("properties", {}).get("publicNetworkAccess") or "Enabled").lower() == "enabled"
        elif resource_type == "service_bus_namespace":
            public_access = (props.get("properties", {}).get("publicNetworkAccess") or "Enabled").lower() == "enabled"
        elif resource_type == "communication_service":
            # Communication services typically require public access for SMS/voice.
            public_access = True
        elif resource_type == "cdn_profile":
            # CDN is inherently public-facing.
            public_access = True
        elif resource_type == "log_analytics_workspace":
            # Log Analytics can be private, but often public for ingestion.
            public_access = True
        elif resource_type == "managed_identity":
            # Managed identities are internal, not directly accessible.
            public_access = False
        elif resource_type == "container_registry":
            # ACR can be public or private; check publicNetworkAccess.
            public_access = (props.get("properties", {}).get("publicNetworkAccess") or "Enabled").lower() == "enabled"
    except Exception:
        pass
    return public_access, encryption_enabled


def _extract_resources(ctx: Any) -> list[dict]:
    """Flatten the collector cache into a list of resource dicts."""
    out: list[dict] = []
    for svc_key, resource_type in _SERVICE_MAP:
        node = ctx.get_source([svc_key, "list", "global"]) or {}
        items = node.get("data") or []
        for item in items:
            if not isinstance(item, dict):
                continue
            rid = item.get("id")
            if not rid:
                continue
            props = item.get("properties") or {}
            tags = item.get("tags") or {}
            public_access, encryption_enabled = _derive_security_flags(resource_type, props)
            out.append({
                "resource_id": rid,
                "name": item.get("name") or rid.split("/")[-1],
                "resource_type": resource_type,
                "azure_type": item.get("type") or "",
                "location": item.get("location") or "global",
                "public_access": public_access,
                "encryption_enabled": encryption_enabled,
                "tags": tags if isinstance(tags, dict) else {},
            })
    return out


async def _service_classify_resource(r: dict) -> Optional[tuple[list[str], str]]:
    """Classify a single Azure resource via the dlp-classifier service.

    Returns (categories, risk_level) or None if the service is unavailable.
    """
    from backend.services import dlp_classifier_client as _clf

    text = (
        f'Azure resource name="{r["name"]}" '
        f'type="{r["azure_type"] or r["resource_type"]}" '
        f'location={r["location"]} public={r["public_access"]} '
        f'encrypted={r["encryption_enabled"]} '
        f'tags={json.dumps(r.get("tags") or {})[:200]}'
    )
    verdict = await _clf.classify_verdict(text)
    if verdict is None:
        return None
    cats = verdict.get("categories") or ["infrastructure"]
    risk = verdict.get("risk_level", "low")
    return cats, risk


async def _classify_resources(resources: list[dict]) -> None:
    """Attach (categories, risk_level, source) to each resource in place.

    The dlp-classifier service is the primary classifier; the deterministic
    heuristic is used only as a fallback for resources the service could not
    classify (e.g. transient outage).
    """
    import asyncio

    from backend.services.cross_cloud_dlp import _classify_heuristic

    to_classify = resources[:_MAX_CLASSIFY]
    service_used = False
    # Bounded concurrency keeps a large inventory fast without hammering the
    # service (it is one HTTP call per resource).
    sem = asyncio.Semaphore(8)

    async def _one(r: dict) -> None:
        nonlocal service_used
        async with sem:
            verdict = await _service_classify_resource(r)
        if verdict is not None:
            cats, risk = verdict
            r["_dlp_categories"] = cats
            r["_dlp_risk_level"] = risk
            r["_dlp_source"] = "dlp-classifier"
            service_used = True

    await asyncio.gather(*(_one(r) for r in to_classify))

    # Heuristic fallback for anything the service did not classify (or all, if
    # the service is unavailable) so no resource is ever left uncategorised.
    for r in resources:
        if r.get("_dlp_categories"):
            continue
        cats, risk = _classify_heuristic(r)
        r["_dlp_categories"] = cats
        r["_dlp_risk_level"] = risk
        r["_dlp_source"] = "heuristic"

    logger.info(
        f"azure_indexer: classified {len(resources)} resources "
        f"(service={'yes' if service_used else 'no'})"
    )


async def index_azure_resources(
    db: AsyncSession,
    org_id: str,
    connection_id: str,
    ctx: Any,
) -> int:
    """
    Persist + Claude-classify Azure resources from a completed scan's context.
    Returns the number of resources upserted.
    """
    await ensure_azure_resources_table(db)

    resources = _extract_resources(ctx)
    if not resources:
        logger.info(f"azure_indexer: no resources found in scan cache for conn={connection_id}")
        return 0

    await _classify_resources(resources)

    upserted = 0
    for r in resources:
        metadata = {
            "azure_type": r.get("azure_type", ""),
            "tags": r.get("tags") or {},
            "dlp_classified": "true",
            "dlp_categories": r.get("_dlp_categories") or [],
            "dlp_risk_level": r.get("_dlp_risk_level") or "low",
            "dlp_source": r.get("_dlp_source") or "heuristic",
        }
        try:
            await db.execute(text("""
                INSERT INTO azure_resources (
                    id, org_id, connection_id, resource_id, name, resource_type,
                    location, public_access, encryption_enabled, metadata, scanned_at
                ) VALUES (
                    gen_random_uuid(), CAST(:org AS UUID), CAST(:conn AS UUID), :rid, :name,
                    :rtype, :loc, :pub, :enc, CAST(:meta AS jsonb), NOW()
                )
                ON CONFLICT (org_id, resource_id) DO UPDATE SET
                    connection_id = EXCLUDED.connection_id,
                    name = EXCLUDED.name,
                    resource_type = EXCLUDED.resource_type,
                    location = EXCLUDED.location,
                    public_access = EXCLUDED.public_access,
                    encryption_enabled = EXCLUDED.encryption_enabled,
                    metadata = EXCLUDED.metadata,
                    scanned_at = NOW()
            """), {
                "org": org_id,
                "conn": connection_id,
                "rid": r["resource_id"],
                "name": r["name"][:512],
                "rtype": r["resource_type"],
                "loc": (r.get("location") or "global")[:64],
                "pub": bool(r.get("public_access")),
                "enc": bool(r.get("encryption_enabled")),
                "meta": json.dumps(metadata),
            })
            upserted += 1
        except Exception as exc:
            logger.debug(f"azure_indexer: upsert failed for {r.get('resource_id')}: {exc}")
            continue

    await db.commit()
    return upserted
