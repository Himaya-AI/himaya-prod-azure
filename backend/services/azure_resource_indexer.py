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
  3. Classifies each resource with **Claude** — connector data classification is
     Claude-driven — falling back to the deterministic heuristic classifier only
     when Claude is unavailable or errors.
  4. Upserts rows into `azure_resources` with
     `dlp_classified` / `dlp_categories` / `dlp_risk_level` / `dlp_source`
     metadata (same shape the rest of the platform reads).
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Claude model used for connector data classification (fast + cheap).
_CLAUDE_MODEL = "claude-haiku-4-5"
# Cap how many resources we ship to Claude per scan to bound cost/latency.
_MAX_CLASSIFY = 400
# Resources per Claude request (batched to keep it to a handful of calls).
_BATCH_SIZE = 50

# Category vocabulary Claude is allowed to choose from — kept aligned with the
# heuristic classifier + DSPM categories so downstream filters stay consistent.
_CATEGORIES = (
    "pii, pci, phi, financial, credentials, source_code, backup, logs, config, "
    "network, ml_data, public_data, database, storage, identity, infrastructure"
)

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
        elif resource_type == "managed_disk":
            encryption_enabled = bool((props.get("encryption") or {}).get("type"))
        elif resource_type == "key_vault":
            acls = props.get("networkAcls") or {}
            public_access = (acls.get("defaultAction") or "Allow").lower() == "allow"
        elif resource_type == "sql_server":
            public_access = (props.get("publicNetworkAccess") or "Enabled").lower() == "enabled"
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


async def _claude_classify_batch(batch: list[dict]) -> Optional[dict[int, tuple[list[str], str]]]:
    """Classify a batch of resources with Claude.

    Returns {index: (categories, risk_level)} or None if Claude is unavailable.
    """
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return None

    listing = "\n".join(
        f'{i}. name="{r["name"]}" type="{r["azure_type"] or r["resource_type"]}" '
        f'location={r["location"]} public={r["public_access"]} '
        f'encrypted={r["encryption_enabled"]} tags={json.dumps(r.get("tags") or {})[:200]}'
        for i, r in enumerate(batch)
    )
    prompt = (
        "You are a cloud data-security classifier. For each Azure resource below, "
        "infer what kind of data it most likely holds or governs and its data-security "
        "risk. Base the decision on the resource name, type, tags, public exposure and "
        "encryption.\n\n"
        f"Allowed categories (choose all that clearly apply): {_CATEGORIES}\n\n"
        f"Resources:\n{listing}\n\n"
        "Respond with a JSON array ONLY, one object per resource index, like:\n"
        '[{"i":0,"categories":["storage","pii"],"risk":"high"},{"i":1,'
        '"categories":["logs"],"risk":"low"}]\n'
        "risk must be one of: low, medium, high, critical. Do not add commentary."
    )
    try:
        async with httpx.AsyncClient(timeout=40) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": _CLAUDE_MODEL,
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code != 200:
                logger.warning(f"azure_indexer: Claude returned {r.status_code}")
                return None
            raw = r.json()["content"][0]["text"].strip()
            raw = re.sub(r"^```[\w]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
            parsed = json.loads(raw)
            result: dict[int, tuple[list[str], str]] = {}
            for entry in parsed:
                try:
                    idx = int(entry.get("i"))
                    cats = [str(c).lower().strip() for c in (entry.get("categories") or []) if c]
                    risk = str(entry.get("risk", "low")).lower().strip()
                    if risk not in ("low", "medium", "high", "critical"):
                        risk = "low"
                    result[idx] = (cats or ["infrastructure"], risk)
                except Exception:
                    continue
            return result
    except Exception as exc:
        logger.warning(f"azure_indexer: Claude classify failed: {exc}")
        return None


async def _classify_resources(resources: list[dict]) -> None:
    """Attach (categories, risk_level, source) to each resource in place.

    Claude is the primary classifier; the deterministic heuristic is used only
    as a fallback for resources Claude did not (or could not) classify.
    """
    from backend.services.cross_cloud_dlp import _classify_heuristic

    to_classify = resources[:_MAX_CLASSIFY]
    claude_used = False

    for start in range(0, len(to_classify), _BATCH_SIZE):
        batch = to_classify[start:start + _BATCH_SIZE]
        verdicts = await _claude_classify_batch(batch)
        if verdicts is not None:
            claude_used = True
            for i, r in enumerate(batch):
                if i in verdicts:
                    cats, risk = verdicts[i]
                    r["_dlp_categories"] = cats
                    r["_dlp_risk_level"] = risk
                    r["_dlp_source"] = "claude"

    # Heuristic fallback for anything Claude did not classify (or all, if Claude
    # is unavailable) so no resource is ever left uncategorised.
    for r in resources:
        if r.get("_dlp_categories"):
            continue
        cats, risk = _classify_heuristic(r)
        r["_dlp_categories"] = cats
        r["_dlp_risk_level"] = risk
        r["_dlp_source"] = "heuristic"

    logger.info(
        f"azure_indexer: classified {len(resources)} resources "
        f"(claude={'yes' if claude_used else 'no'})"
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
