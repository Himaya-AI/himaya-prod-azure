"""
Azure collector — populates ctx.cache with raw Azure ARM API responses.

Auth: client-credential flow (tenant_id + client_id + client_secret + subscription_id).
Stores responses under ctx.cache[<service>][<method>][<location_or_global>] = {data: [...], err: None}.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

from ..types import ScanContext

logger = logging.getLogger(__name__)

ARM_BASE = "https://management.azure.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"


async def acquire_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str = "https://management.azure.com/.default",
) -> Optional[str]:
    """Acquire an OAuth2 token via client_credentials."""
    url = f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(url, data=data)
            r.raise_for_status()
            return r.json().get("access_token")
    except Exception as exc:
        logger.warning(f"Azure token acquire failed: {exc}")
        return None


class AzureCollectorConfig:
    """Credentials + scoping for an Azure scan."""
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        locations: Optional[list[str]] = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.locations = locations or [
            "eastus", "westus", "westus2", "eastus2",
            "westeurope", "northeurope", "uaenorth", "centralus",
        ]


async def _arm_get(token: str, url: str) -> dict:
    async with httpx.AsyncClient(timeout=45.0) as client:
        r = await client.get(
            url if url.startswith("https://") else f"{ARM_BASE}{url}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code >= 400:
            return {"err": f"HTTP {r.status_code}: {r.text[:200]}", "data": None}
        return {"err": None, "data": r.json()}


async def _arm_paged(token: str, url: str, max_pages: int = 5) -> dict:
    """Follow @odata.nextLink for paged ARM responses, collect .value items."""
    all_items: list = []
    next_url: Optional[str] = url if url.startswith("https://") else f"{ARM_BASE}{url}"
    page = 0
    last_err: Optional[str] = None
    while next_url and page < max_pages:
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                r = await client.get(next_url, headers={"Authorization": f"Bearer {token}"})
                if r.status_code >= 400:
                    last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                    break
                body = r.json()
                items = body.get("value", body) if isinstance(body, dict) else body
                if isinstance(items, list):
                    all_items.extend(items)
                next_url = body.get("nextLink") or body.get("@odata.nextLink") if isinstance(body, dict) else None
                page += 1
        except Exception as exc:
            last_err = str(exc)
            break
    return {"err": last_err, "data": all_items}


async def collect_azure(ctx: ScanContext, config: Optional[AzureCollectorConfig] = None) -> None:
    """
    Populate ctx.cache with Azure ARM responses needed by plugins.
    Honors config.locations to limit region fan-out.
    """
    if config is None:
        # Expect creds in ctx.settings
        s = ctx.settings
        config = AzureCollectorConfig(
            tenant_id=s["tenant_id"],
            client_id=s["client_id"],
            client_secret=s["client_secret"],
            subscription_id=s["subscription_id"],
            locations=ctx.regions or None,
        )

    token = await acquire_token(
        config.tenant_id, config.client_id, config.client_secret,
        scope="https://management.azure.com/.default",
    )
    if not token:
        ctx.add_source(["__error__"], "Azure token acquire failed")
        return

    sub = config.subscription_id
    base = f"/subscriptions/{sub}"

    # ── Subscription-level (global) collections ───────────────────────────
    async def _collect_global() -> None:
        # Storage Accounts
        sa = await _arm_paged(token, f"{base}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01")
        ctx.add_source(["storageAccounts", "list", "global"], sa)

        # Key Vaults
        kv = await _arm_paged(token, f"{base}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01")
        ctx.add_source(["vaults", "list", "global"], kv)

        # Virtual Machines
        vm = await _arm_paged(token, f"{base}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01")
        ctx.add_source(["virtualMachines", "list", "global"], vm)

        # Disks
        disks = await _arm_paged(token, f"{base}/providers/Microsoft.Compute/disks?api-version=2023-04-02")
        ctx.add_source(["disks", "list", "global"], disks)

        # SQL Servers
        sql = await _arm_paged(token, f"{base}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview")
        ctx.add_source(["sqlServers", "list", "global"], sql)

        # Network Security Groups
        nsg = await _arm_paged(token, f"{base}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01")
        ctx.add_source(["networkSecurityGroups", "list", "global"], nsg)

        # Public IPs
        pip = await _arm_paged(token, f"{base}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-09-01")
        ctx.add_source(["publicIPAddresses", "list", "global"], pip)

        # App Services (web apps)
        web = await _arm_paged(token, f"{base}/providers/Microsoft.Web/sites?api-version=2023-01-01")
        ctx.add_source(["webApps", "list", "global"], web)

        # Resource Groups
        rg = await _arm_paged(token, f"{base}/resourcegroups?api-version=2022-09-01")
        ctx.add_source(["resourceGroups", "list", "global"], rg)

        # Activity Log Alerts
        ala = await _arm_paged(token, f"{base}/providers/Microsoft.Insights/activityLogAlerts?api-version=2020-10-01")
        ctx.add_source(["activityLogAlerts", "list", "global"], ala)

        # Subscription-level role assignments (sample of recent)
        ra = await _arm_paged(
            token,
            f"{base}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
            max_pages=2,
        )
        ctx.add_source(["roleAssignments", "list", "global"], ra)

        # Defender for Cloud pricings
        pricings = await _arm_get(
            token,
            f"{base}/providers/Microsoft.Security/pricings?api-version=2024-01-01",
        )
        ctx.add_source(["defender", "pricings", "global"], pricings)

        # Security center auto-provisioning
        autoProv = await _arm_get(
            token,
            f"{base}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview",
        )
        ctx.add_source(["defender", "autoProvisioning", "global"], autoProv)

    await _collect_global()

    # ── Per-storage-account details (encryption, blob services, network ACLs) ──
    sa_root = ctx.get_source(["storageAccounts", "list", "global"])
    sa_items = (sa_root or {}).get("data") or []
    sem = asyncio.Semaphore(8)

    async def _enrich_sa(item: dict) -> None:
        sid = item.get("id")
        if not sid:
            return
        async with sem:
            blob = await _arm_get(token, f"{sid}/blobServices/default?api-version=2023-01-01")
            ctx.add_source(["storageAccounts", "blobServices", sid], blob)
            file_svc = await _arm_get(token, f"{sid}/fileServices/default?api-version=2023-01-01")
            ctx.add_source(["storageAccounts", "fileServices", sid], file_svc)

    if sa_items:
        await asyncio.gather(*[_enrich_sa(it) for it in sa_items[:200]], return_exceptions=True)

    # ── Per-keyvault keys/secrets metadata ───────────────────────────────
    kv_root = ctx.get_source(["vaults", "list", "global"])
    kv_items = (kv_root or {}).get("data") or []

    # Try to grab a Vault-data-plane token (needs separate scope)
    vault_token = await acquire_token(
        config.tenant_id, config.client_id, config.client_secret,
        scope="https://vault.azure.net/.default",
    )

    async def _enrich_kv(item: dict) -> None:
        kid = item.get("id")
        props = item.get("properties") or {}
        vault_uri = props.get("vaultUri")
        if not (kid and vault_uri and vault_token):
            return
        async with sem:
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    r = await client.get(
                        f"{vault_uri}keys?api-version=7.4",
                        headers={"Authorization": f"Bearer {vault_token}"},
                    )
                    if r.status_code < 400:
                        ctx.add_source(["vaults", "getKeys", kid], {"err": None, "data": r.json().get("value", [])})
                    else:
                        ctx.add_source(["vaults", "getKeys", kid], {"err": f"HTTP {r.status_code}", "data": []})
                except Exception as exc:
                    ctx.add_source(["vaults", "getKeys", kid], {"err": str(exc), "data": []})
                try:
                    r = await client.get(
                        f"{vault_uri}secrets?api-version=7.4",
                        headers={"Authorization": f"Bearer {vault_token}"},
                    )
                    if r.status_code < 400:
                        ctx.add_source(["vaults", "getSecrets", kid], {"err": None, "data": r.json().get("value", [])})
                    else:
                        ctx.add_source(["vaults", "getSecrets", kid], {"err": f"HTTP {r.status_code}", "data": []})
                except Exception as exc:
                    ctx.add_source(["vaults", "getSecrets", kid], {"err": str(exc), "data": []})

    if kv_items and vault_token:
        await asyncio.gather(*[_enrich_kv(it) for it in kv_items[:100]], return_exceptions=True)

    # ── Per-SQL-server transparent data encryption / auditing ─────────────
    sql_root = ctx.get_source(["sqlServers", "list", "global"])
    sql_items = (sql_root or {}).get("data") or []

    async def _enrich_sql(item: dict) -> None:
        sid = item.get("id")
        if not sid:
            return
        async with sem:
            audit = await _arm_get(token, f"{sid}/auditingSettings/default?api-version=2021-11-01")
            ctx.add_source(["sqlServers", "auditingSettings", sid], audit)
            adAdmin = await _arm_get(token, f"{sid}/administrators/ActiveDirectory?api-version=2021-11-01")
            ctx.add_source(["sqlServers", "azureADAdmin", sid], adAdmin)

    if sql_items:
        await asyncio.gather(*[_enrich_sql(it) for it in sql_items[:100]], return_exceptions=True)

    # ── Per-VM extensions (for log analytics agent presence) ──────────────
    vm_root = ctx.get_source(["virtualMachines", "list", "global"])
    vm_items = (vm_root or {}).get("data") or []

    async def _enrich_vm(item: dict) -> None:
        vid = item.get("id")
        if not vid:
            return
        async with sem:
            ext = await _arm_get(token, f"{vid}/extensions?api-version=2023-09-01")
            ctx.add_source(["virtualMachines", "extensions", vid], ext)

    if vm_items:
        await asyncio.gather(*[_enrich_vm(it) for it in vm_items[:200]], return_exceptions=True)


def make_azure_collector(config: AzureCollectorConfig):
    """Curry a config-bound collector for engine registration."""
    async def _runner(ctx: ScanContext) -> None:
        await collect_azure(ctx, config)
    return _runner
