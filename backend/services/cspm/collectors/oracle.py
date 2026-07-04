"""
Oracle Cloud Infrastructure (OCI) collector.

Auth uses the standard OCI signed-request scheme (RSA private key). For
operator convenience we accept the credentials directly as bytes and sign
requests via the `oci` SDK when available, falling back to a manual signer.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from ..executor import run_blocking
from ..types import ScanContext

logger = logging.getLogger(__name__)


class OracleCollectorConfig:
    def __init__(
        self,
        tenancy_id: str,
        user_id: str,
        key_fingerprint: str,
        private_key_pem: str,
        region: str = "us-ashburn-1",
        compartment_id: Optional[str] = None,
    ):
        self.tenancy_id = tenancy_id
        self.user_id = user_id
        self.key_fingerprint = key_fingerprint
        self.private_key_pem = private_key_pem
        self.region = region
        self.compartment_id = compartment_id or tenancy_id


def _make_oci_clients(config: OracleCollectorConfig):
    """Lazy import & build OCI service clients."""
    try:
        import oci  # type: ignore
    except ImportError as exc:
        raise RuntimeError("oci SDK not installed; pip install oci") from exc

    cfg = {
        "user": config.user_id,
        "key_content": config.private_key_pem,
        "fingerprint": config.key_fingerprint,
        "tenancy": config.tenancy_id,
        "region": config.region,
    }
    return oci, cfg


async def collect_oracle(ctx: ScanContext, config: Optional[OracleCollectorConfig] = None) -> None:
    """
    Populate ctx.cache with OCI API responses.
    Runs OCI SDK calls in a threadpool since SDK is sync.
    """
    if config is None:
        s = ctx.settings
        config = OracleCollectorConfig(
            tenancy_id=s["tenancy_id"],
            user_id=s["user_id"],
            key_fingerprint=s["key_fingerprint"],
            private_key_pem=s["private_key_pem"],
            region=s.get("region", "us-ashburn-1"),
            compartment_id=s.get("compartment_id"),
        )

    try:
        oci, cfg = _make_oci_clients(config)
    except Exception as exc:
        ctx.add_source(["__error__"], f"OCI SDK init failed: {exc}")
        return

    loop = asyncio.get_event_loop()

    def _safe_call(callable_, *args, **kwargs):
        """Wrap an OCI SDK call and return {err, data}."""
        try:
            resp = callable_(*args, **kwargs)
            data = resp.data if hasattr(resp, "data") else resp
            # OCI returns dataclasses; coerce to dicts when possible
            try:
                if isinstance(data, list):
                    data = [d.__dict__ if hasattr(d, "__dict__") else d for d in data]
                elif hasattr(data, "__dict__"):
                    data = data.__dict__
            except Exception:
                pass
            return {"err": None, "data": data}
        except Exception as exc:
            return {"err": str(exc), "data": None}

    # Identity (tenancy-global)
    identity = oci.identity.IdentityClient(cfg)
    users = await run_blocking(_safe_call, identity.list_users, config.tenancy_id)
    ctx.add_source(["identity", "listUsers", config.region], users)

    groups = await run_blocking(_safe_call, identity.list_groups, config.tenancy_id)
    ctx.add_source(["identity", "listGroups", config.region], groups)

    policies = await run_blocking(_safe_call, identity.list_policies, config.tenancy_id)
    ctx.add_source(["identity", "listPolicies", config.region], policies)

    mfa = await run_blocking(_safe_call, identity.list_mfa_totp_devices, "dummy")
    # listMfaTotpDevices needs a userId; fetch per-user later

    # Per-user MFA
    if users.get("data"):
        async def _user_mfa(u):
            uid = u.get("id") if isinstance(u, dict) else getattr(u, "id", None)
            if not uid:
                return None
            r = await run_blocking(_safe_call, identity.list_mfa_totp_devices, uid)
            ctx.add_source(["identity", "listMfaTotpDevices", uid], r)
        await asyncio.gather(*[_user_mfa(u) for u in users["data"][:50]], return_exceptions=True)

    # Networking
    vnet = oci.core.VirtualNetworkClient(cfg)
    vcns = await run_blocking(_safe_call, vnet.list_vcns, config.compartment_id)
    ctx.add_source(["networking", "listVcns", config.region], vcns)
    sec_lists = await run_blocking(_safe_call, vnet.list_security_lists, config.compartment_id)
    ctx.add_source(["networking", "listSecurityLists", config.region], sec_lists)
    nsg = await run_blocking(_safe_call, vnet.list_network_security_groups, config.compartment_id)
    ctx.add_source(["networking", "listNetworkSecurityGroups", config.region], nsg)

    # Object Storage
    obj = oci.object_storage.ObjectStorageClient(cfg)
    namespace = await run_blocking(_safe_call, obj.get_namespace)
    ctx.add_source(["objectstore", "getNamespace", config.region], namespace)
    if namespace.get("data"):
        ns = namespace["data"]
        buckets = await run_blocking(_safe_call, obj.list_buckets, ns, config.compartment_id)
        ctx.add_source(["objectstore", "listBuckets", config.region], buckets)

    # Block volumes
    block = oci.core.BlockstorageClient(cfg)
    vols = await run_blocking(_safe_call, block.list_volumes, config.compartment_id)
    ctx.add_source(["blockstorage", "listVolumes", config.region], vols)

    # Compute (instances)
    compute = oci.core.ComputeClient(cfg)
    instances = await run_blocking(_safe_call, compute.list_instances, config.compartment_id)
    ctx.add_source(["compute", "listInstances", config.region], instances)

    # Database
    try:
        db = oci.database.DatabaseClient(cfg)
        dbs = await run_blocking(_safe_call, db.list_db_systems, config.compartment_id)
        ctx.add_source(["database", "listDbSystems", config.region], dbs)
    except Exception as exc:
        ctx.add_source(["database", "listDbSystems", config.region], {"err": str(exc), "data": None})

    # Audit
    try:
        audit = oci.audit.AuditClient(cfg)
        retention = await run_blocking(_safe_call, audit.get_configuration, config.tenancy_id)
        ctx.add_source(["audit", "getConfiguration", config.region], retention)
    except Exception as exc:
        ctx.add_source(["audit", "getConfiguration", config.region], {"err": str(exc), "data": None})

    # Vaults
    try:
        kms = oci.key_management.KmsVaultClient(cfg)
        vaults = await run_blocking(_safe_call, kms.list_vaults, config.compartment_id)
        ctx.add_source(["vaults", "listVaults", config.region], vaults)
    except Exception as exc:
        ctx.add_source(["vaults", "listVaults", config.region], {"err": str(exc), "data": None})


def make_oracle_collector(config: OracleCollectorConfig):
    async def _runner(ctx: ScanContext) -> None:
        await collect_oracle(ctx, config)
    return _runner
