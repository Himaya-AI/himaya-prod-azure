"""
GCP collector — bridges google-cloud-* SDKs into the CSPM cache shape.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from ..executor import run_blocking
from ..types import ScanContext

logger = logging.getLogger(__name__)


class GcpCollectorConfig:
    def __init__(self, project_id: str, service_account_json: str):
        self.project_id = project_id
        self.service_account_json = service_account_json


def _credentials(config: GcpCollectorConfig):
    """Lazy-import google-auth and build credentials from inline SA JSON."""
    try:
        from google.oauth2 import service_account  # type: ignore
    except ImportError as exc:
        raise RuntimeError("google-auth not installed; pip install google-auth") from exc
    sa_info = json.loads(config.service_account_json) if isinstance(config.service_account_json, str) else config.service_account_json
    return service_account.Credentials.from_service_account_info(sa_info)


async def collect_gcp(ctx: ScanContext, config: Optional[GcpCollectorConfig] = None) -> None:
    if config is None:
        s = ctx.settings
        config = GcpCollectorConfig(
            project_id=s["project_id"],
            service_account_json=s["service_account_json"],
        )

    loop = asyncio.get_event_loop()

    def _safe(callable_, *args, **kwargs):
        try:
            return {"err": None, "data": callable_(*args, **kwargs)}
        except Exception as exc:
            return {"err": str(exc), "data": None}

    try:
        creds = _credentials(config)
    except Exception as exc:
        ctx.add_source(["__error__"], f"GCP creds init failed: {exc}")
        return

    # Storage buckets
    def _list_buckets():
        from google.cloud import storage  # type: ignore
        client = storage.Client(project=config.project_id, credentials=creds)
        out = []
        for b in client.list_buckets():
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                bindings = []
                for binding in policy.bindings:
                    bindings.append({
                        "role": binding.get("role"),
                        "members": list(binding.get("members", [])),
                    })
            except Exception:
                bindings = []
            out.append({
                "name": b.name,
                "location": b.location,
                "storage_class": b.storage_class,
                "iam_configuration": {
                    "uniform_bucket_level_access_enabled": getattr(
                        b.iam_configuration, "uniform_bucket_level_access_enabled", False
                    ),
                    "public_access_prevention": getattr(
                        b.iam_configuration, "public_access_prevention", None
                    ),
                },
                "default_kms_key_name": b.default_kms_key_name,
                "versioning_enabled": b.versioning_enabled,
                "labels": dict(b.labels or {}),
                "iam_bindings": bindings,
            })
        return out

    buckets = await run_blocking(_safe, _list_buckets)
    ctx.add_source(["storage", "listBuckets", "global"], buckets)

    # Cloud SQL instances
    def _list_sql():
        from googleapiclient.discovery import build  # type: ignore
        svc = build("sqladmin", "v1", credentials=creds, cache_discovery=False)
        res = svc.instances().list(project=config.project_id).execute()
        return res.get("items", [])

    sql = await run_blocking(_safe, _list_sql)
    ctx.add_source(["sql", "listInstances", "global"], sql)

    # IAM service accounts
    def _list_sas():
        from googleapiclient.discovery import build  # type: ignore
        svc = build("iam", "v1", credentials=creds, cache_discovery=False)
        res = svc.projects().serviceAccounts().list(
            name=f"projects/{config.project_id}"
        ).execute()
        return res.get("accounts", [])

    sas = await run_blocking(_safe, _list_sas)
    ctx.add_source(["iam", "listServiceAccounts", "global"], sas)

    # Compute Engine instances + firewalls
    def _list_compute_fw():
        from googleapiclient.discovery import build  # type: ignore
        svc = build("compute", "v1", credentials=creds, cache_discovery=False)
        return svc.firewalls().list(project=config.project_id).execute().get("items", [])

    fw = await run_blocking(_safe, _list_compute_fw)
    ctx.add_source(["compute", "listFirewalls", "global"], fw)


def make_gcp_collector(config: GcpCollectorConfig):
    async def _runner(ctx: ScanContext) -> None:
        await collect_gcp(ctx, config)
    return _runner
