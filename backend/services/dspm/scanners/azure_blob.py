"""
DSPM scanner: Azure Blob Storage (via ARM REST API + Storage REST API).

Strategy mirrors aws_s3.py and m365_graph.py:
  1. Acquire ARM token via client_credentials.
  2. List storage accounts in the subscription.
  3. For each account, list containers via ARM management API.
  4. For each container, list blobs (cap), filter to text-like extensions.
  5. For each blob, download first 2 MB via storage data-plane REST.
  6. Decode utf-8 (pdfminer for PDFs), feed to detector, group matches.

No azure-storage-blob SDK needed — pure httpx + ARM/blob REST endpoints.

Cost controls:
  - max_accounts        (default 10)
  - max_containers      (default 10 per account)
  - max_blobs           (default 80 per container)
  - max_bytes_per_blob  (2 MB hard ceiling)
  - text-only extension filter
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx

from ..detector import SensitiveDataDetector
from ..types import (
    DataCategory,
    DSPMFinding,
    DSPMScanReport,
    PatternMatch,
    severity_for,
)

logger = logging.getLogger(__name__)

ARM_BASE = "https://management.azure.com"
LOGIN_BASE = "https://login.microsoftonline.com"

# Default ARM API versions — pinned for stability.
ARM_API_STORAGE = "2023-01-01"
ARM_API_BLOB = "2023-01-01"
BLOB_API_VERSION = "2023-11-03"

MAX_BLOB_BYTES = 2 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
    ".md", ".log", ".sql", ".env", ".cfg", ".conf", ".ini",
    ".html", ".htm", ".js", ".ts", ".py", ".rb", ".go", ".java",
    ".sh", ".bash", ".tf", ".tfvars", ".toml", ".properties",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}


@dataclass
class AzureBlobDSPMConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    max_accounts: int = 10
    max_containers_per_account: int = 10
    max_blobs_per_container: int = 80
    max_bytes_per_blob: int = MAX_BLOB_BYTES
    concurrency: int = 6
    http_timeout: float = 30.0


async def _acquire_arm_token(
    tenant_id: str, client_id: str, client_secret: str
) -> Optional[str]:
    url = f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default",
            })
            r.raise_for_status()
            return r.json().get("access_token")
    except Exception as exc:
        logger.warning("Azure ARM token acquire failed: %s", exc)
        return None


async def _acquire_storage_token(
    tenant_id: str, client_id: str, client_secret: str
) -> Optional[str]:
    """Separate token scoped for Azure Storage data-plane."""
    url = f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://storage.azure.com/.default",
            })
            r.raise_for_status()
            return r.json().get("access_token")
    except Exception as exc:
        logger.warning("Azure storage token acquire failed: %s", exc)
        return None


def _looks_textual(name: str) -> bool:
    name_l = name.lower()
    return any(name_l.endswith(ext) for ext in TEXT_EXTENSIONS)


def _decode_body(name: str, raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if name.lower().endswith(".pdf"):
        try:
            import io
            from pdfminer.high_level import extract_text  # type: ignore
            return extract_text(io.BytesIO(raw)) or None
        except Exception:
            try:
                return raw.decode("latin-1", errors="replace")
            except Exception:
                return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _matches_to_findings(
    matches: list[PatternMatch],
    *,
    storage_account: str,
    container: str,
    blob: str,
    region: str,
    extra_metadata: Optional[dict] = None,
) -> list[DSPMFinding]:
    groups: dict[tuple[str, DataCategory], list[PatternMatch]] = {}
    for m in matches:
        groups.setdefault((m.pattern_name, m.category), []).append(m)

    out: list[DSPMFinding] = []
    for (pattern_name, category), grouped in groups.items():
        sample = grouped[0]
        contexts = [g.context for g in grouped[:3] if g.context]
        meta = dict(extra_metadata or {})
        meta.update({
            "context_samples": contexts,
            "matches_emitted": len(grouped),
            "container": container,
        })
        out.append(
            DSPMFinding(
                cloud="azure",
                resource_type="storage_container",
                resource_id=f"{storage_account}/{container}",
                object_key=blob,
                category=category,
                severity=severity_for(category),
                pattern_name=pattern_name,
                match_count=len(grouped),
                redacted_sample=sample.redacted,
                confidence=sample.confidence,
                region=region,
                metadata=meta,
            )
        )
    return out


async def _list_storage_accounts(
    client: httpx.AsyncClient, arm_token: str, subscription_id: str, cap: int
) -> list[dict]:
    url = (
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Storage/storageAccounts?api-version={ARM_API_STORAGE}"
    )
    try:
        r = await client.get(url, headers={"Authorization": f"Bearer {arm_token}"})
        if r.status_code != 200:
            logger.debug("list storage accounts: %s %s", r.status_code, r.text[:200])
            return []
        return (r.json().get("value") or [])[:cap]
    except Exception as exc:
        logger.warning("list storage accounts failed: %s", exc)
        return []


async def _list_containers(
    client: httpx.AsyncClient, arm_token: str, account_id: str, cap: int
) -> list[dict]:
    """List blob containers under a storage account using ARM management API."""
    url = (
        f"{ARM_BASE}{account_id}/blobServices/default/containers"
        f"?api-version={ARM_API_BLOB}"
    )
    try:
        r = await client.get(url, headers={"Authorization": f"Bearer {arm_token}"})
        if r.status_code != 200:
            logger.debug("list containers %s: %s", account_id, r.status_code)
            return []
        return (r.json().get("value") or [])[:cap]
    except Exception as exc:
        logger.warning("list containers failed for %s: %s", account_id, exc)
        return []


async def _list_blobs(
    client: httpx.AsyncClient,
    storage_token: str,
    account_name: str,
    container_name: str,
    cap: int,
) -> list[dict]:
    """Use the Storage REST API List Blobs operation (XML response)."""
    url = (
        f"https://{account_name}.blob.core.windows.net/{quote(container_name)}"
        f"?restype=container&comp=list&maxresults={min(cap, 5000)}"
    )
    try:
        r = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {storage_token}",
                "x-ms-version": BLOB_API_VERSION,
            },
        )
        if r.status_code != 200:
            logger.debug(
                "list blobs %s/%s: %s", account_name, container_name, r.status_code,
            )
            return []
        # Parse the Atom-ish XML response — only need <Name> entries.
        import xml.etree.ElementTree as ET
        out: list[dict] = []
        try:
            root = ET.fromstring(r.text)
            for blob_el in root.findall(".//Blobs/Blob"):
                name = blob_el.findtext("Name")
                if not name:
                    continue
                props = blob_el.find("Properties")
                size = 0
                if props is not None:
                    size_text = props.findtext("Content-Length")
                    if size_text and size_text.isdigit():
                        size = int(size_text)
                out.append({"name": name, "size": size})
                if len(out) >= cap:
                    break
        except Exception as exc:
            logger.warning(
                "list blobs xml parse failed for %s/%s: %s",
                account_name, container_name, exc,
            )
        return out
    except Exception as exc:
        logger.warning(
            "list blobs request failed for %s/%s: %s",
            account_name, container_name, exc,
        )
        return []


async def _download_blob(
    client: httpx.AsyncClient,
    storage_token: str,
    account_name: str,
    container_name: str,
    blob_name: str,
    max_bytes: int,
) -> Optional[bytes]:
    url = (
        f"https://{account_name}.blob.core.windows.net/"
        f"{quote(container_name)}/{quote(blob_name)}"
    )
    try:
        r = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {storage_token}",
                "x-ms-version": BLOB_API_VERSION,
                "Range": f"bytes=0-{max_bytes - 1}",
            },
        )
        if r.status_code in (200, 206):
            return r.content[:max_bytes]
        return None
    except Exception as exc:
        logger.debug(
            "download blob failed for %s/%s/%s: %s",
            account_name, container_name, blob_name, exc,
        )
        return None


async def scan_azure_blob(
    cfg: AzureBlobDSPMConfig,
    *,
    org_id: str,
    connection_id: str,
    detector: Optional[SensitiveDataDetector] = None,
) -> DSPMScanReport:
    """
    Run a DSPM scan against an Azure subscription's Blob Storage.
    Caller persists the returned report.
    """
    started_at = datetime.now(timezone.utc)
    detector = detector or SensitiveDataDetector()
    report = DSPMScanReport(
        org_id=org_id,
        connection_id=connection_id,
        cloud="azure",
        started_at=started_at,
        finished_at=started_at,
    )

    arm_token = await _acquire_arm_token(
        cfg.tenant_id, cfg.client_id, cfg.client_secret
    )
    storage_token = await _acquire_storage_token(
        cfg.tenant_id, cfg.client_id, cfg.client_secret
    )
    if not arm_token or not storage_token:
        report.errors.append("token acquisition failed (ARM or storage)")
        report.finished_at = datetime.now(timezone.utc)
        return report

    sem = asyncio.Semaphore(cfg.concurrency)

    async with httpx.AsyncClient(timeout=cfg.http_timeout) as client:
        accounts = await _list_storage_accounts(
            client, arm_token, cfg.subscription_id, cfg.max_accounts
        )
        report.resources_scanned = len(accounts)

        async def _scan_blob(
            account_name: str, container: str, blob: dict, region: str,
        ) -> list[DSPMFinding]:
            async with sem:
                blob_name = blob["name"]
                if not _looks_textual(blob_name):
                    return []
                size = int(blob.get("size") or 0)
                if size == 0 or size > cfg.max_bytes_per_blob * 8:
                    return []
                raw = await _download_blob(
                    client, storage_token, account_name, container, blob_name,
                    cfg.max_bytes_per_blob,
                )
                if not raw:
                    return []
                body = _decode_body(blob_name, raw)
                if not body:
                    return []
                report.bytes_inspected += len(body)
                matches = detector.scan_text(
                    body,
                    location={
                        "cloud": "azure",
                        "account": account_name,
                        "container": container,
                        "blob": blob_name,
                        "region": region,
                    },
                )
                if not matches:
                    return []
                return _matches_to_findings(
                    matches,
                    storage_account=account_name,
                    container=container,
                    blob=blob_name,
                    region=region,
                )

        for account in accounts:
            account_name = account.get("name")
            account_id = account.get("id")  # ARM resource id
            region = account.get("location") or "global"
            if not account_name or not account_id:
                continue
            try:
                containers = await _list_containers(
                    client, arm_token, account_id, cfg.max_containers_per_account,
                )
            except Exception as exc:
                report.errors.append(f"account {account_name}: {exc}")
                continue

            for cont in containers:
                container_name = cont.get("name")
                if not container_name:
                    continue
                try:
                    blobs = await _list_blobs(
                        client, storage_token, account_name, container_name,
                        cfg.max_blobs_per_container,
                    )
                except Exception as exc:
                    report.errors.append(
                        f"list {account_name}/{container_name}: {exc}"
                    )
                    continue

                report.objects_sampled += len(blobs)
                if not blobs:
                    continue

                tasks = [
                    _scan_blob(account_name, container_name, b, region) for b in blobs
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        report.errors.append(f"blob scan: {r}")
                        continue
                    report.findings.extend(r)

    report.finished_at = datetime.now(timezone.utc)
    return report
