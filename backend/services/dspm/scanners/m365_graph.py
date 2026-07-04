"""
DSPM scanner: Microsoft 365 (SharePoint + OneDrive via Graph API).

Strategy mirrors aws_s3.py:
  1. List SharePoint sites + OneDrive drives the org has consent for.
  2. For each drive, list root children (capped).
  3. For each text-like item under 2 MB, GET /content via Graph, decode utf-8.
  4. Feed bytes to the shared detector, group matches into DSPMFinding rows.

Costs are bounded by:
  - max_sites           (default 30 SharePoint sites)
  - max_drives          (default 50 OneDrive drives — one per user)
  - max_items_per_drive (default 80)
  - max_bytes           (2 MB per item, hard ceiling)
  - text-only mime+ext filter

Uses httpx with a Bearer token. Caller supplies the token; we don't refresh
it here (the SaaS layer already handles refresh).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

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

GRAPH = "https://graph.microsoft.com/v1.0"
MAX_ITEM_BYTES = 2 * 1024 * 1024

# Microsoft content-types we consider "text-like" for DSPM scanning.
TEXT_MIMES = {
    "text/plain", "text/csv", "text/html", "text/xml", "text/markdown",
    "application/json", "application/xml", "application/yaml",
    "application/x-yaml", "application/x-sh",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
    "application/pdf",
}

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".md",
    ".log", ".sql", ".env", ".cfg", ".conf", ".ini",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf",
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".sh",
}


@dataclass
class M365DSPMConfig:
    access_token: str
    max_sites: int = 30
    max_drives: int = 50
    max_items_per_drive: int = 80
    max_bytes_per_item: int = MAX_ITEM_BYTES
    concurrency: int = 6
    http_timeout: float = 20.0
    # If True, scan SharePoint document libraries
    scan_sharepoint: bool = True
    # If True, scan OneDrive drives (per-user)
    scan_onedrive: bool = True


def _looks_textual(name: str, mime: Optional[str]) -> bool:
    if mime:
        m = mime.split(";", 1)[0].strip().lower()
        if m in TEXT_MIMES or m.startswith("text/"):
            return True
    name_l = name.lower()
    return any(name_l.endswith(ext) for ext in TEXT_EXTENSIONS)


def _decode_body(name: str, mime: Optional[str], raw: bytes) -> Optional[str]:
    """Best-effort body extraction. PDFs use pdfminer, everything else utf-8 decode."""
    if not raw:
        return None
    is_pdf = name.lower().endswith(".pdf") or (mime or "").lower() == "application/pdf"
    if is_pdf:
        try:
            import io
            from pdfminer.high_level import extract_text  # type: ignore
            return extract_text(io.BytesIO(raw)) or None
        except Exception as exc:
            logger.debug("pdfminer failed for %s: %s", name, exc)
            # Fall back to a latin-1 decode so at least obvious text in the
            # PDF byte stream gets matched against secret/key patterns.
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
    resource_type: str,
    resource_id: str,
    object_key: str,
    region: str = "global",
    cloud: str = "m365",
    extra_metadata: Optional[dict] = None,
) -> list[DSPMFinding]:
    """Collapse PatternMatch records into DSPMFinding rows grouped by (pattern, category)."""
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
        })
        out.append(
            DSPMFinding(
                cloud=cloud,
                resource_type=resource_type,
                resource_id=resource_id,
                object_key=object_key,
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


async def _graph_get(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    *,
    return_bytes: bool = False,
) -> Optional[dict | bytes]:
    """GET helper with light error tolerance."""
    try:
        r = await client.get(url, headers=headers, follow_redirects=True)
        if r.status_code != 200:
            logger.debug("graph GET %s -> %s", url, r.status_code)
            return None
        return r.content if return_bytes else r.json()
    except Exception as exc:
        logger.debug("graph GET %s failed: %s", url, exc)
        return None


async def _list_sharepoint_sites(
    client: httpx.AsyncClient, headers: dict, max_sites: int
) -> list[dict]:
    data = await _graph_get(client, f"{GRAPH}/sites?search=*&$top={max_sites}", headers)
    if not isinstance(data, dict):
        return []
    return (data.get("value") or [])[:max_sites]


async def _list_onedrives(
    client: httpx.AsyncClient, headers: dict, max_drives: int
) -> list[dict]:
    """Enumerate user OneDrive drives (one per active user, capped)."""
    out: list[dict] = []
    url = f"{GRAPH}/users?$top={min(max_drives, 100)}&$select=id,userPrincipalName"
    data = await _graph_get(client, url, headers)
    if not isinstance(data, dict):
        return out
    users = (data.get("value") or [])[:max_drives]
    for u in users:
        uid = u.get("id")
        upn = u.get("userPrincipalName") or uid
        if not uid:
            continue
        drive = await _graph_get(client, f"{GRAPH}/users/{uid}/drive", headers)
        if isinstance(drive, dict) and drive.get("id"):
            out.append({
                "driveId": drive["id"],
                "ownerUpn": upn,
                "resource_type": "onedrive_drive",
                "resource_id": upn,
            })
    return out


async def _list_drive_items(
    client: httpx.AsyncClient, headers: dict, drive_url: str, max_items: int
) -> list[dict]:
    items: list[dict] = []
    url = f"{drive_url}/root/children?$top={min(max_items, 200)}"
    while url and len(items) < max_items:
        data = await _graph_get(client, url, headers)
        if not isinstance(data, dict):
            break
        page = data.get("value") or []
        items.extend(page)
        url = data.get("@odata.nextLink")
    return items[:max_items]


async def _fetch_item_content(
    client: httpx.AsyncClient,
    headers: dict,
    drive_url: str,
    item_id: str,
    max_bytes: int,
) -> Optional[bytes]:
    """Fetch first ``max_bytes`` bytes of a drive item."""
    range_headers = dict(headers)
    range_headers["Range"] = f"bytes=0-{max_bytes - 1}"
    try:
        r = await client.get(
            f"{drive_url}/items/{item_id}/content",
            headers=range_headers,
            follow_redirects=True,
        )
        if r.status_code in (200, 206):
            return r.content[:max_bytes]
        return None
    except Exception as exc:
        logger.debug("content fetch failed for item %s: %s", item_id, exc)
        return None


async def scan_m365(
    cfg: M365DSPMConfig,
    *,
    org_id: str,
    integration_id: str,
    detector: Optional[SensitiveDataDetector] = None,
) -> DSPMScanReport:
    """
    Scan a Microsoft 365 tenant for sensitive data in SharePoint + OneDrive.

    Returns a populated DSPMScanReport. Caller persists.
    """
    started_at = datetime.now(timezone.utc)
    detector = detector or SensitiveDataDetector()
    report = DSPMScanReport(
        org_id=org_id,
        connection_id=integration_id,
        cloud="m365",
        started_at=started_at,
        finished_at=started_at,
    )

    headers = {"Authorization": f"Bearer {cfg.access_token}"}
    sem = asyncio.Semaphore(cfg.concurrency)

    async with httpx.AsyncClient(timeout=cfg.http_timeout) as client:
        targets: list[dict] = []

        # SharePoint sites
        if cfg.scan_sharepoint:
            try:
                sites = await _list_sharepoint_sites(client, headers, cfg.max_sites)
                for s in sites:
                    sid = s.get("id")
                    sname = s.get("displayName") or s.get("name") or sid
                    if not sid:
                        continue
                    targets.append({
                        "drive_url": f"{GRAPH}/sites/{sid}/drive",
                        "resource_type": "sharepoint_site",
                        "resource_id": sname,
                        "drive_label": sname,
                    })
            except Exception as exc:
                report.errors.append(f"sharepoint enumerate: {exc}")

        # OneDrive drives
        if cfg.scan_onedrive:
            try:
                od = await _list_onedrives(client, headers, cfg.max_drives)
                for d in od:
                    targets.append({
                        "drive_url": f"{GRAPH}/drives/{d['driveId']}",
                        "resource_type": "onedrive_drive",
                        "resource_id": d["resource_id"],
                        "drive_label": d["resource_id"],
                    })
            except Exception as exc:
                report.errors.append(f"onedrive enumerate: {exc}")

        report.resources_scanned = len(targets)

        async def _scan_item(tgt: dict, item: dict) -> list[DSPMFinding]:
            async with sem:
                name = item.get("name") or "(unnamed)"
                item_id = item.get("id")
                size = int(item.get("size") or 0)
                mime = (item.get("file") or {}).get("mimeType")
                # Folders have a "folder" key — skip
                if item.get("folder") or not item_id:
                    return []
                if not _looks_textual(name, mime):
                    return []
                # Skip clearly empty files and absurdly large ones
                if size == 0 or size > cfg.max_bytes_per_item * 8:
                    return []
                raw = await _fetch_item_content(
                    client, headers, tgt["drive_url"], item_id, cfg.max_bytes_per_item
                )
                if not raw:
                    return []
                body = _decode_body(name, mime, raw)
                if not body:
                    return []
                report.bytes_inspected += len(body)
                location = {
                    "cloud": "m365",
                    "drive": tgt["drive_label"],
                    "item": name,
                    "item_id": item_id,
                }
                matches = detector.scan_text(body, location=location)
                if not matches:
                    return []
                return _matches_to_findings(
                    matches,
                    resource_type=tgt["resource_type"],
                    resource_id=tgt["resource_id"],
                    object_key=name,
                    extra_metadata={
                        "item_id": item_id,
                        "item_url": item.get("webUrl"),
                    },
                )

        for tgt in targets:
            try:
                items = await _list_drive_items(
                    client, headers, tgt["drive_url"], cfg.max_items_per_drive
                )
            except Exception as exc:
                report.errors.append(f"list {tgt['resource_type']} {tgt['resource_id']}: {exc}")
                continue

            file_items = [i for i in items if not i.get("folder")]
            report.objects_sampled += len(file_items)
            if not file_items:
                continue

            tasks = [_scan_item(tgt, i) for i in file_items]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    report.errors.append(f"item scan: {r}")
                    continue
                report.findings.extend(r)

    report.finished_at = datetime.now(timezone.utc)
    return report
