"""
DSPM scanner: Google Cloud Storage (via REST API + service-account JWT).

Strategy mirrors aws_s3.py and azure_blob.py:
  1. Mint a self-signed JWT from the service-account JSON.
  2. Exchange JWT for an OAuth access token via oauth2.googleapis.com.
  3. List buckets in the project via the GCS JSON API.
  4. For each bucket, list objects (cap), filter to text-like extensions.
  5. For each object, download first 2 MB via the GCS media endpoint.
  6. Decode utf-8 (pdfminer for PDFs), feed to detector, group matches.

Uses only httpx + PyJWT (both already in requirements). No google-cloud-storage
SDK needed.

Cost controls:
  - max_buckets        (default 10 per project)
  - max_objects        (default 80 per bucket)
  - max_bytes          (2 MB hard ceiling per object)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
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

GCS_BASE = "https://storage.googleapis.com/storage/v1"
GCS_DOWNLOAD = "https://storage.googleapis.com/storage/v1"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
JWT_AUDIENCE = "https://oauth2.googleapis.com/token"
JWT_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only"

MAX_OBJECT_BYTES = 2 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
    ".md", ".log", ".sql", ".env", ".cfg", ".conf", ".ini",
    ".html", ".htm", ".js", ".ts", ".py", ".rb", ".go", ".java",
    ".sh", ".bash", ".tf", ".tfvars", ".toml", ".properties",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}


@dataclass
class GCSDSPMConfig:
    project_id: str
    service_account_json: str  # raw JSON string
    max_buckets: int = 10
    max_objects_per_bucket: int = 80
    max_bytes_per_object: int = MAX_OBJECT_BYTES
    concurrency: int = 6
    http_timeout: float = 30.0


def _mint_jwt(sa: dict) -> str:
    import jwt  # PyJWT — already a transitive dependency

    now = int(time.time())
    payload = {
        "iss": sa["client_email"],
        "scope": JWT_SCOPE,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
    }
    private_key = sa["private_key"]
    return jwt.encode(payload, private_key, algorithm="RS256")


async def _acquire_token(sa_json: str) -> Optional[str]:
    """Mint JWT, exchange for OAuth access token."""
    try:
        sa = json.loads(sa_json)
    except Exception as exc:
        logger.warning("GCS DSPM: service account JSON parse failed: %s", exc)
        return None

    try:
        signed = _mint_jwt(sa)
    except Exception as exc:
        logger.warning("GCS DSPM: JWT mint failed: %s", exc)
        return None

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(
                OAUTH_TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": signed,
                },
            )
            if r.status_code != 200:
                logger.warning(
                    "GCS DSPM: token exchange failed: %s %s",
                    r.status_code, r.text[:200],
                )
                return None
            return r.json().get("access_token")
    except Exception as exc:
        logger.warning("GCS DSPM: token request failed: %s", exc)
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
    bucket: str,
    object_name: str,
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
        })
        out.append(
            DSPMFinding(
                cloud="gcp",
                resource_type="gcs_bucket",
                resource_id=bucket,
                object_key=object_name,
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


async def _list_buckets(
    client: httpx.AsyncClient, token: str, project_id: str, cap: int,
) -> list[dict]:
    url = f"{GCS_BASE}/b?project={project_id}&maxResults={min(cap, 1000)}"
    try:
        r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            logger.warning(
                "GCS list buckets: %s %s", r.status_code, r.text[:200],
            )
            return []
        return (r.json().get("items") or [])[:cap]
    except Exception as exc:
        logger.warning("GCS list buckets failed: %s", exc)
        return []


async def _list_objects(
    client: httpx.AsyncClient, token: str, bucket: str, cap: int,
) -> list[dict]:
    url = f"{GCS_BASE}/b/{quote(bucket, safe='')}/o?maxResults={min(cap, 1000)}"
    try:
        r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            logger.debug("GCS list objects %s: %s", bucket, r.status_code)
            return []
        return (r.json().get("items") or [])[:cap]
    except Exception as exc:
        logger.warning("GCS list objects failed for %s: %s", bucket, exc)
        return []


async def _download_object(
    client: httpx.AsyncClient,
    token: str,
    bucket: str,
    object_name: str,
    max_bytes: int,
) -> Optional[bytes]:
    url = (
        f"{GCS_DOWNLOAD}/b/{quote(bucket, safe='')}/o/"
        f"{quote(object_name, safe='')}?alt=media"
    )
    try:
        r = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Range": f"bytes=0-{max_bytes - 1}",
            },
        )
        if r.status_code in (200, 206):
            return r.content[:max_bytes]
        return None
    except Exception as exc:
        logger.debug(
            "GCS download %s/%s failed: %s", bucket, object_name, exc,
        )
        return None


async def scan_gcs(
    cfg: GCSDSPMConfig,
    *,
    org_id: str,
    connection_id: str,
    detector: Optional[SensitiveDataDetector] = None,
) -> DSPMScanReport:
    """Run a DSPM scan against a GCS project. Caller persists the report."""
    started_at = datetime.now(timezone.utc)
    detector = detector or SensitiveDataDetector()
    report = DSPMScanReport(
        org_id=org_id,
        connection_id=connection_id,
        cloud="gcp",
        started_at=started_at,
        finished_at=started_at,
    )

    token = await _acquire_token(cfg.service_account_json)
    if not token:
        report.errors.append("token acquisition failed")
        report.finished_at = datetime.now(timezone.utc)
        return report

    sem = asyncio.Semaphore(cfg.concurrency)

    async with httpx.AsyncClient(timeout=cfg.http_timeout) as client:
        buckets = await _list_buckets(client, token, cfg.project_id, cfg.max_buckets)
        report.resources_scanned = len(buckets)

        async def _scan_object(bucket_name: str, item: dict, region: str) -> list[DSPMFinding]:
            async with sem:
                name = item.get("name") or ""
                if not name or not _looks_textual(name):
                    return []
                size_text = item.get("size") or "0"
                try:
                    size = int(size_text)
                except Exception:
                    size = 0
                if size == 0 or size > cfg.max_bytes_per_object * 8:
                    return []
                raw = await _download_object(
                    client, token, bucket_name, name, cfg.max_bytes_per_object,
                )
                if not raw:
                    return []
                body = _decode_body(name, raw)
                if not body:
                    return []
                report.bytes_inspected += len(body)
                matches = detector.scan_text(
                    body,
                    location={
                        "cloud": "gcp",
                        "bucket": bucket_name,
                        "object": name,
                        "region": region,
                    },
                )
                if not matches:
                    return []
                return _matches_to_findings(
                    matches, bucket=bucket_name, object_name=name, region=region,
                )

        for bucket in buckets:
            bucket_name = bucket.get("name")
            region = bucket.get("location") or "global"
            if not bucket_name:
                continue
            try:
                items = await _list_objects(
                    client, token, bucket_name, cfg.max_objects_per_bucket,
                )
            except Exception as exc:
                report.errors.append(f"bucket {bucket_name}: {exc}")
                continue
            report.objects_sampled += len(items)
            if not items:
                continue
            tasks = [_scan_object(bucket_name, it, region) for it in items]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    report.errors.append(f"object scan: {r}")
                    continue
                report.findings.extend(r)

    report.finished_at = datetime.now(timezone.utc)
    return report
