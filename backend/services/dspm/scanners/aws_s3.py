"""
DSPM scanner: AWS S3.

Sampling strategy (inspired by mantissa-stance, adapted for cost control):
  1. list_buckets() — enumerate buckets in the account
  2. for each bucket:
      a. get the bucket's region with get_bucket_location()
      b. list_objects_v2 with MaxKeys cap; filter to text-ish content types
      c. for each sampled object, get_object Range bytes=0-2097151 (2 MB cap)
      d. decode as utf-8 best-effort, feed to detector
  3. group detector matches by (bucket, key, pattern, category) → emit
     one DSPMFinding per group with match_count

Costs are bounded by:
  - max_buckets    (default 50)
  - max_keys       (default 100 per bucket)
  - max_bytes      (2 MB per object, hard ceiling)
  - text-only mime filter (skip images, archives, video)
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from backend.services.cspm.executor import run_blocking

from ..detector import SensitiveDataDetector
from ..types import (
    DataCategory,
    DSPMFinding,
    DSPMScanReport,
    PatternMatch,
    Severity,
    severity_for,
)

logger = logging.getLogger(__name__)


# Content types we'll actually inspect. S3 object content-type is set at
# upload time and may be missing or wrong, so we also fall back on extension.
TEXT_CONTENT_TYPES = {
    "text/plain", "text/csv", "text/html", "text/xml", "text/yaml",
    "text/x-yaml", "text/markdown",
    "application/json", "application/xml", "application/yaml",
    "application/x-yaml", "application/x-sh", "application/sql",
    "application/javascript", "application/typescript",
    "application/octet-stream",  # often misset for text — we'll try anyway
}

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
    ".md", ".markdown", ".log", ".sql", ".env", ".cfg", ".conf", ".ini",
    ".html", ".htm", ".js", ".ts", ".py", ".rb", ".go", ".java", ".kt",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".php", ".sh", ".bash", ".zsh",
    ".tf", ".tfvars", ".toml", ".properties", ".pem", ".key",
}

# Hard ceiling per object — same 2 MB the detector enforces.
MAX_OBJECT_BYTES = 2 * 1024 * 1024


@dataclass
class AWSS3ScanConfig:
    access_key_id: str
    secret_access_key: str
    default_region: str = "us-east-1"
    max_buckets: int = 50
    max_keys_per_bucket: int = 100
    max_bytes_per_object: int = MAX_OBJECT_BYTES
    bucket_name_filter: Optional[list[str]] = field(default=None)  # if set, only these
    concurrency: int = 8


def _looks_textual(key: str, content_type: Optional[str]) -> bool:
    if content_type:
        ct = content_type.split(";", 1)[0].strip().lower()
        if ct in TEXT_CONTENT_TYPES or ct.startswith("text/"):
            return True
    key_lower = key.lower()
    for ext in TEXT_EXTENSIONS:
        if key_lower.endswith(ext):
            return True
    return False


def _matches_to_findings(
    matches: list[PatternMatch],
    *,
    bucket: str,
    key: str,
    region: str,
) -> list[DSPMFinding]:
    """
    Collapse N PatternMatch records into M DSPMFinding records grouped by
    (pattern_name, category). Each finding carries match_count + one
    redacted sample. metadata.context_samples carries up to 3 redacted
    contexts for analyst review.
    """
    groups: dict[tuple[str, DataCategory], list[PatternMatch]] = {}
    for m in matches:
        groups.setdefault((m.pattern_name, m.category), []).append(m)

    out: list[DSPMFinding] = []
    for (pattern_name, category), grouped in groups.items():
        sample = grouped[0]
        contexts = [g.context for g in grouped[:3] if g.context]
        out.append(
            DSPMFinding(
                cloud="aws",
                resource_type="s3_bucket",
                resource_id=bucket,
                object_key=key,
                category=category,
                severity=severity_for(category),
                pattern_name=pattern_name,
                match_count=len(grouped),
                redacted_sample=sample.redacted,
                confidence=sample.confidence,
                region=region,
                metadata={
                    "context_samples": contexts,
                    "matches_emitted": len(grouped),
                },
            )
        )
    return out


def _build_s3_client(cfg: AWSS3ScanConfig, region: str):
    import boto3  # local import to keep import cost off the hot path
    return boto3.client(
        "s3",
        aws_access_key_id=cfg.access_key_id,
        aws_secret_access_key=cfg.secret_access_key,
        region_name=region,
    )


async def _list_buckets(cfg: AWSS3ScanConfig) -> list[dict]:
    client = _build_s3_client(cfg, cfg.default_region)

    def _do() -> list[dict]:
        resp = client.list_buckets()
        return resp.get("Buckets", []) or []

    return await run_blocking(_do)


async def _bucket_region(cfg: AWSS3ScanConfig, bucket: str) -> str:
    client = _build_s3_client(cfg, cfg.default_region)

    def _do() -> str:
        try:
            resp = client.get_bucket_location(Bucket=bucket)
            # AWS returns None for us-east-1 historically
            return resp.get("LocationConstraint") or "us-east-1"
        except Exception as exc:
            logger.debug("get_bucket_location failed for %s: %s", bucket, exc)
            return cfg.default_region

    return await run_blocking(_do)


async def _list_objects(
    cfg: AWSS3ScanConfig, bucket: str, region: str
) -> list[dict]:
    client = _build_s3_client(cfg, region)

    def _do() -> list[dict]:
        try:
            resp = client.list_objects_v2(
                Bucket=bucket, MaxKeys=cfg.max_keys_per_bucket
            )
            return resp.get("Contents", []) or []
        except Exception as exc:
            logger.warning("list_objects_v2 failed for %s: %s", bucket, exc)
            return []

    return await run_blocking(_do)


async def _head_object(
    cfg: AWSS3ScanConfig, bucket: str, key: str, region: str
) -> Optional[str]:
    """Return content-type if head succeeds, else None."""
    client = _build_s3_client(cfg, region)

    def _do() -> Optional[str]:
        try:
            resp = client.head_object(Bucket=bucket, Key=key)
            return resp.get("ContentType")
        except Exception:
            return None

    return await run_blocking(_do)


async def _get_object_text(
    cfg: AWSS3ScanConfig, bucket: str, key: str, region: str
) -> Optional[str]:
    """Fetch the first ``max_bytes_per_object`` bytes of an object as utf-8."""
    client = _build_s3_client(cfg, region)

    range_header = f"bytes=0-{cfg.max_bytes_per_object - 1}"

    def _do() -> Optional[str]:
        try:
            resp = client.get_object(Bucket=bucket, Key=key, Range=range_header)
            body = resp["Body"].read()
            if not body:
                return None
            try:
                return body.decode("utf-8", errors="replace")
            except Exception:
                return None
        except Exception as exc:
            logger.debug("get_object failed for s3://%s/%s: %s", bucket, key, exc)
            return None

    return await run_blocking(_do)


async def scan_aws_s3(
    cfg: AWSS3ScanConfig,
    *,
    org_id: str,
    connection_id: str,
    detector: Optional[SensitiveDataDetector] = None,
) -> DSPMScanReport:
    """
    Run a DSPM scan against the AWS account behind ``cfg``.

    Returns a populated DSPMScanReport — the engine/caller is responsible
    for persisting findings + writing the scan report.
    """
    started_at = datetime.now(timezone.utc)
    detector = detector or SensitiveDataDetector()
    report = DSPMScanReport(
        org_id=org_id,
        connection_id=connection_id,
        cloud="aws",
        started_at=started_at,
        finished_at=started_at,  # placeholder, updated at end
    )

    try:
        buckets = await _list_buckets(cfg)
    except Exception as exc:
        msg = f"list_buckets failed: {exc}"
        logger.warning(msg)
        report.errors.append(msg)
        report.finished_at = datetime.now(timezone.utc)
        return report

    if cfg.bucket_name_filter:
        wanted = set(cfg.bucket_name_filter)
        buckets = [b for b in buckets if b.get("Name") in wanted]

    buckets = buckets[: cfg.max_buckets]
    report.resources_scanned = len(buckets)

    sem = asyncio.Semaphore(cfg.concurrency)

    async def _scan_object(bucket: str, key: str, region: str) -> list[DSPMFinding]:
        async with sem:
            content_type = await _head_object(cfg, bucket, key, region)
            if not _looks_textual(key, content_type):
                return []
            text_body = await _get_object_text(cfg, bucket, key, region)
            if not text_body:
                return []
            location = {
                "cloud": "aws",
                "bucket": bucket,
                "key": key,
                "region": region,
            }
            matches = detector.scan_text(text_body, location=location)
            if not matches:
                return []
            report.bytes_inspected += len(text_body)
            return _matches_to_findings(
                matches, bucket=bucket, key=key, region=region
            )

    for bucket_info in buckets:
        bucket = bucket_info.get("Name")
        if not bucket:
            continue
        try:
            region = await _bucket_region(cfg, bucket)
            objects = await _list_objects(cfg, bucket, region)
        except Exception as exc:
            report.errors.append(f"bucket {bucket}: {exc}")
            continue

        # Filter early on key extensions so we don't HEAD obvious binaries.
        sampled = [
            o for o in objects
            if o.get("Key") and _looks_textual(o["Key"], None)
        ]
        report.objects_sampled += len(sampled)

        tasks = [
            _scan_object(bucket, o["Key"], region) for o in sampled
        ]
        if not tasks:
            continue

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                report.errors.append(f"object scan: {r}")
                continue
            report.findings.extend(r)

    report.finished_at = datetime.now(timezone.utc)
    return report
