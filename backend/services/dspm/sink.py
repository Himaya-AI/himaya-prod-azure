"""
DSPM finding sink — persists findings to Postgres and bridges into the
existing saas_alerts pipeline so CRITICAL/HIGH data exposures appear in
the Alerts tab alongside CSPM findings.

Tables:
    dspm_findings   — one row per (org_id, cloud, fingerprint)
    dspm_scans      — per-run audit log
    saas_alerts     — pre-existing alert table; HIGH/CRITICAL mirrored here
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .types import DSPMFinding, DSPMScanReport, Severity

logger = logging.getLogger(__name__)


async def ensure_dspm_tables(db: AsyncSession) -> None:
    """Create DSPM tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dspm_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID,
            cloud VARCHAR(32) NOT NULL,
            fingerprint VARCHAR(64) NOT NULL,
            resource_type VARCHAR(64) NOT NULL,
            resource_id VARCHAR(512) NOT NULL,
            object_key TEXT NOT NULL,
            category VARCHAR(64) NOT NULL,
            severity VARCHAR(16) NOT NULL,
            pattern_name VARCHAR(128) NOT NULL,
            match_count INTEGER DEFAULT 1,
            redacted_sample TEXT,
            confidence FLOAT DEFAULT 0.8,
            region VARCHAR(64) DEFAULT 'global',
            metadata JSONB DEFAULT '{}'::jsonb,
            first_seen_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            CONSTRAINT dspm_findings_unique UNIQUE (org_id, cloud, fingerprint)
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_dspm_findings_org_cloud
            ON dspm_findings(org_id, cloud)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_dspm_findings_severity
            ON dspm_findings(severity)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_dspm_findings_category
            ON dspm_findings(category)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_dspm_findings_last_seen
            ON dspm_findings(last_seen_at DESC)
    """))

    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS dspm_scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID,
            cloud VARCHAR(32) NOT NULL,
            started_at TIMESTAMPTZ DEFAULT NOW(),
            finished_at TIMESTAMPTZ,
            duration_ms INTEGER,
            resources_scanned INTEGER DEFAULT 0,
            objects_sampled INTEGER DEFAULT 0,
            bytes_inspected BIGINT DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            severity_counts JSONB DEFAULT '{}'::jsonb,
            category_counts JSONB DEFAULT '{}'::jsonb,
            errors JSONB DEFAULT '[]'::jsonb,
            status VARCHAR(32) DEFAULT 'completed'
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_dspm_scans_org_started
            ON dspm_scans(org_id, started_at DESC)
    """))

    # Best-effort: ensure saas_alerts table exists (CSPM also does this — idempotent)
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS saas_alerts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID,
            provider VARCHAR(64),
            alert_type VARCHAR(64),
            severity VARCHAR(16),
            title VARCHAR(512),
            description TEXT,
            resource_id VARCHAR(255),
            resource_name VARCHAR(255),
            resource_url TEXT,
            status VARCHAR(32) DEFAULT 'open',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            classification_result JSONB
        )
    """))
    await db.commit()


async def write_findings(
    db: AsyncSession,
    org_id: str,
    connection_id: str | None,
    findings: Iterable[DSPMFinding],
    *,
    mirror_to_saas_alerts: bool = True,
) -> dict:
    """
    Upsert findings keyed by (org_id, cloud, fingerprint). HIGH/CRITICAL
    are mirrored into saas_alerts so they appear in the Alerts tab.

    Returns: {"inserted": int, "updated": int, "mirrored": int}.
    """
    inserted = 0
    updated = 0
    mirrored = 0

    for f in findings:
        params = {
            "org_id": org_id,
            "connection_id": connection_id,
            "cloud": f.cloud,
            "fingerprint": f.fingerprint,
            "resource_type": f.resource_type,
            "resource_id": f.resource_id[:500],
            "object_key": f.object_key,
            "category": f.category.value,
            "severity": f.severity.value,
            "pattern_name": f.pattern_name,
            "match_count": f.match_count,
            "redacted_sample": f.redacted_sample,
            "confidence": f.confidence,
            "region": f.region,
            "metadata": json.dumps(f.metadata or {}),
        }

        try:
            result = await db.execute(
                text("""
                    INSERT INTO dspm_findings (
                        org_id, connection_id, cloud, fingerprint,
                        resource_type, resource_id, object_key,
                        category, severity, pattern_name,
                        match_count, redacted_sample, confidence, region,
                        metadata, first_seen_at, last_seen_at
                    ) VALUES (
                        CAST(:org_id AS UUID), CAST(:connection_id AS UUID), :cloud, :fingerprint,
                        :resource_type, :resource_id, :object_key,
                        :category, :severity, :pattern_name,
                        :match_count, :redacted_sample, :confidence, :region,
                        CAST(:metadata AS jsonb), NOW(), NOW()
                    )
                    ON CONFLICT (org_id, cloud, fingerprint) DO UPDATE SET
                        match_count = EXCLUDED.match_count,
                        redacted_sample = EXCLUDED.redacted_sample,
                        confidence = EXCLUDED.confidence,
                        severity = EXCLUDED.severity,
                        metadata = EXCLUDED.metadata,
                        last_seen_at = NOW(),
                        resolved_at = NULL
                    RETURNING (xmax = 0) AS is_insert
                """),
                params,
            )
            row = result.first()
            if row and row[0]:
                inserted += 1
            else:
                updated += 1
        except Exception as exc:
            logger.warning(f"dspm_findings upsert failed for {f.fingerprint}: {exc}")
            continue

        # Mirror HIGH/CRITICAL into saas_alerts so they surface in Alerts tab
        if mirror_to_saas_alerts and f.severity in (Severity.HIGH, Severity.CRITICAL):
            try:
                # Dedup at insert time: only mirror a NEW alert if we haven't
                # already alerted on this exact finding. saas_alerts has no
                # UNIQUE constraint (too many insert sites), so ON CONFLICT is a
                # no-op here — instead guard with WHERE NOT EXISTS on the natural
                # key (org, provider, alert_type, resource_id) so re-scanning the
                # same finding never surfaces a duplicate alert.
                await db.execute(
                    text("""
                        INSERT INTO saas_alerts (
                            id, org_id, provider, alert_type, severity, title,
                            description, resource_id, resource_name,
                            status, created_at, classification_result
                        )
                        SELECT
                            gen_random_uuid(), CAST(:org_id AS UUID), :provider, :alert_type, :severity, :title,
                            :description, :resource_id, :resource_name,
                            'open', NOW(), CAST(:classification AS jsonb)
                        WHERE NOT EXISTS (
                            SELECT 1 FROM saas_alerts
                             WHERE org_id = CAST(:org_id AS UUID)
                               AND provider = :provider
                               AND alert_type = :alert_type
                               AND COALESCE(resource_id, '') = COALESCE(:resource_id, '')
                        )
                    """),
                    {
                        "org_id": org_id,
                        "provider": f.cloud,
                        "alert_type": f"dspm_{f.category.value[:48]}",
                        "severity": f.severity.value,
                        "title": (
                            f"Sensitive data exposure: {f.category.value} in "
                            f"{f.resource_id}/{f.object_key}"
                        )[:500],
                        "description": (
                            f"Pattern '{f.pattern_name}' matched {f.match_count} time(s). "
                            f"Sample: {f.redacted_sample}"
                        ),
                        "resource_id": f"{f.resource_id}/{f.object_key}"[:200],
                        "resource_name": f.resource_type[:200],
                        "classification": json.dumps({
                            "dspm_pattern": f.pattern_name,
                            "dspm_fingerprint": f.fingerprint,
                            "category": f.category.value,
                            "region": f.region,
                            "confidence": f.confidence,
                            "match_count": f.match_count,
                        }),
                    },
                )
                mirrored += 1
            except Exception as exc:
                logger.debug(f"saas_alerts mirror failed: {exc}")

    await db.commit()
    return {"inserted": inserted, "updated": updated, "mirrored": mirrored}


async def write_scan_report(
    db: AsyncSession,
    report: DSPMScanReport,
) -> str:
    """Insert a scan audit row, return its id."""
    scan_id = str(uuid.uuid4())
    try:
        await db.execute(
            text("""
                INSERT INTO dspm_scans (
                    id, org_id, connection_id, cloud,
                    started_at, finished_at, duration_ms,
                    resources_scanned, objects_sampled, bytes_inspected,
                    findings_count, severity_counts, category_counts, errors, status
                ) VALUES (
                    CAST(:id AS UUID), CAST(:org_id AS UUID), CAST(:connection_id AS UUID), :cloud,
                    :started_at, :finished_at, :duration_ms,
                    :resources_scanned, :objects_sampled, :bytes_inspected,
                    :findings_count, CAST(:severity_counts AS jsonb),
                    CAST(:category_counts AS jsonb), CAST(:errors AS jsonb), :status
                )
            """),
            {
                "id": scan_id,
                "org_id": report.org_id,
                "connection_id": report.connection_id,
                "cloud": report.cloud,
                "started_at": report.started_at,
                "finished_at": report.finished_at,
                "duration_ms": report.duration_ms,
                "resources_scanned": report.resources_scanned,
                "objects_sampled": report.objects_sampled,
                "bytes_inspected": report.bytes_inspected,
                "findings_count": len(report.findings),
                "severity_counts": json.dumps(report.severity_counts),
                "category_counts": json.dumps(report.category_counts),
                "errors": json.dumps(report.errors[:50]),
                "status": "failed" if report.errors and report.resources_scanned == 0 else "completed",
            },
        )
        await db.commit()
    except Exception as exc:
        logger.warning(f"dspm_scans insert failed: {exc}")
    return scan_id


async def mark_resolved(
    db: AsyncSession,
    org_id: str,
    cloud: str,
    seen_fingerprints: set[str],
) -> int:
    """
    Mark any open finding for this (org_id, cloud) that was NOT seen in
    the current scan as resolved. Returns count.
    """
    if not seen_fingerprints:
        return 0
    try:
        result = await db.execute(
            text("""
                UPDATE dspm_findings
                SET resolved_at = NOW()
                WHERE org_id = CAST(:org_id AS UUID)
                  AND cloud = :cloud
                  AND resolved_at IS NULL
                  AND fingerprint != ALL(:fingerprints)
                RETURNING id
            """),
            {
                "org_id": org_id,
                "cloud": cloud,
                "fingerprints": list(seen_fingerprints),
            },
        )
        rows = result.fetchall()
        await db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning(f"dspm_findings auto-resolve failed: {exc}")
        return 0
