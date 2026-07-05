"""
CSPM finding sink — persists findings to Postgres and bridges into the
existing saas_alerts pipeline so they appear in the Alerts tab.

Tables:
    cspm_findings   — full structured finding record (one row per dedup key)
    cspm_scans      — per-run audit log
    saas_alerts     — pre-existing alert table; high+critical findings get mirrored here
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .types import Finding, PluginStatus, ScanReport, Severity

logger = logging.getLogger(__name__)


async def ensure_cspm_tables(db: AsyncSession) -> None:
    """Create CSPM tables if they don't exist."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS cspm_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID,
            cloud VARCHAR(32) NOT NULL,
            fingerprint VARCHAR(64) NOT NULL,
            plugin_id VARCHAR(128) NOT NULL,
            severity VARCHAR(16) NOT NULL,
            status VARCHAR(16) NOT NULL,
            category VARCHAR(128),
            title VARCHAR(512),
            message TEXT,
            resource VARCHAR(512),
            resource_type VARCHAR(128),
            region VARCHAR(64),
            recommendation TEXT,
            compliance JSONB DEFAULT '{}'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            first_seen_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            CONSTRAINT cspm_findings_unique UNIQUE (org_id, cloud, fingerprint)
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_cspm_findings_org_cloud
            ON cspm_findings(org_id, cloud)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_cspm_findings_severity
            ON cspm_findings(severity)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_cspm_findings_status
            ON cspm_findings(status)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_cspm_findings_last_seen
            ON cspm_findings(last_seen_at DESC)
    """))

    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS cspm_scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            connection_id UUID,
            cloud VARCHAR(32) NOT NULL,
            started_at TIMESTAMPTZ DEFAULT NOW(),
            finished_at TIMESTAMPTZ,
            duration_ms INTEGER,
            plugins_run INTEGER DEFAULT 0,
            plugins_ok INTEGER DEFAULT 0,
            plugins_fail INTEGER DEFAULT 0,
            plugins_unknown INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            severity_counts JSONB DEFAULT '{}'::jsonb,
            errors JSONB DEFAULT '[]'::jsonb,
            status VARCHAR(32) DEFAULT 'completed'
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_cspm_scans_org_started
            ON cspm_scans(org_id, started_at DESC)
    """))

    # Best-effort: ensure saas_alerts table at least exists (it usually does)
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
    findings: Iterable[Finding],
    *,
    mirror_to_saas_alerts: bool = True,
) -> dict:
    """
    Persist a batch of findings. Uses an upsert keyed by (org_id, cloud, fingerprint).
    High and critical findings are mirrored into saas_alerts so they surface in the
    existing Alerts tab.

    Returns counts: {"inserted": int, "updated": int, "mirrored": int}.
    """
    inserted = 0
    updated = 0
    mirrored = 0

    for f in findings:
        # Skip OK results — only persist warn/fail/unknown
        if f.status == PluginStatus.OK:
            continue

        params = {
            "org_id": org_id,
            "connection_id": connection_id,
            "cloud": f.cloud,
            "fingerprint": f.fingerprint,
            "plugin_id": f.plugin_id,
            "severity": f.severity.value,
            "status": f.status.value,
            "category": f.category,
            "title": f.title[:500] if f.title else None,
            "message": f.message,
            "resource": f.resource[:500] if f.resource else None,
            "resource_type": f.resource_type,
            "region": f.region,
            "recommendation": f.recommendation,
            "compliance": json.dumps(f.compliance or {}),
            "metadata": json.dumps(f.metadata or {}),
        }

        try:
            result = await db.execute(
                text("""
                    INSERT INTO cspm_findings (
                        org_id, connection_id, cloud, fingerprint, plugin_id,
                        severity, status, category, title, message,
                        resource, resource_type, region, recommendation,
                        compliance, metadata, first_seen_at, last_seen_at
                    ) VALUES (
                        CAST(:org_id AS UUID), CAST(:connection_id AS UUID), :cloud, :fingerprint, :plugin_id,
                        :severity, :status, :category, :title, :message,
                        :resource, :resource_type, :region, :recommendation,
                        CAST(:compliance AS jsonb), CAST(:metadata AS jsonb), NOW(), NOW()
                    )
                    ON CONFLICT (org_id, cloud, fingerprint) DO UPDATE SET
                        severity = EXCLUDED.severity,
                        status = EXCLUDED.status,
                        title = EXCLUDED.title,
                        message = EXCLUDED.message,
                        recommendation = EXCLUDED.recommendation,
                        compliance = EXCLUDED.compliance,
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
            logger.warning(f"cspm_findings upsert failed for {f.fingerprint}: {exc}")
            continue

        # Mirror high+critical into saas_alerts (best effort)
        if mirror_to_saas_alerts and f.severity in (Severity.HIGH, Severity.CRITICAL):
            try:
                # Dedup at insert time: saas_alerts has no UNIQUE constraint
                # (too many insert sites for ON CONFLICT), so guard with
                # WHERE NOT EXISTS on the natural key (org, provider, alert_type,
                # resource_id) so re-scanning the same misconfiguration every
                # cycle never surfaces a duplicate alert.
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
                        "alert_type": f"cspm_{f.category.lower().replace(' ', '_')[:48]}",
                        "severity": f.severity.value,
                        "title": (f.title or f.plugin_id)[:500],
                        "description": f.message,
                        "resource_id": (f.resource or f.fingerprint)[:200],
                        "resource_name": (f.resource_type or f.category)[:200],
                        "classification": json.dumps({
                            "cspm_plugin_id": f.plugin_id,
                            "cspm_fingerprint": f.fingerprint,
                            "category": f.category,
                            "region": f.region,
                            "recommendation": f.recommendation,
                            "compliance": f.compliance,
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
    report: ScanReport,
) -> str:
    """Insert a scan audit row, return its id."""
    scan_id = str(uuid.uuid4())
    try:
        await db.execute(
            text("""
                INSERT INTO cspm_scans (
                    id, org_id, connection_id, cloud,
                    started_at, finished_at, duration_ms,
                    plugins_run, plugins_ok, plugins_fail, plugins_unknown,
                    findings_count, severity_counts, errors, status
                ) VALUES (
                    CAST(:id AS UUID), CAST(:org_id AS UUID), CAST(:connection_id AS UUID), :cloud,
                    :started_at, :finished_at, :duration_ms,
                    :plugins_run, :plugins_ok, :plugins_fail, :plugins_unknown,
                    :findings_count, CAST(:severity_counts AS jsonb), CAST(:errors AS jsonb), :status
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
                "plugins_run": report.plugins_run,
                "plugins_ok": report.plugins_ok,
                "plugins_fail": report.plugins_fail,
                "plugins_unknown": report.plugins_unknown,
                "findings_count": len(report.findings),
                "severity_counts": json.dumps(report.severity_counts),
                "errors": json.dumps(report.errors[:50]),  # cap error log
                "status": "failed" if report.errors and report.plugins_run == 0 else "completed",
            },
        )
        await db.commit()
    except Exception as exc:
        logger.warning(f"cspm_scans insert failed: {exc}")
    return scan_id


async def mark_resolved(
    db: AsyncSession,
    org_id: str,
    cloud: str,
    seen_fingerprints: set[str],
) -> int:
    """
    Mark any open finding for this (org_id, cloud) that was NOT seen in the
    current scan as resolved. Returns count.
    """
    if not seen_fingerprints:
        return 0
    try:
        # Use a temp array param
        result = await db.execute(
            text("""
                UPDATE cspm_findings
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
        logger.warning(f"cspm_findings auto-resolve failed: {exc}")
        return 0
