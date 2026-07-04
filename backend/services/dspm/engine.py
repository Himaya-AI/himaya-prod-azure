"""
DSPM engine — thin orchestrator that runs a cloud-specific scanner and
persists the resulting findings + scan report.

Use the cloud-specific helpers (run_aws_s3_scan, etc.) from routers; the
engine itself just glues scanner output to the sink.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from .scanners.aws_s3 import AWSS3ScanConfig, scan_aws_s3
from .scanners.azure_blob import AzureBlobDSPMConfig, scan_azure_blob
from .scanners.gcp_gcs import GCSDSPMConfig, scan_gcs
from .scanners.m365_graph import M365DSPMConfig, scan_m365
from .sink import mark_resolved, write_findings, write_scan_report
from .types import DSPMScanReport

logger = logging.getLogger(__name__)


async def run_aws_s3_scan(
    db: AsyncSession,
    *,
    org_id: str,
    connection_id: str,
    access_key_id: str,
    secret_access_key: str,
    default_region: str = "us-east-1",
    max_buckets: int = 50,
    max_keys_per_bucket: int = 100,
) -> DSPMScanReport:
    """
    Run a DSPM scan against an AWS account, persist findings + audit row,
    and return the populated report.
    """
    cfg = AWSS3ScanConfig(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        default_region=default_region,
        max_buckets=max_buckets,
        max_keys_per_bucket=max_keys_per_bucket,
    )
    report = await scan_aws_s3(
        cfg, org_id=org_id, connection_id=connection_id
    )

    # Persist findings, auto-resolve missing ones, write scan audit row.
    try:
        await write_findings(db, org_id, connection_id, report.findings)
        seen = {f.fingerprint for f in report.findings}
        await mark_resolved(db, org_id, "aws", seen)
        await write_scan_report(db, report)
    except Exception as exc:
        logger.warning("DSPM scan persistence failed: %s", exc)
        report.errors.append(f"persistence: {exc}")

    return report


async def run_m365_dspm_scan(
    db: AsyncSession,
    *,
    org_id: str,
    integration_id: str,
    access_token: str,
    scan_sharepoint: bool = True,
    scan_onedrive: bool = True,
    max_sites: int = 30,
    max_drives: int = 50,
    max_items_per_drive: int = 80,
) -> DSPMScanReport:
    """
    Run a DSPM scan against an M365 tenant. Reuses the SaaS layer's Graph
    access token. Persists findings + scan audit row, returns the populated
    report.
    """
    cfg = M365DSPMConfig(
        access_token=access_token,
        scan_sharepoint=scan_sharepoint,
        scan_onedrive=scan_onedrive,
        max_sites=max_sites,
        max_drives=max_drives,
        max_items_per_drive=max_items_per_drive,
    )
    report = await scan_m365(
        cfg, org_id=org_id, integration_id=integration_id
    )

    try:
        await write_findings(db, org_id, integration_id, report.findings)
        seen = {f.fingerprint for f in report.findings}
        await mark_resolved(db, org_id, "m365", seen)
        await write_scan_report(db, report)
    except Exception as exc:
        logger.warning("DSPM M365 scan persistence failed: %s", exc)
        report.errors.append(f"persistence: {exc}")

    return report


async def run_azure_dspm_scan(
    db: AsyncSession,
    *,
    org_id: str,
    connection_id: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_id: str,
    max_accounts: int = 10,
    max_containers_per_account: int = 10,
    max_blobs_per_container: int = 80,
) -> DSPMScanReport:
    """Run a DSPM scan against an Azure subscription's Blob Storage."""
    cfg = AzureBlobDSPMConfig(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id,
        max_accounts=max_accounts,
        max_containers_per_account=max_containers_per_account,
        max_blobs_per_container=max_blobs_per_container,
    )
    report = await scan_azure_blob(
        cfg, org_id=org_id, connection_id=connection_id
    )
    try:
        await write_findings(db, org_id, connection_id, report.findings)
        seen = {f.fingerprint for f in report.findings}
        await mark_resolved(db, org_id, "azure", seen)
        await write_scan_report(db, report)
    except Exception as exc:
        logger.warning("DSPM Azure scan persistence failed: %s", exc)
        report.errors.append(f"persistence: {exc}")
    return report


async def run_gcs_dspm_scan(
    db: AsyncSession,
    *,
    org_id: str,
    connection_id: str,
    project_id: str,
    service_account_json: str,
    max_buckets: int = 10,
    max_objects_per_bucket: int = 80,
) -> DSPMScanReport:
    """Run a DSPM scan against a GCS project."""
    cfg = GCSDSPMConfig(
        project_id=project_id,
        service_account_json=service_account_json,
        max_buckets=max_buckets,
        max_objects_per_bucket=max_objects_per_bucket,
    )
    report = await scan_gcs(cfg, org_id=org_id, connection_id=connection_id)
    try:
        await write_findings(db, org_id, connection_id, report.findings)
        seen = {f.fingerprint for f in report.findings}
        await mark_resolved(db, org_id, "gcp", seen)
        await write_scan_report(db, report)
    except Exception as exc:
        logger.warning("DSPM GCS scan persistence failed: %s", exc)
        report.errors.append(f"persistence: {exc}")
    return report
