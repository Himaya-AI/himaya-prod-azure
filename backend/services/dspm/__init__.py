"""
Himaya DSPM (Data Security Posture Management).

Inspired by clay-good/mantissa-stance. Discovers sensitive data in cloud
storage (S3, GCS, Azure Blob) using a curated catalogue of detection patterns
(PII, PCI, PHI, financial, credentials, ITAR-style), produces dedup-able
findings, and surfaces them in the Workspace Security → Data Inventory tab.

Architecture mirrors backend/services/cspm/ for consistency:
    patterns.py   — pattern catalogue (regex + validation)
    detector.py   — runs patterns over sampled object content
    scanners/     — per-cloud sampling + content fetch
    sink.py       — Postgres persistence (dspm_findings + dspm_scans)
    engine.py     — orchestrator: collects → detects → writes findings
    types.py      — Finding / Pattern / ScanReport
"""
from .types import (
    DataCategory,
    PatternMatch,
    DSPMFinding,
    DSPMScanReport,
    Severity,
)
from .patterns import DEFAULT_PATTERNS
from .detector import SensitiveDataDetector
from .sink import ensure_dspm_tables, write_findings, write_scan_report, mark_resolved
from .engine import (
    run_aws_s3_scan,
    run_m365_dspm_scan,
    run_azure_dspm_scan,
    run_gcs_dspm_scan,
)

__all__ = [
    "DataCategory",
    "PatternMatch",
    "DSPMFinding",
    "DSPMScanReport",
    "Severity",
    "DEFAULT_PATTERNS",
    "SensitiveDataDetector",
    "ensure_dspm_tables",
    "write_findings",
    "write_scan_report",
    "mark_resolved",
    "run_aws_s3_scan",
    "run_m365_dspm_scan",
    "run_azure_dspm_scan",
    "run_gcs_dspm_scan",
]
