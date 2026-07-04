"""
Himaya CSPM (Cloud Security Posture Management) Engine.

Inspired by aquasecurity/cloudsploit. Provides a plugin-based architecture for
scanning cloud accounts (AWS, Azure, GCP, Oracle, GitHub) for misconfigurations
and producing severity-scored findings.

Architecture:
    collectors/  -> per-cloud API collection layer (caches raw API responses)
    plugins/     -> individual security checks (one file per check)
    engine.py    -> orchestrator: runs plugins against collected data
    types.py     -> shared data structures (Finding, PluginResult, etc.)
    sink.py      -> writes findings into Postgres (saas_alerts + cspm_findings)

This module is intentionally pure-Python with no heavy framework dependency so
it can be invoked both in-process (from FastAPI workers) and as a standalone
worker (Celery / background task).
"""
from .types import (
    Severity,
    PluginStatus,
    Finding,
    PluginResult,
    PluginMeta,
    ScanContext,
    ScanReport,
)
from .engine import CSPMEngine, run_scan
from .sink import write_findings, ensure_cspm_tables

__all__ = [
    "Severity",
    "PluginStatus",
    "Finding",
    "PluginResult",
    "PluginMeta",
    "ScanContext",
    "ScanReport",
    "CSPMEngine",
    "run_scan",
    "write_findings",
    "ensure_cspm_tables",
]
