"""
CSPM shared types.

Designed to mirror cloudsploit's `addResult(results, severity, message, region, resource)`
output shape but in idiomatic Python.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Optional


class Severity(str, enum.Enum):
    """Finding severity. Strings chosen to match the existing saas_alerts.severity column."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cloudsploit_code(cls, code: int) -> "Severity":
        """
        cloudsploit uses numeric severity codes in addResult():
            0 = OK / passing
            1 = WARN / low
            2 = FAIL / high
            3 = UNKNOWN (we treat as info)
        We expand this to our 5-level scale.
        """
        return {
            0: cls.INFO,
            1: cls.LOW,
            2: cls.HIGH,
            3: cls.INFO,
        }.get(code, cls.MEDIUM)


class PluginStatus(str, enum.Enum):
    """Result status for an individual plugin run."""
    OK = "ok"             # check passed
    WARN = "warn"         # minor issue (low severity)
    FAIL = "fail"         # check failed (medium/high/critical)
    UNKNOWN = "unknown"   # could not evaluate (API error, permission denied)


@dataclass
class PluginMeta:
    """Metadata describing a plugin. Mirrors cloudsploit's module.exports header."""
    plugin_id: str             # e.g. "azure-keyvault-key-expiration"
    title: str                 # human-readable
    category: str              # e.g. "Key Vaults", "IAM", "Storage"
    domain: str = "Security"   # e.g. "Identity", "Application Integration"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    more_info: str = ""
    recommended_action: str = ""
    link: str = ""
    apis: list[str] = field(default_factory=list)
    compliance: dict[str, str] = field(default_factory=dict)  # framework -> rationale
    cloud: str = "aws"         # aws | azure | gcp | oracle | github | databricks | sap

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Finding:
    """A single security finding produced by a plugin."""
    plugin_id: str
    cloud: str
    severity: Severity
    status: PluginStatus
    category: str
    title: str
    message: str
    resource: str = ""            # ARN / resource ID
    resource_type: str = ""       # e.g. "KeyVault", "Bucket"
    region: str = "global"
    recommendation: str = ""
    compliance: dict[str, str] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        """
        Deterministic ID used for dedup / upsert across scan cycles.
        Same plugin + resource + region = same finding (even if message text changes).
        """
        key = f"{self.cloud}|{self.plugin_id}|{self.region}|{self.resource}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["detected_at"] = self.detected_at.isoformat()
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class PluginResult:
    """Output of a single plugin invocation."""
    plugin_id: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.status == PluginStatus.FAIL)


@dataclass
class ScanContext:
    """
    Per-scan context shared with plugins.
    Holds the collector cache (raw cloud API responses keyed by service+method+region+resource).
    """
    org_id: str
    connection_id: str
    cloud: str
    cache: dict = field(default_factory=dict)
    settings: dict = field(default_factory=dict)  # e.g. govcloud, compliance mode
    regions: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_source(self, path: list[str], value: Any) -> None:
        """
        Insert a raw API response into the cache at the given path.
        Mirrors cloudsploit's source[svc][method][region] = data pattern.
        """
        node = self.cache
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = value

    def get_source(self, path: list[str]) -> Any:
        """
        Read a raw API response from the cache.
        Returns None when missing (matches cloudsploit's helpers.addSource fallback).
        """
        node = self.cache
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node


@dataclass
class ScanReport:
    """Aggregate report returned at the end of a scan run."""
    org_id: str
    connection_id: str
    cloud: str
    started_at: datetime
    finished_at: datetime
    plugins_run: int
    plugins_ok: int
    plugins_fail: int
    plugins_unknown: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at).total_seconds() * 1000)

    @property
    def severity_counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def as_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "connection_id": self.connection_id,
            "cloud": self.cloud,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_ms": self.duration_ms,
            "plugins_run": self.plugins_run,
            "plugins_ok": self.plugins_ok,
            "plugins_fail": self.plugins_fail,
            "plugins_unknown": self.plugins_unknown,
            "severity_counts": self.severity_counts,
            "findings_count": len(self.findings),
            "errors": self.errors,
        }


# Plugin function signature: takes a ScanContext and returns a PluginResult.
PluginFn = Callable[[ScanContext], "PluginResult"]
