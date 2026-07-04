"""DSPM shared types."""
from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class DataCategory(str, enum.Enum):
    """Sensitive data categories — matches Mantissa Stance taxonomy."""
    # PII
    PII_SSN = "pii_ssn"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_DOB = "pii_dob"
    PII_PASSPORT = "pii_passport"
    PII_ADDRESS = "pii_address"
    PII_NAME = "pii_name"
    PII_NATIONAL_ID = "pii_national_id"

    # PCI
    PCI_CARD_NUMBER = "pci_card_number"
    PCI_CVV = "pci_cvv"
    PCI_EXPIRY = "pci_expiry"

    # PHI / healthcare
    PHI = "phi"
    PHI_MEDICAL_RECORD = "phi_medical_record"
    PHI_DIAGNOSIS = "phi_diagnosis"

    # Financial
    FINANCIAL_BANK_ACCOUNT = "financial_bank_account"
    FINANCIAL_ROUTING = "financial_routing"
    FINANCIAL_TAX_ID = "financial_tax_id"
    FINANCIAL_SWIFT = "financial_swift"

    # Credentials
    CREDENTIALS_API_KEY = "credentials_api_key"
    CREDENTIALS_PASSWORD = "credentials_password"
    CREDENTIALS_PRIVATE_KEY = "credentials_private_key"
    CREDENTIALS_TOKEN = "credentials_token"
    CREDENTIALS_CONN_STRING = "credentials_conn_string"

    # Confidential / IP
    CONFIDENTIAL_LEGAL = "confidential_legal"
    CONFIDENTIAL_FINANCIAL = "confidential_financial"
    CONFIDENTIAL_TRADE_SECRET = "confidential_trade_secret"

    # Other
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Category → default severity mapping. Credentials and PCI are most damaging
# in a breach; PII varies by jurisdiction; PHI is regulated.
SEVERITY_BY_CATEGORY: dict[DataCategory, Severity] = {
    DataCategory.PCI_CARD_NUMBER: Severity.CRITICAL,
    DataCategory.PCI_CVV: Severity.CRITICAL,
    DataCategory.CREDENTIALS_PRIVATE_KEY: Severity.CRITICAL,
    DataCategory.CREDENTIALS_API_KEY: Severity.CRITICAL,
    DataCategory.PII_SSN: Severity.HIGH,
    DataCategory.PII_PASSPORT: Severity.HIGH,
    DataCategory.PII_NATIONAL_ID: Severity.HIGH,
    DataCategory.PHI_MEDICAL_RECORD: Severity.HIGH,
    DataCategory.PHI_DIAGNOSIS: Severity.HIGH,
    DataCategory.FINANCIAL_BANK_ACCOUNT: Severity.HIGH,
    DataCategory.FINANCIAL_ROUTING: Severity.HIGH,
    DataCategory.FINANCIAL_TAX_ID: Severity.HIGH,
    DataCategory.CREDENTIALS_PASSWORD: Severity.HIGH,
    DataCategory.CREDENTIALS_TOKEN: Severity.HIGH,
    DataCategory.CREDENTIALS_CONN_STRING: Severity.HIGH,
    DataCategory.CONFIDENTIAL_LEGAL: Severity.MEDIUM,
    DataCategory.CONFIDENTIAL_FINANCIAL: Severity.MEDIUM,
    DataCategory.CONFIDENTIAL_TRADE_SECRET: Severity.MEDIUM,
    DataCategory.PII_EMAIL: Severity.LOW,
    DataCategory.PII_PHONE: Severity.LOW,
    DataCategory.PII_DOB: Severity.MEDIUM,
    DataCategory.PII_ADDRESS: Severity.LOW,
    DataCategory.PII_NAME: Severity.LOW,
    DataCategory.PHI: Severity.MEDIUM,
    DataCategory.FINANCIAL_SWIFT: Severity.MEDIUM,
    DataCategory.PCI_EXPIRY: Severity.MEDIUM,
    DataCategory.UNKNOWN: Severity.INFO,
}


def severity_for(cat: DataCategory) -> Severity:
    return SEVERITY_BY_CATEGORY.get(cat, Severity.MEDIUM)


@dataclass
class DataPattern:
    """One detection pattern. Ported from mantissa.stance.dspm.detector.DataPattern."""
    name: str
    description: str
    pattern: str
    category: DataCategory
    confidence: float = 0.8
    validation: str | None = None
    enabled: bool = True
    _compiled: re.Pattern | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class PatternMatch:
    """Output of a successful pattern run."""
    pattern_name: str
    category: DataCategory
    matched_text: str
    location: dict[str, Any]
    confidence: float
    context: str = ""
    redacted: str = ""

    def __post_init__(self):
        if not self.redacted:
            self.redacted = _redact(self.matched_text)


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


@dataclass
class DSPMFinding:
    """A single DSPM finding — sensitive data discovered in a resource."""
    cloud: str                      # aws | gcp | azure
    resource_type: str              # s3_bucket | gcs_bucket | azure_blob
    resource_id: str                # bucket name or arn
    object_key: str                 # path of the object containing the data
    category: DataCategory          # type of sensitive data
    severity: Severity
    pattern_name: str               # which pattern fired
    match_count: int = 1            # how many matches inside this object
    redacted_sample: str = ""       # one redacted example of the matched text
    confidence: float = 0.8
    region: str = "global"
    metadata: dict = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        """Stable dedup key — same object + pattern = same finding across scans."""
        key = f"{self.cloud}|{self.resource_id}|{self.object_key}|{self.pattern_name}|{self.category.value}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def as_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["detected_at"] = self.detected_at.isoformat()
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class DSPMScanReport:
    """Aggregate report for a single DSPM scan run."""
    org_id: str
    connection_id: str
    cloud: str
    started_at: datetime
    finished_at: datetime
    resources_scanned: int = 0
    objects_sampled: int = 0
    bytes_inspected: int = 0
    findings: list[DSPMFinding] = field(default_factory=list)
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

    @property
    def category_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category.value] = out.get(f.category.value, 0) + 1
        return out

    def as_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "connection_id": self.connection_id,
            "cloud": self.cloud,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_ms": self.duration_ms,
            "resources_scanned": self.resources_scanned,
            "objects_sampled": self.objects_sampled,
            "bytes_inspected": self.bytes_inspected,
            "findings_count": len(self.findings),
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "errors": self.errors,
        }
