"""
DSPM module unit tests.

Covers:
- Pattern catalogue smoke: each non-Luhn pattern matches a representative sample
- Luhn validation: real card number passes, random digits don't
- Detector context window: produces context around matches
- Detector max-matches cap: doesn't flood on repeated matches
- AWSS3ScanConfig defaults sane
- _looks_textual extension + content-type detection
- _matches_to_findings group + count behavior
"""
from __future__ import annotations

import pytest

from backend.services.dspm.detector import (
    CONTEXT_CHARS,
    MAX_MATCHES_PER_PATTERN,
    SensitiveDataDetector,
)
from backend.services.dspm.patterns import (
    DEFAULT_PATTERNS,
    PATTERNS_BY_NAME,
    _luhn_check,
)
from backend.services.dspm.scanners.aws_s3 import (
    AWSS3ScanConfig,
    _looks_textual,
    _matches_to_findings,
)
from backend.services.dspm.scanners.m365_graph import (
    M365DSPMConfig,
    _looks_textual as _m365_looks_textual,
    _decode_body,
    _matches_to_findings as _m365_matches_to_findings,
)
from backend.services.dspm.scanners.azure_blob import (
    AzureBlobDSPMConfig,
    _looks_textual as _az_looks_textual,
    _decode_body as _az_decode_body,
    _matches_to_findings as _az_matches_to_findings,
)
from backend.services.dspm.scanners.gcp_gcs import (
    GCSDSPMConfig,
    _looks_textual as _gcs_looks_textual,
    _decode_body as _gcs_decode_body,
    _matches_to_findings as _gcs_matches_to_findings,
)
from backend.services.dspm.types import (
    DataCategory,
    DSPMFinding,
    PatternMatch,
    Severity,
    severity_for,
)


# ── Pattern catalogue smoke ───────────────────────────────────────────────

PATTERN_SAMPLES: dict[str, str] = {
    "ssn-formatted": "Customer SSN: 219-09-9999",
    "email-address": "Reach out at jane.doe@example.com today",
    "phone-us": "Call (415) 555-2671 for support",
    "phone-international": "International: +44 20 7946 0958",
    "date-of-birth": "DOB: 1985-04-15",
    "us-passport": "Passport A12345678",
    "saudi-national-id": "SA ID: 1098765432",
    "uae-emirates-id": "UAE EID 784-1985-1234567-1",
    # Valid Visa from public test list (Luhn-valid)
    "credit-card-visa": "Visa: 4111111111111111",
    "credit-card-mastercard": "MC: 5555555555554444",
    "credit-card-amex": "Amex: 378282246310005",
    "credit-card-discover": "Discover: 6011111111111117",
    "medical-record-number": "MRN: 12345678",
    "icd10-code": "Diagnosis E11.65",
    "bank-routing-number": "Routing: 021000021",
    "iban": "IBAN GB29NWBK60161331926819",
    "iban-saudi": "SA0380000000608010167519",
    "iban-uae": "AE070331234567890123456",
    "ein": "EIN 12-3456789",
    "swift-code": "SWIFT BOFAUS3N",
    "aws-access-key": "AKIA" + "IOSFODNN7EXAMPLE",
    "private-key-header": "-----BEGIN PRIVATE KEY-----",
    "jwt-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
    "github-token": "gh" + "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "github-app-token": "gh" + "s_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "slack-token": "xo" + "xb-12345678901-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "google-api-key": "AIza" + "SyDOCAbC123dEf456GhI789jKl012-MnoP9",
    "db-connection-string": "postgres://admin:hunter2@db.internal:5432/prod",
    "password-keyvalue": "password = SuperSecret123!",
}


def test_every_pattern_has_a_sample():
    """Coverage: every pattern in the catalogue should have a test sample."""
    sample_keys = set(PATTERN_SAMPLES.keys())
    catalogue_keys = {p.name for p in DEFAULT_PATTERNS}
    missing = catalogue_keys - sample_keys
    # These are intentionally fuzzy patterns that need wider context to fire;
    # treat missing as a fail unless they're in the known-skip list.
    known_skip = {"aws-secret-key", "anthropic-api-key", "openai-api-key"}
    truly_missing = missing - known_skip
    assert not truly_missing, f"Patterns without samples: {truly_missing}"


@pytest.mark.parametrize("pattern_name,sample", list(PATTERN_SAMPLES.items()))
def test_pattern_matches_sample(pattern_name: str, sample: str):
    """Each pattern must match at least once against its representative sample."""
    detector = SensitiveDataDetector(
        patterns=[PATTERNS_BY_NAME[pattern_name]]
    )
    matches = detector.scan_text(sample)
    assert matches, f"Pattern {pattern_name} did not match its own sample"
    assert matches[0].pattern_name == pattern_name


# ── Luhn ──────────────────────────────────────────────────────────────────

def test_luhn_valid_card():
    # Public Stripe test number, Luhn-valid
    assert _luhn_check("4242424242424242")


def test_luhn_invalid_card():
    # Random digits, statistically very unlikely to be valid
    assert not _luhn_check("1234567890123456")


def test_luhn_strips_separators():
    assert _luhn_check("4242-4242-4242-4242")


# ── Detector behavior ─────────────────────────────────────────────────────

def test_detector_context_window():
    """Context window should include chars around the match."""
    detector = SensitiveDataDetector(
        patterns=[PATTERNS_BY_NAME["email-address"]]
    )
    text = "Please contact our admin at admin@acme.example.com immediately."
    matches = detector.scan_text(text)
    assert matches
    # Context should be wider than just the matched email
    assert len(matches[0].context) > len("admin@acme.example.com")
    assert "admin" in matches[0].context


def test_detector_redaction_applied():
    detector = SensitiveDataDetector(
        patterns=[PATTERNS_BY_NAME["email-address"]]
    )
    text = "Email: longuser@example.com"
    matches = detector.scan_text(text)
    assert matches
    assert "*" in matches[0].redacted
    # Original should not appear verbatim in the redacted form (length > 8)
    assert matches[0].redacted != matches[0].matched_text


def test_detector_caps_matches_per_pattern():
    detector = SensitiveDataDetector(
        patterns=[PATTERNS_BY_NAME["email-address"]]
    )
    # 200 unique emails — detector should cap at MAX_MATCHES_PER_PATTERN
    text = "\n".join(f"user{i}@example.com" for i in range(200))
    matches = detector.scan_text(text)
    assert len(matches) == MAX_MATCHES_PER_PATTERN


def test_detector_empty_text():
    detector = SensitiveDataDetector()
    assert detector.scan_text("") == []
    assert detector.scan_text(None) == []  # type: ignore[arg-type]


def test_detector_luhn_filters_invalid_cards():
    """Pattern matches the digit shape but Luhn rejects bad checksums."""
    detector = SensitiveDataDetector(
        patterns=[PATTERNS_BY_NAME["credit-card-visa"]]
    )
    bad = "4111111111111112"  # last digit bumped — Luhn fails
    good = "4111111111111111"
    matches = detector.scan_text(f"bad {bad} good {good}")
    assert len(matches) == 1
    assert matches[0].matched_text == good


# ── Types / severity mapping ──────────────────────────────────────────────

def test_severity_mapping_known_categories():
    assert severity_for(DataCategory.PCI_CARD_NUMBER) == Severity.CRITICAL
    assert severity_for(DataCategory.CREDENTIALS_PRIVATE_KEY) == Severity.CRITICAL
    assert severity_for(DataCategory.PII_EMAIL) == Severity.LOW


def test_dspm_finding_fingerprint_is_stable():
    f1 = DSPMFinding(
        cloud="aws",
        resource_type="s3_bucket",
        resource_id="my-bucket",
        object_key="users.csv",
        category=DataCategory.PII_EMAIL,
        severity=Severity.LOW,
        pattern_name="email-address",
    )
    f2 = DSPMFinding(
        cloud="aws",
        resource_type="s3_bucket",
        resource_id="my-bucket",
        object_key="users.csv",
        category=DataCategory.PII_EMAIL,
        severity=Severity.LOW,
        pattern_name="email-address",
    )
    assert f1.fingerprint == f2.fingerprint
    assert len(f1.fingerprint) == 32


def test_dspm_finding_fingerprint_changes_per_object():
    base = dict(
        cloud="aws",
        resource_type="s3_bucket",
        resource_id="my-bucket",
        category=DataCategory.PII_EMAIL,
        severity=Severity.LOW,
        pattern_name="email-address",
    )
    f1 = DSPMFinding(object_key="users.csv", **base)
    f2 = DSPMFinding(object_key="employees.csv", **base)
    assert f1.fingerprint != f2.fingerprint


# ── AWS S3 scanner helpers ────────────────────────────────────────────────

def test_aws_s3_scan_config_defaults():
    cfg = AWSS3ScanConfig(access_key_id="x", secret_access_key="y")
    assert cfg.default_region == "us-east-1"
    assert cfg.max_buckets == 50
    assert cfg.max_keys_per_bucket == 100
    assert cfg.max_bytes_per_object == 2 * 1024 * 1024


def test_looks_textual_by_content_type():
    assert _looks_textual("file.bin", "text/plain")
    assert _looks_textual("file.bin", "application/json")
    assert not _looks_textual("file.bin", "image/png")
    assert not _looks_textual("file.bin", "video/mp4")


def test_looks_textual_by_extension():
    assert _looks_textual("data/customers.csv", None)
    assert _looks_textual("config.yaml", None)
    assert _looks_textual("script.py", None)
    assert not _looks_textual("photo.jpg", None)
    assert not _looks_textual("archive.zip", None)


def test_matches_to_findings_groups_by_pattern():
    matches = [
        PatternMatch(
            pattern_name="email-address",
            category=DataCategory.PII_EMAIL,
            matched_text="a@b.com",
            location={},
            confidence=0.95,
            context="ctx 1",
        ),
        PatternMatch(
            pattern_name="email-address",
            category=DataCategory.PII_EMAIL,
            matched_text="c@d.com",
            location={},
            confidence=0.95,
            context="ctx 2",
        ),
        PatternMatch(
            pattern_name="ssn-formatted",
            category=DataCategory.PII_SSN,
            matched_text="111-11-1111",
            location={},
            confidence=0.95,
            context="ctx 3",
        ),
    ]
    findings = _matches_to_findings(
        matches, bucket="my-bucket", key="data.csv", region="us-east-1"
    )
    assert len(findings) == 2
    by_pat = {f.pattern_name: f for f in findings}
    assert by_pat["email-address"].match_count == 2
    assert by_pat["ssn-formatted"].match_count == 1
    assert by_pat["email-address"].resource_id == "my-bucket"
    assert by_pat["email-address"].object_key == "data.csv"
    assert by_pat["email-address"].region == "us-east-1"
    # Severity should come from category mapping
    assert by_pat["email-address"].severity == Severity.LOW
    assert by_pat["ssn-formatted"].severity == Severity.HIGH


# ── M365 scanner helpers ─────────────────────────────────────────────────────

def test_m365_scan_config_defaults():
    cfg = M365DSPMConfig(access_token="fake.jwt.token")
    assert cfg.max_sites == 30
    assert cfg.max_drives == 50
    assert cfg.max_items_per_drive == 80
    assert cfg.max_bytes_per_item == 2 * 1024 * 1024
    assert cfg.scan_sharepoint is True
    assert cfg.scan_onedrive is True


def test_m365_looks_textual_by_mime():
    assert _m365_looks_textual("doc.bin", "text/plain")
    assert _m365_looks_textual("doc.bin", "application/json")
    assert _m365_looks_textual(
        "doc.bin",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert not _m365_looks_textual("doc.bin", "image/png")
    assert not _m365_looks_textual("doc.bin", "video/mp4")


def test_m365_looks_textual_by_extension():
    assert _m365_looks_textual("report.docx", None)
    assert _m365_looks_textual("data.csv", None)
    assert _m365_looks_textual("config.yaml", None)
    assert not _m365_looks_textual("photo.png", None)
    assert not _m365_looks_textual("clip.mp4", None)


def test_m365_decode_body_utf8():
    body = _decode_body("notes.txt", "text/plain", b"hello world")
    assert body == "hello world"


def test_m365_decode_body_empty():
    assert _decode_body("x.txt", "text/plain", b"") is None
    assert _decode_body("x.txt", "text/plain", None) is None  # type: ignore[arg-type]


def test_m365_decode_body_pdf_fallback():
    """If pdfminer fails on malformed PDF bytes, scanner should still return
    a latin-1 decode so secret patterns at the start of the file get matched."""
    _fake_key = "AKIA" + "IOSFODNN7EXAMPLE"
    body = _decode_body("x.pdf", "application/pdf", (b"%PDF-1.4\n" + _fake_key.encode() + b" rest"))
    assert body is not None
    assert _fake_key in body


def test_m365_matches_to_findings_groups_correctly():
    matches = [
        PatternMatch(
            pattern_name="email-address", category=DataCategory.PII_EMAIL,
            matched_text="a@b.com", location={}, confidence=0.95, context="c1",
        ),
        PatternMatch(
            pattern_name="email-address", category=DataCategory.PII_EMAIL,
            matched_text="c@d.com", location={}, confidence=0.95, context="c2",
        ),
        PatternMatch(
            pattern_name="aws-access-key", category=DataCategory.CREDENTIALS_API_KEY,
            matched_text="AKIA" + "IOSFODNN7EXAMPLE", location={}, confidence=0.99, context="c3",
        ),
    ]
    findings = _m365_matches_to_findings(
        matches,
        resource_type="sharepoint_site",
        resource_id="Marketing",
        object_key="customers.csv",
        extra_metadata={"item_id": "01ABC", "item_url": "https://t.sp/x"},
    )
    assert len(findings) == 2
    by_pat = {f.pattern_name: f for f in findings}
    assert by_pat["email-address"].cloud == "m365"
    assert by_pat["email-address"].resource_type == "sharepoint_site"
    assert by_pat["email-address"].resource_id == "Marketing"
    assert by_pat["email-address"].match_count == 2
    assert by_pat["aws-access-key"].severity == Severity.CRITICAL
    # extra_metadata should be merged into the finding's metadata
    assert by_pat["email-address"].metadata.get("item_id") == "01ABC"
    assert by_pat["email-address"].metadata.get("item_url") == "https://t.sp/x"


def test_m365_finding_fingerprint_differs_from_aws():
    """Same object key in M365 and AWS should produce different fingerprints."""
    base = dict(
        resource_type="sharepoint_site",
        resource_id="Marketing",
        object_key="customers.csv",
        category=DataCategory.PII_EMAIL,
        severity=Severity.LOW,
        pattern_name="email-address",
    )
    m365_finding = DSPMFinding(cloud="m365", **base)
    aws_finding = DSPMFinding(cloud="aws", **base)
    assert m365_finding.fingerprint != aws_finding.fingerprint


# ── Azure Blob scanner helpers ────────────────────────────────────────────

def test_azure_blob_config_defaults():
    cfg = AzureBlobDSPMConfig(
        tenant_id="t", client_id="c", client_secret="s", subscription_id="sub",
    )
    assert cfg.max_accounts == 10
    assert cfg.max_containers_per_account == 10
    assert cfg.max_blobs_per_container == 80
    assert cfg.max_bytes_per_blob == 2 * 1024 * 1024


def test_azure_blob_looks_textual_by_extension():
    assert _az_looks_textual("file.csv")
    assert _az_looks_textual("deep/path/notes.md")
    assert _az_looks_textual("data.json")
    assert _az_looks_textual("report.pdf")
    assert not _az_looks_textual("image.png")
    assert not _az_looks_textual("archive.zip")


def test_azure_blob_decode_body_utf8():
    assert _az_decode_body("x.txt", b"hello world") == "hello world"


def test_azure_blob_decode_body_pdf_fallback():
    _fake_key = "AKIA" + "IOSFODNN7EXAMPLE"
    body = _az_decode_body("x.pdf", (b"%PDF-1.4\n" + _fake_key.encode() + b" rest"))
    assert body is not None
    assert _fake_key in body


def test_azure_blob_matches_to_findings_groups_by_pattern():
    matches = [
        PatternMatch(
            pattern_name="email-address", category=DataCategory.PII_EMAIL,
            matched_text="a@b.com", location={}, confidence=0.95, context="c1",
        ),
        PatternMatch(
            pattern_name="email-address", category=DataCategory.PII_EMAIL,
            matched_text="c@d.com", location={}, confidence=0.95, context="c2",
        ),
    ]
    findings = _az_matches_to_findings(
        matches, storage_account="sa1", container="docs", blob="users.csv",
        region="eastus",
    )
    assert len(findings) == 1
    assert findings[0].cloud == "azure"
    assert findings[0].resource_type == "storage_container"
    assert findings[0].resource_id == "sa1/docs"
    assert findings[0].object_key == "users.csv"
    assert findings[0].match_count == 2
    assert findings[0].metadata.get("container") == "docs"
    assert findings[0].region == "eastus"


# ── GCS scanner helpers ───────────────────────────────────────────────────────────

def test_gcs_config_defaults():
    cfg = GCSDSPMConfig(project_id="my-proj", service_account_json="{}")
    assert cfg.max_buckets == 10
    assert cfg.max_objects_per_bucket == 80
    assert cfg.max_bytes_per_object == 2 * 1024 * 1024


def test_gcs_looks_textual():
    assert _gcs_looks_textual("data.json")
    assert _gcs_looks_textual("audit.log")
    assert _gcs_looks_textual("export.csv")
    assert not _gcs_looks_textual("img.jpg")
    assert not _gcs_looks_textual("video.mp4")


def test_gcs_decode_body_utf8():
    assert _gcs_decode_body("x.txt", b"hello world") == "hello world"
    assert _gcs_decode_body("x.txt", b"") is None


def test_gcs_matches_to_findings_groups():
    matches = [
        PatternMatch(
            pattern_name="aws-access-key",
            category=DataCategory.CREDENTIALS_API_KEY,
            matched_text="AKIA" + "IOSFODNN7EXAMPLE",
            location={}, confidence=0.99, context="ctx",
        ),
    ]
    findings = _gcs_matches_to_findings(
        matches, bucket="my-bucket", object_name="config.env", region="us-central1",
    )
    assert len(findings) == 1
    assert findings[0].cloud == "gcp"
    assert findings[0].resource_type == "gcs_bucket"
    assert findings[0].resource_id == "my-bucket"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].region == "us-central1"


def test_cross_cloud_fingerprints_are_distinct():
    """AWS / Azure / GCP / M365 same key should all hash differently."""
    base = dict(
        resource_type="container",
        resource_id="acme",
        object_key="users.csv",
        category=DataCategory.PII_EMAIL,
        severity=Severity.LOW,
        pattern_name="email-address",
    )
    fps = {
        DSPMFinding(cloud=c, **base).fingerprint
        for c in ("aws", "azure", "gcp", "m365")
    }
    assert len(fps) == 4  # all distinct
