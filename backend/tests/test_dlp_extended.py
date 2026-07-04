"""
Extended DLP tests — validates all pattern types and merge logic.
Run with: python -m pytest backend/tests/test_dlp_extended.py -v
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.services.dlp_service import _regex_classify, _SEV_ORDER, _ACT_MAP


# ── Pattern tests ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected_category", [
    # PII
    ("My SSN is 123-45-6789", "pii_ssn"),
    ("Card number: 4532015112830366", "pii_credit_card"),
    ("IBAN: GB29NWBK60161331926819", "pii_iban"),
    ("Passport: A12345678", "pii_passport"),
    ("UAE ID: 784-1234-1234567-1", "pii_uae_id"),
    ("Iqama number: 1234567890", "pii_saudi_id"),
    ("Call me at +971 50 123 4567", "pii_gcc_phone"),
    # Credentials
    ("-----BEGIN RSA PRIVATE KEY-----", "credential_privkey"),
    ("AKIA" + "IOSFODNN7EXAMPLE", "credential_awskey"),
    ("api_key = 'sk-test-1234567890abcdefghij'", "credential_apikey"),
    ("password = MySecretPass123", "credential_password"),
    ("mongodb://user:pass@host:27017/db", "credential_connstr"),
    # Financial
    ("SWIFT code: DEUTDEDB", "financial_swift"),
    ("routing number: 021000021", "financial_routing"),
    ("account number: 1234567890", "financial_account"),
    ("Salary increase approved for Q3", "financial_salary"),
    ("Invoice #INV-2024-001 attached", "financial_invoice"),
    # Legal
    ("This NDA must be signed", "legal_nda"),
    ("Settlement agreement attached", "legal_litigation"),
    ("Term sheet for acquisition", "legal_ma"),
    # Source code secrets
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123xyz456def789ghi", "jwt_token"),
    ("xo" + "xb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx", "slack_token"),
    ("gh" + "p_abcdefghijklmnopqrstuvwxyz1234567890ab", "github_token"),
    # Crypto
    ("0x742d35Cc6634C0532925a3b8D4C9B68d5c3e1F4a", "crypto_wallet"),
    # Healthcare
    ("Patient MRN: 12345, diagnosis: diabetes", "hipaa_phi"),
    # Cloud credentials
    ("aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key"),
    ("DefaultEndpointsProtocol=https;AccountName=mystorageaccount", "azure_conn_str"),
    # New types
    ("Wire transfer to correspondent bank NOSTRO account", "financial_wire"),
    ("W-2 form for tax return 2024", "financial_tax"),
    ("Court order signed by Judge Smith", "legal_court_order"),
    ("Trade secret regarding our manufacturing process", "legal_ip_rights"),
    ("Health insurance member ID: ABC123456", "pii_health_insurance"),
    ("Blood type: O+", "pii_blood_type"),
    ("Fingerprint scan required for entry", "pii_biometric"),
    ("INSERT INTO users VALUES (1, 'admin', 'pass')", "db_sql_dump"),
    ("Server=prod-db;User Id=sa;Password=secret123", "db_connection"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "infra_ssh_key"),
])
def test_regex_pattern_detection(text, expected_category):
    result = _regex_classify(text)
    assert expected_category in result["categories"], \
        f"Expected '{expected_category}' in categories for text: {text!r}\n  Got: {result['categories']}"


def test_clean_text_no_match():
    result = _regex_classify("Hello, how are you? Hope you have a great day!")
    assert result["risk_level"] == "low"
    assert result["categories"] == []


def test_critical_severity_for_private_key():
    result = _regex_classify("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...")
    assert result["risk_level"] == "critical"
    assert result["action"] == "BLOCK"


def test_action_mapping():
    assert _ACT_MAP["low"] == "ALLOW"
    assert _ACT_MAP["medium"] == "WARN"
    assert _ACT_MAP["high"] == "HOLD"
    assert _ACT_MAP["critical"] == "BLOCK"


def test_multiple_patterns_takes_highest_severity():
    # SSN (critical) + salary mention (medium) → should be critical
    text = "SSN: 123-45-6789 and salary adjustment memo"
    result = _regex_classify(text)
    assert result["risk_level"] == "critical"
    assert "pii_ssn" in result["categories"]
    assert "financial_salary" in result["categories"]


def test_bulk_exfil_detection():
    # 20+ recipients in BCC
    bcc = "bcc: a@x.com, b@x.com, c@x.com, d@x.com, e@x.com, f@x.com, g@x.com, h@x.com, i@x.com, j@x.com, k@x.com, l@x.com, m@x.com, n@x.com, o@x.com, p@x.com, q@x.com, r@x.com, s@x.com, t@x.com, u@x.com"
    result = _regex_classify(bcc)
    assert "bulk_exfil" in result["categories"]


def test_score_range():
    result = _regex_classify("SSN: 123-45-6789")
    assert 0 <= result.get("confidence", 0) <= 1.0


def test_gcc_phone_detection():
    phones = ["+966 50 123 4567", "+971501234567", "+97450123456"]
    for ph in phones:
        result = _regex_classify(ph)
        assert "pii_gcc_phone" in result["categories"], f"GCC phone not detected: {ph}"


def test_aws_key_detection():
    result = _regex_classify("Access key: " + "AKIA" + "IOSFODNN7EXAMPLE123")
    assert "credential_awskey" in result["categories"]
    assert result["risk_level"] == "critical"
