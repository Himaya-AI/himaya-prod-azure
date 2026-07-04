#!/usr/bin/env python3
"""
Test spam rules and DLP classification patterns.
Run from repo root: python3 scripts/test_rules.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.routers.spam import _match_rule
from backend.services.dlp_service import _PATTERNS

PASS = "✅ PASS"
FAIL = "❌ FAIL"

results = []

def check(label, condition):
    status = PASS if condition else FAIL
    results.append((status, label))
    print(f"  {status}  {label}")

# ── Spam Rule Tests ────────────────────────────────────────────────────────────
print("\n=== SPAM RULE TESTS ===\n")

sample_item = {
    "subject": "Win a FREE iPhone! Claim your prize now!",
    "sender": "test@spammer.com",
    "sender_domain": "spammer.com",
    "body_preview": "Click here to claim your prize. Limited time offer!",
    "classification": "SPAM",
}

check("SENDER_EMAIL: 'spammer' in 'test@spammer.com'",
      _match_rule("SENDER_EMAIL", "spammer", sample_item))

check("SENDER_DOMAIN: 'spammer.com' matches domain",
      _match_rule("SENDER_DOMAIN", "spammer.com", sample_item))

check("SENDER_DOMAIN: 'phishing.net' does NOT match 'spammer.com'",
      not _match_rule("SENDER_DOMAIN", "phishing.net", sample_item))

check("SUBJECT_CONTAINS: 'free' in subject",
      _match_rule("SUBJECT_CONTAINS", "free", sample_item))

check("SUBJECT_CONTAINS: 'iphone' in subject",
      _match_rule("SUBJECT_CONTAINS", "iphone", sample_item))

check("BODY_CONTAINS: 'claim your prize' in body",
      _match_rule("BODY_CONTAINS", "claim your prize", sample_item))

check("BODY_CONTAINS: 'limited time' in body",
      _match_rule("BODY_CONTAINS", "limited time", sample_item))

check("CLASSIFICATION: 'SPAM' matches classification=SPAM",
      _match_rule("CLASSIFICATION", "SPAM", sample_item))

check("CLASSIFICATION: 'HAM' does NOT match classification=SPAM",
      not _match_rule("CLASSIFICATION", "HAM", sample_item))

check("Partial match — SENDER_EMAIL: 'spammer.com' matches full sender",
      _match_rule("SENDER_EMAIL", "spammer.com", sample_item))

# ── DLP Pattern Tests ──────────────────────────────────────────────────────────
print("\n=== DLP PATTERN TESTS ===\n")

def dlp_check(label, pattern_key, text, should_match=True):
    pattern = _PATTERNS.get(pattern_key)
    if pattern is None:
        check(f"{label} [PATTERN MISSING: {pattern_key}]", False)
        return
    matched = bool(pattern.search(text))
    check(label, matched == should_match)

# PII
dlp_check("SSN: '123-45-6789' → pii_ssn", "pii_ssn", "My SSN is 123-45-6789")
dlp_check("Credit card: '4111111111111111' → pii_credit_card", "pii_credit_card", "Card: 4111111111111111")
dlp_check("IBAN: 'GB29NWBK60161331926819' → pii_iban", "pii_iban", "IBAN: GB29NWBK60161331926819")
dlp_check("UAE ID: '784-1234-1234567-1' → pii_uae_id", "pii_uae_id", "ID: 784-1234-1234567-1")
dlp_check("GCC phone: '+971501234567' → pii_gcc_phone", "pii_gcc_phone", "Call me at +971501234567")
dlp_check("Saudi ID: 'iqama 1234567890' → pii_saudi_id", "pii_saudi_id", "iqama 1234567890 issued")

# Credentials
dlp_check("AWS key: 'AKIAIOSFODNN7EXAMPLE' → credential_awskey", "credential_awskey", "aws_access_key=" + "AKIA" + "IOSFODNN7EXAMPLE")
dlp_check("Private key → credential_privkey", "credential_privkey", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
dlp_check("API key → credential_apikey", "credential_apikey", "api_key='abc123secretkey00000000000'")
dlp_check("Password → credential_password", "credential_password", "password=MySecr3t!")
dlp_check("AWS secret key → aws_secret_key", "aws_secret_key", "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
dlp_check("JWT token → jwt_token", "jwt_token", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123DEF456ghi789")
dlp_check("GitHub token → github_token", "github_token", "token=ghp_" + "A" * 36)
dlp_check("Slack token → slack_token", "slack_token", "xo" + "xb-1234567890-abcdefghij")

# Financial
dlp_check("Salary → financial_salary", "financial_salary", "Q3 salary budget is $2.5M")
dlp_check("Invoice → financial_invoice", "financial_invoice", "Please process the wire transfer invoice")
dlp_check("Budget → financial_budget", "financial_budget", "Q4 forecast and budget attached")

# Legal
dlp_check("NDA → legal_nda", "legal_nda", "This NDA is binding and confidential")
dlp_check("M&A → legal_ma", "legal_ma", "Due diligence for the acquisition is complete")
dlp_check("Litigation → legal_litigation", "legal_litigation", "Legal hold notice — without prejudice")

# Healthcare
dlp_check("HIPAA PHI → hipaa_phi", "hipaa_phi", "Patient ID: 12345, diagnosis: hypertension")

# Crypto
dlp_check("Crypto wallet → crypto_wallet", "crypto_wallet", "Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
dlp_check("Seed phrase → crypto_mnemonic", "crypto_mnemonic", "Write down your seed phrase carefully")

# Negative tests
dlp_check("Clean text → NO pii_ssn", "pii_ssn", "Call me at extension 123456", should_match=False)
dlp_check("Clean text → NO credential_awskey", "credential_awskey", "AWS is a cloud provider", should_match=False)

# ── Cloud credentials ──────────────────────────────────────────────────────────
dlp_check("GCP service account → gcp_key", "gcp_key", '{"type": "service_account", "project_id": "my-project"}')
dlp_check("Azure conn string → azure_conn_str", "azure_conn_str", "DefaultEndpointsProtocol=https;AccountName=mystorageaccount")

# ── Summary ────────────────────────────────────────────────────────────────────
print(f"\n=== SUMMARY ===\n")
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
total = len(results)
print(f"  {passed}/{total} passed  |  {failed} failed\n")

if failed:
    print("Failed tests:")
    for status, label in results:
        if status == FAIL:
            print(f"  - {label}")
    sys.exit(1)
else:
    print("All tests passed! ✅")
