"""
DSPM pattern catalogue — 30+ patterns for PII, PCI, PHI, financial, credentials.

Ported from clay-good/mantissa-stance (MIT) and extended with Gulf-region
patterns (Saudi National ID, IBAN-GCC, etc.) for our customer base.
"""
from __future__ import annotations

from .types import DataCategory, DataPattern


def _luhn_check(value: str) -> bool:
    """Validate a number with Luhn algorithm (credit cards, SSNs)."""
    digits = [int(c) for c in value if c.isdigit()]
    if not digits:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


VALIDATORS = {
    "luhn_check": _luhn_check,
}


DEFAULT_PATTERNS: list[DataPattern] = [
    # ── PII ────────────────────────────────────────────────────────────────
    DataPattern(
        name="ssn-formatted",
        description="US Social Security Number (formatted)",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        category=DataCategory.PII_SSN,
        confidence=0.95,
    ),
    DataPattern(
        name="email-address",
        description="Email address",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        category=DataCategory.PII_EMAIL,
        confidence=0.95,
    ),
    DataPattern(
        name="phone-us",
        description="US phone number",
        pattern=r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        category=DataCategory.PII_PHONE,
        confidence=0.85,
    ),
    DataPattern(
        name="phone-international",
        description="International phone number (E.164)",
        # \b before + does not anchor (+ is non-word) — use a negative
        # lookbehind for digits instead.
        pattern=r"(?<!\d)\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
        category=DataCategory.PII_PHONE,
        confidence=0.8,
    ),
    DataPattern(
        name="date-of-birth",
        description="Date that could be DOB",
        pattern=r"\b(?:19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b",
        category=DataCategory.PII_DOB,
        confidence=0.6,
    ),
    DataPattern(
        name="us-passport",
        description="US passport number",
        pattern=r"\b[A-Z]\d{8}\b",
        category=DataCategory.PII_PASSPORT,
        confidence=0.7,
    ),
    DataPattern(
        name="saudi-national-id",
        description="Saudi National ID (Iqama / Mukhayyam)",
        pattern=r"\b[12]\d{9}\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.7,
    ),
    DataPattern(
        name="uae-emirates-id",
        description="UAE Emirates ID",
        pattern=r"\b784-?\d{4}-?\d{7}-?\d\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.95,
    ),

    # ── PCI ────────────────────────────────────────────────────────────────
    DataPattern(
        name="credit-card-visa",
        description="Visa credit card number",
        pattern=r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        category=DataCategory.PCI_CARD_NUMBER,
        confidence=0.95,
        validation="luhn_check",
    ),
    DataPattern(
        name="credit-card-mastercard",
        description="Mastercard credit card number",
        pattern=r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
        category=DataCategory.PCI_CARD_NUMBER,
        confidence=0.95,
        validation="luhn_check",
    ),
    DataPattern(
        name="credit-card-amex",
        description="American Express card number",
        pattern=r"\b3[47][0-9]{13}\b",
        category=DataCategory.PCI_CARD_NUMBER,
        confidence=0.95,
        validation="luhn_check",
    ),
    DataPattern(
        name="credit-card-discover",
        description="Discover card number",
        pattern=r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
        category=DataCategory.PCI_CARD_NUMBER,
        confidence=0.95,
        validation="luhn_check",
    ),

    # ── PHI ────────────────────────────────────────────────────────────────
    DataPattern(
        name="medical-record-number",
        description="Medical record number (MRN)",
        # Allow flexible separators between label and digits (e.g. "MRN: 12345")
        pattern=r"\b(?:MRN|MR)[\s:#-]*\d{6,10}\b",
        category=DataCategory.PHI_MEDICAL_RECORD,
        confidence=0.9,
    ),
    DataPattern(
        name="icd10-code",
        description="ICD-10 diagnosis code",
        pattern=r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b",
        category=DataCategory.PHI_DIAGNOSIS,
        confidence=0.85,
    ),

    # ── Financial ──────────────────────────────────────────────────────────
    DataPattern(
        name="bank-routing-number",
        description="US bank routing number (ABA)",
        pattern=r"\b(?:0[1-9]|[1-4][0-9]|5[0-2]|6[1-9]|7[0-2]|8[0-9])\d{7}\b",
        category=DataCategory.FINANCIAL_ROUTING,
        confidence=0.7,
    ),
    DataPattern(
        name="iban",
        description="International Bank Account Number",
        pattern=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})?\b",
        category=DataCategory.FINANCIAL_BANK_ACCOUNT,
        confidence=0.9,
    ),
    DataPattern(
        name="iban-saudi",
        description="Saudi IBAN (SA followed by 22 digits)",
        pattern=r"\bSA\d{2}\d{20}\b",
        category=DataCategory.FINANCIAL_BANK_ACCOUNT,
        confidence=0.99,
    ),
    DataPattern(
        name="iban-uae",
        description="UAE IBAN (AE followed by 21 digits)",
        pattern=r"\bAE\d{2}\d{19}\b",
        category=DataCategory.FINANCIAL_BANK_ACCOUNT,
        confidence=0.99,
    ),
    DataPattern(
        name="ein",
        description="US Employer Identification Number",
        pattern=r"\b\d{2}-\d{7}\b",
        category=DataCategory.FINANCIAL_TAX_ID,
        confidence=0.8,
    ),
    DataPattern(
        name="swift-code",
        description="SWIFT/BIC code",
        pattern=r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        category=DataCategory.FINANCIAL_SWIFT,
        confidence=0.85,
    ),

    # ── Credentials / secrets ─────────────────────────────────────────────
    DataPattern(
        name="aws-access-key",
        description="AWS access key ID",
        pattern=r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.98,
    ),
    DataPattern(
        name="aws-secret-key",
        description="AWS secret access key",
        pattern=r"\b[A-Za-z0-9/+=]{40}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.6,
    ),
    DataPattern(
        name="private-key-header",
        description="Private key PEM header",
        pattern=r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----",
        category=DataCategory.CREDENTIALS_PRIVATE_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="jwt-token",
        description="JSON Web Token",
        pattern=r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
        category=DataCategory.CREDENTIALS_TOKEN,
        confidence=0.95,
    ),
    DataPattern(
        name="github-token",
        description="GitHub personal access token",
        pattern=r"\bghp_[A-Za-z0-9]{36}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="github-app-token",
        description="GitHub App installation token",
        pattern=r"\bghs_[A-Za-z0-9]{36}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="slack-token",
        description="Slack API token",
        pattern=r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.98,
    ),
    DataPattern(
        name="google-api-key",
        description="Google API key",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.98,
    ),
    DataPattern(
        name="anthropic-api-key",
        description="Anthropic API key",
        pattern=r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="openai-api-key",
        description="OpenAI API key",
        pattern=r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="db-connection-string",
        description="Database connection string with credentials",
        pattern=r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|mssql)://[^:]+:[^@]+@[^/\s]+",
        category=DataCategory.CREDENTIALS_CONN_STRING,
        confidence=0.95,
    ),
    DataPattern(
        name="password-keyvalue",
        description="Password as key=value or YAML-style",
        pattern=r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^'\"\s\n,]{8,}",
        category=DataCategory.CREDENTIALS_PASSWORD,
        confidence=0.6,
    ),

    # ── Extended credential / secret patterns ──────────────────────
    DataPattern(
        name="stripe-secret-key",
        description="Stripe live secret key",
        pattern=r"\bsk_live_[A-Za-z0-9]{20,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="stripe-restricted-key",
        description="Stripe restricted key",
        pattern=r"\brk_(?:live|test)_[A-Za-z0-9]{20,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.95,
    ),
    DataPattern(
        name="sendgrid-api-key",
        description="SendGrid API key",
        pattern=r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="twilio-api-key",
        description="Twilio API key SID",
        pattern=r"\bSK[a-f0-9]{32}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.9,
    ),
    DataPattern(
        name="mailgun-api-key",
        description="Mailgun API key",
        pattern=r"\bkey-[a-z0-9]{32}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.85,
    ),
    DataPattern(
        name="gitlab-pat",
        description="GitLab personal access token",
        pattern=r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="npm-token",
        description="npm access token",
        pattern=r"\bnpm_[A-Za-z0-9]{36}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="pypi-token",
        description="PyPI API token",
        pattern=r"\bpypi-[A-Za-z0-9_-]{40,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="hubspot-key",
        description="HubSpot API key",
        pattern=r"\bpat-na1-[0-9a-f-]{36}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.95,
    ),
    DataPattern(
        name="salesforce-session-id",
        description="Salesforce session id (SID)",
        pattern=r"\b00D[a-zA-Z0-9]{12,15}!A[A-Za-z0-9._-]+\b",
        category=DataCategory.CREDENTIALS_TOKEN,
        confidence=0.95,
    ),
    DataPattern(
        name="jira-token",
        description="Atlassian / Jira API token (ATATT prefix)",
        pattern=r"\bATATT3[A-Za-z0-9_-]{40,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="linear-key",
        description="Linear API key",
        pattern=r"\blin_api_[A-Za-z0-9]{40,}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
    DataPattern(
        name="datadog-key",
        description="Datadog API key (32-char hex)",
        pattern=r"(?i)(?:datadog|dd)[-_]?api[-_]?key\s*[:=]\s*['\"]?[a-f0-9]{32}\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.7,
    ),

    # ── Additional PII / regional IDs ────────────────────────────
    DataPattern(
        name="uk-nino",
        description="UK National Insurance Number (NINO)",
        pattern=r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.85,
    ),
    DataPattern(
        name="indian-aadhaar",
        description="Indian Aadhaar 12-digit ID",
        pattern=r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.7,
    ),
    DataPattern(
        name="indian-pan",
        description="Indian PAN card number",
        pattern=r"\b[A-Z]{5}\d{4}[A-Z]\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.95,
    ),
    DataPattern(
        name="canadian-sin",
        description="Canadian Social Insurance Number",
        pattern=r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b",
        category=DataCategory.PII_SSN,
        confidence=0.5,
    ),
    DataPattern(
        name="singapore-nric",
        description="Singapore NRIC / FIN",
        pattern=r"\b[STFGstfg]\d{7}[A-Za-z]\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.9,
    ),
    DataPattern(
        name="qatar-id",
        description="Qatar Personal Number (QID, 11 digits)",
        pattern=r"\b[2-3]\d{10}\b",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.55,
    ),
    DataPattern(
        name="oman-civil-no",
        description="Oman Civil ID Number",
        pattern=r"\b\d{8}\b(?=[\s,]|$)",
        category=DataCategory.PII_NATIONAL_ID,
        confidence=0.4,
    ),

    # ── Additional PHI ───────────────────────────────────
    DataPattern(
        name="npi-number",
        description="US National Provider Identifier (10 digits)",
        pattern=r"\b(?:NPI[:#-]?\s*)?\d{10}\b",
        category=DataCategory.PHI_MEDICAL_RECORD,
        confidence=0.6,
    ),
    DataPattern(
        name="dea-number",
        description="US DEA registration number",
        pattern=r"\b[A-Z][A-Z9]\d{7}\b",
        category=DataCategory.PHI_MEDICAL_RECORD,
        confidence=0.7,
    ),

    # ── Additional financial ──────────────────────────────
    DataPattern(
        name="crypto-wallet-eth",
        description="Ethereum wallet address",
        pattern=r"\b0x[a-fA-F0-9]{40}\b",
        category=DataCategory.FINANCIAL_BANK_ACCOUNT,
        confidence=0.9,
    ),
    DataPattern(
        name="crypto-wallet-btc",
        description="Bitcoin wallet address (legacy/bech32)",
        pattern=r"\b(?:bc1[ac-hj-np-z02-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        category=DataCategory.FINANCIAL_BANK_ACCOUNT,
        confidence=0.7,
    ),

    # ── Source-code / repo secrets ────────────────────────────
    DataPattern(
        name="oauth-client-secret-env",
        description="OAuth client secret as env var",
        pattern=r"(?i)(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{20,}",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.7,
    ),
    DataPattern(
        name="google-oauth-id",
        description="Google OAuth client ID",
        pattern=r"\b\d{12}-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b",
        category=DataCategory.CREDENTIALS_API_KEY,
        confidence=0.99,
    ),
]


# Quick lookup tables
PATTERNS_BY_NAME = {p.name: p for p in DEFAULT_PATTERNS}
PATTERNS_BY_CATEGORY: dict[DataCategory, list[DataPattern]] = {}
for p in DEFAULT_PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(p.category, []).append(p)
