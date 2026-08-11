"""
PII / sensitive-data discovery — column-level classifier + cross-source scanners.

This module deepens Himaya's data-sovereignty story with *column-level*
classification for structured stores (Snowflake real row-sampling; SAP via the
documented data-dictionary catalog). Every classification carries **confidence
and lineage/evidence** (which detector fired, redacted sample values, the match
ratio over the sample) so a finding is defensible to an auditor.

Design principles:
  - We never persist raw sensitive values. Evidence samples are redacted at the
    source (mask middle) before they ever leave the scanner.
  - Detection is regex + validators (Luhn for cards, mod-97 for IBAN, national-id
    shapes) blended with a column-name signal. This is lightweight, deterministic
    "NER" that runs without a heavyweight ML dependency.
  - Results land in two places: `column_classifications` (the lineage inventory
    that DSAR queries) and `dspm_findings` (so the sovereignty scan already built
    picks them up and enforces residency per jurisdiction).
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Detector vocabulary → normalized sovereignty data_class ─────────────────
# category (specific) → data_class (what the sovereignty policies target)
CATEGORY_TO_DATA_CLASS: dict[str, str] = {
    "pii_email": "pii",
    "pii_phone": "pii",
    "pii_national_id": "pii",
    "pii_passport": "pii",
    "pii_dob": "pii",
    "pii_name": "pii",
    "pii_address": "pii",
    "pii_ip": "pii",
    "phi_medical": "phi",
    "phi_diagnosis": "phi",
    "pci_card": "pci",
    "financial_iban": "financial",
    "financial_account": "financial",
    "financial_swift": "financial",
    "credentials_secret": "highly_confidential",
    "credentials_api_key": "highly_confidential",
}


# ── Value validators ────────────────────────────────────────────────────────

def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
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


def _iban_ok(value: str) -> bool:
    v = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", v):
        return False
    rearranged = v[4:] + v[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


# ── Value-level detectors (regex + optional validator) ──────────────────────

@dataclass
class _Detector:
    category: str
    pattern: re.Pattern
    validator: Optional[callable] = None

    def matches(self, value: str) -> bool:
        if not self.pattern.search(value):
            return False
        if self.validator:
            return self.validator(value)
        return True


_VALUE_DETECTORS: list[_Detector] = [
    _Detector("pii_email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    _Detector("pci_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
    _Detector("financial_iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), _iban_ok),
    _Detector("financial_swift", re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")),
    # KSA national id (10 digits, starts 1 or 2) or UAE eid (784-YYYY-NNNNNNN-N)
    _Detector("pii_national_id", re.compile(r"\b(?:784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d|[12]\d{9})\b")),
    _Detector("pii_passport", re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")),
    _Detector("pii_phone", re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){2,4}\d{2,4}(?!\d)")),
    _Detector("pii_ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    _Detector("pii_dob", re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b")),
    _Detector("credentials_api_key", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b")),
    _Detector("credentials_secret", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


# ── Column-name signals (the "NER" name hints) ──────────────────────────────
# Each maps a set of name tokens to a category. A name hit alone yields a
# lower-confidence "inferred" classification; a name hit + value match is a
# high-confidence "confirmed" classification.
_NAME_SIGNALS: list[tuple[str, list[str]]] = [
    ("pii_email", ["email", "e_mail", "mail_addr", "emailaddress"]),
    ("pii_phone", ["phone", "mobile", "msisdn", "tel", "contact_no", "cell"]),
    ("pii_national_id", ["national_id", "nationalid", "iqama", "eid", "emirates_id", "nid", "ssn", "social_security", "id_number"]),
    ("pii_passport", ["passport"]),
    ("pii_dob", ["dob", "birth", "date_of_birth", "birthdate"]),
    ("pii_name", ["first_name", "last_name", "full_name", "fullname", "surname", "given_name", "customer_name", "employee_name"]),
    ("pii_address", ["address", "street", "postal", "zip", "zipcode", "city", "billing_addr", "shipping_addr"]),
    ("phi_medical", ["diagnosis", "icd10", "icd_10", "mrn", "medical_record", "patient", "prescription", "treatment", "health"]),
    ("phi_diagnosis", ["diagnosis", "icd"]),
    ("pci_card", ["card_number", "cardnumber", "pan", "ccnum", "credit_card", "cardno"]),
    ("financial_iban", ["iban"]),
    ("financial_account", ["account_number", "acct_no", "bank_account", "accountno", "routing", "sort_code"]),
    ("financial_swift", ["swift", "bic"]),
    ("credentials_secret", ["password", "secret", "private_key", "passwd", "pwd", "credential"]),
    ("credentials_api_key", ["api_key", "apikey", "access_token", "token", "client_secret"]),
]


def _redact(value: str) -> str:
    """Mask the middle of a value, keeping a little head/tail for evidence."""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    head = s[: max(1, len(s) // 5)]
    tail = s[-2:]
    return f"{head}{'*' * min(12, max(3, len(s) - len(head) - 2))}{tail}"


@dataclass
class ColumnClassification:
    column_name: str
    data_class: Optional[str]
    category: Optional[str]
    detector: str                    # 'value+name' | 'value' | 'name_only' | 'none'
    confidence: float
    evidence: list[str] = field(default_factory=list)
    sample_size: int = 0
    match_count: int = 0

    @property
    def is_sensitive(self) -> bool:
        return self.data_class is not None


def _name_signal(column_name: str) -> Optional[str]:
    n = (column_name or "").strip().lower()
    for category, tokens in _NAME_SIGNALS:
        for tok in tokens:
            if tok in n:
                return category
    return None


def classify_column(column_name: str, sample_values: list) -> ColumnClassification:
    """Classify a single column from its name + a sample of its values.

    Confidence blends the value-match ratio with the column-name signal:
      - value + matching name  → up to 0.99  (confirmed)
      - value only             → the match ratio (capped 0.95)
      - name only (no values)  → 0.55        (inferred)
    """
    name_cat = _name_signal(column_name)
    non_null = [str(v) for v in (sample_values or []) if v is not None and str(v).strip() != ""]
    sample_size = len(non_null)

    # Tally value detectors across the sample.
    best_cat: Optional[str] = None
    best_matches = 0
    evidence: list[str] = []
    if non_null:
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for val in non_null:
            for det in _VALUE_DETECTORS:
                if det.matches(val):
                    counts[det.category] = counts.get(det.category, 0) + 1
                    if len(samples.setdefault(det.category, [])) < 3:
                        samples[det.category].append(_redact(val))
                    break
        if counts:
            best_cat = max(counts, key=counts.get)
            best_matches = counts[best_cat]
            evidence = samples.get(best_cat, [])

    value_ratio = (best_matches / sample_size) if sample_size else 0.0

    # Decide category + confidence.
    if best_cat and value_ratio >= 0.10:
        category = best_cat
        if name_cat and (name_cat == best_cat or CATEGORY_TO_DATA_CLASS.get(name_cat) == CATEGORY_TO_DATA_CLASS.get(best_cat)):
            detector = "value+name"
            confidence = min(0.99, 0.75 + value_ratio * 0.24)
        else:
            detector = "value"
            confidence = min(0.95, 0.5 + value_ratio * 0.45)
    elif name_cat:
        category = name_cat
        detector = "name_only"
        confidence = 0.55
        if not evidence:
            evidence = [f"column name '{column_name}' matches {name_cat}"]
    else:
        return ColumnClassification(column_name, None, None, "none", 0.0,
                                    sample_size=sample_size, match_count=0)

    return ColumnClassification(
        column_name=column_name,
        data_class=CATEGORY_TO_DATA_CLASS.get(category),
        category=category,
        detector=detector,
        confidence=round(confidence, 3),
        evidence=evidence,
        sample_size=sample_size,
        match_count=best_matches,
    )


def column_fingerprint(source: str, db: str, schema: str, table: str, column: str) -> str:
    return hashlib.sha256(f"{source}|{db}|{schema}|{table}|{column}".encode()).hexdigest()
