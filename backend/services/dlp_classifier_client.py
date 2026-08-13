"""
DLP Classifier client — thin wrapper around the deployed dlp-classifier
microservice (Azure Container Apps).

This service replaces the legacy in-process data-classification stack for
Workspace Security (regex `_simple_classify`, DeepSeek, and Claude Haiku).
It exposes a single `POST /classify` endpoint:

    request : {"text": str, "tenant_id": str, "message_id": str|None,
               "lexicon_version": str}
    response: {"findings": [ {detector, matches[], escalate, error}, ... ],
               "llm_result": {classification, confidence, categories[], reasoning}}

`classify_verdict()` / `classify_content()` normalise that response into the
dict shape the rest of the platform already consumes:

    {risk_level, categories, confidence, explanation, matched_patterns,
     sensitivity_score, inferred_data_type, classification}
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Deployed dlp-classifier service (override via env for staging / local).
DLP_CLASSIFIER_URL = os.getenv(
    "DLP_CLASSIFIER_URL",
    "https://dlp-classifier.redwater-81af5e62.uaenorth.azurecontainerapps.io",
).rstrip("/")

# Bound the payload we ship so cost/latency stay predictable.
_MAX_TEXT_CHARS = 12_000
_TIMEOUT_SEC = float(os.getenv("DLP_CLASSIFIER_TIMEOUT", "30"))

# ── Category normalisation ─────────────────────────────────────────────────
# Map the service's category vocabulary onto the app's existing tokens so
# downstream policy filters (pii_/financial_/credential_ prefixes) and the
# Data Inventory UI keep working.
_CAT_MAP = {
    "PII": "pii",
    "PERSONAL_DATA": "pii",
    "FINANCIAL_DATA": "financial_data",
    "FINANCIAL": "financial_data",
    "PCI": "pci",
    "CREDENTIALS": "credential_secret",
    "SECRETS": "credential_secret",
    "PHI": "phi",
    "HEALTH_DATA": "phi",
    "SOURCE_CODE": "source_code",
    "INTELLECTUAL_PROPERTY": "source_code",
    "CONFIDENTIAL": "confidential",
}

# Presidio-style entity types → specific app category tokens.
_ENTITY_CAT = {
    "CREDIT_CARD": "pii_credit_card",
    "US_SSN": "pii_ssn",
    "SSN": "pii_ssn",
    "EMAIL_ADDRESS": "pii_email",
    "PHONE_NUMBER": "pii_phone",
    "IBAN_CODE": "financial_iban",
    "IBAN": "financial_iban",
    "US_BANK_NUMBER": "financial_bank_account",
    "PERSON": "pii_person",
}

# Entity types / detectors that force a `critical` verdict on their own.
_CRITICAL_ENTITIES = {
    "CREDIT_CARD", "US_SSN", "SSN", "IBAN_CODE", "IBAN",
    "US_BANK_NUMBER", "CRYPTO", "PRIVATE_KEY", "API_KEY", "AWS_ACCESS_KEY",
}

_RISK_SCORE = {"low": 10, "medium": 50, "high": 75, "critical": 95}

_SAFE_LOW = {
    "risk_level": "low",
    "categories": [],
    "confidence": 0.5,
    "explanation": "Classifier unavailable — defaulted to low risk.",
    "matched_patterns": [],
    "sensitivity_score": 10,
    "inferred_data_type": "none",
    "classification": "UNKNOWN",
}


async def classify(
    text: str,
    *,
    tenant_id: str = "default",
    message_id: Optional[str] = None,
    lexicon_version: str = "v1",
) -> Optional[dict]:
    """Call the dlp-classifier /classify endpoint. Returns raw JSON or None."""
    text = (text or "").strip()
    if not text:
        return None
    payload = {
        "text": text[:_MAX_TEXT_CHARS],
        "tenant_id": tenant_id or "default",
        "lexicon_version": lexicon_version,
    }
    if message_id:
        payload["message_id"] = message_id
    # One retry absorbs container cold-start / transient connection resets.
    last_exc: Optional[Exception] = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SEC) as client:
                r = await client.post(f"{DLP_CLASSIFIER_URL}/classify", json=payload)
            if r.status_code != 200:
                logger.warning(f"dlp_classifier: /classify returned {r.status_code}: {r.text[:200]}")
                if r.status_code < 500:
                    return None
                last_exc = None
                continue
            return r.json()
        except Exception as exc:
            last_exc = exc
    logger.warning(f"dlp_classifier: /classify call failed after retry: {last_exc}")
    return None


def map_verdict(resp: dict) -> dict:
    """Normalise a raw service response into the app's classification dict."""
    llm = (resp or {}).get("llm_result") or {}
    findings = (resp or {}).get("findings") or []

    classification = str(llm.get("classification", "UNKNOWN")).upper()
    try:
        confidence = float(llm.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    reasoning = llm.get("reasoning") or ""

    # Collect finding signals.
    entity_types: set[str] = set()
    has_credential = False
    patterns: set[str] = set()
    categories: set[str] = set()

    for det in findings:
        detector = str(det.get("detector", "")).lower()
        matches = det.get("matches") or []
        if detector == "credential" and matches:
            has_credential = True
            categories.add("credential_secret")
        for m in matches:
            et = str(m.get("entity_type", "")).upper()
            if et:
                entity_types.add(et)
                patterns.add(et)
                if et in _ENTITY_CAT:
                    categories.add(_ENTITY_CAT[et])

    # Map LLM-provided categories onto app tokens.
    for c in (llm.get("categories") or []):
        key = str(c).upper().strip()
        categories.add(_CAT_MAP.get(key, str(c).lower().strip()))
        patterns.add(str(c))

    # Per-finding escalate flag from the detector service (set when a match
    # is validated/high-confidence, e.g. a Luhn-passing card number).
    detector_escalate = any(bool(det.get("escalate")) for det in findings)

    # ── Derive risk_level ──────────────────────────────────────────────
    # Adnan 2026-08-12: the old logic escalated to `high` on the mere
    # PRESENCE of any regex entity_type. Weak detectors (US_DRIVER_LICENSE,
    # PHONE_NUMBER, PERSON, generic national-ID regexes) fire on short
    # numeric strings, so a single low-confidence match combined with an
    # inconclusive LLM verdict produced a flood of false-positive HIGH
    # alerts. We now require corroboration: the LLM must affirm sensitivity,
    # OR the signal must be a strong structured identifier, OR the detector
    # explicitly escalated. An ambiguous signal with an inconclusive LLM is
    # flagged for review (medium) or dropped (low) — never HIGH on its own.
    llm_sensitive = classification not in ("NOT_SENSITIVE", "UNKNOWN", "")
    strong_categories = categories & {
        "pii_ssn", "pii_credit_card", "phi", "financial_data",
        "financial_iban", "financial_bank_account",
    }
    if classification == "NOT_SENSITIVE":
        risk = "low"
    elif has_credential or (entity_types & _CRITICAL_ENTITIES) \
            or "credential_secret" in categories or "pci" in categories:
        risk = "critical"
    elif llm_sensitive and (categories or entity_types):
        # LLM affirmatively classified as sensitive with corroborating signal.
        risk = "high"
    elif strong_categories or detector_escalate:
        # Strong structured identifiers, or the detector explicitly escalated.
        risk = "high"
    elif categories or entity_types:
        # Weak/ambiguous signal with an inconclusive LLM verdict — surface for
        # manual review at most, but do not cry "high".
        risk = "medium" if confidence >= 0.6 else "low"
    else:
        risk = "medium" if confidence >= 0.5 else "low"

    score = _RISK_SCORE.get(risk, 10)
    if entity_types & {"CREDIT_CARD", "US_SSN", "SSN"} or has_credential:
        score = 100

    cats_sorted = sorted(categories)
    return {
        "risk_level": risk,
        "categories": cats_sorted,
        "confidence": confidence,
        "explanation": reasoning or f"Classified as {classification}.",
        "matched_patterns": sorted(patterns),
        "sensitivity_score": score,
        "inferred_data_type": ", ".join(cats_sorted) if cats_sorted else (
            "sensitive" if risk != "low" else "none"
        ),
        "classification": classification,
    }


async def classify_verdict(
    text: str,
    *,
    tenant_id: str = "default",
    message_id: Optional[str] = None,
) -> Optional[dict]:
    """Classify `text` and return the normalised verdict, or None on failure.

    Use this where the caller wants to skip/retry on service failure (e.g.
    the background worker leaves the item unclassified for the next pass).
    """
    resp = await classify(text, tenant_id=tenant_id, message_id=message_id)
    if resp is None:
        return None
    return map_verdict(resp)


async def classify_content(
    content: str,
    *,
    context: str = "",
    org_id: str = "default",
    message_id: Optional[str] = None,
) -> dict:
    """Classify content and ALWAYS return a verdict dict.

    On service failure this returns a safe `low` verdict so inline callers
    never crash. `context` (e.g. filename / provider) is prepended to give
    the classifier extra signal.
    """
    text = f"{context}\n\n{content}".strip() if context else (content or "")
    verdict = await classify_verdict(text, tenant_id=org_id, message_id=message_id)
    return verdict if verdict is not None else dict(_SAFE_LOW)
