from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class EmailLanguage(str, Enum):
    AR = "ar"
    EN = "en"
    MIXED = "mixed"


class ThreatClassification(str, Enum):
    BEC = "BEC"
    VEC = "VEC"
    PHISHING = "PHISHING"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    GOV_IMPERSONATION = "GOV_IMPERSONATION"
    IMPERSONATION = "IMPERSONATION"
    MALWARE = "MALWARE"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    FAKE_INVOICE = "FAKE_INVOICE"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    SPAM = "SPAM"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"


class ContentSignal(BaseModel):
    name: str
    value: str
    weight: float = Field(..., ge=0.0, le=1.0)


class EmailVerifyContext(BaseModel):
    valid_format: bool = False
    domain: str | None = None
    root_domain: str | None = None
    subdomain: str | None = None
    tld: str | None = None
    valid_tld: bool = False
    public_domain: bool = False
    has_a_records: bool = False
    has_mx_records: bool = False
    has_txt_records: bool = False
    has_spf_records: bool = False
    spf_qualifier: str | None = None
    spf_strict: bool = False
    dmarc_configured: bool = False
    mx_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ContentClassificationResult(BaseModel):
    threat_indicators: list[str] = Field(default_factory=list)
    urgency_score: int = Field(..., ge=0, le=100)
    impersonation_detected: bool = Field(default=False)
    impersonation_target: str | None = Field(default=None)
    language: EmailLanguage
    classification: ThreatClassification
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation_ar: str
    explanation_en: str
    signals: list[ContentSignal] = Field(default_factory=list)
    model_used: str = Field(default="")
    input_tokens: int = Field(default=0)
    output_tokens: int = Field(default=0)
    cost_usd: float = Field(default=0.0)
    latency_ms: float = Field(default=0.0)


class ClassifyRequest(BaseModel):
    sender: str
    recipient: str
    subject: str
    body: str
    attachments: list[str] | None = None
    headers: dict[str, str] | None = None
    email_verify: EmailVerifyContext | None = None
    include_few_shot: bool = True


# ── Verdict (Helios Analysis auto-triage) ────────────────────────────────────

class VerdictRequest(BaseModel):
    """Full threat dossier as built by backend/services/auto_triage_service.py."""
    # Required-ish fields; everything else is opaque so we don't have to
    # version-lock with the backend dossier shape.
    threat_id: str | None = Field(default=None)
    risk_score: int | float | None = Field(default=None)

    # The actual dossier is huge and frequently changes shape; accept anything.
    model_config = {"extra": "allow"}


class VerdictResult(BaseModel):
    verdict: str = Field(..., description="QUARANTINE | MARK_AS_SPAM | ESCALATE | DISMISS")
    threat_type: str = Field(default="UNKNOWN", description="PHISHING|BEC|MALWARE|SPAM|SAFE|UNKNOWN")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reasoning: str = Field(default="")
    key_evidence: list[str] = Field(default_factory=list)
    notify_recipient: bool = Field(default=False)
    notify_admin: bool = Field(default=True)
    model_used: str = Field(default="")
    input_tokens: int = Field(default=0)
    output_tokens: int = Field(default=0)
    cost_usd: float = Field(default=0.0)
    latency_ms: float = Field(default=0.0)
