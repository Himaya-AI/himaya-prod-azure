"""
Himaya Helios - Shared Pydantic v2 Schemas
All data models for inter-component communication.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EmailDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class ThreatClassification(str, Enum):
    BEC = "BEC"                               # Business Email Compromise
    VEC = "VEC"                               # Vendor/Supplier Email Compromise
    PHISHING = "PHISHING"                     # Generic phishing (credential harvesting)
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"  # Dedicated credential theft
    GOV_IMPERSONATION = "GOV_IMPERSONATION"   # Government entity impersonation
    IMPERSONATION = "IMPERSONATION"           # Executive/colleague display-name spoofing
    MALWARE = "MALWARE"                       # Malicious attachments or drive-by links
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"     # Typosquat / lookalike domains
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"     # Compromised account indicators
    SUPPLY_CHAIN = "SUPPLY_CHAIN"             # Supply chain / trusted-vendor abuse
    FAKE_INVOICE = "FAKE_INVOICE"             # Fraudulent invoice / payment request
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING" # Broad social engineering
    SPAM = "SPAM"                             # Unsolicited bulk email
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"


class RiskAction(str, Enum):
    DELIVER = "DELIVER"
    DELIVER_WITH_BANNER = "DELIVER_WITH_BANNER"
    HOLD_FOR_REVIEW = "HOLD_FOR_REVIEW"
    QUARANTINE = "QUARANTINE"
    BLOCK_DELETE = "BLOCK_DELETE"


class EmailLanguage(str, Enum):
    AR = "ar"
    EN = "en"
    MIXED = "mixed"


# ---------------------------------------------------------------------------
# Email Metadata
# ---------------------------------------------------------------------------

class EmailMetadata(BaseModel):
    """Raw email metadata ingested from mail gateway."""

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = Field(..., description="Sender email address")
    recipient: str = Field(..., description="Recipient email address")
    timestamp: datetime = Field(..., description="Email send time (UTC)")
    subject_hash: str = Field(..., description="SHA-256 hash of subject line")
    direction: EmailDirection = Field(..., description="Email direction")
    org_id: str = Field(..., description="Organization ID for multi-tenancy")
    attachments_count: int = Field(default=0)
    has_links: bool = Field(default=False)
    sender_ip: str | None = Field(default=None)
    raw_headers_hash: str | None = Field(default=None)

    @field_validator("sender", "recipient")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Invalid email address: {v}")
        return v.lower().strip()


# ---------------------------------------------------------------------------
# Graph Analyzer Results (MODEL-001)
# ---------------------------------------------------------------------------

class GraphAnalysisResult(BaseModel):
    """Output from the Communication Graph Analyzer."""

    anomaly_score: float = Field(..., ge=0.0, le=100.0, description="Anomaly score 0-100")
    edge_embedding: list[float] = Field(..., description="Learned edge embedding vector")
    is_anomalous: bool = Field(..., description="True if score >= threshold")
    mahalanobis_distance: float = Field(..., description="Distance from baseline distribution")
    latency_ms: float = Field(..., description="Inference latency in milliseconds")
    sender_node_score: float = Field(default=0.0, description="Sender node anomaly contribution")
    recipient_node_score: float = Field(default=0.0, description="Recipient node anomaly contribution")
    edge_frequency_rank: int | None = Field(default=None, description="Communication frequency percentile")
    model_version: str = Field(default="1.0.0")


# ---------------------------------------------------------------------------
# Content Classifier Results (MODEL-002)
# ---------------------------------------------------------------------------

class ContentSignal(BaseModel):
    """Individual threat signal extracted from email content."""

    name: str
    value: str
    weight: float = Field(..., ge=0.0, le=1.0)


class ContentClassificationResult(BaseModel):
    """Output from the LLM Content Classifier."""

    threat_indicators: list[str] = Field(default_factory=list)
    urgency_score: int = Field(..., ge=0, le=100)
    impersonation_detected: bool = Field(default=False)
    impersonation_target: str | None = Field(default=None)
    language: EmailLanguage
    classification: ThreatClassification
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation_ar: str = Field(..., description="Arabic explanation for analysts")
    explanation_en: str = Field(..., description="English explanation for analysts")
    signals: list[ContentSignal] = Field(default_factory=list)
    model_used: str = Field(default="claude-3-5-sonnet-20241022")
    input_tokens: int = Field(default=0)
    output_tokens: int = Field(default=0)
    cost_usd: float = Field(default=0.0)
    latency_ms: float = Field(default=0.0)


# ---------------------------------------------------------------------------
# Sender Reputation Results (MODEL-003)
# ---------------------------------------------------------------------------

class DmarcResult(BaseModel):
    has_dmarc: bool
    policy: str | None = None  # none, quarantine, reject
    raw_record: str | None = None


class SpfResult(BaseModel):
    has_spf: bool
    qualifier: str | None = None  # +, -, ~, ?
    raw_record: str | None = None


class DkimResult(BaseModel):
    has_dkim: bool
    selector: str = "default"
    raw_record: str | None = None


class LookalikResult(BaseModel):
    is_lookalike: bool
    matched_domain: str | None = None
    distance: int = Field(default=999)
    confidence: str = Field(default="none")  # high, medium, none
    homoglyph_detected: bool = False


class SenderReputationResult(BaseModel):
    """Output from the Sender Reputation Engine."""

    domain: str
    email: str
    domain_age_days: int = Field(default=-1)
    has_dmarc: bool = False
    dmarc: DmarcResult | None = None
    has_spf: bool = False
    spf: SpfResult | None = None
    has_dkim: bool = False
    dkim: DkimResult | None = None
    is_breached: bool = False
    mx_valid: bool = False
    lookalike: LookalikResult | None = None
    is_new_to_org: bool = False
    tld_risk_score: float = Field(default=0.5, ge=0.0, le=1.0)
    domain_entropy: float = Field(default=0.0)
    final_score: float = Field(..., ge=0.0, le=100.0)
    malicious_probability: float = Field(..., ge=0.0, le=1.0)
    signals_breakdown: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0)
    cached: bool = False


# ---------------------------------------------------------------------------
# Risk Orchestrator Results (MODEL-004)
# ---------------------------------------------------------------------------

class ComplianceControl(BaseModel):
    """A regulatory compliance control reference."""

    framework: str  # SAMA, NCA
    control_id: str
    control_name: str
    description: str


class RiskOrchestratorResult(BaseModel):
    """Output from the Risk Orchestrator."""

    final_score: float = Field(..., ge=0.0, le=100.0)
    action: RiskAction
    multipliers_applied: dict[str, float] = Field(default_factory=dict)
    agent_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Individual model scores before weighting"
    )
    weighted_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Weighted contributions per model"
    )
    compliance_controls: list[ComplianceControl] = Field(default_factory=list)
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_classification: ThreatClassification = ThreatClassification.UNCERTAIN
    processing_time_ms: float = Field(default=0.0)


# ---------------------------------------------------------------------------
# Threat Action Record (Full audit/compliance record)
# ---------------------------------------------------------------------------

class ThreatActionRecord(BaseModel):
    """Complete threat action record for database storage and compliance evidence."""

    # Identity
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    org_id: str
    message_id: str

    # Email details
    sender: str
    recipient: str
    timestamp: datetime
    direction: EmailDirection

    # Scores
    final_score: float = Field(..., ge=0.0, le=100.0)
    graph_score: float = Field(..., ge=0.0, le=100.0)
    content_score: float = Field(..., ge=0.0, le=100.0)
    reputation_score: float = Field(..., ge=0.0, le=100.0)

    # Classification
    action: RiskAction
    threat_classification: ThreatClassification
    confidence: float = Field(..., ge=0.0, le=1.0)

    # Compliance
    compliance_controls: list[ComplianceControl] = Field(default_factory=list)
    sama_controls: list[str] = Field(default_factory=list)
    nca_controls: list[str] = Field(default_factory=list)

    # Detailed results
    content_result: ContentClassificationResult | None = None
    reputation_result: SenderReputationResult | None = None
    graph_result: GraphAnalysisResult | None = None
    orchestrator_result: RiskOrchestratorResult | None = None

    # Audit
    created_at: datetime = Field(default_factory=datetime.utcnow)
    processed_by: str = Field(default="himaya-v1")
    redis_published: bool = False
    redis_channel: str | None = None
