from __future__ import annotations
from typing import Optional, List, Any, Dict
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, field_validator


# ── Auth ─────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    org_name: str
    domain: str
    email: str
    password: str
    name: Optional[str] = None
    country: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    org_id: str
    role: str


class UserOut(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    email: str
    name: Optional[str]
    department: Optional[str]
    job_title: Optional[str]
    role: str
    is_vip: bool
    is_active: bool
    risk_score: int
    last_login: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class OrgOut(BaseModel):
    id: UUID
    name: str
    domain: str
    plan: str
    country: Optional[str]
    mailbox_count: int
    risk_score: int
    compliance_score: int
    timezone: str
    language: str
    mfa_enforced: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Dashboard ────────────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    org_id: str
    risk_score: int
    threat_counts: Dict[str, int]
    compliance_score: int
    total_threats_today: int
    total_threats_week: int
    total_threats_month: int
    top_threat_type: Optional[str]


class ThreatTrendPoint(BaseModel):
    date: str
    count: int
    avg_risk: float


class AtRiskEmployee(BaseModel):
    user_id: str
    email: str
    name: Optional[str]
    department: Optional[str]
    risk_score: int
    threat_count: int


# ── Threats ──────────────────────────────────────────────────────────────────

class ThreatOut(BaseModel):
    id: UUID
    org_id: UUID
    email_message_id: Optional[str]
    sender: Optional[str]
    sender_domain: Optional[str]
    recipient_email: Optional[str]
    threat_type: Optional[str]
    risk_score: Optional[int]
    score_breakdown: Optional[Dict[str, Any]]
    graph_score: Optional[int]
    content_score: Optional[int]
    reputation_score: Optional[int]
    status: str
    action_taken: Optional[str]
    ai_explanation_en: Optional[str]
    ai_explanation_ar: Optional[str]
    threat_indicators: Optional[Dict[str, Any]]
    sama_controls: Optional[List[str]]
    nca_controls: Optional[List[str]]
    false_positive: bool
    detected_at: datetime
    resolved_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    items: List[ThreatOut]
    total: int
    page: int
    page_size: int
    pages: int


class BulkActionRequest(BaseModel):
    threat_ids: List[str]
    action: str  # quarantine, false_positive, resolve


# ── People ───────────────────────────────────────────────────────────────────

class PersonOut(BaseModel):
    id: UUID
    email: str
    name: Optional[str]
    department: Optional[str]
    job_title: Optional[str]
    role: str
    is_vip: bool
    risk_score: int
    threat_count: int
    last_threat_at: Optional[datetime]

    class Config:
        from_attributes = True


class PeopleListResponse(BaseModel):
    items: List[PersonOut]
    total: int
    page: int
    page_size: int


# ── Policies ─────────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    priority: int = 100
    conditions: Dict[str, Any]
    action: str
    action_config: Optional[Dict[str, Any]] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    conditions: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    action_config: Optional[Dict[str, Any]] = None


class PolicyOut(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    priority: int
    status: str
    conditions: Dict[str, Any]
    action: str
    action_config: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ── Compliance ───────────────────────────────────────────────────────────────

class FrameworkOverview(BaseModel):
    framework: str
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    not_started: int
    compliance_pct: float


class ComplianceControlOut(BaseModel):
    id: UUID
    framework: str
    control_id: str
    control_name_en: str
    control_name_ar: str
    evidence_type: Optional[str]
    status: str
    evidence_count: int

    class Config:
        from_attributes = True


class EvidenceOut(BaseModel):
    id: UUID
    org_id: UUID
    threat_id: Optional[UUID]
    control_ids: Optional[List[str]]
    framework: Optional[str]
    action_taken: Optional[str]
    outcome: Optional[str]
    immutable: bool
    retention_tier: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Onboarding ───────────────────────────────────────────────────────────────

class OnboardingStatus(BaseModel):
    steps: List[Dict[str, Any]]
    overall_complete: bool
    completion_pct: float


class M365ConnectRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
