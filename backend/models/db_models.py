import uuid
from datetime import datetime, timezone


def _utcnow():
    """Timezone-aware UTC now — use for TIMESTAMPTZ column defaults."""
    return datetime.now(timezone.utc)
from sqlalchemy import (
    Column, String, Boolean, Integer, Text, DateTime, ForeignKey,
    Date, ARRAY, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, REAL
from sqlalchemy.dialects.postgresql import TIMESTAMP as _PG_TIMESTAMP
TIMESTAMPTZ = _PG_TIMESTAMP(timezone=True)  # maps to TIMESTAMPTZ — asyncpg expects tz-aware datetimes
from sqlalchemy.orm import relationship
from backend.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True)
    plan = Column(String(50), default="starter")
    tier = Column(String(20), default="Launch")  # "Launch" or "Enterprise"
    country = Column(String(50))
    status = Column(String(50), default="active")
    mailbox_count = Column(Integer, default=0)
    mailbox_limit = Column(Integer, default=100)
    billing_rate_usd = Column(REAL, default=8.00)
    contact_email = Column(String(255), default="")
    contact_name = Column(String(255), default="")
    risk_score = Column(Integer, default=0)
    compliance_score = Column(Integer, default=0)
    timezone = Column(String(100), default="Asia/Riyadh")
    language = Column(String(10), default="en")
    mfa_enforced = Column(Boolean, default=False)
    org_metadata = Column(JSONB, default=dict)    # Alert prefs, settings, etc. (renamed to avoid SQLAlchemy conflict)
    phish_report_key = Column(String(64), nullable=True)  # Org-scoped key for employee phish report add-ons
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="organization", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="organization", cascade="all, delete-orphan")
    integrations = relationship("OrgIntegration", back_populates="organization", cascade="all, delete-orphan")
    compliance_evidence = relationship("ComplianceEvidence", back_populates="organization", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="organization", cascade="all, delete-orphan")
    saas_integrations = relationship("SaasIntegration", back_populates="organization", cascade="all, delete-orphan")
    saas_alerts = relationship("SaasAlert", back_populates="organization", cascade="all, delete-orphan")
    saas_data_items = relationship("SaasDataItem", back_populates="organization", cascade="all, delete-orphan")
    saas_posture_checks = relationship("SaasPostureCheck", back_populates="organization", cascade="all, delete-orphan")
    saas_user_locations = relationship("SaasUserLocation", back_populates="organization", cascade="all, delete-orphan")
    saas_oauth_apps = relationship("SaasOAuthApp", back_populates="organization", cascade="all, delete-orphan")
    saas_admin_actions = relationship("SaasAdminAction", back_populates="organization", cascade="all, delete-orphan")
    saas_risky_users = relationship("SaasRiskyUser", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    email = Column(String(255), nullable=False, unique=True)
    name = Column(String(255))
    department = Column(String(255))
    job_title = Column(String(255))
    manager_email = Column(String(255))
    role = Column(String(50), default="analyst")
    cognito_id = Column(String(255), unique=True)
    password_hash = Column(String(255))
    is_vip = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    risk_score = Column(Integer, default=0)
    m365_user_id = Column(String(255))
    directory_provider = Column(String(50))   # "google" | "m365" — which provider enrolled this user
    last_login = Column(TIMESTAMPTZ)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    organization = relationship("Organization", back_populates="users")
    threats_received = relationship("Threat", back_populates="recipient_user", foreign_keys="Threat.recipient_user_id")


class OrgIntegration(Base):
    __tablename__ = "org_integrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    provider = Column(String(50), nullable=False)
    access_token_enc = Column(Text)
    refresh_token_enc = Column(Text)
    token_expiry = Column(TIMESTAMPTZ)
    scope = Column(Text)
    org_domain = Column(String(255))          # Domain discovered from this provider's OAuth (per-provider)
    webhook_subscription_id = Column(String(255))
    status = Column(String(50), default="active")
    connected_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)
    # Per-provider directory stats
    mailbox_count = Column(Integer, default=0)
    groups_count = Column(Integer, default=0)
    aliases_count = Column(Integer, default=0)
    shared_count = Column(Integer, default=0)
    last_baseline_at = Column(TIMESTAMPTZ, nullable=True)
    baseline_progress = Column(Integer, default=0)
    scope_group_id = Column(String(255), nullable=True)   # Optional: M365/Google group ID to scope monitoring
    scope_group_name = Column(String(255), nullable=True)

    organization = relationship("Organization", back_populates="integrations")


class SaasIntegration(Base):
    __tablename__ = "saas_integrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)  # 'teams' | 'sharepoint'
    status = Column(String(50), default="disconnected")  # 'disconnected' | 'active' | 'error'
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_expiry = Column(TIMESTAMPTZ, nullable=True)
    tenant_id = Column(String(255), nullable=True)
    scopes = Column(ARRAY(Text), default=list)
    error_message = Column(Text, nullable=True)
    connected_at = Column(TIMESTAMPTZ, nullable=True)
    last_synced_at = Column(TIMESTAMPTZ, nullable=True)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    __table_args__ = (UniqueConstraint("org_id", "provider"),)

    organization = relationship("Organization", back_populates="saas_integrations")


class SaasAlert(Base):
    __tablename__ = "saas_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # 'low' | 'medium' | 'high' | 'critical'
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    resource_id = Column(String(500), nullable=True)
    resource_name = Column(Text, nullable=True)
    resource_url = Column(Text, nullable=True)
    classification_result = Column(JSONB, nullable=True)  # DeepSeek result
    posture_result = Column(JSONB, nullable=True)         # Claude Haiku result
    status = Column(String(50), default="open")          # 'open' | 'acknowledged' | 'resolved' | 'suppressed'
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(TIMESTAMPTZ, nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    raw_data = Column(JSONB, nullable=True)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    organization = relationship("Organization", back_populates="saas_alerts")


class SaasDataItem(Base):
    __tablename__ = "saas_data_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    item_type = Column(String(50), nullable=False)  # 'file' | 'channel_message' | 'site'
    item_id = Column(String(500), nullable=False)
    item_name = Column(Text, nullable=False)
    item_url = Column(Text, nullable=True)
    parent_path = Column(Text, nullable=True)
    owner_email = Column(String(255), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    classification_label = Column(String(100), nullable=True)  # 'public' | 'internal' | 'confidential' | 'highly_confidential'
    classification_score = Column(REAL, nullable=True)
    classification_categories = Column(ARRAY(Text), default=list)
    sharing_scope = Column(String(50), nullable=True)  # 'org' | 'external' | 'public' | 'private'
    last_modified_at = Column(TIMESTAMPTZ, nullable=True)
    last_scanned_at = Column(TIMESTAMPTZ, nullable=True)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    __table_args__ = (UniqueConstraint("org_id", "provider", "item_id"),)

    organization = relationship("Organization", back_populates="saas_data_items")


class SaasPostureCheck(Base):
    __tablename__ = "saas_posture_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    check_name = Column(String(255), nullable=False)
    check_category = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)    # 'pass' | 'fail' | 'warning' | 'unknown'
    severity = Column(String(20), nullable=False)  # 'low' | 'medium' | 'high' | 'critical'
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    evidence = Column(JSONB, nullable=True)
    remediation_steps = Column(ARRAY(Text), default=list)
    last_checked_at = Column(TIMESTAMPTZ, nullable=True)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    organization = relationship("Organization", back_populates="saas_posture_checks")


class SaasUserLocation(Base):
    """Track user sign-in locations for impossible travel detection."""
    __tablename__ = "saas_user_locations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_email = Column(String(255), nullable=False)
    ip_address = Column(String(50), nullable=True)
    city = Column(String(255), nullable=True)
    country = Column(String(255), nullable=True)
    latitude = Column(REAL, nullable=True)
    longitude = Column(REAL, nullable=True)
    provider = Column(String(50), nullable=False)  # 'microsoft' or 'google'
    event_type = Column(String(50), nullable=True)  # 'sign_in', 'file_access', etc.
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    organization = relationship("Organization", back_populates="saas_user_locations")


class SaasOAuthApp(Base):
    """Track OAuth apps for shadow IT discovery."""
    __tablename__ = "saas_oauth_apps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    app_name = Column(Text, nullable=False)
    app_id = Column(String(500), nullable=False)
    provider = Column(String(50), nullable=False)  # 'microsoft' or 'google'
    publisher = Column(Text, nullable=True)
    permissions = Column(JSONB, default=list)
    status = Column(String(50), default="unknown")  # 'sanctioned', 'unsanctioned', 'under_review'
    risk_score = Column(REAL, default=0.5)
    user_count = Column(Integer, default=0)
    first_seen_at = Column(TIMESTAMPTZ, default=_utcnow)
    last_seen_at = Column(TIMESTAMPTZ, default=_utcnow)

    __table_args__ = (UniqueConstraint("org_id", "app_id", "provider"),)

    organization = relationship("Organization", back_populates="saas_oauth_apps")


class SaasAdminAction(Base):
    """Track admin actions for privileged user monitoring."""
    __tablename__ = "saas_admin_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    admin_email = Column(String(255), nullable=False)
    action_type = Column(String(255), nullable=False)
    target_type = Column(String(100), nullable=True)  # 'user', 'policy', 'app', etc.
    target_id = Column(String(500), nullable=True)
    target_name = Column(Text, nullable=True)
    details = Column(JSONB, default=dict)
    provider = Column(String(50), nullable=False)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    organization = relationship("Organization", back_populates="saas_admin_actions")


class SaasRiskyUser(Base):
    """Track risky users from Entra ID Identity Protection."""
    __tablename__ = "saas_risky_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_email = Column(String(255), nullable=False)
    user_id = Column(String(500), nullable=True)
    risk_level = Column(String(50), nullable=False)  # 'low', 'medium', 'high', 'hidden', 'none'
    risk_state = Column(String(100), nullable=True)  # 'atRisk', 'confirmedCompromised', 'remediated', 'dismissed'
    risk_detail = Column(Text, nullable=True)
    risk_last_updated_at = Column(TIMESTAMPTZ, nullable=True)
    provider = Column(String(50), default="microsoft")
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    __table_args__ = (UniqueConstraint("org_id", "user_email", "provider"),)

    organization = relationship("Organization", back_populates="saas_risky_users")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    email_message_id = Column(String(500))
    sender = Column(String(255))
    sender_domain = Column(String(255))
    recipient_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    recipient_email = Column(String(255))
    subject = Column(Text)
    subject_hash = Column(String(64))
    email_received_at = Column(TIMESTAMPTZ)       # Actual delivery time from email Date: header
    auth_results = Column(JSONB)                   # SPF/DKIM/DMARC pass/fail from headers
    threat_type = Column(String(50))
    risk_score = Column(Integer)
    score_breakdown = Column(JSONB)
    graph_score = Column(Integer)
    content_score = Column(Integer)
    reputation_score = Column(Integer)
    status = Column(String(50), default="open")
    action_taken = Column(String(50))
    ai_explanation_ar = Column(Text)
    ai_explanation_en = Column(Text)
    threat_indicators = Column(JSONB)
    sama_controls = Column(ARRAY(Text))
    nca_controls = Column(ARRAY(Text))
    policy_id = Column(UUID(as_uuid=True))
    false_positive = Column(Boolean, default=False)
    detected_at = Column(TIMESTAMPTZ, default=_utcnow)
    resolved_at = Column(TIMESTAMPTZ)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    # LLM classifier metadata
    llm_classification = Column(String(50))       # Raw LLM output class (may differ from threat_type after override)
    llm_confidence = Column(REAL)                 # 0.0–1.0 confidence from LLM
    llm_model = Column(String(100))               # "claude-3-5-sonnet-20241022" | "gpt-4o" | "heuristic_fallback"
    llm_cost_usd = Column(REAL)                   # Per-email inference cost in USD
    impersonation_detected = Column(Boolean, default=False)
    impersonation_target = Column(String(255))    # "ZATCA", "Microsoft", "CEO Ahmed Al-Farsi"
    urgency_score = Column(Integer)               # 0–100 from LLM

    email_body_preview = Column(Text)          # body snippet for message trace / policy matching
    
    # Auto-triage exclusion (for DLP drafts, manual escalations, etc.)
    exclude_auto_triage = Column(Boolean, default=False)  # If True, auto-triage engine skips this threat

    # Analyst feedback (active learning)
    analyst_verdict = Column(String(50))          # confirmed_malicious | false_positive | confirmed_benign
    analyst_email = Column(String(255))
    analyst_notes = Column(Text)
    reviewed_at = Column(TIMESTAMPTZ)

    organization = relationship("Organization", back_populates="threats")
    recipient_user = relationship("User", back_populates="threats_received", foreign_keys=[recipient_user_id])
    compliance_evidence = relationship("ComplianceEvidence", back_populates="threat")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    priority = Column(Integer, default=100)
    status = Column(String(50), default="draft")
    conditions = Column(JSONB, nullable=False)
    action = Column(String(50), nullable=False)
    action_config = Column(JSONB)
    m365_rule_id = Column(String(255))
    shadow_start = Column(TIMESTAMPTZ)
    hit_count = Column(Integer, default=0)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)

    organization = relationship("Organization", back_populates="policies")
    evaluations = relationship("PolicyEvaluation", back_populates="policy")


class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id"))
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id"))
    matched = Column(Boolean, default=False)
    action_taken = Column(String(50))
    shadow_mode = Column(Boolean, default=False)
    evaluated_at = Column(TIMESTAMPTZ, default=_utcnow)

    policy = relationship("Policy", back_populates="evaluations")


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    control_name_en = Column(Text, nullable=False)
    control_name_ar = Column(Text, nullable=False)
    description_en = Column(Text)
    description_ar = Column(Text)
    evidence_type = Column(String(100))

    __table_args__ = (UniqueConstraint("framework", "control_id"),)


class ComplianceStatus(Base):
    __tablename__ = "compliance_status"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    control_id = Column(UUID(as_uuid=True), ForeignKey("compliance_controls.id"))
    status = Column(String(50), default="not_started")
    notes = Column(Text)
    evidence_count = Column(Integer, default=0)
    last_evidence_at = Column(TIMESTAMPTZ)
    last_assessed_at = Column(TIMESTAMPTZ)
    updated_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)
    # Why the control received its current status (human-readable, generated
    # during /api/compliance/assess). Surfaced in the UI drill-down.
    rationale = Column(Text)
    # Snapshot of live signals supporting the score (integrations active,
    # threats observed, policies linked, scan counts). Used by the
    # per-control evidence drill-down so the auditor can verify the score.
    evidence_summary = Column(JSONB)

    __table_args__ = (UniqueConstraint("org_id", "control_id"),)


class ComplianceScoreSnapshot(Base):
    """Daily score-per-framework snapshot for trend charts and audit timelines."""
    __tablename__ = "compliance_score_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    framework = Column(String(50), nullable=False)
    score_pct = Column(Integer, nullable=False)
    total_controls = Column(Integer, default=0)
    compliant = Column(Integer, default=0)
    partial = Column(Integer, default=0)
    non_compliant = Column(Integer, default=0)
    captured_at = Column(TIMESTAMPTZ, default=_utcnow, nullable=False)


class ComplianceEvidence(Base):
    __tablename__ = "compliance_evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id"))
    control_ids = Column(ARRAY(Text))
    framework = Column(String(50))
    action_taken = Column(String(255))
    outcome = Column(String(255))
    s3_key = Column(Text)
    immutable = Column(Boolean, default=True)
    retention_tier = Column(String(20), default="1_year")
    created_at = Column(TIMESTAMPTZ, default=_utcnow)

    organization = relationship("Organization", back_populates="compliance_evidence")
    threat = relationship("Threat", back_populates="compliance_evidence")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    action = Column(String(255), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(UUID(as_uuid=True))
    old_value = Column(JSONB)
    new_value = Column(JSONB)
    ip_address = Column(String(45))
    created_at = Column(TIMESTAMPTZ, default=_utcnow)


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    report_type = Column(String(100))
    framework = Column(String(50))
    date_range_start = Column(Date)
    date_range_end = Column(Date)
    status = Column(String(50), default="pending")
    s3_key = Column(Text)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
    completed_at = Column(TIMESTAMPTZ)

    organization = relationship("Organization", back_populates="reports")


class EmailGroup(Base):
    """Email groups / distribution lists discovered via Google Workspace or M365."""
    __tablename__ = "email_groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)          # "google" | "m365"
    group_email = Column(String(255), nullable=False)       # the group's email address
    group_name = Column(String(255))
    description = Column(Text)
    member_count = Column(Integer, default=0)
    external_id = Column(String(255))                       # provider-native ID
    last_synced_at = Column(TIMESTAMPTZ, default=_utcnow, onupdate=_utcnow)
    created_at = Column(TIMESTAMPTZ, default=_utcnow)
