"""SQLAlchemy models for the independent DLP v2 bounded context."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DlpMessage(Base):
    __tablename__ = "dlp_messages"
    __table_args__ = (
        Index("ix_dlp_messages_org_received", "org_id", "received_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    deduplication_key: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_deployment_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    envelope_from: Mapped[str] = mapped_column(Text, nullable=False)
    envelope_to: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    blob_uri: Mapped[str] = mapped_column(Text, nullable=False)
    mime_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    mime_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="received", index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    gateway_occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )


class DlpMessagePart(Base):
    __tablename__ = "dlp_message_parts"
    __table_args__ = (
        UniqueConstraint(
            "message_id", "part_index", name="uq_dlp_message_parts_position"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    part_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    disposition: Mapped[str | None] = mapped_column(String(64))
    filename: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    extraction_status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )
    extracted_text_sha256: Mapped[str | None] = mapped_column(String(64))
    extracted_text_length: Mapped[int | None] = mapped_column(Integer)
    limitation_code: Mapped[str | None] = mapped_column(String(64))
    limitation_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class DlpClassificationResult(Base):
    __tablename__ = "dlp_classification_results"
    __table_args__ = (
        UniqueConstraint(
            "message_id",
            "run_key",
            name="uq_dlp_classification_results_run",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_key: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    findings: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    llm_result: Mapped[dict | None] = mapped_column(JSONB)
    limitations: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class DlpDecision(Base):
    __tablename__ = "dlp_decisions"
    __table_args__ = (
        UniqueConstraint(
            "message_id",
            "evaluation_version",
            name="uq_dlp_decisions_evaluation",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    classification_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_classification_results.id", ondelete="SET NULL"),
    )
    evaluation_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    intended_action: Mapped[str] = mapped_column(String(16), nullable=False)
    effective_action: Mapped[str] = mapped_column(String(16), nullable=False)
    matched_rule_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    finding_references: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evaluation_latency_ms: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class DlpMessageEvent(Base):
    __tablename__ = "dlp_message_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_key: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class DlpCommandOutbox(Base):
    __tablename__ = "dlp_command_outbox"
    __table_args__ = (
        Index(
            "ix_dlp_command_outbox_pending",
            "status",
            "available_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    command_type: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )


class DlpPolicyVersion(Base):
    __tablename__ = "dlp_policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "version", name="uq_dlp_policy_versions_org_version"
        ),
        Index(
            "ix_dlp_policy_versions_org_status",
            "org_id",
            "status",
        ),
        Index(
            "uq_dlp_policy_versions_one_draft_per_org",
            "org_id",
            unique=True,
            postgresql_where=text("status = 'draft'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    draft_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_document: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    published_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class DlpTenantConfig(Base):
    __tablename__ = "dlp_tenant_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="monitor"
    )
    domains: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    lexicon_version: Mapped[str] = mapped_column(
        String(64), nullable=False, default="v1"
    )
    active_policy_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_policy_versions.id", ondelete="SET NULL"),
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )


class DlpReviewAction(Base):
    __tablename__ = "dlp_review_actions"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "idempotency_key",
            name="uq_dlp_review_actions_idempotency",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dlp_messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    command_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
