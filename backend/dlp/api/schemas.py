"""HTTP schemas for the DLP v2 control plane."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.dlp.policy import PolicyDocument


class FailedOutboxCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    message_id: UUID
    command_type: str
    last_error: str | None = None
    attempts: int = 0
    updated_at: datetime
    envelope_from: str | None = None


class DlpStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["disabled", "ready"]
    pipeline_enabled: bool
    mode: Literal["monitor", "enforce"]
    classifier_url_configured: bool
    legacy_independent: bool = True
    message_counts: dict[str, int] = Field(default_factory=dict)
    reviewable_count: int = 0
    oldest_reviewable_at: datetime | None = None
    oldest_reviewable_from: str | None = None
    failed_outbox_commands: int = 0
    failed_outbox_items: list[FailedOutboxCommand] = Field(
        default_factory=list
    )


class TenantSettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    mode: Literal["monitor", "enforce"]
    domains: list[str]
    lexicon_version: str
    active_policy_version: int | None


class TenantSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    mode: Literal["monitor", "enforce"]
    domains: list[str] = Field(default_factory=list, max_length=100)
    lexicon_version: str = Field(
        default="v1", min_length=1, max_length=64
    )


class PolicyVersionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID | None = None
    version: int
    draft_revision: int | None = None
    status: Literal["builtin", "draft", "published", "archived"]
    document: PolicyDocument
    created_at: datetime | None = None
    updated_at: datetime | None = None
    published_at: datetime | None = None
    updated_by: UUID | None = None
    published_by: UUID | None = None


class PolicyDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document: PolicyDocument
    expected_id: UUID | None = None
    expected_version: int | None = None
    expected_revision: int | None = None


class PolicyPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    draft_id: UUID
    expected_version: int
    expected_revision: int
    document: PolicyDocument


class DlpMessageSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: UUID
    envelope_from: str
    envelope_to: list[str]
    state: str
    received_at: datetime
    intended_action: str | None = None
    effective_action: str | None = None
    explanation: str | None = None
    reviewable: bool = False


class MessageListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DlpMessageSummary]
    next_cursor: datetime | None = None
    next_id: UUID | None = None


class DlpFindingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector: str
    entity_type: str
    confidence: float


class DlpPartSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_index: int
    content_type: str
    filename: str | None = None
    extraction_status: str
    limitation_code: str | None = None
    limitation_detail: str | None = None


class DlpExtractionLimitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    detail: str


class DlpReviewHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["release", "stop"]
    reason: str
    actor_user_id: UUID
    created_at: datetime


class DlpDeliveryAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: str
    resulting_state: str
    attempt_number: int
    smtp_stage: str | None = None
    smtp_code: int | None = None
    smtp_message: str | None = None
    detail: str | None = None
    remote_host: str | None = None
    accepted_recipients: list[str] = Field(default_factory=list)
    refused_recipients: list[str] = Field(default_factory=list)
    attempt_started_at: datetime | None = None
    attempt_finished_at: datetime | None = None
    occurred_at: datetime


class DlpCommandStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    command_type: str
    status: Literal["queued", "sent", "failed"]
    attempts: int = 0
    last_error: str | None = None
    created_at: datetime
    published_at: datetime | None = None
    gateway_status: str | None = None


class DlpMessageDetail(DlpMessageSummary):
    model_config = ConfigDict(extra="forbid")

    policy_version: str | None = None
    matched_rule_ids: list[str] = Field(default_factory=list)
    findings: list[DlpFindingSummary] = Field(default_factory=list)
    extraction_limitations: list[DlpExtractionLimitation] = Field(
        default_factory=list
    )
    parts: list[DlpPartSummary] = Field(default_factory=list)
    subject: str | None = None
    sanitized_preview: str | None = None
    preview_available: bool = False
    review_history: list[DlpReviewHistoryItem] = Field(
        default_factory=list
    )
    deliveries: list[DlpDeliveryAttempt] = Field(default_factory=list)
    commands: list[DlpCommandStatus] = Field(default_factory=list)


class ReviewActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=2000)
    idempotency_key: str = Field(min_length=8, max_length=255)


class ReviewActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: UUID
    action: Literal["release", "stop"]
    command_id: UUID
    status: Literal["queued", "already_queued"]
