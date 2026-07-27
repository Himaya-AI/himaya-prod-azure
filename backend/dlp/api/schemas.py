"""HTTP schemas for the DLP v2 control plane."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.dlp.policy import PolicyDocument


class DlpStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["disabled", "ready"]
    pipeline_enabled: bool
    mode: Literal["monitor", "enforce"]
    classifier_url_configured: bool
    legacy_independent: bool = True
    message_counts: dict[str, int] = Field(default_factory=dict)
    reviewable_count: int = 0
    failed_outbox_commands: int = 0


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
    status: Literal["builtin", "draft", "published", "archived"]
    document: PolicyDocument
    created_at: datetime | None = None
    published_at: datetime | None = None


class PolicyDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
