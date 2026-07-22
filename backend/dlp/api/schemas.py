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


class MessageListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DlpMessageSummary]
    next_cursor: datetime | None = None


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
