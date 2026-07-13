from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MessageState(str, Enum):
    ACCEPTED_IN_SPOOL = "accepted_in_spool"
    CAPTURED = "captured"
    HELD = "held"
    STOPPED = "stopped"
    ALLOW_PENDING = "allow_pending"
    SUBMITTING = "submitting"
    PROVIDER_ACCEPTED = "provider_accepted"
    DEFERRED = "deferred"
    FAILED = "failed"
    OUTCOME_UNCERTAIN = "outcome_uncertain"


class CommandType(str, Enum):
    ALLOW = "allow"
    RELEASE = "release"
    STOP = "stop"
    RETRY = "retry"


class SpoolRecord(BaseModel):
    """Durable acceptance record written before SMTP 250."""

    message_id: UUID = Field(default_factory=uuid4)
    org_id: str
    provider: str
    provider_deployment_id: str
    session_id: str
    envelope_from: str
    envelope_to: list[str]
    mime_sha256: str
    mime_size: int
    received_at: datetime = Field(default_factory=utcnow)
    state: MessageState = MessageState.ACCEPTED_IN_SPOOL
    routing_hostname: str | None = None
    peer: str | None = None
    spool_mime_path: str
    metadata_path: str


class CaptureEvent(BaseModel):
    schema_version: int = 1
    event_type: str = "dlp.message.captured.v1"
    message_id: UUID
    org_id: str
    provider: str
    provider_deployment_id: str
    envelope_from: str
    envelope_to: list[str]
    mime_sha256: str
    mime_size: int
    blob_uri: str
    received_at: datetime
    occurred_at: datetime = Field(default_factory=utcnow)


class GatewayCommand(BaseModel):
    schema_version: int = 1
    command_id: UUID = Field(default_factory=uuid4)
    command_type: CommandType
    message_id: UUID
    org_id: str
    expected_state: MessageState | None = None
    reason: str | None = None
    issued_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeliveryOutcome(str, Enum):
    ACCEPTED = "accepted"
    DEFERRED = "deferred"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class RelayResult(BaseModel):
    outcome: DeliveryOutcome
    smtp_code: int | None = None
    smtp_message: str | None = None
    detail: str | None = None
