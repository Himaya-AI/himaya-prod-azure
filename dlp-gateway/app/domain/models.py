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
    PARTIALLY_ACCEPTED = "partially_accepted"
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
    blob_uri: str | None = None
    processed_command_ids: list[UUID] = Field(default_factory=list)
    stop_reason: str | None = None
    relay_smtp_code: int | None = None
    relay_detail: str | None = None
    relay_smtp_stage: str | None = None
    relay_remote_host: str | None = None
    relay_cert_thumbprint: str | None = None
    relay_accepted_recipients: list[str] = Field(default_factory=list)
    relay_refused_recipients: list[str] = Field(default_factory=list)
    relay_attempt_id: UUID | None = None
    relay_attempt_count: int = 0
    relay_trigger_command_id: UUID | None = None
    relay_outcome: str | None = None
    relay_started_at: datetime | None = None
    relay_finished_at: datetime | None = None
    published_delivery_event_ids: list[UUID] = Field(default_factory=list)


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
    PARTIAL = "partial"
    UNCERTAIN = "uncertain"


class SmtpStage(str, Enum):
    CONNECT = "connect"
    EHLO = "ehlo"
    STARTTLS = "starttls"
    MAIL_FROM = "mail_from"
    RCPT_TO = "rcpt_to"
    DATA_STARTED = "data_started"
    DATA_SENT = "data_sent"
    FINAL_RESPONSE = "final_response_received"


class RelayRequest(BaseModel):
    """Normalized submit request for provider relay adapters."""

    message_id: UUID
    org_id: str
    provider: str
    provider_deployment_id: str
    envelope_from: str
    envelope_to: list[str]
    mime_bytes: bytes
    attempt_id: UUID = Field(default_factory=uuid4)
    # Opaque tenant relay settings resolved by the dispatcher.
    relay_config: dict[str, Any] = Field(default_factory=dict)


class RelayResult(BaseModel):
    outcome: DeliveryOutcome
    smtp_code: int | None = None
    smtp_message: str | None = None
    detail: str | None = None
    smtp_stage: SmtpStage | None = None
    accepted_recipients: list[str] = Field(default_factory=list)
    refused_recipients: list[str] = Field(default_factory=list)
    remote_host: str | None = None
    certificate_thumbprint: str | None = None
    attempt_started_at: datetime | None = None
    attempt_finished_at: datetime | None = None


class DeliveryEvent(BaseModel):
    """Gateway-to-control-plane result for one provider submission attempt."""

    schema_version: int = 1
    event_type: str = "dlp.message.delivery.v1"
    event_id: UUID = Field(default_factory=uuid4)
    message_id: UUID
    org_id: str
    provider: str
    provider_deployment_id: str
    attempt_id: UUID
    attempt_number: int = Field(ge=1)
    trigger_command_id: UUID | None = None
    relay_adapter: str | None = None
    outcome: DeliveryOutcome
    resulting_state: MessageState
    smtp_code: int | None = None
    smtp_message: str | None = None
    detail: str | None = None
    smtp_stage: SmtpStage | None = None
    remote_host: str | None = None
    accepted_recipients: list[str] = Field(default_factory=list)
    refused_recipients: list[str] = Field(default_factory=list)
    certificate_thumbprint: str | None = None
    attempt_started_at: datetime | None = None
    attempt_finished_at: datetime | None = None
    occurred_at: datetime = Field(default_factory=utcnow)

    @property
    def deduplication_key(self) -> str:
        return f"{self.event_type}:{self.attempt_id}"
