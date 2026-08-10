"""Gateway-to-backend event contracts.

These fields intentionally mirror ``dlp-gateway/app/domain/models.py``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.dlp.contracts.commands import GatewayMessageState


class CaptureEvent(BaseModel):
    """Immutable MIME capture notification emitted by the gateway."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    event_type: str = "dlp.message.captured.v1"
    message_id: UUID
    org_id: str
    provider: str
    provider_deployment_id: str
    envelope_from: str
    envelope_to: list[str]
    mime_sha256: str = Field(min_length=64, max_length=64)
    mime_size: int = Field(ge=0)
    blob_uri: str
    received_at: datetime
    occurred_at: datetime

    @property
    def deduplication_key(self) -> str:
        """Stable v1 key because the gateway event has no event_id."""
        return (
            f"{self.event_type}:{self.schema_version}:{self.message_id}"
        )


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


class DeliveryEvent(BaseModel):
    """One durable provider-submission outcome emitted by the gateway."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    event_type: str = "dlp.message.delivery.v1"
    event_id: UUID
    message_id: UUID
    org_id: str
    provider: str
    provider_deployment_id: str
    attempt_id: UUID
    attempt_number: int = Field(ge=1)
    trigger_command_id: UUID | None = None
    relay_adapter: str | None = None
    outcome: DeliveryOutcome
    resulting_state: GatewayMessageState
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
    occurred_at: datetime

    @property
    def deduplication_key(self) -> str:
        return f"{self.event_type}:{self.attempt_id}"
