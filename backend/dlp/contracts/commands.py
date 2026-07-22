"""Backend-to-gateway command contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandType(str, Enum):
    ALLOW = "allow"
    RELEASE = "release"
    STOP = "stop"
    RETRY = "retry"


class GatewayMessageState(str, Enum):
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


class GatewayCommand(BaseModel):
    """Command consumed by ``dlp-gateway``.

    ``command_id`` is the v1 idempotency key.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    command_id: UUID = Field(default_factory=uuid4)
    command_type: CommandType
    message_id: UUID
    org_id: str
    expected_state: GatewayMessageState | None = None
    reason: str | None = None
    issued_at: datetime = Field(default_factory=_utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
