"""Gateway-to-backend event contracts.

These fields intentionally mirror ``dlp-gateway/app/domain/models.py``.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
