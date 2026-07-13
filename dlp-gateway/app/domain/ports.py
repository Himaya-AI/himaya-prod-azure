from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.domain.models import (
    CaptureEvent,
    GatewayCommand,
    RelayResult,
    SpoolRecord,
)


@runtime_checkable
class SpoolStore(Protocol):
    def commit(self, record: SpoolRecord, mime_bytes: bytes) -> SpoolRecord:
        """Persist envelope + MIME with fsync before SMTP 250."""

    def list_pending_capture(self) -> list[SpoolRecord]:
        ...

    def mark_captured(self, message_id: str, blob_uri: str) -> SpoolRecord:
        ...

    def get(self, message_id: str) -> SpoolRecord | None:
        ...

    def read_mime(self, record: SpoolRecord) -> bytes:
        ...

    def update_state(self, message_id: str, state: str, **extra: object) -> SpoolRecord:
        ...


@runtime_checkable
class MimeObjectStore(Protocol):
    def put_immutable(self, org_id: str, message_id: str, mime_bytes: bytes, sha256: str) -> str:
        """Store immutable MIME; return blob URI."""


@runtime_checkable
class EventBus(Protocol):
    def publish_capture(self, event: CaptureEvent) -> None:
        ...

    def consume_captures(self, max_items: int = 10) -> list[CaptureEvent]:
        ...

    def publish_command(self, command: GatewayCommand) -> None:
        ...

    def consume_commands(self, max_items: int = 10) -> list[GatewayCommand]:
        ...

    def ack_capture(self, event: CaptureEvent) -> None:
        ...

    def ack_command(self, command: GatewayCommand) -> None:
        ...


@runtime_checkable
class TenantConfigCache(Protocol):
    def resolve_for_sender(self, envelope_from: str, routing_hostname: str | None = None):
        ...


@runtime_checkable
class ProviderRelayAdapter(Protocol):
    def submit(self, mime_bytes: bytes, envelope_from: str, envelope_to: list[str]) -> RelayResult:
        ...
