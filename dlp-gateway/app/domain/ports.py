from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.domain.models import (
    CaptureEvent,
    CommandAckEvent,
    DeliveryEvent,
    GatewayCommand,
    RelayRequest,
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

    def list_pending_delivery_events(self) -> list[DeliveryEvent]:
        ...

    def mark_delivery_event_published(
        self, message_id: str, event_id: str
    ) -> SpoolRecord:
        ...

    def record_command_ack(self, event: CommandAckEvent) -> CommandAckEvent:
        ...

    def list_pending_command_acks(self) -> list[CommandAckEvent]:
        ...

    def mark_command_ack_published(self, event_id: str) -> None:
        ...

    def recover_stale_submissions(self) -> int:
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

    def publish_delivery(self, event: DeliveryEvent) -> None:
        ...

    def publish_command_ack(self, event: CommandAckEvent) -> None:
        ...

    def consume_commands(self, max_items: int = 10) -> list[GatewayCommand]:
        ...

    def ack_capture(self, event: CaptureEvent) -> None:
        ...

    def ack_command(self, command: GatewayCommand) -> None:
        ...

    def retry_command(self, command: GatewayCommand) -> None:
        ...

    def dead_letter_command(
        self, command: GatewayCommand, reason: str
    ) -> None:
        ...

    def recover_stale(
        self, kind: str, stale_after_seconds: int
    ) -> int:
        ...

    def close(self) -> None:
        ...


@runtime_checkable
class TenantConfigCache(Protocol):
    def resolve_for_sender(self, envelope_from: str, routing_hostname: str | None = None):
        ...

    def resolve_by_org_id(self, org_id: str):
        ...


@runtime_checkable
class ProviderRelayAdapter(Protocol):
    def submit(self, request: RelayRequest) -> RelayResult:
        ...


@runtime_checkable
class RelayCertificateProvider(Protocol):
    def get_certificate(
        self,
        org_id: str,
        cert_path: str,
        key_path: str,
        expected_thumbprint: str | None = None,
    ):
        ...
