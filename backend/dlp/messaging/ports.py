"""Messaging ports for capture/delivery events and gateway commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from backend.dlp.contracts import (
    CaptureEvent,
    DeliveryEvent,
    GatewayCommand,
)


@dataclass(frozen=True)
class ReceivedCapture:
    event: CaptureEvent
    receipt: Any


@dataclass(frozen=True)
class ReceivedDelivery:
    event: DeliveryEvent
    receipt: Any


class DlpMessageBus(Protocol):
    async def receive_captures(
        self, max_messages: int = 10, wait_seconds: int = 5
    ) -> list[ReceivedCapture]: ...

    async def complete_capture(self, receipt: Any) -> None: ...

    async def abandon_capture(self, receipt: Any) -> None: ...

    async def dead_letter_capture(
        self, receipt: Any, reason: str
    ) -> None: ...

    async def receive_deliveries(
        self, max_messages: int = 10, wait_seconds: int = 5
    ) -> list[ReceivedDelivery]: ...

    async def complete_delivery(self, receipt: Any) -> None: ...

    async def abandon_delivery(self, receipt: Any) -> None: ...

    async def dead_letter_delivery(
        self, receipt: Any, reason: str
    ) -> None: ...

    async def publish_command(self, command: GatewayCommand) -> None: ...

    async def recover_stale(self) -> int: ...

    async def close(self) -> None: ...
