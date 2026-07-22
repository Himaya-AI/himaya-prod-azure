"""Messaging ports for DLP capture events and gateway commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from backend.dlp.contracts import CaptureEvent, GatewayCommand


@dataclass(frozen=True)
class ReceivedCapture:
    event: CaptureEvent
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

    async def publish_command(self, command: GatewayCommand) -> None: ...

    async def recover_stale(self) -> int: ...

    async def close(self) -> None: ...
