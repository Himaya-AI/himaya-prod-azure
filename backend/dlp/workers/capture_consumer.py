"""Capture-event consumer with explicit settlement semantics."""

from __future__ import annotations

import asyncio
import logging

from backend.dlp.application.message_orchestrator import (
    MessageOrchestrator,
)
from backend.dlp.messaging.ports import DlpMessageBus

log = logging.getLogger(__name__)


class CaptureConsumer:
    def __init__(
        self,
        bus: DlpMessageBus,
        orchestrator: MessageOrchestrator,
        *,
        batch_size: int = 10,
        wait_seconds: int = 5,
        retry_delay_seconds: float = 1.0,
    ) -> None:
        self.bus = bus
        self.orchestrator = orchestrator
        self.batch_size = batch_size
        self.wait_seconds = wait_seconds
        self.retry_delay_seconds = retry_delay_seconds

    async def run_once(self) -> int:
        deliveries = await self.bus.receive_captures(
            max_messages=self.batch_size,
            wait_seconds=self.wait_seconds,
        )
        for delivery in deliveries:
            try:
                result = await self.orchestrator.process(
                    delivery.event
                )
                await self.bus.complete_capture(delivery.receipt)
                log.info(
                    "dlp_capture_processed",
                    extra={
                        "message_id": str(result.message_id),
                        "intended_action": (
                            result.intended_action.value
                        ),
                        "effective_action": (
                            result.effective_action.value
                        ),
                        "resumed": result.resumed,
                    },
                )
            except asyncio.CancelledError:
                await self.bus.abandon_capture(delivery.receipt)
                raise
            except Exception:
                log.exception(
                    "dlp_capture_processing_failed",
                    extra={
                        "message_id": str(
                            delivery.event.message_id
                        )
                    },
                )
                await self.bus.abandon_capture(delivery.receipt)
                if self.retry_delay_seconds:
                    await asyncio.sleep(self.retry_delay_seconds)
        return len(deliveries)

    async def run_forever(self) -> None:
        await self.bus.recover_stale()
        while True:
            count = await self.run_once()
            if count == 0:
                await asyncio.sleep(0)
