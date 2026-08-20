"""Command-ack consumer with idempotent persistence and settlement."""

from __future__ import annotations

import asyncio
import logging

from backend.dlp.application.command_ack_processor import (
    CommandAckMessageNotReady,
    CommandAckProcessingResult,
    CommandAckProcessor,
    CommandAckRejected,
)
from backend.dlp.contracts import CommandAckEvent
from backend.dlp.messaging.ports import DlpMessageBus

log = logging.getLogger(__name__)


class CommandAckConsumer:
    def __init__(
        self,
        bus: DlpMessageBus,
        processor: CommandAckProcessor,
        *,
        batch_size: int = 10,
        wait_seconds: int = 5,
        retry_delay_seconds: float = 1.0,
        processing_attempts: int = 10,
    ) -> None:
        self.bus = bus
        self.processor = processor
        self.batch_size = batch_size
        self.wait_seconds = wait_seconds
        self.retry_delay_seconds = retry_delay_seconds
        self.processing_attempts = max(processing_attempts, 1)

    async def run_once(self) -> int:
        acks = await self.bus.receive_command_acks(
            max_messages=self.batch_size,
            wait_seconds=self.wait_seconds,
        )
        for ack in acks:
            try:
                result = await self._process_with_retries(ack.event)
                await self.bus.complete_command_ack(ack.receipt)
                log.info(
                    "dlp_command_ack_processed",
                    extra={
                        "event_id": str(ack.event.event_id),
                        "message_id": str(ack.event.message_id),
                        "command_id": str(ack.event.command_id),
                        "status": ack.event.status.value,
                        "inserted": result.inserted,
                        "stopped": result.stopped,
                    },
                )
            except CommandAckMessageNotReady:
                log.info(
                    "dlp_command_ack_message_not_ready",
                    extra={
                        "event_id": str(ack.event.event_id),
                        "message_id": str(ack.event.message_id),
                    },
                )
                await self.bus.abandon_command_ack(ack.receipt)
            except CommandAckRejected as exc:
                log.warning(
                    "dlp_command_ack_rejected",
                    extra={
                        "event_id": str(ack.event.event_id),
                        "reason": str(exc),
                    },
                )
                await self.bus.dead_letter_command_ack(
                    ack.receipt, str(exc)
                )
            except asyncio.CancelledError:
                await self.bus.abandon_command_ack(ack.receipt)
                raise
            except Exception:
                log.exception(
                    "dlp_command_ack_processing_failed",
                    extra={
                        "event_id": str(ack.event.event_id),
                        "message_id": str(ack.event.message_id),
                    },
                )
                await self.bus.abandon_command_ack(ack.receipt)
        return len(acks)

    async def _process_with_retries(
        self, event: CommandAckEvent
    ) -> CommandAckProcessingResult:
        for attempt in range(self.processing_attempts):
            try:
                return await self.processor.process(event)
            except (CommandAckRejected, asyncio.CancelledError):
                raise
            except Exception:
                if attempt + 1 >= self.processing_attempts:
                    raise
                delay = min(
                    self.retry_delay_seconds * (2**attempt),
                    30.0,
                )
                log.warning(
                    "dlp_command_ack_processing_retry",
                    extra={
                        "event_id": str(event.event_id),
                        "attempt": attempt + 1,
                        "delay_seconds": delay,
                    },
                )
                if delay:
                    await asyncio.sleep(delay)
        raise RuntimeError("unreachable command ack retry state")

    async def run_forever(self) -> None:
        while True:
            count = await self.run_once()
            if count == 0:
                await asyncio.sleep(0)
