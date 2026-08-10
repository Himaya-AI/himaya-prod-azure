"""Delivery-event consumer with idempotent persistence and settlement."""

from __future__ import annotations

import asyncio
import logging

from backend.dlp.application.delivery_processor import (
    DeliveryEventProcessor,
    DeliveryEventRejected,
    DeliveryMessageNotReady,
    DeliveryProcessingResult,
)
from backend.dlp.contracts import DeliveryEvent
from backend.dlp.messaging.ports import DlpMessageBus

log = logging.getLogger(__name__)


class DeliveryConsumer:
    def __init__(
        self,
        bus: DlpMessageBus,
        processor: DeliveryEventProcessor,
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
        deliveries = await self.bus.receive_deliveries(
            max_messages=self.batch_size,
            wait_seconds=self.wait_seconds,
        )
        for delivery in deliveries:
            try:
                result = await self._process_with_retries(
                    delivery.event
                )
                await self.bus.complete_delivery(delivery.receipt)
                log.info(
                    "dlp_delivery_processed",
                    extra={
                        "event_id": str(delivery.event.event_id),
                        "message_id": str(delivery.event.message_id),
                        "outcome": delivery.event.outcome.value,
                        "inserted": result.inserted,
                        "retry_scheduled": result.retry_scheduled,
                    },
                )
            except DeliveryMessageNotReady:
                log.info(
                    "dlp_delivery_message_not_ready",
                    extra={
                        "event_id": str(delivery.event.event_id),
                        "message_id": str(delivery.event.message_id),
                    },
                )
                await self.bus.abandon_delivery(delivery.receipt)
            except DeliveryEventRejected as exc:
                log.warning(
                    "dlp_delivery_rejected",
                    extra={
                        "event_id": str(delivery.event.event_id),
                        "reason": str(exc),
                    },
                )
                await self.bus.dead_letter_delivery(
                    delivery.receipt, str(exc)
                )
            except asyncio.CancelledError:
                await self.bus.abandon_delivery(delivery.receipt)
                raise
            except Exception:
                log.exception(
                    "dlp_delivery_processing_failed",
                    extra={
                        "event_id": str(delivery.event.event_id),
                        "message_id": str(delivery.event.message_id),
                    },
                )
                await self.bus.abandon_delivery(delivery.receipt)
        return len(deliveries)

    async def _process_with_retries(
        self, event: DeliveryEvent
    ) -> DeliveryProcessingResult:
        for attempt in range(self.processing_attempts):
            try:
                return await self.processor.process(event)
            except (DeliveryEventRejected, asyncio.CancelledError):
                raise
            except Exception:
                if attempt + 1 >= self.processing_attempts:
                    raise
                delay = min(
                    self.retry_delay_seconds * (2**attempt),
                    30.0,
                )
                log.warning(
                    "dlp_delivery_processing_retry",
                    extra={
                        "event_id": str(event.event_id),
                        "attempt": attempt + 1,
                        "delay_seconds": delay,
                    },
                )
                if delay:
                    await asyncio.sleep(delay)
        raise RuntimeError("unreachable delivery retry state")

    async def run_forever(self) -> None:
        while True:
            count = await self.run_once()
            if count == 0:
                await asyncio.sleep(0)
