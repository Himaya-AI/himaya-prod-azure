"""Persist delivery outcomes and schedule only safe, bounded retries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from backend.dlp.contracts import (
    CommandType,
    DeliveryEvent,
    DeliveryOutcome,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.persistence.repositories import (
    CommandOutboxRepository,
    MessageEventRepository,
    MessageRepository,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeliveryMessageNotReady(LookupError):
    """Capture persistence has not completed yet; abandon for redelivery."""


class DeliveryEventRejected(ValueError):
    """Permanent tenant/provider mismatch."""


@dataclass(frozen=True)
class DeliveryProcessingResult:
    inserted: bool
    retry_scheduled: bool


class DeliveryEventProcessor:
    def __init__(
        self,
        session_factory: Any,
        *,
        max_attempts: int = 4,
        retry_base_seconds: int = 60,
        retry_max_seconds: int = 900,
    ) -> None:
        self.session_factory = session_factory
        self.max_attempts = max_attempts
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds

    async def process(
        self, event: DeliveryEvent
    ) -> DeliveryProcessingResult:
        async with self.session_factory() as session:
            messages = MessageRepository(session)
            events = MessageEventRepository(session)
            outbox = CommandOutboxRepository(session)

            message = await messages.get(event.message_id)
            if message is None:
                raise DeliveryMessageNotReady(str(event.message_id))
            try:
                event_org_id = UUID(event.org_id)
            except ValueError as exc:
                raise DeliveryEventRejected("Invalid event org_id") from exc
            if message.org_id != event_org_id:
                raise DeliveryEventRejected(
                    "Delivery event tenant does not own message"
                )
            if (
                message.provider != event.provider
                or message.provider_deployment_id
                != event.provider_deployment_id
            ):
                raise DeliveryEventRejected(
                    "Delivery event provider deployment mismatch"
                )

            inserted = await events.record_delivery(event)
            if not inserted:
                await session.commit()
                return DeliveryProcessingResult(
                    inserted=False,
                    retry_scheduled=False,
                )

            retry_scheduled = False
            if (
                event.outcome == DeliveryOutcome.DEFERRED
                and event.attempt_number < self.max_attempts
            ):
                command_id = uuid5(
                    NAMESPACE_URL,
                    f"dlp-delivery-retry:{event.attempt_id}",
                )
                command = GatewayCommand(
                    command_id=command_id,
                    command_type=CommandType.RETRY,
                    message_id=event.message_id,
                    org_id=event.org_id,
                    expected_state=GatewayMessageState.DEFERRED,
                    reason="bounded retry after temporary SMTP failure",
                    metadata={
                        "automatic": True,
                        "source_attempt_id": str(event.attempt_id),
                        "source_event_id": str(event.event_id),
                    },
                )
                row = await outbox.enqueue(command)
                delay = min(
                    self.retry_base_seconds
                    * (5 ** max(event.attempt_number - 1, 0)),
                    self.retry_max_seconds,
                )
                row.available_at = _utcnow() + timedelta(seconds=delay)
                retry_scheduled = True
                await messages.set_state(message, "retry_scheduled")
            elif (
                event.outcome == DeliveryOutcome.DEFERRED
                and event.attempt_number >= self.max_attempts
            ):
                await messages.set_state(
                    message, "delivery_retry_exhausted"
                )
            else:
                await messages.set_state(
                    message, event.resulting_state.value
                )

            await session.commit()
            return DeliveryProcessingResult(
                inserted=True,
                retry_scheduled=retry_scheduled,
            )
