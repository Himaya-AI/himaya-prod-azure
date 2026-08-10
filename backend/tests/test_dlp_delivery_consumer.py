from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from backend.dlp.application.delivery_processor import (
    DeliveryEventProcessor,
    DeliveryMessageNotReady,
    DeliveryProcessingResult,
)
from backend.dlp.contracts import (
    DeliveryEvent,
    DeliveryOutcome,
    GatewayMessageState,
)
from backend.dlp.messaging.ports import ReceivedDelivery
from backend.dlp.workers.delivery_consumer import DeliveryConsumer


def _event() -> DeliveryEvent:
    return DeliveryEvent(
        event_id=uuid4(),
        message_id=uuid4(),
        org_id=str(uuid4()),
        provider="m365",
        provider_deployment_id=str(uuid4()),
        attempt_id=uuid4(),
        attempt_number=1,
        outcome=DeliveryOutcome.ACCEPTED,
        resulting_state=GatewayMessageState.PROVIDER_ACCEPTED,
        smtp_code=250,
        occurred_at=datetime.now(timezone.utc),
    )


class _Bus:
    def __init__(self, event: DeliveryEvent) -> None:
        self.delivery = ReceivedDelivery(event=event, receipt="receipt")
        self.completed = False
        self.abandoned = False
        self.abandon_count = 0

    async def receive_deliveries(self, **_kwargs):
        return [self.delivery]

    async def complete_delivery(self, _receipt) -> None:
        self.completed = True

    async def abandon_delivery(self, _receipt) -> None:
        self.abandoned = True
        self.abandon_count += 1

    async def dead_letter_delivery(self, _receipt, _reason) -> None:
        raise AssertionError("event should not be dead-lettered")


@pytest.mark.asyncio
async def test_delivery_consumer_completes_after_processing() -> None:
    event = _event()
    bus = _Bus(event)

    class _Processor:
        async def process(self, received):
            assert received == event
            return DeliveryProcessingResult(
                inserted=True, retry_scheduled=False
            )

    consumer = DeliveryConsumer(
        bus, _Processor(), retry_delay_seconds=0  # type: ignore[arg-type]
    )
    assert await consumer.run_once() == 1
    assert bus.completed is True
    assert bus.abandoned is False


@pytest.mark.asyncio
async def test_delivery_consumer_abandons_when_capture_not_ready() -> None:
    bus = _Bus(_event())

    class _Processor:
        async def process(self, _event):
            raise DeliveryMessageNotReady("not yet")

    consumer = DeliveryConsumer(
        bus, _Processor(), retry_delay_seconds=0  # type: ignore[arg-type]
    )
    assert await consumer.run_once() == 1
    assert bus.completed is False
    assert bus.abandoned is True
    assert bus.abandon_count == 1


@pytest.mark.asyncio
async def test_delivery_consumer_retries_in_memory_before_abandon() -> None:
    bus = _Bus(_event())

    class _Processor:
        def __init__(self) -> None:
            self.calls = 0

        async def process(self, _event):
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("database unavailable")
            return DeliveryProcessingResult(
                inserted=True, retry_scheduled=False
            )

    processor = _Processor()
    consumer = DeliveryConsumer(
        bus,
        processor,  # type: ignore[arg-type]
        retry_delay_seconds=0,
        processing_attempts=3,
    )
    assert await consumer.run_once() == 1
    assert processor.calls == 3
    assert bus.completed is True
    assert bus.abandon_count == 0


@pytest.mark.asyncio
async def test_deferred_event_schedules_bounded_retry(
    monkeypatch,
) -> None:
    event = _event().model_copy(
        update={
            "outcome": DeliveryOutcome.DEFERRED,
            "resulting_state": GatewayMessageState.DEFERRED,
        }
    )
    message = SimpleNamespace(
        id=event.message_id,
        org_id=uuid4(),
        provider=event.provider,
        provider_deployment_id=event.provider_deployment_id,
        state="allow_requested",
    )
    event = event.model_copy(update={"org_id": str(message.org_id)})
    enqueued = []

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def commit(self):
            return None

    class _Messages:
        def __init__(self, _session):
            pass

        async def get(self, _message_id):
            return message

        async def set_state(self, target, state):
            target.state = state

    class _Events:
        def __init__(self, _session):
            pass

        async def record_delivery(self, _event):
            return True

    class _Outbox:
        def __init__(self, _session):
            pass

        async def enqueue(self, command):
            enqueued.append(command)
            return SimpleNamespace(available_at=None)

    import backend.dlp.application.delivery_processor as module

    monkeypatch.setattr(module, "MessageRepository", _Messages)
    monkeypatch.setattr(module, "MessageEventRepository", _Events)
    monkeypatch.setattr(module, "CommandOutboxRepository", _Outbox)

    processor = DeliveryEventProcessor(
        _Session,
        max_attempts=4,
        retry_base_seconds=1,
        retry_max_seconds=10,
    )
    result = await processor.process(event)

    assert result.retry_scheduled is True
    assert len(enqueued) == 1
    assert enqueued[0].command_type.value == "retry"
    assert enqueued[0].expected_state == GatewayMessageState.DEFERRED
    assert message.state == "retry_scheduled"
