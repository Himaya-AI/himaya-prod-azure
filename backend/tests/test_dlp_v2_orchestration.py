from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from backend.dlp.application.message_orchestrator import (
    MessageProcessingResult,
    _gateway_command,
)
from backend.dlp.contracts import CaptureEvent, CommandType
from backend.dlp.messaging.ports import ReceivedCapture
from backend.dlp.persistence.models import DlpCommandOutbox
from backend.dlp.persistence.repositories import (
    CommandOutboxRepository,
)
from backend.dlp.policy import PolicyAction, PolicyDecision
from backend.dlp.workers.capture_consumer import CaptureConsumer


def _event() -> CaptureEvent:
    now = datetime.now(timezone.utc)
    message_id = uuid4()
    return CaptureEvent(
        message_id=message_id,
        org_id=str(uuid4()),
        provider="local",
        provider_deployment_id=str(uuid4()),
        envelope_from="alice@example.test",
        envelope_to=["bob@external.test"],
        mime_sha256="a" * 64,
        mime_size=10,
        blob_uri="http://azurite/dlp-mime/mail.eml",
        received_at=now,
        occurred_at=now,
    )


def _decision(action: PolicyAction) -> PolicyDecision:
    return PolicyDecision(
        policy_version="test-v1",
        intended_action=action,
        effective_action=action,
        matched_rule_ids=(),
        finding_references=(),
        explanation="test",
        evaluation_latency_ms=1,
    )


def test_gateway_command_id_is_deterministic() -> None:
    event = _event()

    first = _gateway_command(event, _decision(PolicyAction.ALLOW))
    second = _gateway_command(event, _decision(PolicyAction.ALLOW))

    assert first is not None
    assert second is not None
    assert first.command_id == second.command_id
    assert first.command_type == CommandType.ALLOW
    assert first.expected_state.value == "captured"


def test_hold_decision_does_not_publish_gateway_command() -> None:
    assert (
        _gateway_command(_event(), _decision(PolicyAction.HOLD))
        is None
    )


class _FakeBus:
    def __init__(self, delivery: ReceivedCapture) -> None:
        self.delivery = delivery
        self.completed = []
        self.abandoned = []

    async def receive_captures(self, **kwargs):
        del kwargs
        return [self.delivery]

    async def complete_capture(self, receipt):
        self.completed.append(receipt)

    async def abandon_capture(self, receipt):
        self.abandoned.append(receipt)


class _FakeOrchestrator:
    def __init__(self, result=None, error=None) -> None:
        self.result = result
        self.error = error

    async def process(self, event):
        if self.error:
            raise self.error
        return self.result


@pytest.mark.asyncio
async def test_capture_is_completed_only_after_processing() -> None:
    event = _event()
    delivery = ReceivedCapture(event=event, receipt="receipt")
    bus = _FakeBus(delivery)
    result = MessageProcessingResult(
        message_id=event.message_id,
        intended_action=PolicyAction.ALLOW,
        effective_action=PolicyAction.ALLOW,
        command_id=uuid4(),
    )
    consumer = CaptureConsumer(
        bus,  # type: ignore[arg-type]
        _FakeOrchestrator(result=result),  # type: ignore[arg-type]
        retry_delay_seconds=0,
    )

    assert await consumer.run_once() == 1
    assert bus.completed == ["receipt"]
    assert bus.abandoned == []


@pytest.mark.asyncio
async def test_capture_is_abandoned_when_processing_fails() -> None:
    delivery = ReceivedCapture(event=_event(), receipt="receipt")
    bus = _FakeBus(delivery)
    consumer = CaptureConsumer(
        bus,  # type: ignore[arg-type]
        _FakeOrchestrator(error=RuntimeError("temporary")),  # type: ignore[arg-type]
        retry_delay_seconds=0,
    )

    assert await consumer.run_once() == 1
    assert bus.completed == []
    assert bus.abandoned == ["receipt"]


class _FlushOnlySession:
    def __init__(self) -> None:
        self.flush_count = 0

    async def flush(self) -> None:
        self.flush_count += 1


@pytest.mark.asyncio
async def test_outbox_failure_schedules_retry() -> None:
    session = _FlushOnlySession()
    repository = CommandOutboxRepository(session)  # type: ignore[arg-type]
    row = DlpCommandOutbox(
        id=uuid4(),
        message_id=uuid4(),
        org_id=uuid4(),
        command_type="allow",
        payload={},
        status="pending",
        attempts=0,
        available_at=datetime.now(timezone.utc),
    )
    before = row.available_at

    await repository.mark_failed(
        row, "offline", retry_delay_seconds=30
    )

    assert row.attempts == 1
    assert row.status == "pending"
    assert row.available_at > before
    assert row.last_error == "offline"
    assert session.flush_count == 1
