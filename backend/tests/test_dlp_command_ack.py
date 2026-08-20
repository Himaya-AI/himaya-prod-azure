from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from backend.dlp.application.command_ack_processor import (
    CommandAckMessageNotReady,
    CommandAckProcessor,
    CommandAckRejected,
)
from backend.dlp.api.message_views import project_command_status
from backend.dlp.contracts import (
    CommandAckEvent,
    CommandAckStatus,
    CommandType,
    GatewayMessageState,
)
from backend.dlp.messaging.ports import ReceivedCommandAck
from backend.dlp.workers.command_ack_consumer import CommandAckConsumer


def _ack(
    *,
    command_type: CommandType = CommandType.STOP,
    org_id: str | None = None,
    message_id=None,
) -> CommandAckEvent:
    return CommandAckEvent(
        event_id=uuid4(),
        command_id=uuid4(),
        message_id=message_id or uuid4(),
        org_id=org_id or str(uuid4()),
        command_type=command_type,
        status=CommandAckStatus.APPLIED,
        resulting_state=GatewayMessageState.STOPPED,
        occurred_at=datetime.now(timezone.utc),
    )


class _Bus:
    def __init__(self, event: CommandAckEvent) -> None:
        self.ack = ReceivedCommandAck(event=event, receipt="receipt")
        self.completed = False
        self.abandoned = False

    async def receive_command_acks(self, **_kwargs):
        return [self.ack]

    async def complete_command_ack(self, _receipt) -> None:
        self.completed = True

    async def abandon_command_ack(self, _receipt) -> None:
        self.abandoned = True

    async def dead_letter_command_ack(self, _receipt, _reason) -> None:
        raise AssertionError("event should not be dead-lettered")


def _session_factory(message):
    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def commit(self):
            return None

    return _Session


@pytest.mark.asyncio
async def test_stop_ack_sets_message_stopped(monkeypatch) -> None:
    org_id = uuid4()
    message = SimpleNamespace(org_id=org_id, state="stop_requested")
    event = _ack(org_id=str(org_id), message_id=uuid4())
    recorded = []

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

        async def record_command_ack(self, ack):
            recorded.append(ack)
            return True

    import backend.dlp.application.command_ack_processor as module

    monkeypatch.setattr(module, "MessageRepository", _Messages)
    monkeypatch.setattr(module, "MessageEventRepository", _Events)

    result = await CommandAckProcessor(_session_factory(message)).process(
        event
    )
    assert result.inserted is True
    assert result.stopped is True
    assert message.state == "stopped"
    assert recorded == [event]


@pytest.mark.asyncio
async def test_allow_ack_does_not_change_state(monkeypatch) -> None:
    org_id = uuid4()
    message = SimpleNamespace(org_id=org_id, state="decided")
    event = _ack(
        command_type=CommandType.ALLOW,
        org_id=str(org_id),
    )
    event = event.model_copy(
        update={"resulting_state": GatewayMessageState.PROVIDER_ACCEPTED}
    )

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

        async def record_command_ack(self, _ack):
            return True

    import backend.dlp.application.command_ack_processor as module

    monkeypatch.setattr(module, "MessageRepository", _Messages)
    monkeypatch.setattr(module, "MessageEventRepository", _Events)

    result = await CommandAckProcessor(_session_factory(message)).process(
        event
    )
    assert result.stopped is False
    assert message.state == "decided"


@pytest.mark.asyncio
async def test_command_ack_not_ready_when_message_missing(
    monkeypatch,
) -> None:
    class _Messages:
        def __init__(self, _session):
            pass

        async def get(self, _message_id):
            return None

    class _Events:
        def __init__(self, _session):
            pass

    import backend.dlp.application.command_ack_processor as module

    monkeypatch.setattr(module, "MessageRepository", _Messages)
    monkeypatch.setattr(module, "MessageEventRepository", _Events)

    with pytest.raises(CommandAckMessageNotReady):
        await CommandAckProcessor(_session_factory(None)).process(_ack())


@pytest.mark.asyncio
async def test_command_ack_rejects_tenant_mismatch(monkeypatch) -> None:
    message = SimpleNamespace(org_id=uuid4(), state="decided")

    class _Messages:
        def __init__(self, _session):
            pass

        async def get(self, _message_id):
            return message

    class _Events:
        def __init__(self, _session):
            pass

    import backend.dlp.application.command_ack_processor as module

    monkeypatch.setattr(module, "MessageRepository", _Messages)
    monkeypatch.setattr(module, "MessageEventRepository", _Events)

    with pytest.raises(CommandAckRejected, match="tenant"):
        await CommandAckProcessor(_session_factory(message)).process(_ack())


@pytest.mark.asyncio
async def test_command_ack_consumer_completes_after_processing() -> None:
    event = _ack()
    bus = _Bus(event)

    class _Processor:
        async def process(self, received):
            assert received == event
            return SimpleNamespace(inserted=True, stopped=True)

    consumer = CommandAckConsumer(
        bus, _Processor(), retry_delay_seconds=0  # type: ignore[arg-type]
    )
    assert await consumer.run_once() == 1
    assert bus.completed is True
    assert bus.abandoned is False


def test_project_command_status_maps_outbox_and_ack() -> None:
    command_id = uuid4()
    row = SimpleNamespace(
        id=command_id,
        command_type="stop",
        status="published",
        attempts=1,
        last_error=None,
        created_at=datetime.now(timezone.utc),
        published_at=datetime.now(timezone.utc),
    )
    event = SimpleNamespace(
        payload={
            "command_id": str(command_id),
            "status": "applied",
        }
    )
    projected = project_command_status([row], [event])
    assert projected == [
        {
            "command_id": command_id,
            "command_type": "stop",
            "status": "sent",
            "attempts": 1,
            "last_error": None,
            "created_at": row.created_at,
            "published_at": row.published_at,
            "gateway_status": "applied",
        }
    ]
