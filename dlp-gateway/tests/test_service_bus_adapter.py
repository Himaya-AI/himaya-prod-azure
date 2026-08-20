from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from app.domain.models import (
    CommandType,
    DeliveryEvent,
    DeliveryOutcome,
    GatewayCommand,
    MessageState,
)
from app.events.service_bus import AzureServiceBusEventBus


class _Sender:
    def __init__(self) -> None:
        self.sent = []

    def send_messages(self, message) -> None:
        self.sent.append(message)


class _Received:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __str__(self) -> str:
        return json.dumps(self.payload)


class _Receiver:
    def __init__(self, messages) -> None:
        self.messages = messages
        self.completed = []

    def receive_messages(self, **_kwargs):
        return self.messages

    def complete_message(self, message) -> None:
        self.completed.append(message)

    def abandon_message(self, _message) -> None:
        return None

    def dead_letter_message(self, _message, **_kwargs) -> None:
        return None


def test_service_bus_startup_uses_least_privilege_queues(
    monkeypatch,
) -> None:
    class _Context:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class _Client:
        def __init__(self) -> None:
            self.senders = []
            self.receivers = []

        def get_queue_sender(self, *, queue_name):
            self.senders.append(queue_name)
            return _Context()

        def get_queue_receiver(self, *, queue_name, **_kwargs):
            self.receivers.append(queue_name)
            return _Context()

        def close(self):
            return None

    client = _Client()
    monkeypatch.setattr(
        "app.events.service_bus.ServiceBusClient.from_connection_string",
        lambda _connection_string: client,
    )

    bus = AzureServiceBusEventBus(
        capture_queue_name="capture",
        command_queue_name="commands",
        delivery_queue_name="delivery",
        command_ack_queue_name="command-acks",
        connection_string="Endpoint=sb://test/",
    )
    assert client.senders == ["capture", "delivery", "command-acks"]
    assert client.receivers == ["commands"]
    bus.close()


def test_service_bus_publishes_delivery_with_event_identity() -> None:
    bus = AzureServiceBusEventBus.__new__(AzureServiceBusEventBus)
    bus._delivery_sender = _Sender()  # type: ignore[attr-defined]
    event = DeliveryEvent(
        message_id=uuid4(),
        org_id=str(uuid4()),
        provider="m365",
        provider_deployment_id=str(uuid4()),
        attempt_id=uuid4(),
        attempt_number=1,
        outcome=DeliveryOutcome.ACCEPTED,
        resulting_state=MessageState.PROVIDER_ACCEPTED,
        occurred_at=datetime.now(timezone.utc),
    )

    bus.publish_delivery(event)

    sent = bus._delivery_sender.sent[0]  # type: ignore[attr-defined]
    assert sent.message_id == str(event.event_id)
    assert sent.correlation_id == str(event.message_id)
    assert sent.subject == event.event_type


def test_service_bus_command_is_settled_by_command_id() -> None:
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=uuid4(),
        org_id=str(uuid4()),
    )
    received = _Received(command.model_dump(mode="json"))
    receiver = _Receiver([received])
    bus = AzureServiceBusEventBus.__new__(AzureServiceBusEventBus)
    bus._command_receiver = receiver  # type: ignore[attr-defined]
    bus._inflight_commands = {}  # type: ignore[attr-defined]

    assert bus.consume_commands() == [command]
    bus.ack_command(command)
    assert receiver.completed == [received]
