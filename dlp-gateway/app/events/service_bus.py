"""Synchronous Azure Service Bus adapter for the AWS gateway worker."""

from __future__ import annotations

import json
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.servicebus import (
    ServiceBusClient,
    ServiceBusMessage,
    ServiceBusReceiveMode,
)

from app.domain.models import (
    CaptureEvent,
    CommandAckEvent,
    DeliveryEvent,
    GatewayCommand,
)


class AzureServiceBusEventBus:
    """Gateway sends capture/delivery events and receives commands."""

    def __init__(
        self,
        *,
        capture_queue_name: str,
        command_queue_name: str,
        delivery_queue_name: str,
        command_ack_queue_name: str,
        connection_string: str = "",
        fully_qualified_namespace: str = "",
    ) -> None:
        if not connection_string and not fully_qualified_namespace:
            raise ValueError(
                "A Service Bus connection string or namespace is required"
            )
        self._credential: DefaultAzureCredential | None = None
        if connection_string:
            self._client = ServiceBusClient.from_connection_string(
                connection_string
            )
        else:
            self._credential = DefaultAzureCredential()
            self._client = ServiceBusClient(
                fully_qualified_namespace,
                credential=self._credential,
            )
        self._capture_sender = self._client.get_queue_sender(
            queue_name=capture_queue_name
        )
        self._delivery_sender = self._client.get_queue_sender(
            queue_name=delivery_queue_name
        )
        self._command_ack_sender = self._client.get_queue_sender(
            queue_name=command_ack_queue_name
        )
        self._command_receiver = self._client.get_queue_receiver(
            queue_name=command_queue_name,
            receive_mode=ServiceBusReceiveMode.PEEK_LOCK,
        )
        self._capture_sender.__enter__()
        self._delivery_sender.__enter__()
        self._command_ack_sender.__enter__()
        self._command_receiver.__enter__()
        self._inflight_commands: dict[str, Any] = {}

    def publish_capture(self, event: CaptureEvent) -> None:
        self._capture_sender.send_messages(
            ServiceBusMessage(
                event.model_dump_json(),
                message_id=str(event.message_id),
                content_type="application/json",
                subject=event.event_type,
            )
        )

    def publish_delivery(self, event: DeliveryEvent) -> None:
        self._delivery_sender.send_messages(
            ServiceBusMessage(
                event.model_dump_json(),
                message_id=str(event.event_id),
                correlation_id=str(event.message_id),
                content_type="application/json",
                subject=event.event_type,
            )
        )

    def publish_command_ack(self, event: CommandAckEvent) -> None:
        self._command_ack_sender.send_messages(
            ServiceBusMessage(
                event.model_dump_json(),
                message_id=str(event.event_id),
                correlation_id=str(event.command_id),
                content_type="application/json",
                subject=event.event_type,
            )
        )

    def publish_command(self, command: GatewayCommand) -> None:
        raise RuntimeError(
            "Gateway Service Bus mode does not publish commands; "
            "FORCE_ALLOW must remain disabled"
        )

    def consume_commands(
        self, max_items: int = 10
    ) -> list[GatewayCommand]:
        messages = self._command_receiver.receive_messages(
            max_message_count=max_items,
            max_wait_time=1,
        )
        commands: list[GatewayCommand] = []
        for message in messages:
            try:
                payload = json.loads(str(message))
                command = GatewayCommand.model_validate(payload)
            except Exception as exc:
                self._command_receiver.dead_letter_message(
                    message,
                    reason="InvalidGatewayCommand",
                    error_description=str(exc)[:4096],
                )
                continue
            self._inflight_commands[str(command.command_id)] = message
            commands.append(command)
        return commands

    def ack_command(self, command: GatewayCommand) -> None:
        message = self._take_command(command)
        self._command_receiver.complete_message(message)

    def retry_command(self, command: GatewayCommand) -> None:
        message = self._take_command(command)
        self._command_receiver.abandon_message(message)

    def dead_letter_command(
        self, command: GatewayCommand, reason: str
    ) -> None:
        message = self._take_command(command)
        self._command_receiver.dead_letter_message(
            message,
            reason="GatewayCommandRejected",
            error_description=reason[:4096],
        )

    def consume_captures(
        self, max_items: int = 10
    ) -> list[CaptureEvent]:
        # FORCE_ALLOW is filesystem-only; production backend consumes captures.
        return []

    def ack_capture(self, event: CaptureEvent) -> None:
        raise RuntimeError("Gateway does not consume Service Bus captures")

    def recover_stale(
        self, kind: str, stale_after_seconds: int
    ) -> int:
        # Peek-lock expiry provides Service Bus redelivery.
        return 0

    def close(self) -> None:
        self._command_receiver.__exit__(None, None, None)
        self._command_ack_sender.__exit__(None, None, None)
        self._delivery_sender.__exit__(None, None, None)
        self._capture_sender.__exit__(None, None, None)
        self._client.close()
        if self._credential is not None:
            self._credential.close()

    def _take_command(self, command: GatewayCommand) -> Any:
        try:
            return self._inflight_commands.pop(str(command.command_id))
        except KeyError as exc:
            raise RuntimeError(
                f"Command is not in flight: {command.command_id}"
            ) from exc
