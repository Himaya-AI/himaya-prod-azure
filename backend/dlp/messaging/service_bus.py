"""Azure Service Bus adapter for production DLP messaging."""

from __future__ import annotations

import json
from typing import Any

from azure.identity.aio import DefaultAzureCredential
from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient

from backend.dlp.contracts import CaptureEvent, GatewayCommand
from backend.dlp.messaging.ports import ReceivedCapture


class AzureServiceBusDlpMessageBus:
    def __init__(
        self,
        *,
        capture_queue_name: str,
        command_queue_name: str,
        connection_string: str = "",
        fully_qualified_namespace: str = "",
    ) -> None:
        if not connection_string and not fully_qualified_namespace:
            raise ValueError(
                "A Service Bus connection string or namespace is required"
            )
        self.capture_queue_name = capture_queue_name
        self.command_queue_name = command_queue_name
        self.connection_string = connection_string
        self.fully_qualified_namespace = fully_qualified_namespace
        self._credential: DefaultAzureCredential | None = None
        self._client: ServiceBusClient | None = None
        self._receiver: Any = None
        self._sender: Any = None

    async def connect(self) -> None:
        if self._client is not None:
            return
        if self.connection_string:
            client = ServiceBusClient.from_connection_string(
                self.connection_string
            )
        else:
            self._credential = DefaultAzureCredential()
            client = ServiceBusClient(
                self.fully_qualified_namespace,
                credential=self._credential,
            )
        self._client = client
        self._receiver = client.get_queue_receiver(
            queue_name=self.capture_queue_name
        )
        self._sender = client.get_queue_sender(
            queue_name=self.command_queue_name
        )
        await self._receiver.__aenter__()
        await self._sender.__aenter__()

    async def receive_captures(
        self, max_messages: int = 10, wait_seconds: int = 5
    ) -> list[ReceivedCapture]:
        self._require_connected()
        messages = await self._receiver.receive_messages(
            max_message_count=max_messages,
            max_wait_time=wait_seconds,
        )
        received: list[ReceivedCapture] = []
        for message in messages:
            try:
                payload = json.loads(str(message))
                event = CaptureEvent.model_validate(payload)
            except Exception as exc:
                await self._receiver.dead_letter_message(
                    message,
                    reason="InvalidCaptureEvent",
                    error_description=str(exc)[:4096],
                )
                continue
            received.append(ReceivedCapture(event=event, receipt=message))
        return received

    async def complete_capture(self, receipt: Any) -> None:
        self._require_connected()
        await self._receiver.complete_message(receipt)

    async def abandon_capture(self, receipt: Any) -> None:
        self._require_connected()
        await self._receiver.abandon_message(receipt)

    async def dead_letter_capture(
        self, receipt: Any, reason: str
    ) -> None:
        self._require_connected()
        await self._receiver.dead_letter_message(
            receipt,
            reason="DlpProcessingRejected",
            error_description=reason[:4096],
        )

    async def publish_command(self, command: GatewayCommand) -> None:
        self._require_connected()
        message = ServiceBusMessage(
            command.model_dump_json(),
            message_id=str(command.command_id),
            content_type="application/json",
            subject=f"dlp.command.{command.command_type.value}.v1",
        )
        await self._sender.send_messages(message)

    async def recover_stale(self) -> int:
        # Service Bus automatically redelivers messages whose locks expire.
        return 0

    async def close(self) -> None:
        if self._sender is not None:
            await self._sender.__aexit__(None, None, None)
        if self._receiver is not None:
            await self._receiver.__aexit__(None, None, None)
        if self._client is not None:
            await self._client.close()
        if self._credential is not None:
            await self._credential.close()
        self._sender = None
        self._receiver = None
        self._client = None
        self._credential = None

    def _require_connected(self) -> None:
        if (
            self._client is None
            or self._receiver is None
            or self._sender is None
        ):
            raise RuntimeError("Service Bus adapter is not connected")
