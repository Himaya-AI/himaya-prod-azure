"""
Queue client: Azure Service Bus first, SQS if Service Bus is not configured.

Public API:
    await queue_client.send_message(queue_name, body)
    messages = await queue_client.receive_messages(queue_name)
    await message.complete()
    await queue_client.close()
"""
from __future__ import annotations

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from azure.identity.aio import DefaultAzureCredential
from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import AutoLockRenewer, ServiceBusClient, ServiceBusReceiver, ServiceBusSender

from backend.utils.helper import parse_json_body, to_json

logger = logging.getLogger(__name__)

# Cover process_email (10–45s) plus retries. Default Service Bus lock is 30s.
_LOCK_RENEW_SECONDS = 300


@dataclass
class QueueMessage:
    """One peeked message. Call complete() after it is processed successfully."""

    id: str
    body: dict[str, Any]
    _complete: Callable[[], Awaitable[None]] = field(repr=False)

    async def complete(self) -> None:
        await self._complete()


def _make_azure_complete(receiver: Any, msg: Any) -> Callable[[], Awaitable[None]]:
    async def _complete() -> None:
        await receiver.complete_message(msg)

    return _complete


def _make_sqs_complete(client: Any, queue_url: str, receipt_handle: str) -> Callable[[], Awaitable[None]]:
    async def _complete() -> None:
        await asyncio.to_thread(
            client.delete_message,
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
        )

    return _complete


class QueueBackend(ABC):
    """One cloud queue implementation."""

    @abstractmethod
    async def send(self, queue_name: str, payload: str, message_id: Optional[str] = None) -> None:
        ...

    @abstractmethod
    async def receive(
        self,
        queue_name: str,
        max_messages: int,
        wait_time: int,
    ) -> list[QueueMessage]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...


class AzureServiceBus(QueueBackend):
    def __init__(self, namespace: str) -> None:
        self._namespace = namespace
        self._credential: Optional[DefaultAzureCredential] = None
        self._client: Optional[ServiceBusClient] = None
        self._renewer: Optional[AutoLockRenewer] = None
        self._senders: dict[str, ServiceBusSender] = {}
        self._receivers: dict[str, ServiceBusReceiver] = {}

    async def connect(self) -> None:
        self._credential = DefaultAzureCredential()
        self._client = ServiceBusClient(
            fully_qualified_namespace=f"{self._namespace}.servicebus.windows.net",
            credential=self._credential,
        )
        self._renewer = AutoLockRenewer(max_lock_renewal_duration=_LOCK_RENEW_SECONDS)
        logger.info("Azure Service Bus client initialized: %s", self._namespace)

    async def send(self, queue_name: str, payload: str, message_id: Optional[str] = None) -> None:
        sender = await self._get_sender(queue_name)
        message = (
            ServiceBusMessage(body=payload, message_id=message_id)
            if message_id
            else ServiceBusMessage(body=payload)
        )
        await sender.send_messages(message)

    async def receive(
        self,
        queue_name: str,
        max_messages: int,
        wait_time: int,
    ) -> list[QueueMessage]:
        receiver = await self._get_receiver(queue_name)
        raw_messages = await receiver.receive_messages(
            max_message_count=max_messages,
            max_wait_time=wait_time,
        )
        return [
            QueueMessage(
                id=msg.message_id or "",
                body=parse_json_body(str(msg)),
                _complete=_make_azure_complete(receiver, msg),
            )
            for msg in raw_messages
        ]

    async def close(self) -> None:
        for sender in self._senders.values():
            await sender.close()
        self._senders.clear()
        for receiver in self._receivers.values():
            await receiver.close()
        self._receivers.clear()
        if self._renewer is not None:
            await self._renewer.close()
            self._renewer = None
        if self._client is not None:
            await self._client.close()
            self._client = None
        if self._credential is not None:
            await self._credential.close()
            self._credential = None

    async def _get_sender(self, queue_name: str) -> ServiceBusSender:
        sender = self._senders.get(queue_name)
        if sender is None:
            if self._client is None:
                raise RuntimeError("Service Bus client is not connected")
            sender = self._client.get_queue_sender(queue_name=queue_name)
            await sender.__aenter__()
            self._senders[queue_name] = sender
        return sender

    async def _get_receiver(self, queue_name: str) -> ServiceBusReceiver:
        receiver = self._receivers.get(queue_name)
        if receiver is None:
            if self._client is None or self._renewer is None:
                raise RuntimeError("Service Bus client is not connected")
            receiver = self._client.get_queue_receiver(
                queue_name=queue_name,
                auto_lock_renewer=self._renewer,
            )
            await receiver.__aenter__()
            self._receivers[queue_name] = receiver
        return receiver


class SqsBackend(QueueBackend):
    def __init__(self, region: str) -> None:
        self._client = boto3.client("sqs", region_name=region)
        self._queue_urls: dict[str, str] = {}
        logger.info("SQS fallback client initialized: %s", region)

    async def send(self, queue_name: str, payload: str, message_id: Optional[str] = None) -> None:
        queue_url = await self._queue_url(queue_name)
        kwargs: dict[str, Any] = {"QueueUrl": queue_url, "MessageBody": payload}
        if message_id and queue_url.endswith(".fifo"):
            kwargs["MessageDeduplicationId"] = message_id
            kwargs["MessageGroupId"] = "email-scan"
        await asyncio.to_thread(self._client.send_message, **kwargs)

    async def receive(
        self,
        queue_name: str,
        max_messages: int,
        wait_time: int,
    ) -> list[QueueMessage]:
        queue_url = await self._queue_url(queue_name)
        response = await asyncio.to_thread(
            self._client.receive_message,
            QueueUrl=queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=wait_time,
        )
        result: list[QueueMessage] = []
        for msg in response.get("Messages", []):
            handle = msg["ReceiptHandle"]
            result.append(
                QueueMessage(
                    id=handle,
                    body=parse_json_body(msg.get("Body", "")),
                    _complete=_make_sqs_complete(self._client, queue_url, handle),
                )
            )
        return result

    async def close(self) -> None:
        return

    async def _queue_url(self, queue_name: str) -> str:
        cached = self._queue_urls.get(queue_name)
        if cached is not None:
            return cached
        response = await asyncio.to_thread(self._client.get_queue_url, QueueName=queue_name)
        url = response["QueueUrl"]
        self._queue_urls[queue_name] = url
        return url


async def _connect_backend() -> QueueBackend:
    namespace = os.getenv("AZURE_SERVICE_BUS_NAMESPACE")
    if namespace:
        azure = AzureServiceBus(namespace)
        try:
            await azure.connect()
            return azure
        except Exception as exc:
            logger.warning("Service Bus init failed: %s", exc)
            await azure.close()

    try:
        region = os.getenv("AWS_REGION", "us-east-1")
        return SqsBackend(region)
    except Exception as exc:
        logger.warning("SQS fallback init failed: %s", exc)

    raise RuntimeError("No queue provider available")


class QueueClient:
    """Facade used by the rest of the app. Picks Azure or SQS on first use."""

    def __init__(self) -> None:
        self._backend: Optional[QueueBackend] = None

    async def send_message(
        self,
        queue_name: str,
        body: dict,
        message_id: Optional[str] = None,
    ) -> None:
        backend = await self._get_backend()
        await backend.send(queue_name, to_json(body), message_id=message_id)

    async def receive_messages(
        self,
        queue_name: str,
        max_messages: int = 10,
        wait_time: int = 20,
    ) -> list[QueueMessage]:
        backend = await self._get_backend()
        return await backend.receive(queue_name, max_messages, wait_time)

    async def close(self) -> None:
        if self._backend is not None:
            await self._backend.close()
            self._backend = None

    async def _get_backend(self) -> QueueBackend:
        if self._backend is None:
            self._backend = await _connect_backend()
        return self._backend


queue_client = QueueClient()
