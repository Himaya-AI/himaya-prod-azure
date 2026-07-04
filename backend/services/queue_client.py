"""
Cloud-agnostic queue abstraction — Azure Service Bus implementation.

Falls back to SQS if AWS_* env vars are still present for gradual migration,
but defaults to Azure Service Bus when AZURE_SERVICE_BUS_NAMESPACE is set.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


class QueueClient:
    """Send/receive messages with Azure Service Bus (or SQS fallback)."""

    def __init__(self) -> None:
        self._sb_client: Optional[object] = None
        self._sb_namespace: Optional[str] = None
        self._sqs_client: Optional[object] = None
        self._provider: str = "none"

    async def _init_service_bus(self) -> None:
        if self._sb_client is not None:
            return
        try:
            from azure.identity.aio import DefaultAzureCredential
            from azure.servicebus.aio import ServiceBusClient

            namespace = os.getenv("AZURE_SERVICE_BUS_NAMESPACE")
            if not namespace:
                raise RuntimeError("AZURE_SERVICE_BUS_NAMESPACE not set")

            self._sb_namespace = namespace
            credential = DefaultAzureCredential()
            self._sb_client = ServiceBusClient(
                fully_qualified_namespace=f"{namespace}.servicebus.windows.net",
                credential=credential,
            )
            self._provider = "azure"
            logger.info(f"Azure Service Bus client initialized: {namespace}")
        except Exception as exc:
            logger.warning(f"Service Bus init failed: {exc}")
            self._sb_client = None

    async def _init_sqs(self) -> None:
        if self._sqs_client is not None:
            return
        try:
            import boto3

            region = os.getenv("AWS_REGION", "us-east-1")
            self._sqs_client = boto3.client("sqs", region_name=region)
            self._provider = "sqs"
            logger.info(f"SQS fallback client initialized: {region}")
        except Exception as exc:
            logger.warning(f"SQS fallback init failed: {exc}")
            self._sqs_client = None

    async def _ensure_client(self) -> None:
        if self._provider in ("azure", "sqs"):
            return
        await self._init_service_bus()
        if self._provider == "azure":
            return
        await self._init_sqs()

    async def send_message(self, queue_name: str, body: dict[str, Any]) -> None:
        """Send a JSON message to a queue."""
        await self._ensure_client()
        message_body = json.dumps(body, default=str)

        if self._provider == "azure":
            from azure.servicebus import ServiceBusMessage

            sender = self._sb_client.get_queue_sender(queue_name=queue_name)
            async with sender:
                await sender.send_messages(ServiceBusMessage(body=message_body))
            return

        if self._provider == "sqs" and self._sqs_client:
            queue_url = await self._get_queue_url(queue_name)
            self._sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_body)
            return

        raise RuntimeError("No queue provider available")

    async def receive_messages(
        self,
        queue_name: str,
        max_messages: int = 10,
        wait_time: int = 20,
    ) -> list[dict[str, Any]]:
        """Receive messages from a queue. Returns list of {id, body, delete_callback}."""
        await self._ensure_client()

        result: list[dict[str, Any]] = []

        if self._provider == "azure":
            from azure.servicebus import AutoLockRenewer

            receiver = self._sb_client.get_queue_receiver(
                queue_name=queue_name,
                max_wait_time=wait_time,
            )
            async with receiver:
                messages = await receiver.receive_messages(max_message_count=max_messages, max_wait_time=wait_time)
                for msg in messages:
                    try:
                        body = json.loads(str(msg))
                    except json.JSONDecodeError:
                        body = {"raw": str(msg)}
                    result.append({
                        "id": msg.message_id,
                        "body": body,
                        "delete_callback": lambda m=msg, r=receiver: r.complete_message(m),
                    })
            return result

        if self._provider == "sqs" and self._sqs_client:
            queue_url = await self._get_queue_url(queue_name)
            response = self._sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=max_messages,
                WaitTimeSeconds=wait_time,
            )
            for msg in response.get("Messages", []):
                try:
                    body = json.loads(msg["Body"])
                except json.JSONDecodeError:
                    body = {"raw": msg["Body"]}
                result.append({
                    "id": msg["ReceiptHandle"],
                    "body": body,
                    "delete_callback": lambda h=msg["ReceiptHandle"]: self._sqs_client.delete_message(
                        QueueUrl=queue_url, ReceiptHandle=h
                    ),
                })
            return result

        raise RuntimeError("No queue provider available")

    async def _get_queue_url(self, queue_name: str) -> str:
        # SQS queue URLs are resolved once per queue name and cached.
        if not hasattr(self, "_queue_url_cache"):
            self._queue_url_cache = {}
        if queue_name not in self._queue_url_cache:
            self._queue_url_cache[queue_name] = self._sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        return self._queue_url_cache[queue_name]

    async def close(self) -> None:
        if self._sb_client:
            await self._sb_client.close()


# Singleton instance
queue_client = QueueClient()
