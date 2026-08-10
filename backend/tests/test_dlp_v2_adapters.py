from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from backend.dlp.contracts import (
    CaptureEvent,
    CommandType,
    DeliveryEvent,
    DeliveryOutcome,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.messaging.filesystem_bus import FilesystemDlpMessageBus
from backend.dlp.messaging.service_bus import AzureServiceBusDlpMessageBus
from backend.dlp.storage.azure_mime_store import (
    AzureBlobMimeStore,
    MimeStorageError,
)

AZURITE_CONNECTION_STRING = (
    "DefaultEndpointsProtocol=http;"
    "AccountName=devstoreaccount1;"
    "AccountKey="
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsu"
    "Fq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://azurite:10000/devstoreaccount1;"
)


def _capture_event() -> CaptureEvent:
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
        mime_size=123,
        blob_uri=(
            "http://azurite:10000/devstoreaccount1/dlp-mime/"
            f"org/{message_id}/{'a' * 64}.eml"
        ),
        received_at=now,
        occurred_at=now,
    )


def _delivery_event(message_id=None, org_id=None) -> DeliveryEvent:
    return DeliveryEvent(
        event_id=uuid4(),
        message_id=message_id or uuid4(),
        org_id=org_id or str(uuid4()),
        provider="local",
        provider_deployment_id=str(uuid4()),
        attempt_id=uuid4(),
        attempt_number=1,
        outcome=DeliveryOutcome.ACCEPTED,
        resulting_state=GatewayMessageState.PROVIDER_ACCEPTED,
        smtp_code=250,
        accepted_recipients=["bob@external.test"],
        occurred_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_filesystem_bus_settles_capture_and_publishes_command(
    tmp_path: Path,
) -> None:
    bus = FilesystemDlpMessageBus(tmp_path)
    event = _capture_event()
    ready = tmp_path / "captures" / "ready" / "capture.json"
    ready.write_text(event.model_dump_json(), encoding="utf-8")

    received = await bus.receive_captures(
        max_messages=1, wait_seconds=0
    )
    assert received[0].event == event
    await bus.complete_capture(received[0].receipt)
    assert (tmp_path / "captures" / "done" / "capture.json").exists()

    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=event.message_id,
        org_id=event.org_id,
    )
    await bus.publish_command(command)
    command_file = next((tmp_path / "commands" / "ready").glob("*.json"))
    assert json.loads(command_file.read_text())["command_id"] == str(
        command.command_id
    )


@pytest.mark.asyncio
async def test_filesystem_bus_recovers_stale_capture(tmp_path: Path) -> None:
    bus = FilesystemDlpMessageBus(
        tmp_path, reclaim_after_seconds=30
    )
    event = _capture_event()
    ready = tmp_path / "captures" / "ready" / "capture.json"
    ready.write_text(event.model_dump_json(), encoding="utf-8")
    received = await bus.receive_captures(
        max_messages=1, wait_seconds=0
    )
    processing = (
        tmp_path / "captures" / "processing" / received[0].receipt
    )
    old_time = time.time() - 60
    os.utime(processing, (old_time, old_time))

    assert await bus.recover_stale() == 1
    assert (tmp_path / "captures" / "ready" / "capture.json").exists()


@pytest.mark.asyncio
async def test_filesystem_bus_settles_delivery(tmp_path: Path) -> None:
    bus = FilesystemDlpMessageBus(tmp_path)
    event = _delivery_event()
    ready = tmp_path / "deliveries" / "ready" / "delivery.json"
    ready.write_text(event.model_dump_json(), encoding="utf-8")

    received = await bus.receive_deliveries(
        max_messages=1, wait_seconds=0
    )
    assert received[0].event == event
    await bus.complete_delivery(received[0].receipt)
    assert (
        tmp_path / "deliveries" / "done" / "delivery.json"
    ).exists()


@pytest.mark.asyncio
async def test_service_bus_receives_and_settles_delivery() -> None:
    event = _delivery_event()

    class _Message:
        def __str__(self) -> str:
            return event.model_dump_json()

    message = _Message()

    class _Receiver:
        def __init__(self) -> None:
            self.completed = []

        async def receive_messages(self, **_kwargs):
            return [message]

        async def complete_message(self, receipt):
            self.completed.append(receipt)

        async def dead_letter_message(self, *_args, **_kwargs):
            raise AssertionError("valid event must not dead-letter")

    receiver = _Receiver()
    bus = AzureServiceBusDlpMessageBus.__new__(
        AzureServiceBusDlpMessageBus
    )
    bus._client = object()  # type: ignore[attr-defined]
    bus._receiver = object()  # type: ignore[attr-defined]
    bus._delivery_receiver = receiver  # type: ignore[attr-defined]
    bus._sender = object()  # type: ignore[attr-defined]

    deliveries = await bus.receive_deliveries(
        max_messages=1, wait_seconds=0
    )
    assert deliveries[0].event == event
    await bus.complete_delivery(deliveries[0].receipt)
    assert receiver.completed == [message]


def test_blob_store_accepts_only_configured_host_and_container() -> None:
    store = AzureBlobMimeStore(
        container="dlp-mime",
        connection_string=AZURITE_CONNECTION_STRING,
    )
    reference = store._parse_blob_reference(  # noqa: SLF001
        "http://azurite:10000/devstoreaccount1/dlp-mime/org/mail.eml"
    )

    assert reference.container == "dlp-mime"
    assert reference.blob_name == "org/mail.eml"

    with pytest.raises(MimeStorageError, match="host"):
        store._parse_blob_reference(  # noqa: SLF001
            "https://attacker.test/dlp-mime/org/mail.eml"
        )
    with pytest.raises(MimeStorageError, match="container"):
        store._parse_blob_reference(  # noqa: SLF001
            "http://azurite:10000/devstoreaccount1/other/mail.eml"
        )
