from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from backend.dlp.contracts import CaptureEvent, CommandType, GatewayCommand
from backend.dlp.messaging.filesystem_bus import FilesystemDlpMessageBus
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
