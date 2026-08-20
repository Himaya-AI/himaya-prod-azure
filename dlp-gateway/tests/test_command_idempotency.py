from __future__ import annotations

import os
import time
from pathlib import Path
from uuid import uuid4

import pytest

from app.commands.processor import (
    CommandProcessingStatus,
    CommandProcessor,
    CommandNotReadyError,
    CommandRejectedError,
)
from app.commands.consumer import CommandConsumer
from app.domain.models import (
    CommandType,
    GatewayCommand,
    MessageState,
    SpoolRecord,
)
from app.events.bus import FilesystemEventBus
from app.events.delivery_worker import DeliveryEventPublisherWorker
from app.events.publisher import EventPublisher
from app.spool.mta_spool import FilesystemSpoolStore, sha256_hex


class _AcceptingRelay:
    def __init__(self, spool: FilesystemSpoolStore) -> None:
        self.spool = spool
        self.calls = 0

    def relay_message(
        self, message_id: str, command_id: str | None = None
    ):
        self.calls += 1
        self.spool.update_state(
            message_id, MessageState.PROVIDER_ACCEPTED.value
        )
        if command_id is not None:
            self.spool.record_command_processed(message_id, command_id)


def _captured_message(
    tmp_path: Path,
) -> tuple[FilesystemSpoolStore, SpoolRecord]:
    spool = FilesystemSpoolStore(tmp_path / "spool")
    mime = b"From: alice@example.test\r\n\r\nhello\r\n"
    record = SpoolRecord(
        org_id=str(uuid4()),
        provider="local",
        provider_deployment_id=str(uuid4()),
        session_id="session",
        envelope_from="alice@example.test",
        envelope_to=["bob@external.test"],
        mime_sha256=sha256_hex(mime),
        mime_size=len(mime),
        spool_mime_path="",
        metadata_path="",
    )
    spool.commit(record, mime)
    return spool, spool.mark_captured(
        str(record.message_id), "http://azurite/blob.eml"
    )


def test_duplicate_allow_does_not_relay_twice(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    relay = _AcceptingRelay(spool)
    processor = CommandProcessor(spool, relay)  # type: ignore[arg-type]
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=record.message_id,
        org_id=record.org_id,
        expected_state=MessageState.CAPTURED,
    )

    first = processor.process(command)
    second = processor.process(command)

    assert first == CommandProcessingStatus.APPLIED
    assert second == CommandProcessingStatus.DUPLICATE
    assert relay.calls == 1


def test_stop_is_terminal_for_later_allow(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    relay = _AcceptingRelay(spool)
    processor = CommandProcessor(spool, relay)  # type: ignore[arg-type]
    processor.process(
        GatewayCommand(
            command_type=CommandType.STOP,
            message_id=record.message_id,
            org_id=record.org_id,
            expected_state=MessageState.CAPTURED,
        )
    )

    with pytest.raises(CommandRejectedError, match="terminal"):
        processor.process(
            GatewayCommand(
                command_type=CommandType.ALLOW,
                message_id=record.message_id,
                org_id=record.org_id,
            )
        )

    assert relay.calls == 0


def test_stop_records_durable_command_ack(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    processor = CommandProcessor(
        spool, _AcceptingRelay(spool)  # type: ignore[arg-type]
    )
    command = GatewayCommand(
        command_type=CommandType.STOP,
        message_id=record.message_id,
        org_id=record.org_id,
        expected_state=MessageState.CAPTURED,
        reason="policy stop",
    )

    assert processor.process(command) == CommandProcessingStatus.APPLIED
    acks = spool.list_pending_command_acks()
    assert len(acks) == 1
    assert acks[0].command_id == command.command_id
    assert acks[0].status.value == "applied"
    assert acks[0].resulting_state == MessageState.STOPPED
    assert acks[0].event_type == "dlp.message.command.v1"

    assert processor.process(command) == CommandProcessingStatus.DUPLICATE
    assert len(spool.list_pending_command_acks()) == 1


def test_command_ack_is_published_without_relaying(
    tmp_path: Path,
) -> None:
    spool, record = _captured_message(tmp_path)
    processor = CommandProcessor(
        spool, _AcceptingRelay(spool)  # type: ignore[arg-type]
    )
    command = GatewayCommand(
        command_type=CommandType.STOP,
        message_id=record.message_id,
        org_id=record.org_id,
        expected_state=MessageState.CAPTURED,
    )
    processor.process(command)

    bus = FilesystemEventBus(tmp_path / "queues")
    worker = DeliveryEventPublisherWorker(spool, EventPublisher(bus))
    assert worker.run_once() == 1
    assert spool.list_pending_command_acks() == []
    ready = tmp_path / "queues" / "command-acks" / "ready"
    published = list(ready.glob("*.json"))
    assert len(published) == 1
    payload = published[0].read_text(encoding="utf-8")
    assert '"event_type": "dlp.message.command.v1"' in payload
    assert str(command.command_id) in payload


def test_expected_state_is_enforced(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    processor = CommandProcessor(
        spool, _AcceptingRelay(spool)  # type: ignore[arg-type]
    )

    with pytest.raises(CommandRejectedError, match="Expected held"):
        processor.process(
            GatewayCommand(
                command_type=CommandType.RELEASE,
                message_id=record.message_id,
                org_id=record.org_id,
                expected_state=MessageState.HELD,
            )
        )


def test_accepted_message_is_retryable_during_capture_race(
    tmp_path: Path,
) -> None:
    spool = FilesystemSpoolStore(tmp_path / "spool")
    mime = b"From: alice@example.test\r\n\r\nhello\r\n"
    record = SpoolRecord(
        org_id=str(uuid4()),
        provider="local",
        provider_deployment_id=str(uuid4()),
        session_id="session",
        envelope_from="alice@example.test",
        envelope_to=["bob@external.test"],
        mime_sha256=sha256_hex(mime),
        mime_size=len(mime),
        spool_mime_path="",
        metadata_path="",
    )
    spool.commit(record, mime)
    processor = CommandProcessor(
        spool, _AcceptingRelay(spool)  # type: ignore[arg-type]
    )

    with pytest.raises(CommandNotReadyError):
        processor.process(
            GatewayCommand(
                command_type=CommandType.ALLOW,
                message_id=record.message_id,
                org_id=record.org_id,
                expected_state=MessageState.CAPTURED,
            )
        )


def test_stale_processing_command_is_recovered(tmp_path: Path) -> None:
    bus = FilesystemEventBus(tmp_path / "queues")
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=uuid4(),
        org_id=str(uuid4()),
    )
    bus.publish_command(command)
    assert bus.consume_commands() == [command]

    processing = next(
        (tmp_path / "queues" / "commands" / "processing").glob("*.json")
    )
    old_time = time.time() - 60
    os.utime(processing, (old_time, old_time))

    assert bus.recover_stale("commands", stale_after_seconds=30) == 1
    assert bus.consume_commands() == [command]


def test_unexpected_command_failure_is_returned_to_ready(
    tmp_path: Path,
) -> None:
    bus = FilesystemEventBus(tmp_path / "queues")
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=uuid4(),
        org_id=str(uuid4()),
    )
    bus.publish_command(command)

    class _FailingProcessor:
        def process(self, _command):
            raise RuntimeError("unexpected")

    consumer = CommandConsumer(
        bus, _FailingProcessor()  # type: ignore[arg-type]
    )
    assert consumer.run_once() == 1
    assert bus.consume_commands() == [command]
