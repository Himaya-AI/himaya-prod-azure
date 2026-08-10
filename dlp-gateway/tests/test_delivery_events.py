from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest

from app.commands.processor import CommandProcessor, CommandRejectedError
from app.domain.models import (
    CommandType,
    DeliveryOutcome,
    DeliveryEvent,
    GatewayCommand,
    MessageState,
    RelayResult,
    SpoolRecord,
    SmtpStage,
)
from app.events.delivery_worker import DeliveryEventPublisherWorker
from app.spool.mta_spool import FilesystemSpoolStore, sha256_hex


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
        str(record.message_id), "blob://message"
    )


def _finish(
    spool: FilesystemSpoolStore,
    record: SpoolRecord,
    outcome: DeliveryOutcome,
    command_id=None,
) -> None:
    spool.begin_relay_attempt(str(record.message_id), command_id)
    spool.finalize_relay_attempt(
        str(record.message_id),
        RelayResult(
            outcome=outcome,
            smtp_code=250 if outcome == DeliveryOutcome.ACCEPTED else None,
            smtp_stage=SmtpStage.FINAL_RESPONSE,
            accepted_recipients=(
                list(record.envelope_to)
                if outcome == DeliveryOutcome.ACCEPTED
                else []
            ),
        ),
        relay_adapter="local",
    )


def test_delivery_outbox_retries_publish_without_relay(
    tmp_path: Path,
) -> None:
    spool, record = _captured_message(tmp_path)
    _finish(spool, record, DeliveryOutcome.ACCEPTED)

    class _Publisher:
        def __init__(self) -> None:
            self.fail = True
            self.events = []

        def publish_delivery(self, event) -> None:
            if self.fail:
                raise RuntimeError("queue unavailable")
            self.events.append(event)

    publisher = _Publisher()
    worker = DeliveryEventPublisherWorker(
        spool, publisher  # type: ignore[arg-type]
    )
    assert worker.run_once() == 0
    assert len(spool.list_pending_delivery_events()) == 1

    publisher.fail = False
    assert worker.run_once() == 1
    assert len(publisher.events) == 1
    assert spool.list_pending_delivery_events() == []

    loaded = spool.get(str(record.message_id))
    assert loaded is not None
    assert loaded.state == MessageState.PROVIDER_ACCEPTED
    assert loaded.relay_attempt_count == 1


def test_steady_state_recovery_does_not_scan_retained_spool(
    tmp_path: Path, monkeypatch
) -> None:
    spool, _record = _captured_message(tmp_path)

    def _fail_scan():
        raise AssertionError("retained spool must not be scanned per tick")
        yield  # pragma: no cover

    monkeypatch.setattr(spool, "_iter_records", _fail_scan)
    assert spool.recover_stale_submissions() == 0
    assert spool.list_pending_delivery_events() == []


def test_active_marker_failure_leaves_message_retryable(
    tmp_path: Path, monkeypatch
) -> None:
    spool, record = _captured_message(tmp_path)

    def _fail_write(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(spool, "_write_atomic", _fail_write)
    with pytest.raises(OSError, match="disk unavailable"):
        spool.begin_relay_attempt(str(record.message_id), uuid4())

    loaded = spool.get(str(record.message_id))
    assert loaded is not None
    assert loaded.state == MessageState.CAPTURED


def test_failed_submitting_update_removes_active_marker(
    tmp_path: Path, monkeypatch
) -> None:
    spool, record = _captured_message(tmp_path)

    def _fail_update(*_args, **_kwargs):
        raise OSError("metadata unavailable")

    monkeypatch.setattr(spool, "update_state", _fail_update)
    with pytest.raises(OSError, match="metadata unavailable"):
        spool.begin_relay_attempt(str(record.message_id), uuid4())

    active = (
        tmp_path
        / "spool"
        / "relay-attempts"
        / "active"
        / f"{record.message_id}.json"
    )
    assert not active.exists()


def test_stale_submitting_becomes_uncertain_and_is_not_retried(
    tmp_path: Path,
) -> None:
    spool, record = _captured_message(tmp_path)
    command_id = uuid4()
    spool.begin_relay_attempt(str(record.message_id), command_id)

    assert spool.recover_stale_submissions() == 1
    loaded = spool.get(str(record.message_id))
    assert loaded is not None
    assert loaded.state == MessageState.OUTCOME_UNCERTAIN
    assert command_id in loaded.processed_command_ids

    events = spool.list_pending_delivery_events()
    assert len(events) == 1
    assert events[0].outcome == DeliveryOutcome.UNCERTAIN


def test_recovery_reapplies_write_ahead_delivery_event(
    tmp_path: Path,
) -> None:
    spool, record = _captured_message(tmp_path)
    command_id = uuid4()
    attempt = spool.begin_relay_attempt(
        str(record.message_id), command_id
    )
    event = DeliveryEvent(
        message_id=record.message_id,
        org_id=record.org_id,
        provider=record.provider,
        provider_deployment_id=record.provider_deployment_id,
        attempt_id=attempt.relay_attempt_id,
        attempt_number=1,
        trigger_command_id=command_id,
        relay_adapter="local",
        outcome=DeliveryOutcome.ACCEPTED,
        resulting_state=MessageState.PROVIDER_ACCEPTED,
        smtp_code=250,
        accepted_recipients=list(record.envelope_to),
    )
    spool._write_atomic(  # noqa: SLF001 - crash-boundary fixture
        spool._delivery_event_path(event.event_id),  # noqa: SLF001
        event.model_dump_json().encode(),
    )

    assert spool.recover_stale_submissions() == 1
    loaded = spool.get(str(record.message_id))
    assert loaded is not None
    assert loaded.state == MessageState.PROVIDER_ACCEPTED
    assert command_id in loaded.processed_command_ids
    assert spool.list_pending_delivery_events() == [event]


def test_recovery_repairs_split_bucket_move(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    command_id = uuid4()
    attempt = spool.begin_relay_attempt(
        str(record.message_id), command_id
    )
    event = DeliveryEvent(
        message_id=record.message_id,
        org_id=record.org_id,
        provider=record.provider,
        provider_deployment_id=record.provider_deployment_id,
        attempt_id=attempt.relay_attempt_id,
        attempt_number=1,
        trigger_command_id=command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        resulting_state=MessageState.PROVIDER_ACCEPTED,
        smtp_code=250,
    )
    spool._write_atomic(  # noqa: SLF001 - crash-boundary fixture
        spool._delivery_event_path(event.event_id),  # noqa: SLF001
        event.model_dump_json().encode(),
    )
    message_id = str(record.message_id)
    os.replace(
        tmp_path / "spool" / "captured" / f"{message_id}.json",
        tmp_path / "spool" / "done" / f"{message_id}.json",
    )

    restarted = FilesystemSpoolStore(tmp_path / "spool")
    assert restarted.recover_stale_submissions() == 1
    loaded = restarted.get(message_id)
    assert loaded is not None
    assert loaded.state == MessageState.PROVIDER_ACCEPTED
    assert Path(loaded.metadata_path).parent.name == "done"
    assert Path(loaded.spool_mime_path).parent.name == "done"
    assert restarted.read_mime(loaded).endswith(b"hello\r\n")


@pytest.mark.parametrize(
    "state",
    [
        MessageState.PARTIALLY_ACCEPTED,
        MessageState.OUTCOME_UNCERTAIN,
    ],
)
def test_whole_message_retry_rejected_for_unsafe_states(
    tmp_path: Path, state: MessageState
) -> None:
    spool, record = _captured_message(tmp_path)
    spool.update_state(str(record.message_id), state.value)

    class _Relay:
        def relay_message(self, message_id: str, command_id: str) -> None:
            raise AssertionError("unsafe state must not relay")

    processor = CommandProcessor(
        spool, _Relay()  # type: ignore[arg-type]
    )
    with pytest.raises(CommandRejectedError):
        processor.process(
            GatewayCommand(
                command_type=CommandType.RETRY,
                message_id=record.message_id,
                org_id=record.org_id,
            )
        )


def test_deferred_retry_is_bounded(tmp_path: Path) -> None:
    spool, record = _captured_message(tmp_path)
    spool.update_state(
        str(record.message_id),
        MessageState.DEFERRED.value,
        relay_attempt_count=4,
    )

    class _Relay:
        def relay_message(self, message_id: str, command_id: str) -> None:
            raise AssertionError("attempt limit must prevent relay")

    processor = CommandProcessor(
        spool,
        _Relay(),  # type: ignore[arg-type]
        max_relay_attempts=4,
    )
    with pytest.raises(CommandRejectedError, match="Maximum"):
        processor.process(
            GatewayCommand(
                command_type=CommandType.RETRY,
                message_id=record.message_id,
                org_id=record.org_id,
            )
        )
