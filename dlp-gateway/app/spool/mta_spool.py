from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

from app.domain.models import (
    DeliveryEvent,
    DeliveryOutcome,
    MessageState,
    RelayResult,
    SpoolRecord,
    utcnow,
)
from app.logging_setup import get_logger
from app.relay.outcomes import spool_state_for_outcome

log = get_logger(__name__)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FilesystemSpoolStore:
    """Durable MTA spool using directory rename + fsync.

    Layout:
      spool/tmp/<id>.mime
      spool/tmp/<id>.json
      spool/accepted/<id>.mime
      spool/accepted/<id>.json
      spool/captured/<id>.*
      spool/done/<id>.*
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        for name in (
            "tmp",
            "accepted",
            "captured",
            "held",
            "stopped",
            "done",
            "failed",
            "delivery-events/ready",
            "relay-attempts/active",
        ):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def commit(self, record: SpoolRecord, mime_bytes: bytes) -> SpoolRecord:
        mid = str(record.message_id)
        tmp_mime = self.root / "tmp" / f"{mid}.mime"
        tmp_meta = self.root / "tmp" / f"{mid}.json"
        final_mime = self.root / "accepted" / f"{mid}.mime"
        final_meta = self.root / "accepted" / f"{mid}.json"

        record.mime_sha256 = sha256_hex(mime_bytes)
        record.mime_size = len(mime_bytes)
        record.spool_mime_path = str(final_mime)
        record.metadata_path = str(final_meta)
        record.state = MessageState.ACCEPTED_IN_SPOOL

        self._write_fsynced(tmp_mime, mime_bytes)
        self._write_fsynced(tmp_meta, record.model_dump_json(indent=2).encode("utf-8"))

        os.replace(tmp_mime, final_mime)
        os.replace(tmp_meta, final_meta)
        self._fsync_dir(self.root / "accepted")

        log.info("spool.committed", message_id=mid, size=record.mime_size)
        return record

    def list_pending_capture(self) -> list[SpoolRecord]:
        records: list[SpoolRecord] = []
        for meta in sorted((self.root / "accepted").glob("*.json")):
            records.append(self._load_meta(meta))
        return records

    def annotate_accepted(self, message_id: str, **extra: object) -> SpoolRecord:
        """Update accepted metadata in place (e.g. blob_uri) before event publish."""
        meta = self.root / "accepted" / f"{message_id}.json"
        if not meta.exists():
            raise KeyError(message_id)
        data = json.loads(meta.read_text(encoding="utf-8"))
        data.update(extra)
        self._write_atomic(
            meta,
            json.dumps(data, indent=2, default=str).encode("utf-8"),
        )
        return self._load_meta(meta)

    def mark_captured(self, message_id: str, blob_uri: str) -> SpoolRecord:
        record = self._move_bucket(message_id, "accepted", "captured")
        record.state = MessageState.CAPTURED
        record.blob_uri = blob_uri
        self._persist_record(record)
        return record

    def get(self, message_id: str) -> SpoolRecord | None:
        for bucket in ("accepted", "captured", "held", "stopped", "done", "failed"):
            meta = self.root / bucket / f"{message_id}.json"
            if meta.exists():
                return self._load_meta(meta)
        return None

    def begin_relay_attempt(
        self, message_id: str, command_id: str | UUID | None
    ) -> SpoolRecord:
        """Durably identify an attempt before any provider network I/O."""
        record = self.get(message_id)
        if record is None:
            raise KeyError(message_id)
        parsed_command_id = UUID(str(command_id)) if command_id else None
        attempt_id = uuid4()
        self._write_atomic(
            self._active_attempt_path(message_id),
            json.dumps(
                {
                    "message_id": message_id,
                    "attempt_id": str(attempt_id),
                }
            ).encode("utf-8"),
        )
        try:
            return self.update_state(
                message_id,
                MessageState.SUBMITTING.value,
                relay_attempt_id=attempt_id,
                relay_attempt_count=record.relay_attempt_count + 1,
                relay_trigger_command_id=parsed_command_id,
                relay_outcome=None,
                relay_started_at=utcnow(),
                relay_finished_at=None,
                relay_smtp_code=None,
                relay_detail=None,
                relay_smtp_stage=None,
                relay_remote_host=None,
                relay_cert_thumbprint=None,
                relay_accepted_recipients=[],
                relay_refused_recipients=[],
            )
        except Exception:
            # No provider I/O has started, so removing the marker leaves the
            # original state safely retryable.
            self._clear_active_attempt(message_id)
            raise

    def finalize_relay_attempt(
        self,
        message_id: str,
        result: RelayResult,
        *,
        relay_adapter: str | None,
    ) -> DeliveryEvent:
        """Write event first, then apply its result to spool metadata.

        If the process dies between those steps, startup recovery reapplies
        the durable event instead of guessing that the SMTP outcome is
        uncertain.
        """
        record = self.get(message_id)
        if record is None:
            raise KeyError(message_id)
        if record.relay_attempt_id is None:
            raise ValueError("relay attempt was not started")

        resulting_state = spool_state_for_outcome(result.outcome)
        event = DeliveryEvent(
            message_id=record.message_id,
            org_id=record.org_id,
            provider=record.provider,
            provider_deployment_id=record.provider_deployment_id,
            attempt_id=record.relay_attempt_id,
            attempt_number=record.relay_attempt_count,
            trigger_command_id=record.relay_trigger_command_id,
            relay_adapter=relay_adapter,
            outcome=result.outcome,
            resulting_state=resulting_state,
            smtp_code=result.smtp_code,
            smtp_message=result.smtp_message,
            detail=result.detail,
            smtp_stage=result.smtp_stage,
            remote_host=result.remote_host,
            accepted_recipients=result.accepted_recipients,
            refused_recipients=result.refused_recipients,
            certificate_thumbprint=result.certificate_thumbprint,
            attempt_started_at=(
                result.attempt_started_at or record.relay_started_at
            ),
            attempt_finished_at=(
                result.attempt_finished_at or utcnow()
            ),
        )

        self._write_atomic(
            self._delivery_event_path(event.event_id),
            event.model_dump_json(indent=2).encode("utf-8"),
        )
        self._apply_delivery_event(event)
        return event

    def list_pending_delivery_events(self) -> list[DeliveryEvent]:
        ready = self.root / "delivery-events" / "ready"
        events = [
            DeliveryEvent.model_validate_json(
                path.read_text(encoding="utf-8")
            )
            for path in ready.glob("*.json")
        ]
        return sorted(events, key=lambda event: event.occurred_at)

    def mark_delivery_event_published(
        self, message_id: str, event_id: str | UUID
    ) -> SpoolRecord:
        record = self.get(message_id)
        if record is None:
            raise KeyError(message_id)
        parsed_event_id = UUID(str(event_id))
        published = list(record.published_delivery_event_ids)
        if parsed_event_id not in published:
            published.append(parsed_event_id)
        updated = self.update_state(
            message_id,
            record.state.value,
            published_delivery_event_ids=published,
        )
        event_path = self._delivery_event_path(parsed_event_id)
        try:
            event_path.unlink()
        except FileNotFoundError:
            pass
        self._fsync_dir(event_path.parent)
        return updated

    def recover_stale_submissions(
        self, *, full_scan: bool = False
    ) -> int:
        """Conservatively mark interrupted submissions as uncertain."""
        recovered = 0
        pending_by_attempt = {
            event.attempt_id: event
            for event in self.list_pending_delivery_events()
        }
        records: dict[UUID, SpoolRecord] = {}
        active_dir = self.root / "relay-attempts" / "active"
        for marker in active_dir.glob("*.json"):
            record = self.get(marker.stem)
            if record is None or record.state != MessageState.SUBMITTING:
                self._clear_active_attempt(marker.stem)
                continue
            records[record.message_id] = record
        if full_scan:
            for record in self._iter_records():
                if record.state == MessageState.SUBMITTING:
                    records[record.message_id] = record

        for record in records.values():
            if record.state != MessageState.SUBMITTING:
                continue
            if (
                record.relay_attempt_id is not None
                and record.relay_attempt_id in pending_by_attempt
            ):
                self._apply_delivery_event(
                    pending_by_attempt[record.relay_attempt_id]
                )
                recovered += 1
                continue
            result = RelayResult(
                outcome=DeliveryOutcome.UNCERTAIN,
                detail="gateway restarted during provider submission",
                remote_host=record.relay_remote_host,
                attempt_started_at=record.relay_started_at,
                attempt_finished_at=utcnow(),
            )
            self.finalize_relay_attempt(
                str(record.message_id),
                result,
                relay_adapter=None,
            )
            recovered += 1
        if recovered:
            log.warning("spool.recovered_submissions", count=recovered)
        return recovered

    def _apply_delivery_event(self, event: DeliveryEvent) -> SpoolRecord:
        record = self.get(str(event.message_id))
        if record is None:
            raise KeyError(str(event.message_id))
        processed_ids = list(record.processed_command_ids)
        if (
            event.trigger_command_id is not None
            and event.trigger_command_id not in processed_ids
        ):
            processed_ids.append(event.trigger_command_id)
        updated = self.update_state(
            str(event.message_id),
            event.resulting_state.value,
            relay_smtp_code=event.smtp_code,
            relay_detail=event.detail or event.smtp_message,
            relay_smtp_stage=(
                event.smtp_stage.value if event.smtp_stage else None
            ),
            relay_remote_host=event.remote_host,
            relay_cert_thumbprint=event.certificate_thumbprint,
            relay_accepted_recipients=event.accepted_recipients,
            relay_refused_recipients=event.refused_recipients,
            relay_outcome=event.outcome.value,
            relay_finished_at=event.attempt_finished_at,
            processed_command_ids=processed_ids,
        )
        self._clear_active_attempt(str(event.message_id))
        return updated

    def _delivery_event_path(self, event_id: str | UUID) -> Path:
        return (
            self.root
            / "delivery-events"
            / "ready"
            / f"{event_id}.json"
        )

    def _active_attempt_path(self, message_id: str) -> Path:
        return (
            self.root
            / "relay-attempts"
            / "active"
            / f"{message_id}.json"
        )

    def _clear_active_attempt(self, message_id: str) -> None:
        path = self._active_attempt_path(message_id)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        self._fsync_dir(path.parent)

    def read_mime(self, record: SpoolRecord) -> bytes:
        return Path(record.spool_mime_path).read_bytes()

    def update_state(self, message_id: str, state: str, **extra: object) -> SpoolRecord:
        record = self.get(message_id)
        if record is None:
            raise KeyError(message_id)
        bucket = {
            MessageState.HELD.value: "held",
            MessageState.STOPPED.value: "stopped",
            MessageState.PROVIDER_ACCEPTED.value: "done",
            MessageState.FAILED.value: "failed",
            MessageState.PARTIALLY_ACCEPTED.value: "failed",
            MessageState.OUTCOME_UNCERTAIN.value: "failed",
            MessageState.CAPTURED.value: "captured",
            MessageState.ALLOW_PENDING.value: "captured",
            MessageState.SUBMITTING.value: "captured",
            MessageState.DEFERRED.value: "captured",
        }.get(state, "captured")

        current_bucket = Path(record.metadata_path).parent.name
        if current_bucket != bucket:
            record = self._move_bucket(message_id, current_bucket, bucket)
        else:
            expected_mime = (
                self.root / bucket / f"{message_id}.mime"
            )
            if not expected_mime.is_file():
                mime_source = self._locate_mime(record)
                os.replace(mime_source, expected_mime)
                self._fsync_dir(mime_source.parent)
                self._fsync_dir(expected_mime.parent)
                record.spool_mime_path = str(expected_mime)

        record.state = MessageState(state)
        for key, value in extra.items():
            if key in SpoolRecord.model_fields:
                setattr(record, key, value)
        self._persist_record(record)
        return record

    def _iter_records(self):
        for bucket in (
            "accepted",
            "captured",
            "held",
            "stopped",
            "done",
            "failed",
        ):
            for meta in sorted((self.root / bucket).glob("*.json")):
                yield self._load_meta(meta)

    def record_command_processed(
        self, message_id: str, command_id: str
    ) -> SpoolRecord:
        record = self.get(message_id)
        if record is None:
            raise KeyError(message_id)
        parsed_id = UUID(command_id)
        if parsed_id not in record.processed_command_ids:
            record.processed_command_ids.append(parsed_id)
            self._persist_record(record)
        return record

    def _move_bucket(self, message_id: str, src: str, dst: str) -> SpoolRecord:
        if src == dst:
            record = self.get(message_id)
            if record is None:
                raise KeyError(message_id)
            return record

        src_meta = self.root / src / f"{message_id}.json"
        dst_mime = self.root / dst / f"{message_id}.mime"
        dst_meta = self.root / dst / f"{message_id}.json"
        if not src_meta.exists():
            raise KeyError(message_id)
        record = self._load_meta(src_meta)
        mime_source = self._locate_mime(record)

        # Metadata moves first. Until MIME follows, its persisted path still
        # points at the source, so either crash position remains recoverable.
        os.replace(src_meta, dst_meta)
        self._fsync_dir(self.root / src)
        self._fsync_dir(self.root / dst)
        if mime_source != dst_mime:
            os.replace(mime_source, dst_mime)
            self._fsync_dir(mime_source.parent)
            self._fsync_dir(self.root / dst)

        record.spool_mime_path = str(dst_mime)
        record.metadata_path = str(dst_meta)
        self._persist_record(record)
        return record

    def _persist_record(self, record: SpoolRecord) -> None:
        self._write_atomic(
            Path(record.metadata_path),
            record.model_dump_json(indent=2).encode("utf-8"),
        )

    def _locate_mime(self, record: SpoolRecord) -> Path:
        configured = Path(record.spool_mime_path)
        if configured.is_file():
            return configured
        message_id = str(record.message_id)
        for bucket in (
            "accepted",
            "captured",
            "held",
            "stopped",
            "done",
            "failed",
        ):
            candidate = self.root / bucket / f"{message_id}.mime"
            if candidate.is_file():
                return candidate
        raise FileNotFoundError(f"spool MIME not found: {message_id}")

    def _load_meta(self, path: Path) -> SpoolRecord:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Ignore forward-compatible fields from newer gateway versions.
        filtered = {k: v for k, v in data.items() if k in SpoolRecord.model_fields}
        record = SpoolRecord.model_validate(filtered)
        record.metadata_path = str(path)
        mime = path.with_suffix(".mime")
        if mime.exists():
            record.spool_mime_path = str(mime)
        return record

    @staticmethod
    def _write_fsynced(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    def _write_atomic(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.parent / (
            f".{path.name}.{uuid4().hex}.tmp"
        )
        try:
            self._write_fsynced(temporary, data)
            os.replace(temporary, path)
            self._fsync_dir(path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        # Directory fsync is best-effort. Windows often denies O_RDONLY on dirs.
        if os.name == "nt":
            return
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
