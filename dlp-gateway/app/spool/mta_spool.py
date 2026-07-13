from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from app.domain.models import MessageState, SpoolRecord
from app.logging_setup import get_logger

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
        for name in ("tmp", "accepted", "captured", "held", "stopped", "done", "failed"):
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
        self._write_fsynced(meta, json.dumps(data, indent=2, default=str).encode("utf-8"))
        return self._load_meta(meta)

    def mark_captured(self, message_id: str, blob_uri: str) -> SpoolRecord:
        record = self._move_bucket(message_id, "accepted", "captured")
        extra = record.model_dump()
        extra["state"] = MessageState.CAPTURED
        extra["blob_uri"] = blob_uri
        updated = SpoolRecord.model_validate(
            {k: v for k, v in extra.items() if k in SpoolRecord.model_fields}
        )
        # Persist extended fields beside core record
        path = Path(updated.metadata_path)
        payload = updated.model_dump(mode="json")
        payload["blob_uri"] = blob_uri
        self._write_fsynced(path, json.dumps(payload, indent=2, default=str).encode("utf-8"))
        return updated

    def get(self, message_id: str) -> SpoolRecord | None:
        for bucket in ("accepted", "captured", "held", "stopped", "done", "failed"):
            meta = self.root / bucket / f"{message_id}.json"
            if meta.exists():
                return self._load_meta(meta)
        return None

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
            MessageState.OUTCOME_UNCERTAIN.value: "failed",
            MessageState.CAPTURED.value: "captured",
            MessageState.ALLOW_PENDING.value: "captured",
            MessageState.SUBMITTING.value: "captured",
            MessageState.DEFERRED.value: "captured",
        }.get(state, "captured")

        current_bucket = Path(record.metadata_path).parent.name
        if current_bucket != bucket:
            record = self._move_bucket(message_id, current_bucket, bucket)

        payload = record.model_dump(mode="json")
        payload["state"] = state
        payload.update(extra)
        path = Path(record.metadata_path)
        if path.parent.name != bucket:
            path = self.root / bucket / f"{message_id}.json"
        self._write_fsynced(path, json.dumps(payload, indent=2, default=str).encode("utf-8"))
        record.state = MessageState(state)
        record.metadata_path = str(path)
        return record

    def _move_bucket(self, message_id: str, src: str, dst: str) -> SpoolRecord:
        src_mime = self.root / src / f"{message_id}.mime"
        src_meta = self.root / src / f"{message_id}.json"
        dst_mime = self.root / dst / f"{message_id}.mime"
        dst_meta = self.root / dst / f"{message_id}.json"
        if not src_meta.exists():
            raise KeyError(message_id)
        os.replace(src_mime, dst_mime)
        os.replace(src_meta, dst_meta)
        self._fsync_dir(self.root / dst)
        record = self._load_meta(dst_meta)
        record.spool_mime_path = str(dst_mime)
        record.metadata_path = str(dst_meta)
        self._write_fsynced(
            dst_meta, record.model_dump_json(indent=2).encode("utf-8")
        )
        return record

    def _load_meta(self, path: Path) -> SpoolRecord:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Ignore non-model extras such as blob_uri when validating
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
