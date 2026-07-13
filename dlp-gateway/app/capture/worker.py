from __future__ import annotations

from app.capture.mime_store import AzureBlobMimeStore
from app.domain.models import CaptureEvent, MessageState
from app.events.publisher import EventPublisher
from app.logging_setup import get_logger
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


class CaptureWorker:
    """Spool → immutable MIME blob → capture event."""

    def __init__(
        self,
        spool: FilesystemSpoolStore,
        mime_store: AzureBlobMimeStore,
        publisher: EventPublisher,
    ) -> None:
        self.spool = spool
        self.mime_store = mime_store
        self.publisher = publisher

    def run_once(self) -> int:
        processed = 0
        for record in self.spool.list_pending_capture():
            mime = self.spool.read_mime(record)
            blob_uri = self.mime_store.put_immutable(
                org_id=record.org_id,
                message_id=str(record.message_id),
                mime_bytes=mime,
                sha256=record.mime_sha256,
            )
            self.spool.mark_captured(str(record.message_id), blob_uri)
            event = CaptureEvent(
                message_id=record.message_id,
                org_id=record.org_id,
                provider=record.provider,
                provider_deployment_id=record.provider_deployment_id,
                envelope_from=record.envelope_from,
                envelope_to=record.envelope_to,
                mime_sha256=record.mime_sha256,
                mime_size=record.mime_size,
                blob_uri=blob_uri,
                received_at=record.received_at,
            )
            self.publisher.publish_capture(event)
            processed += 1
            log.info(
                "capture.published",
                message_id=str(record.message_id),
                state=MessageState.CAPTURED.value,
            )
        return processed
