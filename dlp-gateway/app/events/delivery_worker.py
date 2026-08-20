from __future__ import annotations

from app.events.publisher import EventPublisher
from app.logging_setup import get_logger
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


class DeliveryEventPublisherWorker:
    """Publish the spool-backed delivery outbox without resubmitting SMTP."""

    def __init__(
        self,
        spool: FilesystemSpoolStore,
        publisher: EventPublisher,
    ) -> None:
        self.spool = spool
        self.publisher = publisher

    def recover_stale_submissions(self) -> int:
        # Startup-only full scan also repairs attempts created before active
        # markers existed.
        return self.spool.recover_stale_submissions(full_scan=True)

    def run_once(self) -> int:
        # Relay and event publishing share this worker thread, so no provider
        # submission is active when this recovery check runs.
        self.spool.recover_stale_submissions()
        published = 0
        for event in self.spool.list_pending_delivery_events():
            try:
                self.publisher.publish_delivery(event)
                self.spool.mark_delivery_event_published(
                    str(event.message_id), str(event.event_id)
                )
            except Exception:
                log.exception(
                    "delivery_event.publish_failed",
                    event_id=str(event.event_id),
                    message_id=str(event.message_id),
                )
                continue
            published += 1
            log.info(
                "delivery_event.published",
                event_id=str(event.event_id),
                message_id=str(event.message_id),
                attempt_id=str(event.attempt_id),
                outcome=event.outcome.value,
            )
        for event in self.spool.list_pending_command_acks():
            try:
                self.publisher.publish_command_ack(event)
                self.spool.mark_command_ack_published(str(event.event_id))
            except Exception:
                log.exception(
                    "command_ack.publish_failed",
                    event_id=str(event.event_id),
                    message_id=str(event.message_id),
                    command_id=str(event.command_id),
                )
                continue
            published += 1
            log.info(
                "command_ack.published",
                event_id=str(event.event_id),
                message_id=str(event.message_id),
                command_id=str(event.command_id),
                status=event.status.value,
            )
        return published
