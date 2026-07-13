from __future__ import annotations

from app.domain.models import DeliveryOutcome, RelayResult
from app.logging_setup import get_logger
from app.relay.adapters.local_sink import SmtpSinkRelayAdapter
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


def build_egress_copy(original_mime: bytes) -> bytes:
    """Egress transmission copy derived from immutable original.

    Local MVP returns the original bytes unchanged. Production may add
    approved transport headers only — never reconstruct body/attachments.
    """
    return original_mime


class RelayDispatcher:
    def __init__(
        self,
        spool: FilesystemSpoolStore,
        adapter: SmtpSinkRelayAdapter,
    ) -> None:
        self.spool = spool
        self.adapter = adapter

    def relay_message(self, message_id: str) -> RelayResult:
        record = self.spool.get(message_id)
        if record is None:
            return RelayResult(
                outcome=DeliveryOutcome.FAILED, detail="message not found"
            )
        self.spool.update_state(message_id, "submitting")
        mime = build_egress_copy(self.spool.read_mime(record))
        result = self.adapter.submit(
            mime_bytes=mime,
            envelope_from=record.envelope_from,
            envelope_to=record.envelope_to,
        )
        state = {
            DeliveryOutcome.ACCEPTED: "provider_accepted",
            DeliveryOutcome.DEFERRED: "deferred",
            DeliveryOutcome.FAILED: "failed",
            DeliveryOutcome.UNCERTAIN: "outcome_uncertain",
        }[result.outcome]
        self.spool.update_state(
            message_id,
            state,
            relay_smtp_code=result.smtp_code,
            relay_detail=result.detail or result.smtp_message,
        )
        log.info(
            "relay.finished",
            message_id=message_id,
            outcome=result.outcome.value,
            smtp_code=result.smtp_code,
        )
        return result
