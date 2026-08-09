from __future__ import annotations

import re

from app.config_cache.snapshot import FileTenantConfigCache
from app.domain.models import DeliveryOutcome, RelayRequest, RelayResult
from app.logging_setup import get_logger
from app.relay.adapters import RelayAdapterRegistry
from app.relay.outcomes import spool_state_for_outcome
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)

RETURN_MARKER_HEADER = b"X-Himaya-DLP-Return: 1\r\n"

# Header section regexes operate on bytes to avoid re-serializing the message.
_HEADER_END = re.compile(rb"\r?\n\r?\n")
_X_HIMAYA_LINE = re.compile(rb"(?im)^x-himaya-[^\r\n]*\r?\n(?:[ \t][^\r\n]*\r?\n)*")


def build_egress_copy(original_mime: bytes) -> bytes:
    """Egress transmission copy derived from immutable original.

    Byte-surgical header edit: removes any pre-existing X-Himaya-* header
    lines from the header block, then prepends the Himaya return marker so
    M365 route rules can bypass the gateway on the return hop.

    Unlike parse-and-reserialize, this never rewrites existing headers,
    encodings, DKIM signatures, or the body — it only touches the header
    block at the byte level. On any anomaly, falls back to prepending the
    marker before the untouched message.
    """
    match = _HEADER_END.search(original_mime)
    if match is None:
        # No header/body separator: prepend marker ahead of the whole blob.
        return RETURN_MARKER_HEADER + original_mime

    header_block = original_mime[: match.start()]
    body = original_mime[match.start():]
    # Strip existing X-Himaya-* headers (with their continuation folds).
    header_block = _X_HIMAYA_LINE.sub(b"", header_block)
    return RETURN_MARKER_HEADER + header_block + body


class RelayDispatcher:
    def __init__(
        self,
        spool: FilesystemSpoolStore,
        adapters: RelayAdapterRegistry,
        tenant_cache: FileTenantConfigCache,
    ) -> None:
        self.spool = spool
        self.adapters = adapters
        self.tenant_cache = tenant_cache

    def relay_message(self, message_id: str) -> RelayResult:
        record = self.spool.get(message_id)
        if record is None:
            return RelayResult(
                outcome=DeliveryOutcome.FAILED, detail="message not found"
            )

        tenant = self.tenant_cache.resolve_by_org_id(record.org_id)
        if tenant is None:
            result = RelayResult(
                outcome=DeliveryOutcome.FAILED,
                detail="tenant config not found for relay",
            )
            self.spool.update_state(
                message_id,
                spool_state_for_outcome(result.outcome),
                relay_detail=result.detail,
            )
            return result

        self.spool.update_state(message_id, "submitting")
        mime = build_egress_copy(self.spool.read_mime(record))
        request = RelayRequest(
            message_id=record.message_id,
            org_id=record.org_id,
            provider=record.provider,
            provider_deployment_id=record.provider_deployment_id,
            envelope_from=record.envelope_from,
            envelope_to=list(record.envelope_to),
            mime_bytes=mime,
            relay_config=tenant.relay.as_dict(),
        )
        adapter = self.adapters.get(tenant.relay)
        result = adapter.submit(request)
        self.spool.update_state(
            message_id,
            spool_state_for_outcome(result.outcome),
            relay_smtp_code=result.smtp_code,
            relay_detail=result.detail or result.smtp_message,
            relay_smtp_stage=(
                result.smtp_stage.value if result.smtp_stage else None
            ),
            relay_remote_host=result.remote_host,
            relay_cert_thumbprint=result.certificate_thumbprint,
            relay_accepted_recipients=result.accepted_recipients,
            relay_refused_recipients=result.refused_recipients,
        )
        log.info(
            "relay.finished",
            message_id=message_id,
            adapter=tenant.relay.adapter,
            outcome=result.outcome.value,
            smtp_code=result.smtp_code,
            smtp_stage=(
                result.smtp_stage.value if result.smtp_stage else None
            ),
            remote_host=result.remote_host,
        )
        return result
