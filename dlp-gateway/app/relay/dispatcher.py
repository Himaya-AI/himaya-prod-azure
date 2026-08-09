from __future__ import annotations

from app.config_cache.snapshot import FileTenantConfigCache
from app.domain.models import DeliveryOutcome, RelayRequest, RelayResult
from app.logging_setup import get_logger
from app.relay.adapters import RelayAdapterRegistry
from app.relay.outcomes import spool_state_for_outcome
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


def build_egress_copy(original_mime: bytes) -> bytes:
    """Egress transmission copy derived from immutable original.

    Local/MVP returns the original bytes unchanged. Later we add only approved
    loop-prevention transport headers — never reconstruct body/attachments.
    """
    return original_mime


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
