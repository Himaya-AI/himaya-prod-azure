from __future__ import annotations

from app.config_cache.snapshot import TenantRelayConfig
from app.domain.ports import ProviderRelayAdapter
from app.relay.adapters.local_sink import SmtpSinkRelayAdapter
from app.relay.adapters.microsoft import Microsoft365RelayAdapter
from app.relay.certificates import FilesystemRelayCertificateProvider


class RelayAdapterRegistry:
    """Select local MailHog sink or Microsoft return adapter."""

    def __init__(
        self,
        local_adapter: SmtpSinkRelayAdapter,
        microsoft_adapter: Microsoft365RelayAdapter,
    ) -> None:
        self._local = local_adapter
        self._microsoft = microsoft_adapter

    def get(self, relay: TenantRelayConfig) -> ProviderRelayAdapter:
        adapter = (relay.adapter or "local").lower()
        if adapter in {"microsoft", "m365"}:
            return self._microsoft
        return self._local


def build_default_registry(
    *,
    default_local_host: str = "mailhog",
    default_local_port: int = 1025,
) -> RelayAdapterRegistry:
    return RelayAdapterRegistry(
        local_adapter=SmtpSinkRelayAdapter(
            host=default_local_host,
            port=default_local_port,
            use_tls=False,
        ),
        microsoft_adapter=Microsoft365RelayAdapter(
            certificate_provider=FilesystemRelayCertificateProvider()
        ),
    )
