from __future__ import annotations

from app.config_cache.snapshot import FileTenantConfigCache, TenantSnapshot


class TenantResolver:
    def __init__(self, cache: FileTenantConfigCache) -> None:
        self.cache = cache

    def resolve(
        self, envelope_from: str, routing_hostname: str | None = None
    ) -> TenantSnapshot | None:
        return self.cache.resolve_for_sender(envelope_from, routing_hostname)
