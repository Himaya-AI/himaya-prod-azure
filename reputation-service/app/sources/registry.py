from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Type

import yaml

from app.api.schemas import EntityType, SourceStatus
from app.config.settings import Settings
from app.sources.base import AdapterStatus, SourceConfig, ThreatIntelAdapter

logger = logging.getLogger(__name__)


class SourceRegistry:
    def __init__(self, adapters: list[ThreatIntelAdapter]) -> None:
        self.adapters = adapters

    def for_entity(self, entity_type: EntityType, max_sources: int | None = None) -> list[ThreatIntelAdapter]:
        matching = [
            adapter
            for adapter in self.adapters
            if adapter.config.enabled
            and adapter.is_configured
            and adapter.supports(entity_type)
        ]
        matching.sort(key=lambda adapter: adapter.config.priority)
        return matching[:max_sources] if max_sources else matching

    async def statuses(self) -> list[SourceStatus]:
        statuses: list[SourceStatus] = []
        for adapter in self.adapters:
            status = await adapter.health()
            statuses.append(to_source_status(status))
        return statuses


def load_source_registry(settings: Settings) -> SourceRegistry:
    from app.sources.alienvault import AlienVaultAdapter
    from app.sources.dns import DnsAdapter
    from app.sources.ioc_feeds import IocFeedsAdapter
    from app.sources.malwarebazaar import MalwareBazaarAdapter
    from app.sources.urlscan import UrlscanAdapter
    from app.sources.virustotal import VirusTotalAdapter
    from app.sources.whois import WhoisAdapter

    adapter_classes: dict[str, Type[ThreatIntelAdapter]] = {
        "virustotal": VirusTotalAdapter,
        "alienvault": AlienVaultAdapter,
        "whois": WhoisAdapter,
        "ioc_feeds": IocFeedsAdapter,
        "dns": DnsAdapter,
        "urlscan": UrlscanAdapter,
        "malwarebazaar": MalwareBazaarAdapter,
    }

    source_config = _load_yaml(settings.sources_config_path)
    adapters: list[ThreatIntelAdapter] = []
    for name, raw in source_config.get("sources", {}).items():
        config = SourceConfig(
            name=name,
            enabled=bool(raw.get("enabled", False)),
            priority=int(raw.get("priority", 3)),
            timeout_ms=int(raw.get("timeout_ms", 3000)),
            supported_entities=set(raw.get("supported_entities", [])),
        )
        adapter_class = adapter_classes.get(name)
        if not adapter_class:
            logger.info("Source %s configured but no adapter exists yet", name)
            continue
        adapters.append(adapter_class(config=config, settings=settings))

    return SourceRegistry(adapters=adapters)


def to_source_status(status: AdapterStatus) -> SourceStatus:
    return SourceStatus(
        name=status.name,
        enabled=status.enabled,
        configured=status.configured,
        priority=status.priority,
        supported_entities=sorted(status.supported_entities),
        status=status.status,
        detail=status.detail,
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        logger.warning("Source config missing at %s; no sources enabled", path)
        return {"sources": {}}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {"sources": {}}
