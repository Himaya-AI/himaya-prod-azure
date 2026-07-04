from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from app.api.schemas import EntityType, ReputationEntity
from app.config.settings import load_settings
from app.core.cache import ReputationCache
from app.core.correlator import SignalCorrelator
from app.core.orchestrator import ReputationOrchestrator
from app.core.scorer import DeterministicScorer
from app.sources.registry import load_source_registry

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PurgeStats:
    scanned: int
    deleted: int
    refreshed_domains: int


async def run_purge_job() -> PurgeStats:
    """
    Lambda-compatible cache maintenance job.

    - Purges expired in-memory entries and expired override records
    - Refreshes cached domain threat-intel entries before Redis TTL expiry
    """
    settings = load_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
    cache = ReputationCache(
        redis_url=settings.redis_url,
        default_ttl_seconds=settings.cache_ttl_seconds,
        error_ttl_seconds=settings.error_ttl_seconds,
    )
    await cache.connect()
    try:
        registry = load_source_registry(settings)
        orchestrator = ReputationOrchestrator(
            cache=cache,
            registry=registry,
            correlator=SignalCorrelator(),
            scorer=DeterministicScorer(),
        )

        deleted = await cache.purge_expired_memory_entries()
        deleted += await cache.purge_expired_overrides()

        domain_keys = await cache.keys("rep:v1:domain:*")
        refreshed = 0
        for key in domain_keys:
            cached = await cache.get_entry(key)
            if not cached:
                continue
            lookup_value = cached.lookup_value
            if not lookup_value and cached.result:
                lookup_value = cached.result.normalized_value
            if not lookup_value:
                continue
            await orchestrator.lookup_entity(
                ReputationEntity(type=EntityType.domain, value=lookup_value),
                force_refresh=True,
            )
            refreshed += 1

        logger.info(
            "Purge job complete: deleted=%s refreshed_domains=%s scanned=%s",
            deleted,
            refreshed,
            len(domain_keys),
        )
        return PurgeStats(scanned=len(domain_keys), deleted=deleted, refreshed_domains=refreshed)
    finally:
        await cache.close()


def lambda_handler(_event, _context):
    stats = asyncio.run(run_purge_job())
    return {
        "scanned": stats.scanned,
        "deleted": stats.deleted,
        "refreshed_domains": stats.refreshed_domains,
    }


if __name__ == "__main__":
    print(asyncio.run(run_purge_job()))
