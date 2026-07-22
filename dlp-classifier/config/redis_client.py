from __future__ import annotations

import redis.asyncio as redis

from config.settings import Settings


def create_redis_client(settings: Settings) -> redis.Redis:
    """Builds the Redis client once at startup, from settings.REDIS_URL.
    Callers receive this instance rather than each lazily creating their own."""
    return redis.from_url(settings.REDIS_URL)
