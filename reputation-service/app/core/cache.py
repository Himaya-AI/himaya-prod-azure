from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app.api.schemas import CacheEntry, EntityType, ReputationResult, Verdict
from app.sources.base import SourceSignal

logger = logging.getLogger(__name__)


class ReputationCache:
    def __init__(
        self,
        redis_url: str,
        default_ttl_seconds: int,
        error_ttl_seconds: int,
    ) -> None:
        self.redis_url = redis_url
        self.default_ttl_seconds = default_ttl_seconds
        self.error_ttl_seconds = error_ttl_seconds
        self._redis: Any | None = None
        self._memory: dict[str, tuple[dict[str, Any], float | None]] = {}

    async def connect(self) -> None:
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
            await self._redis.ping()
            logger.info("Redis reputation cache connected")
        except Exception as exc:
            self._redis = None
            logger.warning("Redis unavailable; using in-memory cache: %s", exc)

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def ping(self) -> bool:
        if self._redis is None:
            return False
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False

    async def get_entry(self, key: str) -> CacheEntry | None:
        raw = await self._get_json(key)
        if not raw:
            return None
        try:
            return CacheEntry.model_validate(raw)
        except Exception as exc:
            logger.debug("Invalid cache entry for %s: %s", key, exc)
            return None

    async def get_result(self, key: str) -> ReputationResult | None:
        entry = await self.get_entry(key)
        if entry is None:
            return None
        if entry.result is not None:
            result = entry.result
            result.cache_hit = True
            result.cached_at = entry.cached_at
            result.expires_at = entry.expires_at
            return result
        if not entry.source_signals:
            return None
        return None

    async def get_source_signals(self, key: str) -> list[SourceSignal] | None:
        raw = await self._get_json(key)
        if raw is None or "source_signals" not in raw:
            return None
        signals_raw = raw.get("source_signals") or []
        if not signals_raw:
            return []
        try:
            return [SourceSignal.from_dict(item) for item in signals_raw]
        except Exception as exc:
            logger.debug("Invalid source signals for %s: %s", key, exc)
            return None

    async def set_source_signals(
        self,
        key: str,
        signals: list[SourceSignal],
        *,
        ttl_seconds: int | None = None,
        snapshot: ReputationResult | None = None,
        lookup_type: EntityType | None = None,
        lookup_value: str | None = None,
    ) -> None:
        ttl = ttl_seconds or self.default_ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(time.time() + ttl, timezone.utc)
        entry = CacheEntry(
            source_signals=[signal.to_public_dict(include_raw=True) for signal in signals],
            result=snapshot,
            lookup_type=lookup_type,
            lookup_value=lookup_value,
            cached_at=now,
            expires_at=expires_at,
        )
        await self._set_json(key, entry.model_dump(mode="json"), ttl)

    async def set_result(
        self,
        key: str,
        result: ReputationResult,
        ttl_seconds: int | None = None,
    ) -> None:
        ttl = ttl_seconds or self.default_ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(time.time() + ttl, timezone.utc)
        result.cached_at = now
        result.expires_at = expires_at
        entry = CacheEntry(result=result, cached_at=now, expires_at=expires_at)
        await self._set_json(key, entry.model_dump(mode="json"), ttl)

    @staticmethod
    def ttl_for_signals(signals: list[SourceSignal], default_ttl: int, error_ttl: int) -> int:
        useful = [signal for signal in signals if signal.verdict != Verdict.unknown]
        return error_ttl if not useful else default_ttl

    async def get_override(self, key: str) -> dict[str, Any] | None:
        return await self._get_json(self.override_key(key))

    async def set_override(
        self,
        key: str,
        value: dict[str, Any],
        ttl_seconds: int | None = None,
    ) -> None:
        await self._set_json(self.override_key(key), value, ttl_seconds)

    async def delete(self, key: str) -> bool:
        deleted_main = await self._delete(key)
        deleted_override = await self._delete(self.override_key(key))
        return deleted_main or deleted_override

    async def keys(self, pattern: str) -> list[str]:
        if self._redis is not None:
            try:
                return [
                    key
                    async for key in self._redis.scan_iter(match=pattern, count=250)
                    if not key.endswith(":override")
                ]
            except Exception as exc:
                logger.warning("Redis scan failed for %s: %s", pattern, exc)
        self._purge_expired_memory()
        return [
            key
            for key in self._memory
            if _match_simple(pattern, key) and not key.endswith(":override")
        ]

    async def purge_expired_overrides(self) -> int:
        deleted = 0
        if self._redis is not None:
            try:
                override_keys = [
                    key async for key in self._redis.scan_iter(match="rep:v1:*:override", count=250)
                ]
            except Exception:
                override_keys = []
        else:
            self._purge_expired_memory()
            override_keys = [key for key in self._memory if key.endswith(":override")]

        now = datetime.now(timezone.utc)
        for key in override_keys:
            raw = await self._get_json(key)
            if not raw:
                continue
            expires_at = raw.get("expires_at")
            if not expires_at:
                continue
            try:
                parsed = datetime.fromisoformat(expires_at)
            except ValueError:
                continue
            if parsed <= now and await self._delete(key):
                deleted += 1
        return deleted

    async def purge_expired_memory_entries(self) -> int:
        before = len(self._memory)
        self._purge_expired_memory()
        return before - len(self._memory)

    @staticmethod
    def override_key(key: str) -> str:
        return f"{key}:override"

    async def _get_json(self, key: str) -> dict[str, Any] | None:
        if self._redis is not None:
            try:
                raw = await self._redis.get(key)
                return json.loads(raw) if raw else None
            except Exception as exc:
                logger.debug("Redis get failed for %s: %s", key, exc)

        self._purge_expired_memory()
        item = self._memory.get(key)
        return item[0] if item else None

    async def _set_json(
        self,
        key: str,
        value: dict[str, Any],
        ttl_seconds: int | None,
    ) -> None:
        if self._redis is not None:
            try:
                payload = json.dumps(value, default=str)
                if ttl_seconds:
                    await self._redis.setex(key, ttl_seconds, payload)
                else:
                    await self._redis.set(key, payload)
                return
            except Exception as exc:
                logger.debug("Redis set failed for %s: %s", key, exc)

        expires_at = time.time() + ttl_seconds if ttl_seconds else None
        self._memory[key] = (value, expires_at)

    async def _delete(self, key: str) -> bool:
        deleted = False
        if self._redis is not None:
            try:
                deleted = bool(await self._redis.delete(key))
            except Exception as exc:
                logger.debug("Redis delete failed for %s: %s", key, exc)

        deleted = self._memory.pop(key, None) is not None or deleted
        return deleted

    def _purge_expired_memory(self) -> None:
        now = time.time()
        expired = [key for key, (_, exp) in self._memory.items() if exp and exp <= now]
        for key in expired:
            self._memory.pop(key, None)


def _match_simple(pattern: str, key: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return key.startswith(pattern[:-1])
    return key == pattern
