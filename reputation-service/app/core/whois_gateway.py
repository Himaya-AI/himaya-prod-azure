"""
Shared gateway for all python-whois lookups.

Both the whois adapter and the DNS email_verify path used to call
whois.whois() independently. This module is the single entry point:

  - Redis cache keyed by domain
  - single-flight for concurrent callers of the same domain
  - bounded thread pool for the blocking whois socket call

If Redis is down, lookups go straight to WHOIS (no in-process cache).
Treat WhoisStatus.error as unknown age — do not score it as suspicious.
"""
from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import redis.asyncio as aioredis

from app.config.settings import Settings

try:
    import whois
except ImportError:
    whois = None

logger = logging.getLogger(__name__)

CACHE_KEY_PREFIX = "whois:v1:record"


class WhoisStatus(str, Enum):
    ok = "ok"
    no_creation_date = "no_creation_date"
    error = "error"


@dataclass(frozen=True)
class WhoisLookup:
    status: WhoisStatus
    domain: str
    creation_date: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def age_days(self) -> int | None:
        if self.creation_date is None:
            return None
        created = self.creation_date
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)


class WhoisGateway:
    def __init__(
        self,
        *,
        redis_url: str,
        record_ttl_seconds: int,
        negative_ttl_seconds: int,
        max_workers: int,
        socket_timeout_seconds: int,
    ) -> None:
        self.redis_url = redis_url
        self.record_ttl_seconds = record_ttl_seconds
        self.negative_ttl_seconds = negative_ttl_seconds
        self.socket_timeout_seconds = socket_timeout_seconds

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="whois",
        )
        self._slots = asyncio.Semaphore(max_workers)
        self._inflight: dict[str, asyncio.Task[WhoisLookup]] = {}
        self._redis: aioredis.Redis | None = None
        self._redis_attempted = False

    @property
    def is_available(self) -> bool:
        return whois is not None

    async def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None

    async def lookup(self, domain: str | None) -> WhoisLookup:
        normalized = (domain or "").strip().lower().rstrip(".")
        if not normalized:
            return WhoisLookup(status=WhoisStatus.error, domain="")
        if not self.is_available:
            return WhoisLookup(status=WhoisStatus.error, domain=normalized)

        cached = await self._read_cache(normalized)
        if cached is not None:
            return cached

        task = self._inflight.get(normalized)
        if task is None:
            task = asyncio.create_task(self._fetch(normalized))
            self._inflight[normalized] = task
            task.add_done_callback(
                lambda _t, key=normalized: self._inflight.pop(key, None)
            )

        # Keep the shared fetch alive if one caller times out early.
        return await asyncio.shield(task)

    async def age_days(self, domain: str | None) -> int | None:
        return (await self.lookup(domain)).age_days

    async def _fetch(self, domain: str) -> WhoisLookup:
        async with self._slots:
            try:
                loop = asyncio.get_running_loop()
                record = await asyncio.wait_for(
                    loop.run_in_executor(
                        self._executor,
                        _blocking_whois,
                        domain,
                        self.socket_timeout_seconds,
                    ),
                    timeout=self.socket_timeout_seconds + 2,
                )
                result = _interpret(domain, record)
            except Exception as exc:
                logger.info("whois: lookup failed for %s: %s", domain, exc)
                result = WhoisLookup(status=WhoisStatus.error, domain=domain)

        await self._write_cache(result)
        return result

    async def _read_cache(self, domain: str) -> WhoisLookup | None:
        payload = await self._get_json(f"{CACHE_KEY_PREFIX}:{domain}")
        if not payload:
            return None
        try:
            status = WhoisStatus(payload["status"])
        except (KeyError, ValueError):
            return None

        creation_raw = payload.get("creation_date")
        creation_date = (
            datetime.fromisoformat(creation_raw) if creation_raw else None
        )
        return WhoisLookup(
            status=status,
            domain=domain,
            creation_date=creation_date,
            raw=payload.get("raw") or {},
        )

    async def _write_cache(self, result: WhoisLookup) -> None:
        # Creation dates are stable; errors get a short TTL so they can recover.
        ttl = (
            self.record_ttl_seconds
            if result.status != WhoisStatus.error
            else self.negative_ttl_seconds
        )
        payload = {
            "status": result.status.value,
            "creation_date": (
                result.creation_date.isoformat() if result.creation_date else None
            ),
            "raw": result.raw,
        }
        await self._set_json(f"{CACHE_KEY_PREFIX}:{result.domain}", payload, ttl)

    async def _connect(self) -> aioredis.Redis | None:
        if self._redis is not None or self._redis_attempted:
            return self._redis

        self._redis_attempted = True
        try:
            client = aioredis.from_url(self.redis_url, decode_responses=True)
            await client.ping()
            self._redis = client
            logger.info("whois gateway: Redis cache connected")
        except Exception as exc:
            logger.warning(
                "whois gateway: Redis unavailable, WHOIS lookups will not be cached: %s",
                exc,
            )
        return self._redis

    async def _get_json(self, key: str) -> dict[str, Any] | None:
        client = await self._connect()
        if client is None:
            return None
        try:
            raw = await client.get(key)
            return json.loads(raw) if raw else None
        except Exception as exc:
            logger.debug("whois gateway: redis get failed for %s: %s", key, exc)
            return None

    async def _set_json(self, key: str, payload: dict[str, Any], ttl: int) -> None:
        client = await self._connect()
        if client is None:
            return
        try:
            await client.setex(key, ttl, json.dumps(payload, default=str))
        except Exception as exc:
            logger.debug("whois gateway: redis set failed for %s: %s", key, exc)


def _blocking_whois(domain: str, timeout_seconds: int) -> Any:
    if whois is None:
        raise RuntimeError("python-whois is not installed")
    return whois.whois(domain, timeout=timeout_seconds, quiet=True)


def _interpret(domain: str, record: Any) -> WhoisLookup:
    if record is None:
        return WhoisLookup(status=WhoisStatus.error, domain=domain)

    creation_date = _first_date(getattr(record, "creation_date", None))
    raw = _safe_raw(record)

    if creation_date is None:
        return WhoisLookup(
            status=WhoisStatus.no_creation_date,
            domain=domain,
            raw=raw,
        )

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    return WhoisLookup(
        status=WhoisStatus.ok,
        domain=domain,
        creation_date=creation_date,
        raw=raw,
    )


def _safe_raw(record: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for attr in ("registrar", "creation_date", "expiration_date", "updated_date"):
        value = getattr(record, attr, None)
        raw[attr] = str(value) if value is not None else None
    return raw


def _first_date(value: Any) -> datetime | None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, datetime):
                return item
        return None
    return value if isinstance(value, datetime) else None


_gateway: WhoisGateway | None = None


def get_whois_gateway(settings: Settings) -> WhoisGateway:
    """Return the process-wide gateway so adapters share cache and thread pool."""
    global _gateway
    if _gateway is None:
        _gateway = WhoisGateway(
            redis_url=settings.redis_url,
            record_ttl_seconds=settings.whois_record_ttl_seconds,
            negative_ttl_seconds=settings.whois_negative_ttl_seconds,
            max_workers=settings.whois_max_workers,
            socket_timeout_seconds=settings.whois_socket_timeout_seconds,
        )
    return _gateway


async def close_whois_gateway() -> None:
    global _gateway
    if _gateway is not None:
        await _gateway.close()
        _gateway = None
