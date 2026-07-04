"""
Response cache for hot read-only endpoints.

Goal: short-lived (15–60s) Redis-backed cache for endpoints that are hit hard
by the dashboard auto-refresh + multi-panel mount fan-out (Workspace Security
loads ~6 endpoints in parallel on every page load). Each restart of the
backend used to leave panels blank because every call missed cache and raced
against task replacement.

This is intentionally simple:
- key = f"{prefix}:{org_id}:{stable_hash(extra)}"
- value = pickled return value (we use json with a sentinel for dict/list)
- TTL = caller-specified (default 30s)
- soft-fail: if Redis is unreachable, just compute and return uncached
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
_PREFIX = "rc:"  # response-cache prefix to keep keys segregated


async def _get_redis():
    """Return an async Redis client, or None if unavailable."""
    try:
        import redis.asyncio as aioredis  # type: ignore
        return aioredis.from_url(_REDIS_URL, decode_responses=True, socket_timeout=1.0)
    except Exception as exc:
        logger.debug(f"response_cache: redis unavailable ({exc})")
        return None


def _key(prefix: str, org_id: str, extra: Optional[dict] = None) -> str:
    if extra:
        # canonicalise
        blob = json.dumps(extra, sort_keys=True, default=str)
        h = hashlib.sha1(blob.encode()).hexdigest()[:12]
        return f"{_PREFIX}{prefix}:{org_id}:{h}"
    return f"{_PREFIX}{prefix}:{org_id}"


async def cache_get(prefix: str, org_id: str, extra: Optional[dict] = None) -> Optional[Any]:
    """Return cached value or None."""
    r = await _get_redis()
    if r is None:
        return None
    try:
        raw = await r.get(_key(prefix, org_id, extra))
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.debug(f"response_cache.get failed ({exc})")
        return None
    finally:
        try:
            await r.aclose()
        except Exception:
            pass


async def cache_set(
    prefix: str,
    org_id: str,
    value: Any,
    ttl: int = 30,
    extra: Optional[dict] = None,
) -> None:
    """Store value with TTL seconds. Non-JSON-serialisable values are skipped."""
    r = await _get_redis()
    if r is None:
        return
    try:
        payload = json.dumps(value, default=str)
        await r.set(_key(prefix, org_id, extra), payload, ex=ttl)
    except (TypeError, ValueError) as exc:
        logger.debug(f"response_cache.set skipped non-serialisable value for {prefix}: {exc}")
    except Exception as exc:
        logger.debug(f"response_cache.set failed ({exc})")
    finally:
        try:
            await r.aclose()
        except Exception:
            pass


async def cache_invalidate(prefix: str, org_id: str, extra: Optional[dict] = None) -> None:
    """Delete a single cache entry (best-effort)."""
    r = await _get_redis()
    if r is None:
        return
    try:
        await r.delete(_key(prefix, org_id, extra))
    except Exception as exc:
        logger.debug(f"response_cache.invalidate failed ({exc})")
    finally:
        try:
            await r.aclose()
        except Exception:
            pass


def cached_endpoint(prefix: str, ttl: int = 30):
    """
    Decorator for FastAPI endpoint functions that take `current_user` and
    return a JSON-serialisable dict/list. Caches per-org for `ttl` seconds.

    The decorator inspects kwargs for any non-(db/current_user) primitive
    args and uses them as part of the cache key so query-param variations
    (page, filters) get their own entries.

    NOTE: keep `ttl` short (15–60s). This exists to absorb dashboard
    auto-refresh bursts and panel fan-out, not to mask stale data.
    """
    def decorator(fn: Callable):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            if current_user is None:
                return await fn(*args, **kwargs)
            try:
                org_id = str(current_user.org_id)
            except Exception:
                return await fn(*args, **kwargs)

            # Build extra-key dict from primitive query params
            extra = {
                k: v for k, v in kwargs.items()
                if k not in ("current_user", "db", "background")
                and isinstance(v, (str, int, float, bool, type(None)))
            }

            cached = await cache_get(prefix, org_id, extra=extra)
            if cached is not None:
                return cached

            result = await fn(*args, **kwargs)
            # only cache JSON-serialisable results
            try:
                json.dumps(result, default=str)
                await cache_set(prefix, org_id, result, ttl=ttl, extra=extra)
            except (TypeError, ValueError):
                pass
            return result
        return wrapper
    return decorator
