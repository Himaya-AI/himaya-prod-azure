"""
Shared, hardened async Redis client.

Why this exists
---------------
The codebase historically called ``redis.asyncio.from_url(REDIS_URL,
decode_responses=True)`` in dozens of places — often once per request or per
background-loop iteration — with NO socket timeouts. On Azure Managed Redis
(cluster mode, TLS on :10000) this is fragile:

- No ``socket_connect_timeout`` → a slow/unreachable node blocks the asyncio
  event loop until the OS TCP timeout (tens of seconds), surfacing as
  ``redis.exceptions.TimeoutError: Timeout connecting to server`` and stalling
  delta-sync / auto-triage / password-reset.
- A fresh client per call means a new TLS handshake every time, multiplying
  connect latency and connection churn.

This module exposes a single, process-wide pooled client with bounded
timeouts, retry-on-timeout, periodic health checks, and correct TLS cert
handling for ``rediss://``. Callers should use ``get_redis()`` and MUST NOT
call ``aclose()`` on the returned client (it is shared).
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# One shared client per (decode_responses) mode. redis.asyncio.from_url keeps
# its own connection pool internally, so a single client fans out safely across
# all coroutines.
_clients: dict[bool, "object"] = {}


def get_redis(decode_responses: bool = True):
    """Return a shared, hardened async Redis client.

    Do NOT ``aclose()`` the returned client — it is a process-wide singleton.
    """
    global _clients
    existing = _clients.get(decode_responses)
    if existing is not None:
        return existing

    import redis.asyncio as aioredis

    kwargs = dict(
        decode_responses=decode_responses,
        # Bounded timeouts so a Redis hiccup can never block the event loop.
        socket_connect_timeout=3.0,
        socket_timeout=3.0,
        # Transparently retry a single timed-out command instead of bubbling
        # a hard error up into delta-sync / auto-triage.
        retry_on_timeout=True,
        # Detect and recycle dead connections (Azure Redis drops idle conns).
        health_check_interval=30,
        socket_keepalive=True,
        max_connections=32,
    )
    # Azure Managed Redis uses TLS (rediss://). redis-py needs an explicit
    # cert requirement or the handshake config is ambiguous.
    if _REDIS_URL.startswith("rediss://"):
        import ssl as _ssl
        kwargs["ssl_cert_reqs"] = _ssl.CERT_REQUIRED

    client = aioredis.from_url(_REDIS_URL, **kwargs)
    _clients[decode_responses] = client
    logger.info("Shared hardened Redis client initialised (decode_responses=%s)", decode_responses)
    return client
