"""
Gmail per-user quota cooldown + background-loop leader election.

Problem this solves
-------------------
Heavily-polled mailboxes get HTTP 429 on nearly every Gmail call. Four separate
background pollers hit the SAME mailbox every cycle — delta sync (~35s), drafts
scan, spam sync, and the exfil/inbox-rules monitor — and because the backend is
HTTP-autoscaled to multiple replicas with no leader election, EACH loop runs on
EVERY replica. That multiplies Gmail API pressure until the per-user quota is
exhausted, at which point interactive quarantine/spam actions ALSO 429 and,
after retry backoff, surface to the user as a 504 gateway timeout.

Two mitigations, both best-effort (fail-open so ingestion never stops):

1. Per-user cooldown — when any background poller sees a 429 for a mailbox, it
   marks the mailbox; all background pollers then SKIP it until the cooldown
   expires, leaving quota headroom for interactive, user-initiated actions.

2. Loop leader election — a given background loop runs on only ONE replica at a
   time via a short-lived Redis key refreshed each cycle by the holder.
"""
from __future__ import annotations

import logging
import os
import socket

from backend.utils.redis_client import get_redis

logger = logging.getLogger(__name__)

_COOLDOWN_PREFIX = "gmail_cooldown:"
_DEFAULT_COOLDOWN = int(os.getenv("GMAIL_COOLDOWN_SECONDS", "600"))  # 10 min

# Stable-ish identity for this process/replica. Container Apps replicas get a
# unique HOSTNAME; fall back to socket hostname.
_REPLICA_ID = os.getenv("HOSTNAME") or socket.gethostname() or "unknown"


async def gmail_user_cooling_down(user_email: str) -> bool:
    """True if this mailbox was recently 429'd and should be skipped by
    background pollers."""
    if not user_email:
        return False
    try:
        return bool(await get_redis().get(_COOLDOWN_PREFIX + user_email.lower()))
    except Exception:
        return False


async def note_gmail_429(user_email: str, seconds: int = _DEFAULT_COOLDOWN) -> None:
    """Record that a mailbox is rate-limited so background pollers back off."""
    if not user_email:
        return
    try:
        await get_redis().set(_COOLDOWN_PREFIX + user_email.lower(), "1", ex=seconds)
        logger.info(
            f"Gmail cooldown set for {user_email} ({seconds}s) — background pollers will skip it"
        )
    except Exception:
        pass


async def acquire_loop_leader(name: str, ttl: int) -> bool:
    """Best-effort single-runner guard for a background loop across replicas.

    Returns True if THIS replica should run the loop body this cycle. The holder
    re-acquires (refreshes) every cycle; if it dies, the key expires after ``ttl``
    and another replica takes over. ``ttl`` should be ~2-3x the loop interval so a
    slow cycle doesn't drop leadership. Fails OPEN (returns True) if Redis is
    unavailable so ingestion never halts on a Redis hiccup.
    """
    key = f"loop_leader:{name}"
    try:
        r = get_redis()
        cur = await r.get(key)
        if cur is None:
            got = await r.set(key, _REPLICA_ID, nx=True, ex=ttl)
            return bool(got)
        if cur == _REPLICA_ID:
            # Still leader — refresh our hold.
            await r.set(key, _REPLICA_ID, ex=ttl)
            return True
        return False
    except Exception:
        return True
