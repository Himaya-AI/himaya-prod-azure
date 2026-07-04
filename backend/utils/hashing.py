"""
Password hashing using bcrypt directly — avoids passlib ARM64 wrap-bug crash.

Threading model
---------------
bcrypt.checkpw and bcrypt.hashpw are CPU-bound and intentionally slow
(~200-500ms each on ARM64). Running them on the asyncio event loop blocks
ALL other request handlers for the duration. Under sustained CSPM scan
activity, multiple concurrent logins can stack and push response times
past the ALB / curl timeout cliff (15s), surfacing as intermittent 504s
on /api/auth/login and any endpoint scheduled behind it.

The sync ``hash_password`` / ``verify_password`` helpers are kept for
internal/CLI/migration use, but request handlers should use the async
``hash_password_async`` / ``verify_password_async`` versions which offload
the bcrypt call to a thread via ``asyncio.to_thread``. ``asyncio.to_thread``
uses the default executor (separate from the CSPM/DSPM pool), so a busy
scan loop can't starve auth.
"""
from __future__ import annotations

import asyncio

import bcrypt


def hash_password(password: str) -> str:
    """Sync bcrypt hash. Use ``hash_password_async`` from request handlers."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Sync bcrypt verify. Use ``verify_password_async`` from request handlers."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


async def hash_password_async(password: str) -> str:
    """Offload bcrypt hashing to a thread to keep the event loop responsive."""
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(plain: str, hashed: str) -> bool:
    """Offload bcrypt verification to a thread to keep the event loop responsive."""
    return await asyncio.to_thread(verify_password, plain, hashed)
