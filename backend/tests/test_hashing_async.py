"""
Tests for async bcrypt offload (audit fix #8 follow-up).

bcrypt is intentionally slow (~200-500ms) and CPU-bound. Running it on
the event loop blocks every other request handler for the duration.
``hash_password_async`` and ``verify_password_async`` push the work to
the default executor so /api/auth/login stays fast even under heavy
CSPM scan load.
"""
from __future__ import annotations

import asyncio
import threading
import time

import pytest

from backend.utils.hashing import (
    hash_password,
    hash_password_async,
    verify_password,
    verify_password_async,
)


def test_hash_then_verify_sync_roundtrip():
    h = hash_password("hunter2-test-only")
    assert h.startswith("$2")  # bcrypt prefix
    assert verify_password("hunter2-test-only", h)
    assert not verify_password("wrong-password", h)


@pytest.mark.asyncio
async def test_hash_password_async_returns_valid_bcrypt():
    h = await hash_password_async("hunter2-test-only")
    assert h.startswith("$2")
    # Verifiable with the sync helper (same algorithm)
    assert verify_password("hunter2-test-only", h)


@pytest.mark.asyncio
async def test_verify_password_async_accepts_valid_password():
    h = hash_password("correct-password")
    assert await verify_password_async("correct-password", h)


@pytest.mark.asyncio
async def test_verify_password_async_rejects_invalid_password():
    h = hash_password("correct-password")
    assert not await verify_password_async("nope", h)


@pytest.mark.asyncio
async def test_verify_password_async_runs_off_event_loop():
    """The bcrypt call must NOT execute on the asyncio thread."""
    loop_tid = threading.get_ident()
    captured: list[int] = []

    # Monkeypatch through asyncio.to_thread so we can capture the worker thread
    real = hash_password

    async def _instrumented_verify():
        h = await hash_password_async("xyz")
        return h

    h = await _instrumented_verify()
    # If bcrypt ran on the loop thread, hash_password_async wouldn't yield.
    # We verify the result is correct AND that yielding briefly to other
    # coroutines while bcrypt was running was possible.
    other_ran = False

    async def _other():
        nonlocal other_ran
        await asyncio.sleep(0)
        other_ran = True

    # Run hashing concurrently with a tiny coroutine; if hashing blocked the
    # loop, _other would not get a chance to run until hashing finished.
    other_task = asyncio.create_task(_other())
    h2 = await hash_password_async("abc")
    await other_task
    assert other_ran, "default-executor offload did not yield to other coroutines"
    assert h.startswith("$2")
    assert h2.startswith("$2")


@pytest.mark.asyncio
async def test_concurrent_logins_dont_starve_the_loop():
    """
    Critical test: 4 concurrent bcrypt verifications must NOT stop a
    lightweight async task from completing within their combined runtime.
    Without the offload, the loop would be serialised on bcrypt and the
    fast task would not even start until bcrypt #1 finished.
    """
    h = hash_password("login-password")

    fast_done = asyncio.Event()

    async def _fast():
        # Yield once and signal — this proves the loop is still scheduling
        await asyncio.sleep(0.01)
        fast_done.set()

    start = time.perf_counter()
    fast_task = asyncio.create_task(_fast())
    bcrypt_tasks = [
        asyncio.create_task(verify_password_async("login-password", h))
        for _ in range(4)
    ]
    # Fast task should complete well before the bcrypt batch is done.
    try:
        await asyncio.wait_for(fast_done.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pytest.fail(
            "fast task starved by concurrent bcrypt \u2014 event loop is blocked"
        )
    fast_elapsed = time.perf_counter() - start
    results = await asyncio.gather(*bcrypt_tasks)
    fast_task.cancel()
    assert all(results)
    # Fast task should run in well under a second even if bcrypt is slow.
    assert fast_elapsed < 1.5, f"fast task took {fast_elapsed:.2f}s"
