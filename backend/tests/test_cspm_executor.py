"""
Tests for the dedicated CSPM/DSPM thread pool.

The pool isolates blocking I/O (sync boto3, OCI SDK, google-cloud-* SDK)
from the default asyncio executor so /health and request handlers stay
responsive during scans.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time

import pytest

from backend.services.cspm import executor as cspm_executor


@pytest.fixture(autouse=True)
def _reset_pool():
    """Ensure each test starts with a fresh pool."""
    cspm_executor.shutdown(wait=True)
    yield
    cspm_executor.shutdown(wait=True)


def test_get_executor_returns_singleton():
    p1 = cspm_executor.get_executor()
    p2 = cspm_executor.get_executor()
    assert p1 is p2


def test_executor_uses_configured_worker_count(monkeypatch):
    monkeypatch.setenv("HELIOS_CSPM_EXECUTOR_WORKERS", "8")
    cspm_executor.shutdown(wait=True)
    pool = cspm_executor.get_executor()
    assert pool._max_workers == 8


def test_executor_clamps_invalid_worker_count(monkeypatch):
    monkeypatch.setenv("HELIOS_CSPM_EXECUTOR_WORKERS", "not-a-number")
    cspm_executor.shutdown(wait=True)
    pool = cspm_executor.get_executor()
    # Falls back to default
    assert pool._max_workers == 4


def test_executor_clamps_excessive_worker_count(monkeypatch):
    monkeypatch.setenv("HELIOS_CSPM_EXECUTOR_WORKERS", "9999")
    cspm_executor.shutdown(wait=True)
    pool = cspm_executor.get_executor()
    assert pool._max_workers <= 32


def test_executor_thread_name_prefix():
    """Threads from the CSPM pool must be distinguishable from defaults."""
    pool = cspm_executor.get_executor()
    fut = pool.submit(lambda: threading.current_thread().name)
    name = fut.result(timeout=5)
    assert name.startswith("cspm-dspm")


@pytest.mark.asyncio
async def test_run_blocking_returns_value():
    result = await cspm_executor.run_blocking(lambda: 42)
    assert result == 42


@pytest.mark.asyncio
async def test_run_blocking_passes_args():
    result = await cspm_executor.run_blocking(lambda a, b: a + b, 3, 4)
    assert result == 7


@pytest.mark.asyncio
async def test_run_blocking_passes_kwargs():
    def _do(a, b=10):
        return a * b
    result = await cspm_executor.run_blocking(_do, 3, b=5)
    assert result == 15


@pytest.mark.asyncio
async def test_run_blocking_propagates_exception():
    def _boom():
        raise RuntimeError("nope")
    with pytest.raises(RuntimeError, match="nope"):
        await cspm_executor.run_blocking(_boom)


@pytest.mark.asyncio
async def test_run_blocking_runs_off_event_loop():
    """The blocking function must NOT run on the asyncio loop thread."""
    loop_thread = threading.get_ident()

    def _do():
        return threading.get_ident()

    worker_thread = await cspm_executor.run_blocking(_do)
    assert worker_thread != loop_thread


@pytest.mark.asyncio
async def test_run_blocking_pool_is_isolated_from_default():
    """
    Hammering the CSPM pool with many slow tasks must NOT block tasks
    submitted to the default loop executor. This is the bug fix \u2014 health
    checks (which use the default pool) must stay responsive during scans.
    """
    loop = asyncio.get_event_loop()

    async def _slow_cspm_task():
        # Block a CSPM pool worker for 300 ms
        return await cspm_executor.run_blocking(lambda: time.sleep(0.3) or "cspm-done")

    async def _default_pool_task():
        # Should complete quickly even under CSPM load
        start = time.perf_counter()
        await loop.run_in_executor(None, lambda: "default-done")
        return time.perf_counter() - start

    # Saturate the CSPM pool (4 workers) with 8 slow tasks
    cspm_tasks = [asyncio.create_task(_slow_cspm_task()) for _ in range(8)]
    await asyncio.sleep(0.05)  # let CSPM tasks start

    # Default pool task should still complete fast
    default_latency = await _default_pool_task()
    assert default_latency < 0.5, (
        f"default executor was blocked by CSPM pool ({default_latency:.2f}s)"
    )

    # Drain CSPM tasks
    results = await asyncio.gather(*cspm_tasks)
    assert all(r == "cspm-done" for r in results)
