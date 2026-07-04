"""
Dedicated thread pool for sync-IO CSPM/DSPM scan work.

Why this exists
---------------
The default asyncio executor is shared with uvicorn's request handlers,
SQLAlchemy's sync fallback path, and every ``loop.run_in_executor(None, ...)``
call in the codebase. When CSPM fires multi-region sync boto3 calls (S3,
IAM, EC2, CloudTrail across many regions), it can saturate that pool and
make ``/health`` time out, which causes ECS to recycle the task.

Routing CSPM/DSPM blocking work to a dedicated pool with a fixed, small
worker cap keeps the default executor available for /health + API
handlers, and gives us a single knob to tune scan throughput.

Usage
-----
    from backend.services.cspm.executor import run_blocking

    result = await run_blocking(sync_function, arg1, arg2)

Configuration
-------------
Set ``HELIOS_CSPM_EXECUTOR_WORKERS`` env var to override the worker count.
Defaults to 4 \u2014 enough to keep multi-region AWS scans moving without
opening too many concurrent TCP sockets to AWS endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

_DEFAULT_WORKERS = 4


def _make_executor() -> ThreadPoolExecutor:
    raw = os.getenv("HELIOS_CSPM_EXECUTOR_WORKERS", "")
    try:
        workers = int(raw) if raw else _DEFAULT_WORKERS
    except ValueError:
        workers = _DEFAULT_WORKERS
    workers = max(1, min(workers, 32))
    logger.info(f"CSPM/DSPM thread pool initialised with {workers} workers")
    return ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="cspm-dspm",
    )


# Lazy-initialised singleton. We intentionally don't create the pool at
# import time so test runs that never touch CSPM don't pay the overhead.
_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def get_executor() -> ThreadPoolExecutor:
    """Get (or create) the shared CSPM/DSPM thread pool."""
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:  # double-checked locking
                _executor = _make_executor()
    return _executor


async def run_blocking(func: Callable[..., T], *args, **kwargs) -> T:
    """
    Run ``func(*args, **kwargs)`` in the dedicated CSPM/DSPM pool.

    Functionally equivalent to ``loop.run_in_executor(None, func, *args)``
    but isolated from the default pool used by request handlers.
    """
    loop = asyncio.get_event_loop()
    pool = get_executor()
    if kwargs:
        # run_in_executor doesn't support kwargs directly
        from functools import partial
        return await loop.run_in_executor(pool, partial(func, *args, **kwargs))
    return await loop.run_in_executor(pool, func, *args)


def shutdown(wait: bool = False) -> None:
    """Shutdown the pool (for clean test teardown)."""
    global _executor
    with _executor_lock:
        if _executor is not None:
            _executor.shutdown(wait=wait)
            _executor = None
