from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import redis.asyncio as aioredis
from fastapi import FastAPI

from app.routers import classify
from app.service.deterministic.runner import DeterministicRunner
from config.redis_client import create_redis_client
from config.settings import get_settings

settings = get_settings()

logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger(__name__)


def _verify_betterleaks() -> None:
    """Fails fast at startup if BetterLeaks isn't installed where configured."""
    binary = settings.BETTERLEAKS_BINARY

    if not Path(binary).is_file():
        raise RuntimeError(
            f"BetterLeaks binary not found: {binary} — run scripts/install_betterleaks.sh"
        )
    if not os.access(binary, os.X_OK):
        raise RuntimeError(f"BetterLeaks binary not executable: {binary}")


async def _warmup_betterleaks() -> None:
    """Runs a dummy scan so the binary is warm in the OS page cache before
    real traffic hits it."""
    proc = await asyncio.create_subprocess_exec(
        settings.BETTERLEAKS_BINARY,
        "stdin",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
        "--redact",
        "--exit-code",
        "0",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.wait_for(proc.communicate(input=b"warmup"), timeout=10)


async def _verify_redis() -> aioredis.Redis:
    client = create_redis_client(settings)
    try:
        await client.ping()
    except Exception as exc:
        raise RuntimeError(f"Redis unreachable at {settings.REDIS_URL}") from exc
    return client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --------------------------------------------------------
    logger.info("Starting dlp-classifier...")

    logger.info("Verifying BetterLeaks binary...")
    _verify_betterleaks()

    logger.info("Warming up BetterLeaks...")
    await _warmup_betterleaks()

    logger.info("Connecting to Redis...")
    app.state.redis = await _verify_redis()

    logger.info("Initializing DeterministicRunner...")
    app.state.runner = DeterministicRunner(app.state.redis)
    app.state.engine = app.state.runner.engine

    logger.info("dlp-classifier ready.")
    yield

    # -- Shutdown ---------------------------------------------------------
    logger.info("Shutting down...")
    await app.state.redis.aclose()


app = FastAPI(
    title="dlp-classifier",
    description="DLP classification microservice",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(classify.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.APP_HOST, port=settings.APP_PORT, log_level=settings.LOG_LEVEL.lower())
