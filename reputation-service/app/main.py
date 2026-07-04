from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as reputation_router
from app.config.settings import load_settings
from app.core.cache import ReputationCache
from app.core.correlator import SignalCorrelator
from app.core.orchestrator import ReputationOrchestrator
from app.core.scorer import DeterministicScorer
from app.sources.registry import load_source_registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cache = ReputationCache(
        redis_url=settings.redis_url,
        default_ttl_seconds=settings.cache_ttl_seconds,
        error_ttl_seconds=settings.error_ttl_seconds,
    )
    await cache.connect()
    registry = load_source_registry(settings)
    app.state.settings = settings
    app.state.cache = cache
    app.state.registry = registry
    app.state.orchestrator = ReputationOrchestrator(
        cache=cache,
        registry=registry,
        correlator=SignalCorrelator(),
        scorer=DeterministicScorer(),
    )
    try:
        yield
    finally:
        await cache.close()


app = FastAPI(
    title="Helios Reputation Service",
    description="Sender, link, domain, and attachment-hash reputation lookup service.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(reputation_router)


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "service": "helios-reputation-service",
        "status": "ok",
        "docs": "/docs",
    }
