from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.api.schemas import (
    CacheDeleteResponse,
    CacheOverrideRequest,
    CacheOverrideResponse,
    HealthResponse,
    ReputationLookupRequest,
    ReputationLookupResponse,
    SourceListResponse,
)
from app.config.settings import Settings
from app.core.orchestrator import ReputationOrchestrator


router = APIRouter(prefix="/api/v1/reputation", tags=["reputation"])


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_orchestrator(request: Request) -> ReputationOrchestrator:
    return request.app.state.orchestrator


async def require_admin(
    request: Request,
    x_admin_api_key: str | None = Header(default=None),
) -> None:
    settings: Settings = request.app.state.settings
    if settings.environment != "local" and not settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API key is not configured for this environment",
        )
    if settings.admin_api_key:
        if x_admin_api_key != settings.admin_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin API key",
            )


@router.post("/lookup", response_model=ReputationLookupResponse)
async def lookup_reputation(
    payload: ReputationLookupRequest,
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
) -> ReputationLookupResponse:
    request_id = f"rep_{uuid.uuid4().hex[:12]}"
    started = time.perf_counter()
    results = await orchestrator.lookup_many(
        payload.entities,
        force_refresh=payload.options.force_refresh,
        include_raw_signals=payload.options.include_raw_signals,
        max_sources=payload.options.max_sources,
    )
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    return ReputationLookupResponse(
        results=results,
        request_id=request_id,
        latency_ms=latency_ms,
    )


@router.get("/cache/{key:path}")
async def get_cache_entry(
    key: str,
    _: None = Depends(require_admin),
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
):
    ti_key = key if key.startswith("rep:v1:") else key
    entry = await orchestrator.cache.get_entry(ti_key)
    if entry is None:
        raise HTTPException(status_code=404, detail="Cache entry not found")
    return entry


@router.delete("/cache/{key:path}", response_model=CacheDeleteResponse)
async def delete_cache_entry(
    key: str,
    _: None = Depends(require_admin),
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
) -> CacheDeleteResponse:
    deleted = await orchestrator.cache.delete(key)
    return CacheDeleteResponse(key=key, deleted=deleted)


@router.put("/cache/{key:path}/override", response_model=CacheOverrideResponse)
async def override_cache_entry(
    key: str,
    payload: CacheOverrideRequest,
    _: None = Depends(require_admin),
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
) -> CacheOverrideResponse:
    ttl_seconds = None
    if payload.expires_at:
        ttl_seconds = max(
            int((payload.expires_at - datetime.now(timezone.utc)).total_seconds()),
            1,
        )
    await orchestrator.cache.set_override(
        key,
        {
            "verdict": payload.verdict.value,
            "score": payload.score,
            "confidence": payload.confidence,
            "reason": payload.reason,
            "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
        },
        ttl_seconds=ttl_seconds,
    )
    return CacheOverrideResponse(
        key=key,
        status="override_set",
        expires_at=payload.expires_at,
    )


@router.get("/health", response_model=HealthResponse)
async def health(
    request: Request,
    settings: Settings = Depends(get_settings),
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
) -> HealthResponse:
    redis_ok = await orchestrator.cache.ping()
    sources = await orchestrator.source_statuses()
    source_problem = any(source.enabled and source.status not in {"healthy", "not_configured"} for source in sources)
    status_text = "degraded" if source_problem else "healthy"
    return HealthResponse(
        service=settings.service_name,
        environment=settings.environment,
        status=status_text,
        redis="connected" if redis_ok else "memory_fallback",
        sources=sources,
    )


@router.get("/sources", response_model=SourceListResponse)
async def sources(
    orchestrator: ReputationOrchestrator = Depends(get_orchestrator),
) -> SourceListResponse:
    return SourceListResponse(sources=await orchestrator.source_statuses())
