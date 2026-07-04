from __future__ import annotations

from fastapi import APIRouter, Request

from utils.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(req: Request) -> HealthResponse:
    neo4j_ok = await req.app.state.neo4j.is_connected()
    return HealthResponse(
        status="ok" if neo4j_ok else "degraded",
        neo4j=neo4j_ok,
    )
