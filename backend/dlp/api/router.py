"""DLP v2 control-plane routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.dlp.api.schemas import DlpStatusResponse
from backend.dlp.config import get_dlp_settings
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/api/dlp/v2", tags=["DLP v2"])


@router.get("/status", response_model=DlpStatusResponse)
async def get_status(current_user=Depends(get_current_user)) -> DlpStatusResponse:
    """Return non-sensitive runtime configuration for an authenticated user."""
    del current_user
    settings = get_dlp_settings()
    return DlpStatusResponse(
        status="ready" if settings.gateway_pipeline_enabled else "disabled",
        pipeline_enabled=settings.gateway_pipeline_enabled,
        mode=settings.tenant_mode,
        classifier_url_configured=bool(settings.classifier_service_url),
    )
