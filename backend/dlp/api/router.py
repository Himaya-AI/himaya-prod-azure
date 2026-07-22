"""DLP v2 control-plane routes."""

from __future__ import annotations

from fastapi import APIRouter

from backend.dlp.api import messages, policies, settings, status

router = APIRouter(prefix="/api/dlp/v2", tags=["DLP v2"])
router.include_router(status.router)
router.include_router(settings.router)
router.include_router(policies.router)
router.include_router(messages.router)
