"""DLP v2 runtime status endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.schemas import DlpStatusResponse
from backend.dlp.config import get_dlp_settings
from backend.dlp.persistence.models import (
    DlpCommandOutbox,
    DlpMessage,
)
from backend.models.db_models import User
from backend.routers.auth import get_current_user

router = APIRouter()


@router.get("/status", response_model=DlpStatusResponse)
async def get_status(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DlpStatusResponse:
    settings = get_dlp_settings()
    counts_result = await session.execute(
        select(DlpMessage.state, func.count())
        .where(DlpMessage.org_id == current_user.org_id)
        .group_by(DlpMessage.state)
    )
    failed_outbox = await session.scalar(
        select(func.count())
        .select_from(DlpCommandOutbox)
        .where(
            DlpCommandOutbox.org_id == current_user.org_id,
            DlpCommandOutbox.status == "failed",
        )
    )
    return DlpStatusResponse(
        status=(
            "ready"
            if settings.gateway_pipeline_enabled
            else "disabled"
        ),
        pipeline_enabled=settings.gateway_pipeline_enabled,
        mode=settings.tenant_mode,
        classifier_url_configured=bool(
            settings.classifier_service_url
        ),
        message_counts={
            state: count for state, count in counts_result.all()
        },
        failed_outbox_commands=int(failed_outbox or 0),
    )
