"""DLP v2 runtime status endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_enterprise
from backend.dlp.api.message_views import REVIEWABLE_STATES
from backend.dlp.api.schemas import DlpStatusResponse
from backend.dlp.config import get_dlp_settings
from backend.dlp.persistence.models import (
    DlpCommandOutbox,
    DlpDecision,
    DlpMessage,
)
from backend.models.db_models import User

router = APIRouter()


@router.get("/status", response_model=DlpStatusResponse)
async def get_status(
    current_user: User = Depends(require_dlp_enterprise),
    session: AsyncSession = Depends(get_db),
) -> DlpStatusResponse:
    settings = get_dlp_settings()
    counts_result = await session.execute(
        select(DlpMessage.state, func.count())
        .where(DlpMessage.org_id == current_user.org_id)
        .group_by(DlpMessage.state)
    )
    reviewable_count = await session.scalar(
        select(func.count())
        .select_from(DlpMessage)
        .join(
            DlpDecision,
            and_(
                DlpDecision.message_id == DlpMessage.id,
                DlpDecision.evaluation_version == 1,
            ),
        )
        .where(
            DlpMessage.org_id == current_user.org_id,
            DlpMessage.state.in_(tuple(REVIEWABLE_STATES)),
            DlpDecision.effective_action == "hold",
        )
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
        reviewable_count=int(reviewable_count or 0),
        failed_outbox_commands=int(failed_outbox or 0),
    )
