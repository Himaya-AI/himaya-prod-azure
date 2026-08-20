"""DLP v2 runtime status endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_enterprise
from backend.dlp.api.message_views import reviewable_clause
from backend.dlp.api.schemas import DlpStatusResponse, FailedOutboxCommand
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
    reviewable_join = and_(
        DlpDecision.message_id == DlpMessage.id,
        DlpDecision.evaluation_version == 1,
    )
    reviewable_where = (
        DlpMessage.org_id == current_user.org_id,
        reviewable_clause(),
    )
    counts_result = await session.execute(
        select(DlpMessage.state, func.count())
        .where(DlpMessage.org_id == current_user.org_id)
        .group_by(DlpMessage.state)
    )
    reviewable_count = await session.scalar(
        select(func.count())
        .select_from(DlpMessage)
        .join(DlpDecision, reviewable_join)
        .where(*reviewable_where)
    )
    oldest_reviewable = (
        await session.execute(
            select(DlpMessage.received_at, DlpMessage.envelope_from)
            .join(DlpDecision, reviewable_join)
            .where(*reviewable_where)
            .order_by(DlpMessage.received_at.asc())
            .limit(1)
        )
    ).first()
    failed_outbox = await session.scalar(
        select(func.count())
        .select_from(DlpCommandOutbox)
        .where(
            DlpCommandOutbox.org_id == current_user.org_id,
            DlpCommandOutbox.status == "failed",
        )
    )
    failed_rows = (
        await session.execute(
            select(DlpCommandOutbox, DlpMessage.envelope_from)
            .outerjoin(
                DlpMessage,
                DlpMessage.id == DlpCommandOutbox.message_id,
            )
            .where(
                DlpCommandOutbox.org_id == current_user.org_id,
                DlpCommandOutbox.status == "failed",
            )
            .order_by(DlpCommandOutbox.updated_at.desc())
            .limit(20)
        )
    ).all()
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
        oldest_reviewable_at=(
            oldest_reviewable[0] if oldest_reviewable else None
        ),
        oldest_reviewable_from=(
            oldest_reviewable[1] if oldest_reviewable else None
        ),
        failed_outbox_commands=int(failed_outbox or 0),
        failed_outbox_items=[
            FailedOutboxCommand(
                command_id=row.id,
                message_id=row.message_id,
                command_type=row.command_type,
                last_error=row.last_error,
                attempts=row.attempts,
                updated_at=row.updated_at,
                envelope_from=envelope_from,
            )
            for row, envelope_from in failed_rows
        ],
    )
