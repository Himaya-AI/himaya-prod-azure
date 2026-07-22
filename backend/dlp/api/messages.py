"""Tenant-scoped DLP message review and action APIs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin
from backend.dlp.api.schemas import (
    DlpMessageSummary,
    MessageListResponse,
    ReviewActionRequest,
    ReviewActionResponse,
)
from backend.dlp.contracts import (
    CommandType,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.persistence.models import (
    DlpDecision,
    DlpMessage,
    DlpReviewAction,
)
from backend.dlp.persistence.repositories import (
    CommandOutboxRepository,
)
from backend.models.db_models import User
from backend.routers.auth import get_current_user

router = APIRouter()


@router.get("/messages", response_model=MessageListResponse)
async def list_messages(
    state: str | None = None,
    before: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MessageListResponse:
    statement = (
        select(DlpMessage, DlpDecision)
        .outerjoin(
            DlpDecision,
            and_(
                DlpDecision.message_id == DlpMessage.id,
                DlpDecision.evaluation_version == 1,
            ),
        )
        .where(DlpMessage.org_id == current_user.org_id)
        .order_by(DlpMessage.received_at.desc())
        .limit(limit + 1)
    )
    if state:
        statement = statement.where(DlpMessage.state == state)
    if before:
        statement = statement.where(DlpMessage.received_at < before)
    rows = (await session.execute(statement)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        _message_summary(message, decision)
        for message, decision in rows
    ]
    return MessageListResponse(
        items=items,
        next_cursor=(
            items[-1].received_at if has_more and items else None
        ),
    )


@router.get(
    "/messages/{message_id}", response_model=DlpMessageSummary
)
async def get_message(
    message_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DlpMessageSummary:
    message, decision = await _tenant_message(
        session, current_user.org_id, message_id
    )
    return _message_summary(message, decision)


@router.post(
    "/messages/{message_id}/release",
    response_model=ReviewActionResponse,
)
async def release_message(
    message_id: UUID,
    payload: ReviewActionRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> ReviewActionResponse:
    return await _review_action(
        session=session,
        current_user=current_user,
        message_id=message_id,
        payload=payload,
        action="release",
    )


@router.post(
    "/messages/{message_id}/stop",
    response_model=ReviewActionResponse,
)
async def stop_message(
    message_id: UUID,
    payload: ReviewActionRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> ReviewActionResponse:
    return await _review_action(
        session=session,
        current_user=current_user,
        message_id=message_id,
        payload=payload,
        action="stop",
    )


async def _review_action(
    *,
    session: AsyncSession,
    current_user: User,
    message_id: UUID,
    payload: ReviewActionRequest,
    action: Literal["release", "stop"],
) -> ReviewActionResponse:
    existing_result = await session.execute(
        select(DlpReviewAction).where(
            DlpReviewAction.org_id == current_user.org_id,
            DlpReviewAction.idempotency_key
            == payload.idempotency_key,
        )
    )
    existing = existing_result.scalar_one_or_none()
    if existing is not None:
        if (
            existing.message_id != message_id
            or existing.action != action
        ):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key was used for another action",
            )
        return ReviewActionResponse(
            message_id=message_id,
            action=action,
            command_id=existing.command_id,
            status="already_queued",
        )

    message, decision = await _tenant_message(
        session, current_user.org_id, message_id
    )
    if (
        decision is None
        or decision.effective_action != "hold"
        or message.state not in {"decided", "held"}
    ):
        raise HTTPException(
            status_code=409,
            detail="Only a held DLP message can be reviewed",
        )
    command_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        (
            f"dlp-review-v1:{current_user.org_id}:"
            f"{payload.idempotency_key}"
        ),
    )
    command_type = (
        CommandType.RELEASE
        if action == "release"
        else CommandType.STOP
    )
    command = GatewayCommand(
        command_id=command_id,
        command_type=command_type,
        message_id=message_id,
        org_id=str(current_user.org_id),
        expected_state=GatewayMessageState.CAPTURED,
        reason=payload.reason,
        metadata={
            "reviewed_by": str(current_user.id),
            "policy_version": decision.policy_version,
        },
    )
    session.add(
        DlpReviewAction(
            org_id=current_user.org_id,
            message_id=message_id,
            actor_user_id=current_user.id,
            action=action,
            reason=payload.reason,
            idempotency_key=payload.idempotency_key,
            command_id=command_id,
        )
    )
    await CommandOutboxRepository(session).enqueue(command)
    message.state = f"{action}_requested"
    await session.flush()
    return ReviewActionResponse(
        message_id=message_id,
        action=action,
        command_id=command_id,
        status="queued",
    )


async def _tenant_message(
    session: AsyncSession, org_id: UUID, message_id: UUID
) -> tuple[DlpMessage, DlpDecision | None]:
    result = await session.execute(
        select(DlpMessage, DlpDecision)
        .outerjoin(
            DlpDecision,
            and_(
                DlpDecision.message_id == DlpMessage.id,
                DlpDecision.evaluation_version == 1,
            ),
        )
        .where(
            DlpMessage.id == message_id,
            DlpMessage.org_id == org_id,
        )
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404, detail="DLP message not found"
        )
    return row[0], row[1]


def _message_summary(
    message: DlpMessage, decision: DlpDecision | None
) -> DlpMessageSummary:
    return DlpMessageSummary(
        message_id=message.id,
        envelope_from=message.envelope_from,
        envelope_to=list(message.envelope_to),
        state=message.state,
        received_at=message.received_at,
        intended_action=(
            decision.intended_action if decision else None
        ),
        effective_action=(
            decision.effective_action if decision else None
        ),
        explanation=decision.explanation if decision else None,
    )
