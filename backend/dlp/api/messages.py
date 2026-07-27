"""Tenant-scoped DLP message review and action APIs."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin, require_dlp_enterprise
from backend.dlp.api.message_views import (
    PREVIEW_MAX_MIME_BYTES,
    PREVIEW_MAX_TEXT_CHARS,
    REVIEWABLE_STATES,
    is_reviewable,
    sanitize_findings,
    sanitize_limitations,
    sanitize_preview_text,
)
from backend.dlp.api.schemas import (
    DlpExtractionLimitation,
    DlpFindingSummary,
    DlpMessageDetail,
    DlpMessageSummary,
    DlpPartSummary,
    DlpReviewHistoryItem,
    MessageListResponse,
    ReviewActionRequest,
    ReviewActionResponse,
)
from backend.dlp.config import get_dlp_settings
from backend.dlp.contracts import (
    CommandType,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.extraction import (
    MimeExtractionLimits,
    SafeMimeExtractor,
)
from backend.dlp.persistence.models import (
    DlpClassificationResult,
    DlpDecision,
    DlpMessage,
    DlpMessagePart,
    DlpReviewAction,
)
from backend.dlp.persistence.repositories import (
    CommandOutboxRepository,
)
from backend.dlp.storage.azure_mime_store import (
    AzureBlobMimeStore,
    MimeStorageError,
)
from backend.models.db_models import User

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/messages", response_model=MessageListResponse)
async def list_messages(
    state: str | None = None,
    reviewable: bool | None = Query(default=None),
    before: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(require_dlp_enterprise),
    session: AsyncSession = Depends(get_db),
) -> MessageListResponse:
    if reviewable is True and state is not None:
        raise HTTPException(
            status_code=422,
            detail="Cannot combine reviewable=true with state",
        )

    decision_join = and_(
        DlpDecision.message_id == DlpMessage.id,
        DlpDecision.evaluation_version == 1,
    )
    if reviewable is True:
        statement = (
            select(DlpMessage, DlpDecision)
            .join(DlpDecision, decision_join)
            .where(
                DlpMessage.org_id == current_user.org_id,
                DlpMessage.state.in_(tuple(REVIEWABLE_STATES)),
                DlpDecision.effective_action == "hold",
            )
            .order_by(DlpMessage.received_at.desc())
            .limit(limit + 1)
        )
    else:
        statement = (
            select(DlpMessage, DlpDecision)
            .outerjoin(DlpDecision, decision_join)
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
    "/messages/{message_id}", response_model=DlpMessageDetail
)
async def get_message(
    message_id: UUID,
    current_user: User = Depends(require_dlp_enterprise),
    session: AsyncSession = Depends(get_db),
) -> DlpMessageDetail:
    message, decision = await _tenant_message(
        session, current_user.org_id, message_id
    )
    classification = await _latest_classification(session, message.id)
    parts_result = await session.execute(
        select(DlpMessagePart)
        .where(DlpMessagePart.message_id == message.id)
        .order_by(DlpMessagePart.part_index.asc())
    )
    parts = list(parts_result.scalars().all())
    history_result = await session.execute(
        select(DlpReviewAction)
        .where(
            DlpReviewAction.org_id == current_user.org_id,
            DlpReviewAction.message_id == message.id,
        )
        .order_by(DlpReviewAction.created_at.desc())
    )
    history = list(history_result.scalars().all())

    findings = sanitize_findings(
        list(decision.finding_references)
        if decision is not None
        else None,
        list(classification.findings)
        if classification is not None
        else None,
    )
    limitations = sanitize_limitations(
        list(classification.limitations)
        if classification is not None
        else None
    )
    for part in parts:
        if part.limitation_code:
            limitations.extend(
                sanitize_limitations(
                    [
                        {
                            "code": part.limitation_code,
                            "detail": part.limitation_detail or "",
                        }
                    ]
                )
            )

    subject, preview, preview_available = await _safe_preview(message)
    summary = _message_summary(message, decision)
    return DlpMessageDetail(
        **summary.model_dump(),
        policy_version=(
            decision.policy_version if decision is not None else None
        ),
        matched_rule_ids=(
            list(decision.matched_rule_ids)
            if decision is not None
            else []
        ),
        findings=[
            DlpFindingSummary.model_validate(item) for item in findings
        ],
        extraction_limitations=[
            DlpExtractionLimitation.model_validate(item)
            for item in limitations
        ],
        parts=[
            DlpPartSummary(
                part_index=part.part_index,
                content_type=part.content_type,
                filename=part.filename,
                extraction_status=part.extraction_status,
                limitation_code=part.limitation_code,
                limitation_detail=part.limitation_detail,
            )
            for part in parts
        ],
        subject=subject,
        sanitized_preview=preview,
        preview_available=preview_available,
        review_history=[
            DlpReviewHistoryItem(
                action=cast(Literal["release", "stop"], item.action),
                reason=item.reason,
                actor_user_id=item.actor_user_id,
                created_at=item.created_at,
            )
            for item in history
            if item.action in {"release", "stop"}
        ],
    )


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
    if not is_reviewable(message, decision):
        raise HTTPException(
            status_code=409,
            detail="Only a held DLP message can be reviewed",
        )
    assert decision is not None
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


async def _latest_classification(
    session: AsyncSession, message_id: UUID
) -> DlpClassificationResult | None:
    result = await session.execute(
        select(DlpClassificationResult)
        .where(DlpClassificationResult.message_id == message_id)
        .order_by(DlpClassificationResult.started_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


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
        reviewable=is_reviewable(message, decision),
    )


async def _safe_preview(
    message: DlpMessage,
) -> tuple[str | None, str | None, bool]:
    """Best-effort subject/preview. Never fails the detail response."""
    settings = get_dlp_settings()
    if not (
        settings.azure_storage_connection_string
        or settings.azure_storage_account
    ):
        return None, None, False
    if message.mime_size > PREVIEW_MAX_MIME_BYTES:
        return None, None, False

    store: AzureBlobMimeStore | None = None
    try:
        store = AzureBlobMimeStore(
            container=settings.mime_blob_container,
            connection_string=settings.azure_storage_connection_string,
            storage_account=settings.azure_storage_account,
        )
        raw = await store.download(
            message.blob_uri,
            expected_sha256=message.mime_sha256,
            max_bytes=PREVIEW_MAX_MIME_BYTES,
        )
        extraction = await SafeMimeExtractor(
            MimeExtractionLimits(
                max_mime_bytes=PREVIEW_MAX_MIME_BYTES,
                max_text_bytes=PREVIEW_MAX_TEXT_CHARS * 4,
                max_parts=40,
                attachment_timeout_seconds=3.0,
            )
        ).extract(raw)
        subject = extraction.subject.strip() or None
        preview = sanitize_preview_text(extraction.text) or None
        return subject, preview, bool(subject or preview)
    except (MimeStorageError, Exception) as exc:
        logger.info(
            "dlp.message_preview_unavailable message_id=%s error=%s",
            message.id,
            exc,
        )
        return None, None, False
    finally:
        if store is not None:
            try:
                await store.close()
            except Exception:
                pass
