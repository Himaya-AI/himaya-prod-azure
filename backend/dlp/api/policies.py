"""Immutable tenant DLP policy version APIs."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin
from backend.dlp.api.schemas import (
    PolicyDraftRequest,
    PolicyVersionResponse,
)
from backend.dlp.persistence.models import (
    DlpPolicyVersion,
    DlpTenantConfig,
)
from backend.dlp.policy import (
    build_default_policy,
    policy_to_document,
)
from backend.models.db_models import User
from backend.routers.auth import get_current_user

router = APIRouter()


@router.get("/policy", response_model=PolicyVersionResponse)
async def get_active_policy(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    config = await session.get(DlpTenantConfig, current_user.org_id)
    if config is None or config.active_policy_version_id is None:
        return PolicyVersionResponse(
            version=0,
            status="builtin",
            document=policy_to_document(build_default_policy()),
        )
    version = await session.get(
        DlpPolicyVersion, config.active_policy_version_id
    )
    if version is None or version.org_id != current_user.org_id:
        raise HTTPException(
            status_code=409,
            detail="Active DLP policy reference is invalid",
        )
    return _policy_response(version)


@router.get(
    "/policy/draft", response_model=PolicyVersionResponse | None
)
async def get_policy_draft(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse | None:
    draft = await _latest_draft(session, current_user.org_id)
    return _policy_response(draft) if draft else None


@router.put(
    "/policy/draft", response_model=PolicyVersionResponse
)
async def save_policy_draft(
    payload: PolicyDraftRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    draft = await _latest_draft(session, current_user.org_id)
    if draft is None:
        latest_version = await session.scalar(
            select(
                func.coalesce(func.max(DlpPolicyVersion.version), 0)
            ).where(
                DlpPolicyVersion.org_id == current_user.org_id
            )
        )
        draft = DlpPolicyVersion(
            org_id=current_user.org_id,
            version=int(latest_version or 0) + 1,
            status="draft",
            policy_document=payload.document.model_dump(
                mode="json"
            ),
            created_by=current_user.id,
        )
        session.add(draft)
    else:
        draft.policy_document = payload.document.model_dump(
            mode="json"
        )
        draft.created_by = current_user.id
    await session.flush()
    return _policy_response(draft)


@router.post(
    "/policy/publish", response_model=PolicyVersionResponse
)
async def publish_policy(
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    draft = await _latest_draft(session, current_user.org_id)
    if draft is None:
        raise HTTPException(
            status_code=404, detail="No DLP policy draft to publish"
        )
    await session.execute(
        update(DlpPolicyVersion)
        .where(
            DlpPolicyVersion.org_id == current_user.org_id,
            DlpPolicyVersion.status == "published",
        )
        .values(status="archived")
    )
    draft.status = "published"
    draft.published_at = datetime.now(timezone.utc)
    config = await session.get(DlpTenantConfig, current_user.org_id)
    if config is None:
        config = DlpTenantConfig(
            org_id=current_user.org_id,
            enabled=False,
            mode="monitor",
            domains=[],
            active_policy_version_id=draft.id,
            updated_by=current_user.id,
        )
        session.add(config)
    else:
        config.active_policy_version_id = draft.id
        config.updated_by = current_user.id
        config.updated_at = datetime.now(timezone.utc)
    await session.flush()
    return _policy_response(draft)


async def _latest_draft(
    session: AsyncSession, org_id
) -> DlpPolicyVersion | None:
    result = await session.execute(
        select(DlpPolicyVersion)
        .where(
            DlpPolicyVersion.org_id == org_id,
            DlpPolicyVersion.status == "draft",
        )
        .order_by(DlpPolicyVersion.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _policy_response(
    version: DlpPolicyVersion,
) -> PolicyVersionResponse:
    return PolicyVersionResponse(
        id=version.id,
        version=version.version,
        status=version.status,
        document=version.policy_document,
        created_at=version.created_at,
        published_at=version.published_at,
    )
