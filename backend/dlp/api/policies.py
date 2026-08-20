"""Immutable tenant DLP policy version APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin, require_dlp_enterprise
from backend.dlp.api.schemas import (
    PolicyDraftRequest,
    PolicyPublishRequest,
    PolicyVersionResponse,
)
from backend.dlp.config import get_dlp_settings
from backend.dlp.persistence.models import (
    DlpPolicyVersion,
    DlpTenantConfig,
)
from backend.dlp.policy import (
    PolicyDocument,
    build_default_policy,
    policy_to_document,
)
from backend.models.db_models import User

router = APIRouter()


@router.get("/policy", response_model=PolicyVersionResponse)
async def get_active_policy(
    current_user: User = Depends(require_dlp_enterprise),
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
    current_user: User = Depends(require_dlp_enterprise),
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
    draft = await _latest_draft(
        session, current_user.org_id, for_update=True
    )
    if payload.expected_id is not None:
        if (
            draft is None
            or draft.id != payload.expected_id
            or (
                payload.expected_version is not None
                and draft.version != payload.expected_version
            )
        ):
            raise HTTPException(
                status_code=409,
                detail="Policy draft has changed. Reload and try again.",
            )
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
    payload: PolicyPublishRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    draft = await _latest_draft(
        session, current_user.org_id, for_update=True
    )
    if draft is None:
        raise HTTPException(
            status_code=404, detail="No DLP policy draft to publish"
        )
    if (
        draft.id != payload.draft_id
        or draft.version != payload.expected_version
    ):
        raise HTTPException(
            status_code=409,
            detail="Policy draft has changed. Reload and try again.",
        )
    stored = PolicyDocument.model_validate(draft.policy_document)
    if stored.model_dump(mode="json") != payload.document.model_dump(
        mode="json"
    ):
        raise HTTPException(
            status_code=409,
            detail="Policy draft has changed. Reload and try again.",
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
    config_result = await session.execute(
        select(DlpTenantConfig)
        .where(DlpTenantConfig.org_id == current_user.org_id)
        .with_for_update()
    )
    config = config_result.scalar_one_or_none()
    if config is None:
        defaults = get_dlp_settings()
        config = DlpTenantConfig(
            org_id=current_user.org_id,
            enabled=defaults.gateway_pipeline_enabled,
            mode=defaults.tenant_mode,
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
    session: AsyncSession,
    org_id: UUID,
    *,
    for_update: bool = False,
) -> DlpPolicyVersion | None:
    statement = (
        select(DlpPolicyVersion)
        .where(
            DlpPolicyVersion.org_id == org_id,
            DlpPolicyVersion.status == "draft",
        )
        .order_by(DlpPolicyVersion.version.desc())
        .limit(1)
    )
    if for_update:
        statement = statement.with_for_update()
    result = await session.execute(statement)
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
