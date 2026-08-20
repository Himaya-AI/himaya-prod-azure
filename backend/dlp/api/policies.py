"""Immutable tenant DLP policy version APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin, require_dlp_enterprise
from backend.dlp.api.schemas import (
    PolicyDiscardRequest,
    PolicyDiscardResponse,
    PolicyDraftRequest,
    PolicyIssueResponse,
    PolicyPublishRequest,
    PolicyRollbackRequest,
    PolicyValidateRequest,
    PolicyValidateResponse,
    PolicyVersionListItem,
    PolicyVersionListResponse,
    PolicyVersionResponse,
)
from backend.dlp.config import get_dlp_settings
from backend.dlp.persistence.models import (
    DlpPolicyVersion,
    DlpTenantConfig,
)
from backend.dlp.policy import (
    PolicyCapabilitiesResponse,
    PolicyDocument,
    PolicyWriteError,
    build_default_policy,
    build_policy_capabilities,
    collect_policy_issues,
    evaluation_order,
    policy_to_document,
    validate_policy_write,
)
from backend.models.db_models import User

router = APIRouter()


def _draft_conflict() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail="Policy draft has changed. Reload and try again.",
    )


def _require_writable_policy(document: PolicyDocument) -> None:
    try:
        validate_policy_write(document)
    except PolicyWriteError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
    "/policy/capabilities",
    response_model=PolicyCapabilitiesResponse,
)
async def get_policy_capabilities(
    _current_user: User = Depends(require_dlp_enterprise),
) -> PolicyCapabilitiesResponse:
    return build_policy_capabilities()


@router.post(
    "/policy/validate",
    response_model=PolicyValidateResponse,
)
async def validate_policy(
    payload: PolicyValidateRequest,
    _current_user: User = Depends(require_dlp_enterprise),
) -> PolicyValidateResponse:
    errors, warnings = collect_policy_issues(payload.document)
    return PolicyValidateResponse(
        valid=not errors,
        errors=[
            PolicyIssueResponse(rule_id=item.rule_id, message=item.message)
            for item in errors
        ],
        warnings=[
            PolicyIssueResponse(rule_id=item.rule_id, message=item.message)
            for item in warnings
        ],
        evaluation_order=evaluation_order(payload.document),
    )


@router.get(
    "/policy/versions",
    response_model=PolicyVersionListResponse,
)
async def list_policy_versions(
    current_user: User = Depends(require_dlp_enterprise),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionListResponse:
    result = await session.execute(
        select(DlpPolicyVersion)
        .where(
            DlpPolicyVersion.org_id == current_user.org_id,
            DlpPolicyVersion.status.in_(("published", "archived")),
        )
        .order_by(DlpPolicyVersion.version.desc())
    )
    versions = result.scalars().all()
    return PolicyVersionListResponse(
        items=[_version_list_item(version) for version in versions]
    )


@router.post(
    "/policy/rollback",
    response_model=PolicyVersionResponse,
)
async def rollback_policy(
    payload: PolicyRollbackRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    source = await session.get(DlpPolicyVersion, payload.source_id)
    if source is None or source.org_id != current_user.org_id:
        raise HTTPException(
            status_code=404, detail="Policy version not found"
        )
    if source.status not in {"published", "archived"}:
        raise HTTPException(
            status_code=422,
            detail="Only published or archived versions can be restored.",
        )
    document = PolicyDocument.model_validate(source.policy_document)
    _require_writable_policy(document)
    now = datetime.now(timezone.utc)
    draft = await _latest_draft(
        session, current_user.org_id, for_update=True
    )
    if draft is None:
        if (
            payload.expected_draft_id is not None
            or payload.expected_draft_revision is not None
        ):
            raise _draft_conflict()
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
            draft_revision=1,
            status="draft",
            policy_document=document.model_dump(mode="json"),
            created_by=current_user.id,
            updated_by=current_user.id,
            updated_at=now,
        )
        session.add(draft)
    else:
        if (
            payload.expected_draft_id is None
            or payload.expected_draft_revision is None
            or draft.id != payload.expected_draft_id
            or draft.draft_revision != payload.expected_draft_revision
            or (
                payload.expected_draft_version is not None
                and draft.version != payload.expected_draft_version
            )
        ):
            raise _draft_conflict()
        if draft.id == source.id:
            raise HTTPException(
                status_code=422,
                detail="Cannot restore the current draft onto itself.",
            )
        draft.policy_document = document.model_dump(mode="json")
        draft.draft_revision = draft.draft_revision + 1
        draft.updated_by = current_user.id
        draft.updated_at = now
    try:
        await session.flush()
    except IntegrityError as exc:
        raise _draft_conflict() from exc
    return _policy_response(draft)


@router.post(
    "/policy/draft/discard",
    response_model=PolicyDiscardResponse,
)
async def discard_policy_draft(
    payload: PolicyDiscardRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyDiscardResponse:
    draft = await _latest_draft(
        session, current_user.org_id, for_update=True
    )
    if draft is None:
        raise HTTPException(
            status_code=404, detail="No DLP policy draft to discard"
        )
    if (
        draft.id != payload.expected_id
        or draft.draft_revision != payload.expected_revision
        or (
            payload.expected_version is not None
            and draft.version != payload.expected_version
        )
    ):
        raise _draft_conflict()
    draft_id = draft.id
    await session.delete(draft)
    await session.flush()
    return PolicyDiscardResponse(id=draft_id)


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
    _require_writable_policy(payload.document)
    draft = await _latest_draft(
        session, current_user.org_id, for_update=True
    )
    now = datetime.now(timezone.utc)
    if draft is None:
        if (
            payload.expected_id is not None
            or payload.expected_revision is not None
        ):
            raise _draft_conflict()
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
            draft_revision=1,
            status="draft",
            policy_document=payload.document.model_dump(
                mode="json"
            ),
            created_by=current_user.id,
            updated_by=current_user.id,
            updated_at=now,
        )
        session.add(draft)
    else:
        if (
            payload.expected_id is None
            or payload.expected_revision is None
            or draft.id != payload.expected_id
            or draft.draft_revision != payload.expected_revision
            or (
                payload.expected_version is not None
                and draft.version != payload.expected_version
            )
        ):
            raise _draft_conflict()
        draft.policy_document = payload.document.model_dump(
            mode="json"
        )
        draft.draft_revision = draft.draft_revision + 1
        draft.updated_by = current_user.id
        draft.updated_at = now
    try:
        await session.flush()
    except IntegrityError as exc:
        raise _draft_conflict() from exc
    return _policy_response(draft)


@router.post(
    "/policy/publish", response_model=PolicyVersionResponse
)
async def publish_policy(
    payload: PolicyPublishRequest,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> PolicyVersionResponse:
    _require_writable_policy(payload.document)
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
        or draft.draft_revision != payload.expected_revision
    ):
        raise _draft_conflict()
    stored = PolicyDocument.model_validate(draft.policy_document)
    if stored.model_dump(mode="json") != payload.document.model_dump(
        mode="json"
    ):
        raise _draft_conflict()
    now = datetime.now(timezone.utc)
    await session.execute(
        update(DlpPolicyVersion)
        .where(
            DlpPolicyVersion.org_id == current_user.org_id,
            DlpPolicyVersion.status == "published",
        )
        .values(status="archived")
    )
    draft.status = "published"
    draft.published_at = now
    draft.published_by = current_user.id
    draft.updated_by = current_user.id
    draft.updated_at = now
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
        config.updated_at = now
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
        draft_revision=version.draft_revision,
        status=version.status,
        document=version.policy_document,
        created_at=version.created_at,
        updated_at=version.updated_at,
        published_at=version.published_at,
        updated_by=version.updated_by,
        published_by=version.published_by,
    )


def _version_list_item(version: DlpPolicyVersion) -> PolicyVersionListItem:
    document = version.policy_document or {}
    rules = document.get("rules") if isinstance(document, dict) else None
    return PolicyVersionListItem(
        id=version.id,
        version=version.version,
        status=version.status,
        created_at=version.created_at,
        updated_at=version.updated_at,
        published_at=version.published_at,
        published_by=version.published_by,
        rule_count=len(rules) if isinstance(rules, list) else 0,
    )
