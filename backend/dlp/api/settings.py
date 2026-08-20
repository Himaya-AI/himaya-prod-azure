"""Tenant DLP v2 enablement and mode settings."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dlp.api.deps import require_dlp_admin, require_dlp_enterprise
from backend.dlp.api.schemas import (
    TenantSettingsResponse,
    TenantSettingsUpdate,
)
from backend.dlp.config import get_dlp_settings
from backend.dlp.persistence.models import (
    DlpPolicyVersion,
    DlpTenantConfig,
)
from backend.models.db_models import Organization, User

router = APIRouter()


@router.get("/settings", response_model=TenantSettingsResponse)
async def get_settings(
    current_user: User = Depends(require_dlp_enterprise),
    session: AsyncSession = Depends(get_db),
) -> TenantSettingsResponse:
    config = await session.get(DlpTenantConfig, current_user.org_id)
    return await _settings_response(
        session, config, current_user.org_id
    )


@router.put("/settings", response_model=TenantSettingsResponse)
async def update_settings(
    payload: TenantSettingsUpdate,
    current_user: User = Depends(require_dlp_admin),
    session: AsyncSession = Depends(get_db),
) -> TenantSettingsResponse:
    domains = sorted({_normalize_domain(value) for value in payload.domains})
    config = await session.get(DlpTenantConfig, current_user.org_id)
    if config is None:
        config = DlpTenantConfig(
            org_id=current_user.org_id,
            enabled=payload.enabled,
            mode=payload.mode,
            domains=domains,
            lexicon_version=payload.lexicon_version,
            updated_by=current_user.id,
        )
        session.add(config)
    else:
        config.enabled = payload.enabled
        config.mode = payload.mode
        config.domains = domains
        config.lexicon_version = payload.lexicon_version
        config.updated_by = current_user.id
        config.updated_at = datetime.now(timezone.utc)
    await session.flush()
    return await _settings_response(
        session, config, current_user.org_id
    )


async def _settings_response(
    session: AsyncSession,
    config: DlpTenantConfig | None,
    org_id,
) -> TenantSettingsResponse:
    defaults = get_dlp_settings()
    active_version = None
    if config is not None and config.active_policy_version_id:
        policy = await session.get(
            DlpPolicyVersion, config.active_policy_version_id
        )
        active_version = policy.version if policy else None
    organization = await session.get(Organization, org_id)
    organization_domain = None
    if organization is not None and organization.domain:
        organization_domain = str(organization.domain).lower().rstrip(".")
    return TenantSettingsResponse(
        enabled=(
            config.enabled
            if config is not None
            else defaults.gateway_pipeline_enabled
        ),
        mode=(
            config.mode
            if config is not None
            else defaults.tenant_mode
        ),
        domains=list(config.domains) if config is not None else [],
        organization_domain=organization_domain,
        lexicon_version=(
            config.lexicon_version if config is not None else "v1"
        ),
        active_policy_version=active_version,
    )


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if (
        not domain
        or len(domain) > 253
        or "@" in domain
        or "/" in domain
        or any(not label for label in domain.split("."))
        or any(
            not label.replace("-", "").isalnum()
            for label in domain.split(".")
        )
    ):
        raise HTTPException(
            status_code=422, detail=f"Invalid domain: {value}"
        )
    return domain
