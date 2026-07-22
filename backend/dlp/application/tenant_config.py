"""Tenant runtime configuration independent from legacy DLP settings."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dlp.config import DlpSettings
from backend.dlp.domain import TenantMode
from backend.dlp.persistence.models import (
    DlpPolicyVersion,
    DlpTenantConfig,
)
from backend.dlp.policy import (
    PolicySet,
    build_default_policy,
    policy_from_document,
)
from backend.models.db_models import Organization


@dataclass(frozen=True)
class TenantRuntimeConfig:
    enabled: bool
    mode: TenantMode
    domains: frozenset[str]
    lexicon_version: str
    policy: PolicySet


class DatabaseTenantConfigProvider:
    """Reads only core organization metadata, never legacy DLP tables."""

    def __init__(self, defaults: DlpSettings) -> None:
        self.defaults = defaults

    async def get(
        self, session: AsyncSession, org_id: UUID
    ) -> TenantRuntimeConfig:
        result = await session.execute(
            select(Organization.domain).where(
                Organization.id == org_id
            )
        )
        domain = result.scalar_one_or_none()
        if domain is None:
            raise LookupError(f"Organization not found: {org_id}")

        config = await session.get(DlpTenantConfig, org_id)
        domains = {str(domain).lower().rstrip(".")}
        if config is not None:
            domains.update(
                str(value).lower().rstrip(".")
                for value in config.domains
                if value
            )
        policy = build_default_policy()
        if config is not None and config.active_policy_version_id:
            version = await session.get(
                DlpPolicyVersion,
                config.active_policy_version_id,
            )
            if version is None or version.status != "published":
                raise RuntimeError(
                    "Active DLP policy version is unavailable"
                )
            policy = policy_from_document(
                version.policy_document,
                version=f"tenant-v{version.version}",
            )
        return TenantRuntimeConfig(
            enabled=(
                config.enabled
                if config is not None
                else self.defaults.gateway_pipeline_enabled
            ),
            mode=TenantMode(
                config.mode
                if config is not None
                else self.defaults.tenant_mode
            ),
            domains=frozenset(domains),
            lexicon_version=(
                config.lexicon_version
                if config is not None
                else "v1"
            ),
            policy=policy,
        )
