"""Tenant runtime configuration independent from legacy DLP settings."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dlp.config import DlpSettings
from backend.dlp.domain import TenantMode
from backend.dlp.policy import PolicySet, build_default_policy
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
            select(
                Organization.domain,
                Organization.org_metadata,
            ).where(Organization.id == org_id)
        )
        row = result.one_or_none()
        if row is None:
            raise LookupError(f"Organization not found: {org_id}")

        metadata = row.org_metadata or {}
        dlp_metadata = metadata.get("dlp_v2") or {}
        domains = {
            str(row.domain).lower().rstrip(".")
        } if row.domain else set()
        domains.update(
            str(domain).lower().rstrip(".")
            for domain in dlp_metadata.get("domains", [])
            if domain
        )
        mode_value = dlp_metadata.get(
            "mode", self.defaults.tenant_mode
        )
        return TenantRuntimeConfig(
            enabled=bool(
                dlp_metadata.get(
                    "enabled",
                    self.defaults.gateway_pipeline_enabled,
                )
            ),
            mode=TenantMode(mode_value),
            domains=frozenset(domains),
            lexicon_version=str(
                dlp_metadata.get("lexicon_version", "v1")
            ),
            policy=build_default_policy(),
        )
