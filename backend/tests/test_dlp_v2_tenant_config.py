from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from backend.dlp.application.tenant_config import DatabaseTenantConfigProvider
from backend.dlp.config import DlpSettings
from backend.dlp.domain import TenantMode
from backend.dlp.persistence.models import DlpPolicyVersion, DlpTenantConfig
from backend.dlp.policy import PolicyAction, PolicyDocument, PolicyRuleDocument, RuleConditionsDocument


class _OrgResult:
    def __init__(self, domain: str) -> None:
        self._domain = domain

    def scalar_one_or_none(self):
        return self._domain


class _Session:
    def __init__(self, *, domain: str, config, policy) -> None:
        self.domain = domain
        self.config = config
        self.policy = policy

    async def execute(self, _statement):
        return _OrgResult(self.domain)

    async def get(self, model, ident):
        if model is DlpTenantConfig:
            return self.config
        if model is DlpPolicyVersion:
            return self.policy
        raise AssertionError(f"unexpected model {model} ident={ident}")


@pytest.mark.asyncio
async def test_published_policy_uses_tenant_version_and_org_domain_union() -> None:
    org_id = uuid4()
    policy_id = uuid4()
    document = PolicyDocument(
        rules=[
            PolicyRuleDocument(
                rule_id="tenant.pii",
                name="Tenant PII",
                action=PolicyAction.HOLD,
                conditions=RuleConditionsDocument(detectors=["pii"]),
            )
        ]
    )
    config = SimpleNamespace(
        enabled=True,
        mode="enforce",
        domains=["alias.test", "Example.TEST."],
        lexicon_version="v2",
        active_policy_version_id=policy_id,
    )
    policy = SimpleNamespace(
        id=policy_id,
        version=7,
        status="published",
        policy_document=document.model_dump(mode="json"),
    )
    session = _Session(
        domain="Example.TEST.",
        config=config,
        policy=policy,
    )
    provider = DatabaseTenantConfigProvider(
        DlpSettings(
            gateway_pipeline_enabled=False,
            tenant_mode="monitor",
        )
    )

    runtime = await provider.get(session, org_id)

    assert runtime.policy.version == "tenant-v7"
    assert runtime.enabled is True
    assert runtime.mode == TenantMode.ENFORCE
    assert runtime.domains == frozenset({"example.test", "alias.test"})
    assert runtime.lexicon_version == "v2"
    assert runtime.policy.rules[0].rule_id == "tenant.pii"
