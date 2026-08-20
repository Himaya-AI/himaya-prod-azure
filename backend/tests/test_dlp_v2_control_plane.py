from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from backend.dlp.api.deps import require_dlp_admin, require_dlp_enterprise
from backend.dlp.api.message_views import (
    is_reviewable,
    sanitize_findings,
    sanitize_preview_text,
)
from backend.dlp.api.router import router
from backend.dlp.api.schemas import (
    DlpStatusResponse,
    PolicyDraftRequest,
    PolicyPublishRequest,
)
from backend.dlp.api.settings import _normalize_domain
from backend.dlp.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyRuleDocument,
    RuleConditionsDocument,
    policy_from_document,
    policy_to_document,
)


def test_status_response_includes_oldest_reviewable_sla() -> None:
    received_at = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
    payload = DlpStatusResponse(
        status="ready",
        pipeline_enabled=True,
        mode="enforce",
        classifier_url_configured=True,
        reviewable_count=2,
        oldest_reviewable_at=received_at,
        oldest_reviewable_from="alice@example.test",
    )

    assert payload.oldest_reviewable_at == received_at
    assert payload.oldest_reviewable_from == "alice@example.test"
    dumped = payload.model_dump()
    assert dumped["oldest_reviewable_at"] == received_at
    assert dumped["reviewable_count"] == 2


def test_control_plane_routes_are_versioned() -> None:
    route_paths = {route.path for route in router.routes}

    assert "/api/dlp/v2/status" in route_paths
    assert "/api/dlp/v2/settings" in route_paths
    assert "/api/dlp/v2/policy/draft" in route_paths
    assert "/api/dlp/v2/policy/publish" in route_paths
    assert "/api/dlp/v2/messages/{message_id}/release" in route_paths
    assert "/api/dlp/v2/messages/{message_id}/stop" in route_paths


def test_policy_document_round_trip_normalizes_rules() -> None:
    document = PolicyDocument(
        rules=[
            PolicyRuleDocument(
                rule_id="financial",
                name="Financial data",
                action=PolicyAction.STOP,
                conditions=RuleConditionsDocument(
                    entity_types=["credit_card"],
                    recipient_domains=["EXTERNAL.TEST."],
                    min_confidence=0.9,
                ),
            )
        ]
    )

    policy = policy_from_document(document, version="tenant-v1")
    serialized = policy_to_document(policy)

    assert policy.rules[0].conditions.entity_types == frozenset(
        {"CREDIT_CARD"}
    )
    assert serialized.rules[0].conditions.recipient_domains == [
        "external.test"
    ]


def test_policy_document_rejects_duplicate_rule_ids() -> None:
    rule = {
        "rule_id": "duplicate",
        "name": "Duplicate",
        "action": "hold",
        "conditions": {},
    }

    with pytest.raises(ValidationError, match="unique"):
        PolicyDocument.model_validate({"rules": [rule, rule]})


def test_domain_normalization_rejects_email_addresses() -> None:
    assert _normalize_domain("Example.TEST.") == "example.test"
    with pytest.raises(HTTPException):
        _normalize_domain("user@example.test")


@pytest.mark.asyncio
async def test_require_dlp_enterprise_rejects_launch_tier() -> None:
    user = SimpleNamespace(org_id=uuid4(), role="admin")
    session = SimpleNamespace(
        get=AsyncMock(return_value=SimpleNamespace(tier="Launch"))
    )

    with pytest.raises(HTTPException) as exc:
        await require_dlp_enterprise(current_user=user, session=session)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_dlp_enterprise_allows_enterprise_trial() -> None:
    user = SimpleNamespace(org_id=uuid4(), role="viewer")
    session = SimpleNamespace(
        get=AsyncMock(
            return_value=SimpleNamespace(tier="Enterprise Trial")
        )
    )

    result = await require_dlp_enterprise(
        current_user=user, session=session
    )
    assert result is user


@pytest.mark.asyncio
async def test_require_dlp_admin_requires_admin_role() -> None:
    user = SimpleNamespace(org_id=uuid4(), role="viewer")

    with pytest.raises(HTTPException) as exc:
        await require_dlp_admin(current_user=user)

    assert exc.value.status_code == 403
    assert "administrator" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_require_dlp_admin_allows_owner_role() -> None:
    user = SimpleNamespace(org_id=uuid4(), role="owner")

    result = await require_dlp_admin(current_user=user)

    assert result is user


def test_is_reviewable_requires_hold_decision_and_state() -> None:
    message = SimpleNamespace(state="decided")
    decision = SimpleNamespace(effective_action="hold")
    assert is_reviewable(message, decision) is True
    assert is_reviewable(message, None) is False
    assert (
        is_reviewable(
            SimpleNamespace(state="release_requested"),
            decision,
        )
        is False
    )
    assert (
        is_reviewable(
            message,
            SimpleNamespace(effective_action="stop"),
        )
        is False
    )


def test_is_reviewable_allows_failed_command_retry() -> None:
    decision = SimpleNamespace(effective_action="hold")
    assert (
        is_reviewable(
            SimpleNamespace(state="release_requested"),
            decision,
            has_failed_command=True,
        )
        is True
    )
    assert (
        is_reviewable(
            SimpleNamespace(state="stop_requested"),
            decision,
            has_failed_command=True,
        )
        is True
    )
    assert (
        is_reviewable(
            SimpleNamespace(state="release_requested"),
            decision,
            has_failed_command=False,
        )
        is False
    )
    assert (
        is_reviewable(
            SimpleNamespace(state="provider_accepted"),
            decision,
            has_failed_command=True,
        )
        is False
    )
    assert (
        is_reviewable(
            SimpleNamespace(state="stop_requested"),
            decision,
            has_failed_command=True,
            has_inflight_command=True,
        )
        is False
    )


def test_sanitize_findings_drops_raw_match_payload() -> None:
    findings = sanitize_findings(
        [
            {
                "detector": "pii",
                "entity_type": "CREDIT_CARD",
                "confidence": 0.95,
                "start": 10,
                "end": 29,
                "match": "4111 1111 1111 1111",
                "metadata": {"raw": "secret"},
            }
        ]
    )

    assert findings == [
        {
            "detector": "pii",
            "entity_type": "CREDIT_CARD",
            "confidence": 0.95,
        }
    ]


def test_sanitize_preview_text_bounds_output() -> None:
    preview = sanitize_preview_text("a" * 5000, max_chars=32)
    assert len(preview) == 32
    assert preview.endswith("…")


def test_policy_publish_request_requires_draft_identity() -> None:
    with pytest.raises(ValidationError):
        PolicyPublishRequest()  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_first_publish_uses_runtime_tenant_defaults(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import publish_policy
    from backend.dlp.persistence.models import DlpTenantConfig

    org_id = uuid4()
    draft_id = uuid4()
    document = PolicyDocument(default_action=PolicyAction.ALLOW, rules=[])
    draft = SimpleNamespace(
        id=draft_id,
        version=1,
        draft_revision=1,
        status="draft",
        policy_document=document.model_dump(mode="json"),
        created_at=None,
        updated_at=None,
        published_at=None,
        updated_by=None,
        published_by=None,
        org_id=org_id,
    )
    added: list[object] = []

    class _ConfigResult:
        def scalar_one_or_none(self):
            return None

    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )
    monkeypatch.setattr(
        policies_module,
        "get_dlp_settings",
        lambda: SimpleNamespace(
            gateway_pipeline_enabled=True,
            tenant_mode="enforce",
        ),
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_ConfigResult()),
        add=added.append,
        flush=AsyncMock(),
    )
    payload = PolicyPublishRequest(
        draft_id=draft_id,
        expected_version=1,
        expected_revision=1,
        document=document,
    )
    user_id = uuid4()

    result = await publish_policy(
        payload=payload,
        current_user=SimpleNamespace(id=user_id, org_id=org_id),
        session=session,
    )

    assert result.status == "published"
    assert draft.status == "published"
    assert draft.published_by == user_id
    assert len(added) == 1
    config = added[0]
    assert isinstance(config, DlpTenantConfig)
    assert config.enabled is True
    assert config.mode == "enforce"
    assert config.active_policy_version_id == draft_id


@pytest.mark.asyncio
async def test_publish_rejects_document_mismatch(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import publish_policy

    draft_id = uuid4()
    stored = PolicyDocument(default_action=PolicyAction.ALLOW, rules=[])
    submitted = PolicyDocument(default_action=PolicyAction.STOP, rules=[])
    draft = SimpleNamespace(
        id=draft_id,
        version=1,
        draft_revision=1,
        status="draft",
        policy_document=stored.model_dump(mode="json"),
        created_at=None,
        updated_at=None,
        published_at=None,
        updated_by=None,
        published_by=None,
    )
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )

    with pytest.raises(HTTPException) as exc:
        await publish_policy(
            payload=PolicyPublishRequest(
                draft_id=draft_id,
                expected_version=1,
                expected_revision=1,
                document=submitted,
            ),
            current_user=SimpleNamespace(id=uuid4(), org_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert exc.value.status_code == 409
    assert draft.status == "draft"


def _empty_document() -> PolicyDocument:
    return PolicyDocument(default_action=PolicyAction.ALLOW, rules=[])


def _draft_namespace(*, org_id, draft_id, revision=1, document=None):
    payload = (document or _empty_document()).model_dump(mode="json")
    return SimpleNamespace(
        id=draft_id,
        version=1,
        draft_revision=revision,
        status="draft",
        policy_document=payload,
        created_at=None,
        updated_at=None,
        published_at=None,
        updated_by=None,
        published_by=None,
        org_id=org_id,
        created_by=uuid4(),
    )


@pytest.mark.asyncio
async def test_save_draft_without_token_does_not_overwrite(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import save_policy_draft

    org_id = uuid4()
    original = {"default_action": "allow", "rules": []}
    draft = _draft_namespace(org_id=org_id, draft_id=uuid4())
    draft.policy_document = original
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )

    with pytest.raises(HTTPException) as exc:
        await save_policy_draft(
            payload=PolicyDraftRequest(document=_empty_document()),
            current_user=SimpleNamespace(id=uuid4(), org_id=org_id),
            session=SimpleNamespace(),
        )

    assert exc.value.status_code == 409
    assert draft.policy_document is original
    assert draft.draft_revision == 1


@pytest.mark.asyncio
async def test_save_draft_increments_revision(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import save_policy_draft

    org_id = uuid4()
    user_id = uuid4()
    draft_id = uuid4()
    draft = _draft_namespace(
        org_id=org_id, draft_id=draft_id, revision=3
    )
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )
    session = SimpleNamespace(flush=AsyncMock())
    next_document = PolicyDocument(
        default_action=PolicyAction.STOP, rules=[]
    )

    result = await save_policy_draft(
        payload=PolicyDraftRequest(
            document=next_document,
            expected_id=draft_id,
            expected_version=1,
            expected_revision=3,
        ),
        current_user=SimpleNamespace(id=user_id, org_id=org_id),
        session=session,
    )

    assert draft.draft_revision == 4
    assert draft.updated_by == user_id
    assert draft.policy_document["default_action"] == "stop"
    assert result.draft_revision == 4


@pytest.mark.asyncio
async def test_save_draft_stale_revision_conflicts(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import save_policy_draft

    org_id = uuid4()
    draft_id = uuid4()
    draft = _draft_namespace(
        org_id=org_id, draft_id=draft_id, revision=5
    )
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )

    with pytest.raises(HTTPException) as exc:
        await save_policy_draft(
            payload=PolicyDraftRequest(
                document=_empty_document(),
                expected_id=draft_id,
                expected_version=1,
                expected_revision=4,
            ),
            current_user=SimpleNamespace(id=uuid4(), org_id=org_id),
            session=SimpleNamespace(),
        )

    assert exc.value.status_code == 409
    assert draft.draft_revision == 5


@pytest.mark.asyncio
async def test_first_save_creates_revision_one(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import save_policy_draft
    from backend.dlp.persistence.models import DlpPolicyVersion

    org_id = uuid4()
    user_id = uuid4()
    added: list[object] = []
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=None),
    )
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=2),
        add=added.append,
        flush=AsyncMock(),
    )

    result = await save_policy_draft(
        payload=PolicyDraftRequest(document=_empty_document()),
        current_user=SimpleNamespace(id=user_id, org_id=org_id),
        session=session,
    )

    assert len(added) == 1
    created = added[0]
    assert isinstance(created, DlpPolicyVersion)
    assert created.version == 3
    assert created.draft_revision == 1
    assert created.status == "draft"
    assert created.created_by == user_id
    assert created.updated_by == user_id
    assert result.draft_revision == 1


@pytest.mark.asyncio
async def test_first_save_with_stale_token_conflicts(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import save_policy_draft

    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=None),
    )

    with pytest.raises(HTTPException) as exc:
        await save_policy_draft(
            payload=PolicyDraftRequest(
                document=_empty_document(),
                expected_id=uuid4(),
                expected_revision=1,
            ),
            current_user=SimpleNamespace(id=uuid4(), org_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_publish_rejects_stale_revision(monkeypatch) -> None:
    from backend.dlp.api import policies as policies_module
    from backend.dlp.api.policies import publish_policy

    draft_id = uuid4()
    document = _empty_document()
    draft = _draft_namespace(
        org_id=uuid4(), draft_id=draft_id, revision=4, document=document
    )
    monkeypatch.setattr(
        policies_module,
        "_latest_draft",
        AsyncMock(return_value=draft),
    )

    with pytest.raises(HTTPException) as exc:
        await publish_policy(
            payload=PolicyPublishRequest(
                draft_id=draft_id,
                expected_version=1,
                expected_revision=3,
                document=document,
            ),
            current_user=SimpleNamespace(id=uuid4(), org_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert exc.value.status_code == 409
    assert draft.status == "draft"
