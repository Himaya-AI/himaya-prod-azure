from __future__ import annotations

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
from backend.dlp.api.settings import _normalize_domain
from backend.dlp.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyRuleDocument,
    RuleConditionsDocument,
    policy_from_document,
    policy_to_document,
)


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
