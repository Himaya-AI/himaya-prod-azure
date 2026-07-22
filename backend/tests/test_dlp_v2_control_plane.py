from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

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
