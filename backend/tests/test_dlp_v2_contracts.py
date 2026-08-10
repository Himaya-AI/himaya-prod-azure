from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.dlp.contracts import (
    CaptureEvent,
    ClassifyResponse,
    CommandType,
    DeliveryEvent,
    DeliveryOutcome,
    GatewayCommand,
    GatewayMessageState,
    SmtpStage,
)


def _capture_payload() -> dict:
    message_id = uuid4()
    now = datetime.now(timezone.utc)
    return {
        "schema_version": 1,
        "event_type": "dlp.message.captured.v1",
        "message_id": str(message_id),
        "org_id": str(uuid4()),
        "provider": "local",
        "provider_deployment_id": str(uuid4()),
        "envelope_from": "alice@example.test",
        "envelope_to": ["bob@external.test"],
        "mime_sha256": "a" * 64,
        "mime_size": 123,
        "blob_uri": (
            "http://azurite:10000/devstoreaccount1/dlp-mime/"
            f"org/{message_id}/{'a' * 64}.eml"
        ),
        "received_at": now.isoformat(),
        "occurred_at": now.isoformat(),
    }


def test_capture_event_matches_gateway_wire_shape() -> None:
    event = CaptureEvent.model_validate(_capture_payload())

    assert event.event_type == "dlp.message.captured.v1"
    assert event.envelope_to == ["bob@external.test"]
    assert event.deduplication_key.endswith(str(event.message_id))


def test_capture_event_rejects_unversioned_extra_fields() -> None:
    payload = _capture_payload()
    payload["raw_mime_storage_ref"] = "roadmap-only-name"

    with pytest.raises(ValidationError):
        CaptureEvent.model_validate(payload)


def test_delivery_event_matches_gateway_wire_shape() -> None:
    now = datetime.now(timezone.utc)
    attempt_id = uuid4()
    event = DeliveryEvent(
        event_id=uuid4(),
        message_id=uuid4(),
        org_id=str(uuid4()),
        provider="m365",
        provider_deployment_id=str(uuid4()),
        attempt_id=attempt_id,
        attempt_number=1,
        outcome=DeliveryOutcome.UNCERTAIN,
        resulting_state=GatewayMessageState.OUTCOME_UNCERTAIN,
        smtp_stage=SmtpStage.DATA_STARTED,
        remote_host="tenant.mail.protection.outlook.com",
        occurred_at=now,
    )

    assert event.event_type == "dlp.message.delivery.v1"
    assert event.deduplication_key.endswith(str(attempt_id))
    assert event.model_dump(mode="json")["outcome"] == "uncertain"


def test_gateway_command_serializes_gateway_enum_values() -> None:
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=uuid4(),
        org_id=str(uuid4()),
        expected_state=GatewayMessageState.CAPTURED,
    )
    wire = command.model_dump(mode="json")

    assert wire["command_type"] == "allow"
    assert wire["expected_state"] == "captured"
    assert wire["command_id"] == str(command.command_id)


def test_classifier_response_normalizes_nested_findings() -> None:
    response = ClassifyResponse.model_validate(
        {
            "findings": [
                {
                    "detector": "pii",
                    "matches": [
                        {
                            "detector": "pii",
                            "entity_type": "CREDIT_CARD",
                            "score": 0.97,
                            "start": 10,
                            "end": 29,
                            "metadata": {"masked": "xxxxxxxxxxxx1111"},
                        }
                    ],
                    "escalate": False,
                    "error": None,
                }
            ],
            "llm_result": {
                "classification": "SENSITIVE",
                "confidence": 0.91,
                "categories": ["financial"],
                "reasoning": "Payment data was detected.",
            },
        }
    )

    assert response.findings[0].matches[0].entity_type == "CREDIT_CARD"
    assert response.llm_result.classification == "SENSITIVE"
