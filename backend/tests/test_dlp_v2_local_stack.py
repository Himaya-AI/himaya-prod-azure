from __future__ import annotations

import pytest

from backend.dlp.contracts import ClassifyRequest, ClassifyResponse
from backend.dlp.testing.classifier_stub import classify


@pytest.mark.asyncio
async def test_local_classifier_stub_matches_production_contract() -> None:
    clean = await classify(
        ClassifyRequest(
            text="Routine project update",
            tenant_id="tenant",
            message_id="clean",
        )
    )
    blocked = await classify(
        ClassifyRequest(
            text="Card 4111 1111 1111 1111",
            tenant_id="tenant",
            message_id="blocked",
        )
    )

    assert ClassifyResponse.model_validate(clean).findings[0].matches == []
    assert (
        ClassifyResponse.model_validate(blocked)
        .findings[0]
        .matches[0]
        .entity_type
        == "CREDIT_CARD"
    )
