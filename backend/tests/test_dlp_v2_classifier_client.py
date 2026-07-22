from __future__ import annotations

import httpx
import pytest

from backend.dlp.classification import (
    ClassifierClient,
    ClassifierContractError,
    ClassifierRejectedError,
    ClassifierUnavailableError,
)


def _valid_response() -> dict:
    return {
        "findings": [
            {
                "detector": "pii",
                "matches": [
                    {
                        "detector": "pii",
                        "entity_type": "credit_card",
                        "score": 0.97,
                        "start": 5,
                        "end": 24,
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
            "categories": ["Financial"],
            "reasoning": "Financial identifier detected.",
        },
    }


@pytest.mark.asyncio
async def test_classifier_client_validates_and_normalizes() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-correlation-id"] == "message-1"
        return httpx.Response(200, json=_valid_response())

    http_client = httpx.AsyncClient(
        base_url="http://classifier",
        transport=httpx.MockTransport(handler),
    )
    client = ClassifierClient(
        "http://classifier", http_client=http_client
    )

    outcome = await client.classify(
        "card data",
        tenant_id="tenant-1",
        message_id="message-1",
    )

    assert outcome.findings[0].entity_type == "CREDIT_CARD"
    assert outcome.findings[0].confidence == 0.97
    assert outcome.llm_categories == ("financial",)
    await http_client.aclose()


@pytest.mark.asyncio
async def test_classifier_client_retries_transient_failure() -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(503)
        return httpx.Response(200, json=_valid_response())

    http_client = httpx.AsyncClient(
        base_url="http://classifier",
        transport=httpx.MockTransport(handler),
    )
    client = ClassifierClient(
        "http://classifier",
        http_client=http_client,
        max_attempts=3,
        base_backoff_seconds=0,
        jitter_seconds=0,
    )

    await client.classify(
        "card data",
        tenant_id="tenant-1",
        message_id="message-1",
    )

    assert attempts == 3
    await http_client.aclose()


@pytest.mark.asyncio
async def test_classifier_contract_drift_fails_closed() -> None:
    response = _valid_response()
    response["llm_result"]["classification"] = "TOP_SECRET"

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response)

    http_client = httpx.AsyncClient(
        base_url="http://classifier",
        transport=httpx.MockTransport(handler),
    )
    client = ClassifierClient(
        "http://classifier", http_client=http_client
    )

    with pytest.raises(ClassifierContractError):
        await client.classify(
            "card data",
            tenant_id="tenant-1",
            message_id="message-1",
        )
    await http_client.aclose()


@pytest.mark.asyncio
async def test_classifier_circuit_opens_after_failures() -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("offline", request=request)

    http_client = httpx.AsyncClient(
        base_url="http://classifier",
        transport=httpx.MockTransport(handler),
    )
    client = ClassifierClient(
        "http://classifier",
        http_client=http_client,
        max_attempts=1,
        circuit_failure_threshold=2,
        circuit_recovery_seconds=60,
    )

    for _ in range(2):
        with pytest.raises(ClassifierUnavailableError):
            await client.classify(
                "data",
                tenant_id="tenant-1",
                message_id="message-1",
            )
    with pytest.raises(
        ClassifierUnavailableError, match="circuit breaker"
    ):
        await client.classify(
            "data",
            tenant_id="tenant-1",
            message_id="message-1",
        )

    assert attempts == 2
    await http_client.aclose()


@pytest.mark.asyncio
async def test_classifier_rejects_oversized_text_before_http() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP request should not be sent")

    http_client = httpx.AsyncClient(
        base_url="http://classifier",
        transport=httpx.MockTransport(handler),
    )
    client = ClassifierClient(
        "http://classifier",
        http_client=http_client,
        max_text_bytes=4,
    )

    with pytest.raises(ClassifierRejectedError, match="byte limit"):
        await client.classify(
            "12345",
            tenant_id="tenant-1",
            message_id="message-1",
        )
    await http_client.aclose()
