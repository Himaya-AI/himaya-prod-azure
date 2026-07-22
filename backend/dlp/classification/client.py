"""Resilient typed HTTP client for the separate classifier service."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass

import httpx
from pydantic import ValidationError

from backend.dlp.classification.normalize import (
    normalize_classification,
)
from backend.dlp.contracts import ClassifyRequest, ClassifyResponse
from backend.dlp.domain import ClassificationOutcome


class ClassifierError(RuntimeError):
    pass


class ClassifierUnavailableError(ClassifierError):
    pass


class ClassifierContractError(ClassifierError):
    pass


class ClassifierRejectedError(ClassifierError):
    pass


@dataclass
class _CircuitBreaker:
    failure_threshold: int
    recovery_seconds: float
    failures: int = 0
    open_until: float = 0.0

    def ensure_available(self) -> None:
        if self.open_until > time.monotonic():
            raise ClassifierUnavailableError(
                "Classifier circuit breaker is open"
            )

    def record_success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.open_until = (
                time.monotonic() + self.recovery_seconds
            )


class ClassifierClient:
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        base_url: str,
        *,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 45.0,
        max_attempts: int = 3,
        base_backoff_seconds: float = 0.25,
        jitter_seconds: float = 0.1,
        circuit_failure_threshold: int = 5,
        circuit_recovery_seconds: float = 30.0,
        max_text_bytes: int = 2 * 1024 * 1024,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.max_attempts = max_attempts
        self.base_backoff_seconds = base_backoff_seconds
        self.jitter_seconds = jitter_seconds
        self.max_text_bytes = max_text_bytes
        self._breaker = _CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            recovery_seconds=circuit_recovery_seconds,
        )
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(
                connect=connect_timeout_seconds,
                read=read_timeout_seconds,
                write=10.0,
                pool=5.0,
            ),
        )

    async def classify(
        self,
        text: str,
        *,
        tenant_id: str,
        message_id: str,
        lexicon_version: str = "v1",
    ) -> ClassificationOutcome:
        if len(text.encode("utf-8")) > self.max_text_bytes:
            raise ClassifierRejectedError(
                "Classifier text exceeds configured byte limit"
            )
        self._breaker.ensure_available()
        request = ClassifyRequest(
            text=text,
            tenant_id=tenant_id,
            message_id=message_id,
            lexicon_version=lexicon_version,
        )

        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                response = await self._client.post(
                    "/classify",
                    json=request.model_dump(mode="json"),
                    headers={
                        "x-correlation-id": message_id,
                        "accept": "application/json",
                    },
                )
                if (
                    response.status_code
                    in self.RETRYABLE_STATUS_CODES
                ):
                    last_error = ClassifierUnavailableError(
                        "Classifier returned a retryable status"
                    )
                elif response.is_error:
                    raise ClassifierRejectedError(
                        "Classifier rejected the request with "
                        f"HTTP {response.status_code}"
                    )
                else:
                    try:
                        wire_response = ClassifyResponse.model_validate(
                            response.json()
                        )
                    except (
                        ValueError,
                        ValidationError,
                    ) as exc:
                        self._breaker.record_failure()
                        raise ClassifierContractError(
                            "Classifier response violated the v1 contract"
                        ) from exc
                    self._breaker.record_success()
                    return normalize_classification(wire_response)
            except ClassifierRejectedError:
                raise
            except ClassifierContractError:
                raise
            except (
                httpx.TimeoutException,
                httpx.TransportError,
            ) as exc:
                last_error = exc

            if attempt + 1 < self.max_attempts:
                await asyncio.sleep(
                    self.base_backoff_seconds * (2**attempt)
                    + random.uniform(0, self.jitter_seconds)
                )

        self._breaker.record_failure()
        raise ClassifierUnavailableError(
            "Classifier request failed after retries"
        ) from last_error

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
