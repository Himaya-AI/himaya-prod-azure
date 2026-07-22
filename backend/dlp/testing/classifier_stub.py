"""Contract-faithful local classifier stub; never deploy to production."""

from __future__ import annotations

import re

from fastapi import FastAPI

from backend.dlp.contracts import (
    ClassifyRequest,
    ClassifyResponse,
    DetectionMatch,
    DetectionResult,
    LlmClassificationResult,
)

app = FastAPI(title="DLP classifier contract stub")
_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/classify", response_model=ClassifyResponse)
async def classify(payload: ClassifyRequest) -> ClassifyResponse:
    match = _CARD_PATTERN.search(payload.text)
    findings: list[DetectionResult] = []
    if match:
        findings.append(
            DetectionResult(
                detector="pii",
                matches=[
                    DetectionMatch(
                        detector="pii",
                        entity_type="CREDIT_CARD",
                        score=0.99,
                        start=match.start(),
                        end=match.end(),
                        metadata={"masked": "xxxxxxxxxxxx1111"},
                    )
                ],
                escalate=False,
            )
        )
    else:
        findings.append(
            DetectionResult(
                detector="pii",
                matches=[],
                escalate=False,
            )
        )
    return ClassifyResponse(
        findings=findings,
        llm_result=LlmClassificationResult(
            classification=(
                "SENSITIVE" if match else "NOT_SENSITIVE"
            ),
            confidence=0.99,
            categories=["financial"] if match else [],
            reasoning=(
                "Local stub detected a payment-card-shaped value."
                if match
                else "Local stub found no sensitive value."
            ),
        ),
    )
