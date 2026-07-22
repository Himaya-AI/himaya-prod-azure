from __future__ import annotations

import dataclasses
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/classify", tags=["classify"])


class ClassifyRequest(BaseModel):
    text: str
    tenant_id: str = "default"
    message_id: str | None = None
    lexicon_version: str = "v1"


class ClassifyResponse(BaseModel):
    findings: list[dict[str, Any]]
    llm_result: dict[str, Any]


@router.post("", response_model=ClassifyResponse)
async def classify(payload: ClassifyRequest, request: Request) -> ClassifyResponse:
    metadata = {
        "tenant_id": payload.tenant_id,
        "message_id": payload.message_id,
        "lexicon_version": payload.lexicon_version,
    }

    outcome = await request.app.state.pipeline.classify(payload.text, metadata)

    return ClassifyResponse(
        findings=[dataclasses.asdict(result) for result in outcome.findings],
        llm_result=outcome.llm_result.model_dump(),
    )
