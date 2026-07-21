from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from app.utils.prompt_builder import SYSTEM_PROMPT
from config.aws import (
    CLASSIFICATION_MODEL,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    LLM_TIMEOUT_SECONDS,
    bedrock_runtime,
)

logger = logging.getLogger(__name__)


class LLMClassificationResult(BaseModel):
    classification: str = Field(default="UNCERTAIN")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    reasoning: str = Field(default="")


_UNCERTAIN_RESULT: dict[str, Any] = {
    "classification": "UNCERTAIN",
    "confidence": 0.0,
    "categories": [],
    "reasoning": "LLM analysis was inconclusive. Manual review is recommended.",
}


def _parse_llm_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    return json.loads(text)


class KimiClassifier:
    """Tier 2 (LLM) classifier — Bedrock-backed Kimi K2.5. Accepts an
    already-built prompt; callers assemble the prompt (e.g. via
    app.utils.prompt_builder) and hand it over."""

    def __init__(
        self,
        model_id: str = CLASSIFICATION_MODEL,
        timeout_seconds: float = LLM_TIMEOUT_SECONDS,
    ) -> None:
        self.model_id = model_id
        self.timeout = timeout_seconds

    async def _call_llm(self, prompt: str) -> str:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                bedrock_runtime.converse,
                modelId=self.model_id,
                system=[{"text": SYSTEM_PROMPT}],
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={
                    "temperature": LLM_TEMPERATURE,
                    "maxTokens": LLM_MAX_TOKENS,
                },
            ),
            timeout=self.timeout,
        )

        content_blocks = response.get("output", {}).get("message", {}).get("content", [])
        return content_blocks[0].get("text", "") if content_blocks else ""

    async def classify(self, prompt: str) -> LLMClassificationResult:
        """Never raises — any failure returns an UNCERTAIN result instead."""
        try:
            raw = await self._call_llm(prompt)
            parsed = _parse_llm_response(raw)
            return LLMClassificationResult(**{**_UNCERTAIN_RESULT, **parsed})
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Kimi classify failed: {type(exc).__name__}: {exc}")
            return LLMClassificationResult(**_UNCERTAIN_RESULT)
