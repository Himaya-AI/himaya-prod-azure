from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.service.base import DetectionResult
from app.service.deterministic.runner import DeterministicRunner
from app.service.llm.classifier import KimiClassifier, LLMClassificationResult
from app.utils.prompt_builder import build_classification_prompt


@dataclass
class ClassificationOutcome:
    findings: list[DetectionResult]
    llm_result: LLMClassificationResult


class ClassificationPipeline:
    """Entry point for classifying one email: runs Tier 0 first, then always
    runs the Tier 2 LLM with the Tier 0 findings as context to reach the
    final result."""

    def __init__(self, deterministic: DeterministicRunner, llm: KimiClassifier) -> None:
        self._deterministic = deterministic
        self._llm = llm

    async def classify(self, text: str, metadata: dict[str, Any]) -> ClassificationOutcome:
        findings = await self._deterministic.run(text, metadata)
        prompt = build_classification_prompt(text, findings)
        llm_result = await self._llm.classify(prompt)

        return ClassificationOutcome(findings=findings, llm_result=llm_result)
