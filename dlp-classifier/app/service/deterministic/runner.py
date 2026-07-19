from __future__ import annotations

from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

from app.service.base import DetectionResult
from app.service.deterministic.ner import NERDetector
from app.service.deterministic.pii import PIIDetector
from app.service.deterministic.recognizers.credit_card import CreditCardValidator
from app.service.deterministic.recognizers.organization import OrganizationRecognizer


def _build_shared_engine() -> AnalyzerEngine:
    """Builds a single shared AnalyzerEngine — loads spaCy en_core_web_sm
    exactly once and registers all custom recognizers."""
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    registry.add_recognizer(CreditCardValidator())
    registry.add_recognizer(OrganizationRecognizer())

    return AnalyzerEngine(registry=registry, supported_languages=["en"])


class DeterministicRunner:
    """Orchestrates all Tier 0 deterministic detectors. Owns the shared
    AnalyzerEngine lifecycle so spaCy loads once, runs every detector, and
    aggregates their findings."""

    def __init__(self) -> None:
        engine = _build_shared_engine()
        self._detectors = [
            PIIDetector(engine),
            NERDetector(engine),
        ]

    def run(self, text: str, metadata: dict[str, Any]) -> list[DetectionResult]:
        """Runs all detectors against the extracted text. Never raises —
        a failed detector returns escalate=True with error set instead."""
        return [detector.analyze(text, metadata) for detector in self._detectors]

    def should_escalate(self, results: list[DetectionResult]) -> bool:
        """True if any detector was inconclusive — Tier 2 runs if even one
        detector couldn't decide."""
        return any(result.escalate for result in results)
