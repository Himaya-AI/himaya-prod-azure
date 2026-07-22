from __future__ import annotations

from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.recognizer_result import RecognizerResult

from app.service.base import BaseDetector, DetectionMatch, DetectionResult

ENTITIES_NER = [
    "PERSON",  # full person names
    "LOCATION",  # cities, countries, regions
    "NRP",  # nationality, religion, political group
    "ORGANIZATION",  # companies, institutions — via custom recognizer
]


def _to_detection_match(
    result: RecognizerResult, text: str, detector_name: str
) -> DetectionMatch:
    snippet = text[result.start : result.end]
    return DetectionMatch(
        detector=detector_name,
        entity_type=result.entity_type,
        score=result.score,
        start=result.start,
        end=result.end,
        metadata={
            "snippet": snippet,
            "recognizer": result.recognition_metadata.get(
                "recognizer_name", "unknown"
            ),
            "score": result.score,
        },
    )


class NERDetector(BaseDetector):
    def __init__(self, engine: AnalyzerEngine) -> None:
        self._engine = engine

    @property
    def name(self) -> str:
        return "ner"

    async def analyze(self, text: str, metadata: dict[str, Any]) -> DetectionResult:
        try:
            results = self._engine.analyze(
                text=text, entities=ENTITIES_NER, language="en"
            )
            matches = [
                _to_detection_match(result, text, self.name) for result in results
            ]
            return DetectionResult(
                detector=self.name, matches=matches, escalate=len(matches) == 0
            )
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name, matches=[], escalate=True, error=str(exc)
            )
