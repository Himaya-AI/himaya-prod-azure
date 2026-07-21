from __future__ import annotations

from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.recognizer_result import RecognizerResult

from app.service.base import BaseDetector, DetectionMatch, DetectionResult

ENTITIES_FINANCIAL = ["CREDIT_CARD", "IBAN_CODE", "US_BANK_NUMBER", "CRYPTO"]
ENTITIES_CONTACT = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "URL"]
ENTITIES_IDENTITY_US = ["US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE", "US_ITIN"]
ENTITIES_IDENTITY_UK = ["UK_NHS", "UK_NINO", "UK_PASSPORT"]
ENTITIES_IDENTITY_IN = ["IN_AADHAAR", "IN_PAN", "IN_PASSPORT"]

_SUPPORTED_ENTITIES = (
    ENTITIES_FINANCIAL
    + ENTITIES_CONTACT
    + ENTITIES_IDENTITY_US
    + ENTITIES_IDENTITY_UK
    + ENTITIES_IDENTITY_IN
)


def _mask_snippet(entity_type: str, raw: str) -> str:
    if entity_type != "CREDIT_CARD":
        return "****"
    masked = raw[-4:].rjust(len(raw), "x")
    return " ".join(masked[i : i + 4] for i in range(0, len(masked), 4))


def _to_detection_match(result: RecognizerResult, text: str) -> DetectionMatch:
    raw = text[result.start : result.end]
    return DetectionMatch(
        detector="pii",
        entity_type=result.entity_type,
        score=result.score,
        start=result.start,
        end=result.end,
        metadata={"masked": _mask_snippet(result.entity_type, raw)},
    )


class PIIDetector(BaseDetector):
    def __init__(self, engine: AnalyzerEngine) -> None:
        self._engine = engine

    @property
    def name(self) -> str:
        return "pii"

    async def analyze(self, text: str, metadata: dict[str, Any]) -> DetectionResult:
        try:
            results = self._engine.analyze(
                text=text, entities=_SUPPORTED_ENTITIES, language="en"
            )
            matches = [_to_detection_match(result, text) for result in results]
            return DetectionResult(
                detector=self.name, matches=matches, escalate=len(matches) == 0
            )
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name, matches=[], escalate=True, error=str(exc)
            )
