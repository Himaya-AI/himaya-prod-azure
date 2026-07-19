from __future__ import annotations

from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


class OrganizationRecognizer(EntityRecognizer):
    """Surfaces spaCy's ORG label as a Presidio ORGANIZATION entity."""

    supported_entities = ["ORGANIZATION"]
    supported_language = "en"

    def load(self) -> None:
        """No-op — the spaCy model is already loaded by the engine's NLP engine."""

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts
    ) -> list[RecognizerResult]:
        return [
            RecognizerResult(
                entity_type="ORGANIZATION",
                start=entity.start_char,
                end=entity.end_char,
                score=0.6,
            )
            for entity in nlp_artifacts.entities
            if entity.label_ == "ORG"
        ]
