"""Service-independent classification findings consumed by policy."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    detector: str
    entity_type: str
    confidence: float
    start: int
    end: int
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ClassificationOutcome:
    findings: tuple[Finding, ...]
    llm_classification: str
    llm_confidence: float
    llm_categories: tuple[str, ...]
    llm_reasoning: str
    detector_errors: tuple[str, ...] = ()
    escalation_requested: bool = False

    @property
    def inspection_complete(self) -> bool:
        return not self.detector_errors
