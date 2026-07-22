"""Normalize classifier wire responses into policy-domain findings."""

from backend.dlp.contracts import ClassifyResponse
from backend.dlp.domain import ClassificationOutcome, Finding


def normalize_classification(
    response: ClassifyResponse,
) -> ClassificationOutcome:
    findings = tuple(
        Finding(
            detector=match.detector,
            entity_type=match.entity_type.upper(),
            confidence=match.score,
            start=match.start,
            end=match.end,
            metadata=dict(match.metadata),
        )
        for result in response.findings
        for match in result.matches
    )
    detector_errors = tuple(
        f"{result.detector}: {result.error}"
        for result in response.findings
        if result.error
    )
    return ClassificationOutcome(
        findings=findings,
        llm_classification=response.llm_result.classification.upper(),
        llm_confidence=response.llm_result.confidence,
        llm_categories=tuple(
            category.lower()
            for category in response.llm_result.categories
        ),
        llm_reasoning=response.llm_result.reasoning,
        detector_errors=detector_errors,
        escalation_requested=any(
            result.escalate for result in response.findings
        ),
    )
