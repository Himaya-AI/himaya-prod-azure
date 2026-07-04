from __future__ import annotations

from dataclasses import dataclass

from app.api.schemas import EntityType, SignalEvidence, Verdict
from app.core.correlator import CorrelationResult
from app.sources.base import SourceSignal


@dataclass(frozen=True)
class ScoreResult:
    score: int
    verdict: Verdict
    confidence: float
    indicators: list[str]
    evidence: list[SignalEvidence]
    summary: str


class DeterministicScorer:
    def score(
        self,
        entity_type: EntityType,
        signals: list[SourceSignal],
        correlation: CorrelationResult,
    ) -> ScoreResult:
        useful = [signal for signal in signals if signal.verdict != Verdict.unknown]
        raw_score = sum(signal.score_impact for signal in useful)
        minimum_score = max(
            [signal.minimum_score or 0 for signal in useful],
            default=0,
        )
        score = max(raw_score, minimum_score)
        score = max(0, min(100, score))

        verdict = self._verdict(score=score, useful=useful)
        confidence = self._confidence(useful, correlation)
        indicators = [
            indicator
            for signal in useful
            for indicator in signal.indicators
        ]
        evidence = [
            SignalEvidence(
                source=signal.source,
                indicator=indicator,
                impact=signal.score_impact,
                detail=signal.detail,
            )
            for signal in useful
            for indicator in signal.indicators
        ]
        summary = self._summary(entity_type, verdict, correlation, useful)

        return ScoreResult(
            score=score,
            verdict=verdict,
            confidence=confidence,
            indicators=indicators,
            evidence=evidence,
            summary=summary,
        )

    @staticmethod
    def _verdict(score: int, useful: list[SourceSignal]) -> Verdict:
        if not useful:
            return Verdict.unknown
        if score <= 30 and any(signal.verdict == Verdict.suspicious for signal in useful):
            return Verdict.suspicious
        if score <= 30:
            return Verdict.benign
        if score <= 60:
            return Verdict.suspicious
        return Verdict.malicious

    @staticmethod
    def _confidence(
        useful: list[SourceSignal],
        correlation: CorrelationResult,
    ) -> float:
        if not useful:
            return 0.0

        avg_signal_confidence = sum(signal.confidence for signal in useful) / len(useful)
        confidence = 0.30 + (avg_signal_confidence * 0.40)

        if correlation.agreement_level.value == "strong":
            confidence += 0.20
        elif correlation.agreement_level.value == "partial":
            confidence += 0.05
        elif correlation.agreement_level.value == "conflict":
            confidence -= 0.20

        if any(signal.priority == 1 and signal.verdict == Verdict.malicious for signal in useful):
            confidence += 0.20

        if correlation.sources_queried and correlation.sources_responded < correlation.sources_queried:
            missing_ratio = 1 - (correlation.sources_responded / correlation.sources_queried)
            confidence -= min(0.15, missing_ratio * 0.15)

        return round(max(0.0, min(1.0, confidence)), 2)

    @staticmethod
    def _summary(
        entity_type: EntityType,
        verdict: Verdict,
        correlation: CorrelationResult,
        useful: list[SourceSignal],
    ) -> str:
        if not useful:
            return f"No actionable reputation data found for {entity_type.value}; returning unknown."

        top_sources = ", ".join(dict.fromkeys(signal.source for signal in useful))
        return (
            f"{correlation.summary_prefix} Final verdict is {verdict.value}. "
            f"Sources: {top_sources}."
        )
