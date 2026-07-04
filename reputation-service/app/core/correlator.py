from __future__ import annotations

from dataclasses import dataclass

from app.api.schemas import AgreementLevel, Verdict
from app.sources.base import SourceSignal


@dataclass(frozen=True)
class CorrelationResult:
    agreement_level: AgreementLevel
    sources_queried: int
    sources_responded: int
    sources_flagged: int
    has_conflict: bool
    summary_prefix: str


class SignalCorrelator:
    def correlate(
        self,
        signals: list[SourceSignal],
        sources_queried: int,
        sources_responded: int | None = None,
    ) -> CorrelationResult:
        useful = [signal for signal in signals if signal.verdict != Verdict.unknown]
        malicious = [signal for signal in useful if signal.verdict == Verdict.malicious]
        suspicious = [signal for signal in useful if signal.verdict == Verdict.suspicious]
        benign = [signal for signal in useful if signal.verdict == Verdict.benign]
        flagged = malicious + suspicious
        responded = sources_responded if sources_responded is not None else len(signals)

        has_conflict = bool(flagged and benign)
        if has_conflict:
            agreement = AgreementLevel.conflict
            prefix = "Threat sources returned conflicting reputation signals."
        elif len(malicious) >= 2 or _has_priority_one_malicious(malicious):
            agreement = AgreementLevel.strong
            prefix = "Multiple high-confidence signals indicate malicious reputation."
        elif len(flagged) >= 2:
            agreement = AgreementLevel.strong
            prefix = "Multiple sources agree on suspicious or malicious reputation."
        elif len(flagged) == 1:
            agreement = AgreementLevel.partial
            prefix = "One source reported suspicious or malicious reputation."
        elif benign:
            agreement = AgreementLevel.partial
            prefix = "Available sources lean benign, with no malicious consensus."
        else:
            agreement = AgreementLevel.none
            prefix = "No source returned actionable reputation data."

        return CorrelationResult(
            agreement_level=agreement,
            sources_queried=sources_queried,
            sources_responded=responded,
            sources_flagged=len(flagged),
            has_conflict=has_conflict,
            summary_prefix=prefix,
        )


def _has_priority_one_malicious(signals: list[SourceSignal]) -> bool:
    return any(signal.priority == 1 for signal in signals)
