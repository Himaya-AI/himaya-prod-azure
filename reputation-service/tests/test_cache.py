from app.api.schemas import EntityType, Verdict
from app.core.cache import ReputationCache
from app.sources.base import SourceSignal


def test_ttl_for_signals_uses_error_ttl_when_all_unknown():
    signals = [
        SourceSignal(
            source="virustotal",
            entity_type=EntityType.domain,
            verdict=Verdict.unknown,
            priority=2,
            confidence=0.0,
            indicators=["vt_not_found"],
        )
    ]

    ttl = ReputationCache.ttl_for_signals(signals, default_ttl=3600, error_ttl=900)

    assert ttl == 900


def test_ttl_for_signals_uses_default_ttl_when_useful_signal_present():
    signals = [
        SourceSignal(
            source="virustotal",
            entity_type=EntityType.domain,
            verdict=Verdict.suspicious,
            priority=2,
            confidence=0.5,
            indicators=["vt_suspicious:1/70"],
        )
    ]

    ttl = ReputationCache.ttl_for_signals(signals, default_ttl=3600, error_ttl=900)

    assert ttl == 3600
