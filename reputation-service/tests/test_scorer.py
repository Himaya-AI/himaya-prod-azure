from app.api.schemas import EntityType, Verdict
from app.core.correlator import SignalCorrelator
from app.core.scorer import DeterministicScorer
from app.sources.base import SourceSignal


def test_multi_source_consensus_scores_malicious():
    signals = [
        SourceSignal(
            source="virustotal",
            entity_type=EntityType.url,
            verdict=Verdict.malicious,
            priority=2,
            confidence=0.85,
            indicators=["vt_malicious:5/80"],
            score_impact=50,
        ),
        SourceSignal(
            source="alienvault",
            entity_type=EntityType.url,
            verdict=Verdict.malicious,
            priority=2,
            confidence=0.80,
            indicators=["otx_pulse_match:2"],
            score_impact=50,
        ),
    ]

    correlation = SignalCorrelator().correlate(signals, sources_queried=2)
    score = DeterministicScorer().score(EntityType.url, signals, correlation)

    assert correlation.agreement_level == "strong"
    assert score.verdict == Verdict.malicious
    assert score.score == 100
    assert score.confidence >= 0.8


def test_whois_only_new_domain_is_suspicious_not_malicious():
    signals = [
        SourceSignal(
            source="whois",
            entity_type=EntityType.domain,
            verdict=Verdict.suspicious,
            priority=3,
            confidence=0.60,
            indicators=["whois_new_domain:5d"],
            score_impact=40,
        )
    ]

    correlation = SignalCorrelator().correlate(signals, sources_queried=1)
    score = DeterministicScorer().score(EntityType.domain, signals, correlation)

    assert score.score == 40
    assert score.verdict == Verdict.suspicious


def test_minimum_score_for_exact_hash_match_wins():
    signals = [
        SourceSignal(
            source="virustotal",
            entity_type=EntityType.file,
            verdict=Verdict.malicious,
            priority=2,
            confidence=0.85,
            indicators=["vt_malicious:3/70"],
            score_impact=70,
            minimum_score=85,
        )
    ]

    correlation = SignalCorrelator().correlate(signals, sources_queried=1)
    score = DeterministicScorer().score(EntityType.file, signals, correlation)

    assert score.score == 85
    assert score.verdict == Verdict.malicious
