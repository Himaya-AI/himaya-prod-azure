from app.api.schemas import EntityType, Verdict
from app.core.orchestrator import _should_run_whois
from app.sources.base import SourceSignal
from app.sources.virustotal import VirusTotalAdapter, _vt_reputation_adjustment


def test_vt_reputation_penalty_when_no_harmless_consensus():
    impact, indicator = _vt_reputation_adjustment(-25, malicious=0, harmless=0)

    assert impact == 20
    assert indicator == "vt_reputation:-25"


def test_vt_reputation_skipped_for_large_infra_domains():
    impact, indicator = _vt_reputation_adjustment(-25, malicious=1, harmless=100)

    assert impact == 0
    assert indicator is None


def test_vt_signal_includes_reputation_penalty():
    adapter = VirusTotalAdapter.__new__(VirusTotalAdapter)
    adapter.config = type("Cfg", (), {"priority": 2, "name": "virustotal"})()

    signal = adapter._signal_from_attributes(
        EntityType.domain,
        {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 70,
            },
            "reputation": -30,
        },
        12.5,
    )

    assert signal.verdict == Verdict.suspicious
    assert signal.score_impact == 20
    assert "vt_reputation:-30" in signal.indicators


def test_should_run_whois_when_virustotal_missing():
    assert _should_run_whois(EntityType.domain, []) is True


def test_should_run_whois_when_virustotal_not_found():
    signal = SourceSignal(
        source="virustotal",
        entity_type=EntityType.domain,
        verdict=Verdict.unknown,
        priority=2,
        confidence=0.0,
        indicators=["virustotal_not_found"],
    )

    assert _should_run_whois(EntityType.domain, [signal]) is True


def test_should_skip_whois_when_virustotal_responded():
    signal = SourceSignal(
        source="virustotal",
        entity_type=EntityType.domain,
        verdict=Verdict.unknown,
        priority=2,
        confidence=0.0,
        indicators=["vt_no_actionable_signal"],
    )

    assert _should_run_whois(EntityType.domain, [signal]) is False


def test_should_not_run_whois_for_non_domain_lookup():
    assert _should_run_whois(EntityType.url, []) is False
