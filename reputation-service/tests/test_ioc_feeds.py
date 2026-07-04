import asyncio
from unittest.mock import AsyncMock

from app.api.schemas import EntityType, Verdict
from app.config.settings import load_settings
from app.sources.base import SourceConfig
from app.sources.ioc_feeds import IocFeedsAdapter, feed_entries_key


def _adapter() -> IocFeedsAdapter:
    config = SourceConfig(
        name="ioc_feeds",
        enabled=True,
        priority=1,
        timeout_ms=2000,
        supported_entities={"domain", "url", "ip"},
    )
    return IocFeedsAdapter(config=config, settings=load_settings())


def test_url_feed_match_returns_malicious_signal():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sismember = AsyncMock(side_effect=[True, False])
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.url, "https://evil.example/malware"))

    assert signal is not None
    assert signal.verdict == Verdict.malicious
    assert "ioc_feed_url_match:ioc_urlhaus" in signal.indicators
    assert signal.score_impact == 60
    redis.sismember.assert_any_call(feed_entries_key("ioc_urlhaus"), "https://evil.example/malware")


def test_openphish_match_uses_domain_and_path_without_scheme():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sismember = AsyncMock(side_effect=[False, True])
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.url, "https://phish.example/login"))

    assert signal is not None
    assert signal.verdict == Verdict.malicious
    assert "ioc_openphish" in signal.indicators[0]
    redis.sismember.assert_any_call(
        feed_entries_key("ioc_openphish"),
        "phish.example/login",
    )


def test_ip_feed_exact_match_returns_malicious_signal():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sismember = AsyncMock(return_value=True)
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.ip, "203.0.113.50"))

    assert signal is not None
    assert signal.verdict == Verdict.malicious
    assert signal.score_impact == 30
    assert "ioc_feed_ip_match" in signal.indicators[0]


def test_ip_cidr_feed_match():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sismember = AsyncMock(return_value=False)
    redis.sscan = AsyncMock(side_effect=[(0, ["203.0.113.0/24"])])
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.ip, "203.0.113.10"))

    assert signal is not None
    assert signal.verdict == Verdict.malicious
    assert "ioc_spamhaus_drop" in signal.indicators[0]


def test_domain_substring_match_returns_suspicious_signal():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sscan = AsyncMock(
        side_effect=[
            (0, ["https://bad.example/payload"]),
            (0, []),
        ]
    )
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.domain, "bad.example"))

    assert signal is not None
    assert signal.verdict == Verdict.suspicious
    assert "ioc_feed_domain_match" in signal.indicators[0]


def test_no_feed_match_returns_unknown():
    adapter = _adapter()
    redis = AsyncMock()
    redis.sismember = AsyncMock(return_value=False)
    redis.sscan = AsyncMock(side_effect=[(0, []), (0, [])])
    redis.aclose = AsyncMock()
    adapter._connect = AsyncMock(return_value=redis)  # type: ignore[method-assign]

    signal = asyncio.run(adapter.lookup(EntityType.url, "https://clean.example"))

    assert signal is not None
    assert signal.verdict == Verdict.unknown
    assert signal.indicators == ["ioc_feed_no_url_match"]
