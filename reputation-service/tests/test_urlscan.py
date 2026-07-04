import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.schemas import EntityType, Verdict
from app.config.settings import load_settings
from app.sources.base import SourceConfig
from app.sources.urlscan import UrlscanAdapter


def _adapter() -> UrlscanAdapter:
    config = SourceConfig(
        name="urlscan",
        enabled=True,
        priority=2,
        timeout_ms=4000,
        supported_entities={"domain", "url", "ip"},
    )
    settings = load_settings()
    adapter = UrlscanAdapter(config=config, settings=settings)
    adapter.api_key = "test-key"
    return adapter


def _mock_client(response: MagicMock) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(return_value=response)
    return client


def test_malicious_lookup_returns_malicious_for_high_count():
    adapter = _adapter()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "observable": "evil.example",
        "type": "domain",
        "count": 5,
        "firstSeen": "2024-01-01T00:00:00Z",
        "lastSeen": "2026-01-01T00:00:00Z",
    }
    response.raise_for_status = MagicMock()

    with patch("app.sources.urlscan.httpx.AsyncClient", return_value=_mock_client(response)):
        signal = asyncio.run(adapter.lookup(EntityType.domain, "evil.example"))

    assert signal is not None
    assert signal.verdict == Verdict.malicious
    assert signal.score_impact == 50
    assert signal.indicators == ["urlscan_malicious:5"]


def test_malicious_lookup_returns_suspicious_for_single_hit():
    adapter = _adapter()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"count": 1}
    response.raise_for_status = MagicMock()

    with patch("app.sources.urlscan.httpx.AsyncClient", return_value=_mock_client(response)):
        signal = asyncio.run(adapter.lookup(EntityType.url, "https://evil.example/login"))

    assert signal is not None
    assert signal.verdict == Verdict.suspicious
    assert signal.score_impact == 25


def test_malicious_lookup_404_returns_unknown():
    adapter = _adapter()
    response = MagicMock()
    response.status_code = 404

    with patch("app.sources.urlscan.httpx.AsyncClient", return_value=_mock_client(response)):
        signal = asyncio.run(adapter.lookup(EntityType.ip, "203.0.113.10"))

    assert signal is not None
    assert signal.verdict == Verdict.unknown
    assert signal.indicators == ["urlscan_not_found"]


def test_search_fallback_used_when_malicious_api_forbidden():
    adapter = _adapter()
    forbidden = MagicMock()
    forbidden.status_code = 403

    search_ok = MagicMock()
    search_ok.status_code = 200
    search_ok.json.return_value = {"total": 2, "results": []}
    search_ok.raise_for_status = MagicMock()

    client = _mock_client(forbidden)
    client.get = AsyncMock(side_effect=[forbidden, search_ok])

    with patch("app.sources.urlscan.httpx.AsyncClient", return_value=client):
        signal = asyncio.run(adapter.lookup(EntityType.domain, "evil.example"))

    assert signal is not None
    assert signal.verdict == Verdict.suspicious
    assert signal.indicators == ["urlscan_search_malicious:2"]
    assert client.get.await_count == 2
