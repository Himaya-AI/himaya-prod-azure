import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.api.schemas import EntityType, Verdict
from app.config.settings import load_settings
from app.sources.base import SourceConfig
from app.sources.dns import DnsAdapter


def _adapter() -> DnsAdapter:
    config = SourceConfig(
        name="dns",
        enabled=True,
        priority=3,
        timeout_ms=3000,
        supported_entities={"domain"},
    )
    return DnsAdapter(config=config, settings=load_settings())


def test_dns_flags_missing_mx_spf_and_dmarc(monkeypatch):
    adapter = _adapter()
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda: MagicMock(),
    )

    async def fake_has_mx(_resolver, _domain):
        return False

    async def fake_has_spf(_resolver, _domain):
        return False

    async def fake_has_dmarc(_resolver, _domain):
        return False

    monkeypatch.setattr(adapter, "_has_mx", fake_has_mx)
    monkeypatch.setattr(adapter, "_has_spf_record", fake_has_spf)
    monkeypatch.setattr(adapter, "_has_dmarc_record", fake_has_dmarc)

    signal = asyncio.run(adapter.lookup(EntityType.domain, "no-mail.example"))

    assert signal is not None
    assert signal.verdict == Verdict.suspicious
    assert signal.score_impact == 40
    assert signal.indicators == ["no_mx_record", "no_spf_record", "no_dmarc_record"]


def test_dns_returns_none_when_records_are_present(monkeypatch):
    adapter = _adapter()
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: MagicMock())

    async def ok(_resolver, _domain):
        return True

    monkeypatch.setattr(adapter, "_has_mx", ok)
    monkeypatch.setattr(adapter, "_has_spf_record", ok)
    monkeypatch.setattr(adapter, "_has_dmarc_record", ok)

    signal = asyncio.run(adapter.lookup(EntityType.domain, "healthy.example"))

    assert signal is None
