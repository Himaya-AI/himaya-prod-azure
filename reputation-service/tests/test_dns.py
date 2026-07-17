import asyncio
from unittest.mock import MagicMock

from app.api.schemas import EntityType, Verdict
from app.config.settings import load_settings
from app.sources.base import SourceConfig
from app.sources.dns import DnsAdapter, DnsVerificationResult


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
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: MagicMock())

    async def fake_inspect(_domain):
        return DnsVerificationResult(
            valid_format=True,
            domain="no-mail.example",
            root_domain="no-mail.example",
            subdomain=None,
            tld="example",
            valid_tld=True,
            public_domain=True,
            has_a_records=False,
            has_mx_records=False,
            has_txt_records=False,
            has_spf_records=False,
            spf_qualifier=None,
            spf_strict=False,
            dmarc_configured=False,
            indicators=["no_a_record", "no_mx_record", "no_spf_record", "no_dmarc_record"],
            notes=[],
        )

    monkeypatch.setattr(adapter, "inspect_domain", fake_inspect)

    signal = asyncio.run(adapter.lookup(EntityType.domain, "no-mail.example"))

    assert signal is not None
    assert signal.verdict == Verdict.suspicious
    assert signal.score_impact == 40
    assert signal.indicators == ["no_mx_record", "no_spf_record", "no_dmarc_record"]


def test_dns_returns_none_when_records_are_present(monkeypatch):
    adapter = _adapter()
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: MagicMock())

    async def fake_inspect(_domain):
        return DnsVerificationResult(
            valid_format=True,
            domain="healthy.example",
            root_domain="healthy.example",
            subdomain=None,
            tld="example",
            valid_tld=True,
            public_domain=True,
            has_a_records=True,
            has_mx_records=True,
            has_txt_records=True,
            has_spf_records=True,
            spf_qualifier="pass",
            spf_strict=False,
            dmarc_configured=True,
            mx_records=["mx.healthy.example"],
            txt_records=["v=spf1 include:_spf.healthy.example ~all"],
            indicators=[],
            notes=["registrable_domain:healthy.example"],
        )

    monkeypatch.setattr(adapter, "inspect_domain", fake_inspect)

    signal = asyncio.run(adapter.lookup(EntityType.domain, "healthy.example"))

    assert signal is None


def test_dns_inspect_domain_returns_structured_evidence(monkeypatch):
    adapter = _adapter()
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: MagicMock())

    async def has_a(_resolver, _domain):
        return True

    async def mx_records(_resolver, _domain):
        return ["mx1.example.com", "mx2.example.com"]

    async def txt_records(_resolver, _domain):
        return ["v=spf1 include:_spf.example.com -all", "google-site-verification=abc"]

    async def has_dmarc(_resolver, _domain):
        return True

    monkeypatch.setattr(adapter, "_has_a_records", has_a)
    monkeypatch.setattr(adapter, "_mx_records", mx_records)
    monkeypatch.setattr(adapter, "_txt_records", txt_records)
    monkeypatch.setattr(adapter, "_has_dmarc_record", has_dmarc)

    result = asyncio.run(adapter.inspect_domain("account-security-noreply@accountprotection.microsoft.com"))

    assert result is not None
    assert result.valid_format is True
    assert result.domain == "accountprotection.microsoft.com"
    assert result.root_domain == "microsoft.com"
    assert result.subdomain == "accountprotection"
    assert result.tld == "com"
    assert result.has_a_records is True
    assert result.has_mx_records is True
    assert result.has_txt_records is True
    assert result.has_spf_records is True
    assert result.spf_qualifier == "fail"
    assert result.spf_strict is True
    assert result.dmarc_configured is True
    assert result.mx_records == ["mx1.example.com", "mx2.example.com"]
