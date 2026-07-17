from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.core.tld import TldService
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup

try:
    from dns import asyncresolver as dns_asyncresolver
except ImportError:
    dns_asyncresolver = None

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DnsVerificationResult:
    valid_format: bool
    domain: str | None
    root_domain: str | None
    subdomain: str | None
    tld: str | None
    valid_tld: bool
    public_domain: bool
    has_a_records: bool
    has_mx_records: bool
    has_txt_records: bool
    has_spf_records: bool
    spf_qualifier: str | None
    spf_strict: bool
    dmarc_configured: bool
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class DnsAdapter(BaseAdapter):
    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.settings = settings
        self._tld_service = TldService()

    @property
    def is_configured(self) -> bool:
        return dns_asyncresolver is not None

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=None if self.is_configured else "dnspython is not installed",
        )

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        if entity_type != EntityType.domain or not self.is_configured:
            return None

        with TimedLookup() as timer:
            try:
                verification = await self.inspect_domain(value)
                if verification is None:
                    return None

                indicators = list(verification.indicators)
                score_impact = 0

                if not verification.has_mx_records:
                    score_impact += 20
                if not verification.has_spf_records:
                    score_impact += 10
                if not verification.dmarc_configured:
                    score_impact += 10

                if not indicators:
                    return None

                return SourceSignal(
                    source=self.name,
                    entity_type=entity_type,
                    verdict=Verdict.suspicious,
                    priority=self.config.priority,
                    confidence=0.55,
                    indicators=indicators,
                    score_impact=score_impact,
                    severity="medium",
                    detail="Domain DNS records indicate weak or missing mail authentication setup",
                    raw=self._verification_to_raw(verification),
                    latency_ms=timer.latency_ms,
                )
            except Exception as exc:
                logger.debug("DNS reputation check failed for %s: %s", value, exc)
                return SourceSignal(
                    source=self.name,
                    entity_type=entity_type,
                    verdict=Verdict.unknown,
                    priority=self.config.priority,
                    confidence=0.0,
                    indicators=["dns_lookup_error"],
                    detail="DNS lookup failed",
                    latency_ms=timer.latency_ms,
                )

    async def inspect_domain(self, value: str) -> DnsVerificationResult | None:
        if not self.is_configured:
            return None

        with TimedLookup() as timer:
            try:
                if dns_asyncresolver is None:
                    return None

                resolver = dns_asyncresolver.Resolver()
                resolver.timeout = self.config.timeout_ms / 1000
                resolver.lifetime = self.config.timeout_ms / 1000

                tld_result = self._tld_service.analyze(value)
                domain = tld_result.domain or value.strip().lower().rstrip(".") or None

                has_a_records = await self._has_a_records(resolver, domain) if domain else False
                mx_records = await self._mx_records(resolver, domain) if domain else []
                txt_records = await self._txt_records(resolver, domain) if domain else []
                spf_record = _first_spf_record(txt_records)
                has_spf_records = spf_record is not None
                spf_qualifier, spf_strict = _parse_spf(spf_record)
                dmarc_configured = await self._has_dmarc_record(resolver, domain) if domain else False

                indicators: list[str] = []
                notes: list[str] = []

                if not has_a_records:
                    indicators.append("no_a_record")
                if not mx_records:
                    indicators.append("no_mx_record")
                if not has_spf_records:
                    indicators.append("no_spf_record")
                if not dmarc_configured:
                    indicators.append("no_dmarc_record")

                if tld_result.root_domain:
                    notes.append(f"registrable_domain:{tld_result.root_domain}")
                if tld_result.subdomain:
                    notes.append(f"subdomain:{tld_result.subdomain}")
                if mx_records:
                    notes.append(f"mx_count:{len(mx_records)}")
                if spf_record:
                    notes.append(f"spf_record:{spf_record}")

                return DnsVerificationResult(
                    valid_format=tld_result.valid_format,
                    domain=tld_result.domain,
                    root_domain=tld_result.root_domain,
                    subdomain=tld_result.subdomain,
                    tld=tld_result.tld,
                    valid_tld=tld_result.valid_tld,
                    public_domain=tld_result.public_domain,
                    has_a_records=has_a_records,
                    has_mx_records=bool(mx_records),
                    has_txt_records=bool(txt_records),
                    has_spf_records=has_spf_records,
                    spf_qualifier=spf_qualifier,
                    spf_strict=spf_strict,
                    dmarc_configured=dmarc_configured,
                    mx_records=mx_records,
                    txt_records=txt_records,
                    indicators=indicators,
                    notes=notes,
                )
            except Exception as exc:
                logger.debug("DNS inspect failed for %s: %s", value, exc)
                return DnsVerificationResult(
                    valid_format=False,
                    domain=None,
                    root_domain=None,
                    subdomain=None,
                    tld=None,
                    valid_tld=False,
                    public_domain=False,
                    has_a_records=False,
                    has_mx_records=False,
                    has_txt_records=False,
                    has_spf_records=False,
                    spf_qualifier=None,
                    spf_strict=False,
                    dmarc_configured=False,
                    indicators=["dns_lookup_error"],
                    notes=[f"dns_lookup_failed:{type(exc).__name__}"],
                )

    @staticmethod
    async def _has_mx(resolver, domain: str) -> bool:
        try:
            await resolver.resolve(domain, "MX")
            return True
        except Exception:
            return False

    @staticmethod
    async def _has_a_records(resolver, domain: str) -> bool:
        try:
            await resolver.resolve(domain, "A")
            return True
        except Exception:
            return False

    @staticmethod
    async def _mx_records(resolver, domain: str) -> list[str]:
        try:
            answers = await resolver.resolve(domain, "MX")
            records: list[str] = []
            for answer in answers:
                exchange = getattr(answer, "exchange", None)
                if exchange:
                    records.append(str(exchange).rstrip("."))
            return list(dict.fromkeys(records))
        except Exception:
            return []

    @staticmethod
    async def _txt_records(resolver, domain: str) -> list[str]:
        try:
            answers = await resolver.resolve(domain, "TXT")
            records: list[str] = []
            for record in answers:
                chunks = getattr(record, "strings", []) or []
                text = b"".join(chunks).decode("utf-8", errors="ignore").strip()
                if text:
                    records.append(text)
            return records
        except Exception:
            return []

    @staticmethod
    async def _has_spf_record(resolver, domain: str) -> bool:
        try:
            answers = await resolver.resolve(domain, "TXT")
            return any(b"v=spf1" in b"".join(record.strings) for record in answers)
        except Exception:
            return False

    @staticmethod
    async def _has_dmarc_record(resolver, domain: str) -> bool:
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            return any(b"v=DMARC1" in b"".join(record.strings) for record in answers)
        except Exception:
            return False

    @staticmethod
    def _verification_to_raw(verification: DnsVerificationResult) -> dict[str, Any]:
        return {
            "valid_format": verification.valid_format,
            "domain": verification.domain,
            "root_domain": verification.root_domain,
            "subdomain": verification.subdomain,
            "tld": verification.tld,
            "valid_tld": verification.valid_tld,
            "public_domain": verification.public_domain,
            "has_a_records": verification.has_a_records,
            "has_mx_records": verification.has_mx_records,
            "has_txt_records": verification.has_txt_records,
            "has_spf_records": verification.has_spf_records,
            "spf_qualifier": verification.spf_qualifier,
            "spf_strict": verification.spf_strict,
            "dmarc_configured": verification.dmarc_configured,
            "mx_records": verification.mx_records,
            "txt_records": verification.txt_records,
            "indicators": verification.indicators,
            "notes": verification.notes,
        }


def _first_spf_record(txt_records: list[str]) -> str | None:
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _parse_spf(record: str | None) -> tuple[str | None, bool]:
    if not record:
        return None, False

    parts = record.split()
    if not parts or parts[0].lower() != "v=spf1":
        return None, False

    qualifier = None
    strict = False
    for part in parts[1:]:
        if part.endswith("all"):
            prefix = part[:-3]
            if prefix == "-":
                qualifier = "fail"
                strict = True
                break
            if prefix == "~":
                qualifier = "softfail"
                strict = False
                break
            if prefix == "?":
                qualifier = "neutral"
                strict = False
                break
            if prefix == "+":
                qualifier = "pass"
                strict = False
                break
    return qualifier, strict
