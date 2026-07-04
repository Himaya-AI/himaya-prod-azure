from __future__ import annotations

import logging

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup

logger = logging.getLogger(__name__)


class DnsAdapter(BaseAdapter):
    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.settings = settings

    @property
    def is_configured(self) -> bool:
        try:
            import dns.asyncresolver  # noqa: F401

            return True
        except ImportError:
            return False

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
                import dns.asyncresolver

                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = self.config.timeout_ms / 1000
                resolver.lifetime = self.config.timeout_ms / 1000

                has_mx = await self._has_mx(resolver, value)
                has_spf_record = await self._has_spf_record(resolver, value)
                has_dmarc_record = await self._has_dmarc_record(resolver, value)

                indicators: list[str] = []
                score_impact = 0

                if not has_mx:
                    score_impact += 20
                    indicators.append("no_mx_record")
                if not has_spf_record:
                    score_impact += 10
                    indicators.append("no_spf_record")
                if not has_dmarc_record:
                    score_impact += 10
                    indicators.append("no_dmarc_record")

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
                    raw={
                        "has_mx": has_mx,
                        "has_spf_record": has_spf_record,
                        "has_dmarc_record": has_dmarc_record,
                    },
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

    @staticmethod
    async def _has_mx(resolver, domain: str) -> bool:
        try:
            await resolver.resolve(domain, "MX")
            return True
        except Exception:
            return False

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
