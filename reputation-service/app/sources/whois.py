from __future__ import annotations

from typing import Any

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.core.whois_gateway import WhoisGateway, WhoisStatus, get_whois_gateway
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup


class WhoisAdapter(BaseAdapter):
    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.settings = settings
        self._gateway: WhoisGateway = get_whois_gateway(settings)

    @property
    def is_configured(self) -> bool:
        return self._gateway.is_available

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=None if self.is_configured else "python-whois is not installed",
        )

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        if entity_type != EntityType.domain:
            return None
        if not self.is_configured:
            return None

        with TimedLookup() as timer:
            result = await self._gateway.lookup(value)

            if result.status == WhoisStatus.ok:
                return _age_signal(
                    source=self.name,
                    entity_type=entity_type,
                    priority=self.config.priority,
                    age_days=result.age_days or 0,
                    raw=result.raw,
                    latency_ms=timer.latency_ms,
                )

            if result.status == WhoisStatus.no_creation_date:
                return SourceSignal(
                    source=self.name,
                    entity_type=entity_type,
                    verdict=Verdict.suspicious,
                    priority=self.config.priority,
                    confidence=0.45,
                    indicators=["whois_no_creation_date"],
                    score_impact=15,
                    severity="medium",
                    detail="WHOIS returned no domain creation date",
                    raw=result.raw,
                    latency_ms=timer.latency_ms,
                )

            return SourceSignal(
                source=self.name,
                entity_type=entity_type,
                verdict=Verdict.unknown,
                priority=self.config.priority,
                confidence=0.0,
                indicators=["whois_error"],
                detail="WHOIS lookup failed",
                latency_ms=timer.latency_ms,
            )


def _age_signal(
    source: str,
    entity_type: EntityType,
    priority: int,
    age_days: int,
    raw: dict[str, Any],
    latency_ms: float,
) -> SourceSignal:
    if age_days < 30:
        return SourceSignal(
            source=source,
            entity_type=entity_type,
            verdict=Verdict.suspicious,
            priority=priority,
            confidence=0.60,
            indicators=[f"whois_new_domain:{age_days}d"],
            score_impact=40,
            severity="medium",
            detail=f"Domain was created {age_days} days ago",
            raw=raw,
            latency_ms=latency_ms,
        )
    if age_days < 90:
        return SourceSignal(
            source=source,
            entity_type=entity_type,
            verdict=Verdict.suspicious,
            priority=priority,
            confidence=0.45,
            indicators=[f"whois_young_domain:{age_days}d"],
            score_impact=20,
            severity="low",
            detail=f"Domain was created {age_days} days ago",
            raw=raw,
            latency_ms=latency_ms,
        )
    if age_days < 365:
        return SourceSignal(
            source=source,
            entity_type=entity_type,
            verdict=Verdict.suspicious,
            priority=priority,
            confidence=0.35,
            indicators=[f"whois_recent_domain:{age_days}d"],
            score_impact=5,
            severity="low",
            detail=f"Domain was created {age_days} days ago",
            raw=raw,
            latency_ms=latency_ms,
        )
    if age_days >= 365:
        return SourceSignal(
            source=source,
            entity_type=entity_type,
            verdict=Verdict.benign,
            priority=priority,
            confidence=0.45,
            indicators=[f"whois_established:{age_days}d"],
            score_impact=-5,
            severity="info",
            detail=f"Domain age is established at {age_days} days",
            raw=raw,
            latency_ms=latency_ms,
        )
    return SourceSignal(
        source=source,
        entity_type=entity_type,
        verdict=Verdict.unknown,
        priority=priority,
        confidence=0.20,
        indicators=[f"whois_domain_age:{age_days}d"],
        detail=f"Domain age is {age_days} days",
        raw=raw,
        latency_ms=latency_ms,
    )
