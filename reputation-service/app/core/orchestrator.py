from __future__ import annotations

import asyncio
import re
from datetime import datetime

from app.api.schemas import (
    AgreementLevel,
    EntityType,
    ReputationEntity,
    ReputationResult,
    Verdict,
)
from app.core.cache import ReputationCache
from app.core.correlator import SignalCorrelator
from app.core.normalizer import NormalizedEntity, build_ti_cache_key, normalize_entity
from app.core.scorer import DeterministicScorer
from app.sources.base import SourceSignal, ThreatIntelAdapter
from app.sources.registry import SourceRegistry


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".vbs",
    ".js",
    ".ps1",
    ".bat",
    ".cmd",
    ".msi",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".jar",
}

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click")
BRAND_WORDS = ("paypal", "amazon", "microsoft", "google", "zatca", "sama")


class ReputationOrchestrator:
    def __init__(
        self,
        cache: ReputationCache,
        registry: SourceRegistry,
        correlator: SignalCorrelator | None = None,
        scorer: DeterministicScorer | None = None,
    ) -> None:
        self.cache = cache
        self.registry = registry
        self.correlator = correlator or SignalCorrelator()
        self.scorer = scorer or DeterministicScorer()

    async def lookup_entity(
        self,
        entity: ReputationEntity,
        *,
        force_refresh: bool = False,
        include_raw_signals: bool = False,
        max_sources: int | None = None,
    ) -> ReputationResult:
        normalized = normalize_entity(entity)

        override = await self.cache.get_override(normalized.entity_key)
        if override:
            return self._result_from_override(entity, normalized, override)

        ti_cache_key = build_ti_cache_key(normalized)
        adapters = self._adapters_for(normalized, max_sources=max_sources)
        source_signals: list[SourceSignal]
        ti_cache_hit = False

        if ti_cache_key and not force_refresh:
            cached_signals = await self.cache.get_source_signals(ti_cache_key)
            if cached_signals is not None:
                source_signals = cached_signals
                ti_cache_hit = True
            else:
                source_signals = await self._collect_source_signals(normalized, adapters)
                await self._store_ti_signals(ti_cache_key, source_signals, normalized)
        else:
            source_signals = await self._collect_source_signals(normalized, adapters)
            if ti_cache_key:
                await self._store_ti_signals(ti_cache_key, source_signals, normalized)

        context_signals = self._context_signals(entity, normalized)
        signals = source_signals + context_signals
        correlation = self.correlator.correlate(
            signals,
            sources_queried=len(adapters),
            sources_responded=len(source_signals),
        )
        score = self.scorer.score(normalized.entity_type, signals, correlation)

        return ReputationResult(
            type=normalized.entity_type,
            value=normalized.original_value,
            normalized_value=normalized.normalized_value,
            entity_key=normalized.entity_key,
            verdict=score.verdict,
            score=score.score,
            confidence=score.confidence,
            cache_hit=ti_cache_hit,
            sources=sorted(dict.fromkeys(signal.source for signal in signals)),
            indicators=score.indicators,
            evidence=score.evidence,
            agreement_level=correlation.agreement_level,
            summary=score.summary,
            raw_signals=[
                signal.to_public_dict(include_raw=True)
                for signal in signals
            ]
            if include_raw_signals
            else None,
        )

    async def _store_ti_signals(
        self,
        ti_cache_key: str,
        source_signals: list[SourceSignal],
        normalized: NormalizedEntity,
    ) -> None:
        ttl = self.cache.ttl_for_signals(
            source_signals,
            self.cache.default_ttl_seconds,
            self.cache.error_ttl_seconds,
        )
        await self.cache.set_source_signals(
            ti_cache_key,
            source_signals,
            ttl_seconds=ttl,
            lookup_type=normalized.lookup_type,
            lookup_value=normalized.lookup_value,
        )

    async def lookup_many(
        self,
        entities: list[ReputationEntity],
        *,
        force_refresh: bool = False,
        include_raw_signals: bool = False,
        max_sources: int | None = None,
    ) -> list[ReputationResult]:
        return await asyncio.gather(
            *[
                self.lookup_entity(
                    entity,
                    force_refresh=force_refresh,
                    include_raw_signals=include_raw_signals,
                    max_sources=max_sources,
                )
                for entity in entities
            ]
        )

    async def source_statuses(self):
        return await self.registry.statuses()

    def _adapters_for(
        self,
        normalized: NormalizedEntity,
        max_sources: int | None = None,
    ) -> list[ThreatIntelAdapter]:
        adapters = self.registry.for_entity(normalized.lookup_type, max_sources=max_sources)

        if normalized.entity_type == EntityType.url and normalized.related_domain:
            if max_sources is None or len(adapters) < max_sources:
                whois_adapters = [
                    adapter
                    for adapter in self.registry.for_entity(EntityType.domain)
                    if adapter.name == "whois"
                ]
                adapters = _dedupe_adapters(adapters + whois_adapters)
                if max_sources is not None:
                    adapters = adapters[:max_sources]

        return adapters

    async def _collect_source_signals(
        self,
        normalized: NormalizedEntity,
        adapters: list[ThreatIntelAdapter],
    ) -> list[SourceSignal]:
        whois_adapters = [adapter for adapter in adapters if adapter.name == "whois"]
        primary_adapters = [adapter for adapter in adapters if adapter.name != "whois"]

        primary_results = await asyncio.gather(
            *[self._run_adapter(adapter, normalized) for adapter in primary_adapters]
        )
        signals = [signal for signal in primary_results if signal is not None]

        if whois_adapters and _should_run_whois(normalized.lookup_type, primary_results):
            whois_results = await asyncio.gather(
                *[self._run_adapter(adapter, normalized) for adapter in whois_adapters]
            )
            signals.extend(signal for signal in whois_results if signal is not None)

        return signals

    async def _run_adapter(
        self,
        adapter: ThreatIntelAdapter,
        normalized: NormalizedEntity,
    ) -> SourceSignal | None:
        lookup_type = normalized.lookup_type
        lookup_value = normalized.lookup_value
        if normalized.entity_type == EntityType.url and adapter.name == "whois":
            lookup_type = EntityType.domain
            lookup_value = normalized.related_domain or normalized.lookup_value
        try:
            return await asyncio.wait_for(
                adapter.lookup(lookup_type, lookup_value),
                timeout=adapter.config.timeout_ms / 1000,
            )
        except Exception:
            return SourceSignal(
                source=adapter.name,
                entity_type=lookup_type,
                verdict=Verdict.unknown,
                priority=adapter.config.priority,
                confidence=0.0,
                indicators=[f"{adapter.name}_timeout"],
                detail="Source lookup timed out or failed",
            )

    def _context_signals(
        self,
        entity: ReputationEntity,
        normalized: NormalizedEntity,
    ) -> list[SourceSignal]:
        signals: list[SourceSignal] = []
        context = entity.context
        if context and context.auth_results and entity.type == EntityType.sender:
            signals.extend(_auth_signals(context.auth_results, normalized.entity_type))

        if entity.type == EntityType.url:
            suspicious_reasons = _suspicious_url_reasons(normalized.normalized_value)
            if suspicious_reasons:
                signals.append(
                    SourceSignal(
                        source="heuristic",
                        entity_type=EntityType.url,
                        verdict=Verdict.suspicious,
                        priority=3,
                        confidence=0.45,
                        indicators=suspicious_reasons,
                        score_impact=min(30, len(suspicious_reasons) * 10),
                        severity="low",
                        detail="URL matched suspicious pattern heuristics",
                    )
                )

        if context and entity.type == EntityType.file:
            ext = (context.extension or "").lower()
            if not ext and context.filename and "." in context.filename:
                ext = "." + context.filename.rsplit(".", 1)[-1].lower()
            if ext in DANGEROUS_EXTENSIONS:
                signals.append(
                    SourceSignal(
                        source="heuristic",
                        entity_type=EntityType.file,
                        verdict=Verdict.suspicious,
                        priority=3,
                        confidence=0.45,
                        indicators=[f"dangerous_attachment_extension:{ext}"],
                        score_impact=20,
                        severity="medium",
                        detail="Attachment extension is commonly abused",
                    )
                )
        return signals

    def _result_from_override(
        self,
        entity: ReputationEntity,
        normalized: NormalizedEntity,
        override: dict,
    ) -> ReputationResult:
        expires_at = override.get("expires_at")
        parsed_expires = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else None
        return ReputationResult(
            type=normalized.entity_type,
            value=normalized.original_value,
            normalized_value=normalized.normalized_value,
            entity_key=normalized.entity_key,
            verdict=Verdict(override["verdict"]),
            score=int(override["score"]),
            confidence=float(override.get("confidence", 1.0)),
            cache_hit=True,
            sources=["override"],
            indicators=["manual_override"],
            agreement_level=AgreementLevel.strong,
            summary=f"Manual override applied: {override.get('reason', 'no reason provided')}",
            expires_at=parsed_expires,
        )


def _auth_signals(auth_results, entity_type: EntityType) -> list[SourceSignal]:
    signals: list[SourceSignal] = []
    auth_values = {
        "spf": (auth_results.spf or "").lower(),
        "dkim": (auth_results.dkim or "").lower(),
        "dmarc": (auth_results.dmarc or "").lower(),
    }
    impacts = {"spf": 15, "dkim": 15, "dmarc": 20}
    none_impacts = {"spf": 5, "dkim": 5, "dmarc": 10}

    for name, value in auth_values.items():
        if value in ("fail", "softfail"):
            signals.append(
                SourceSignal(
                    source="email_auth",
                    entity_type=entity_type,
                    verdict=Verdict.suspicious,
                    priority=3,
                    confidence=0.60,
                    indicators=[f"{name}_{value}"],
                    score_impact=impacts[name],
                    severity="medium",
                    detail=f"{name.upper()} authentication returned {value}",
                )
            )
        elif value == "none":
            signals.append(
                SourceSignal(
                    source="email_auth",
                    entity_type=entity_type,
                    verdict=Verdict.suspicious,
                    priority=3,
                    confidence=0.40,
                    indicators=[f"{name}_none"],
                    score_impact=none_impacts[name],
                    severity="low",
                    detail=f"{name.upper()} authentication is missing",
                )
            )
    return signals


def _suspicious_url_reasons(url: str) -> list[str]:
    domain = re.sub(r"^https?://", "", url).split("/", 1)[0]
    reasons = []
    if len(domain) > 50:
        reasons.append("suspicious_url_long_domain")
    if domain.count(".") > 4:
        reasons.append("suspicious_url_many_subdomains")
    domain_stripped = domain.replace(".", "").replace("-", "")
    if any(char.isdigit() for char in domain_stripped[:5]):
        reasons.append("suspicious_url_digit_prefix")
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("suspicious_url_tld")
    lower = url.lower()
    if "login" in lower and "google" not in lower and "microsoft" not in lower:
        reasons.append("suspicious_url_login_lure")
    if "verify" in lower and "account" in lower:
        reasons.append("suspicious_url_verify_account")
    if "-" in domain and any(brand in domain for brand in BRAND_WORDS):
        reasons.append("suspicious_url_brand_impersonation")
    return reasons


def _dedupe_adapters(adapters: list[ThreatIntelAdapter]) -> list[ThreatIntelAdapter]:
    deduped: dict[str, ThreatIntelAdapter] = {}
    for adapter in adapters:
        deduped[adapter.name] = adapter
    return list(deduped.values())


def _should_run_whois(
    lookup_type: EntityType,
    primary_results: list[SourceSignal | None],
) -> bool:
    """Match Helios inline behavior: WHOIS runs when VT did not return HTTP 200 data."""
    if lookup_type != EntityType.domain:
        return False

    vt_signals = [
        signal
        for signal in primary_results
        if signal is not None and signal.source == "virustotal"
    ]
    if not vt_signals:
        return True

    indicator = vt_signals[0].indicators[0] if vt_signals[0].indicators else ""
    return indicator in {"virustotal_not_found", "virustotal_error"}
