from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup

logger = logging.getLogger(__name__)


class VirusTotalAdapter(BaseAdapter):
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.api_key = settings.virustotal_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        if not self.is_configured:
            return None

        endpoint = self._endpoint(entity_type, value)
        if endpoint is None:
            return None

        with TimedLookup() as timer:
            try:
                async with httpx.AsyncClient(timeout=self.config.timeout_ms / 1000) as client:
                    response = await client.get(
                        f"{self.base_url}/{endpoint}",
                        headers={"x-apikey": self.api_key or ""},
                    )
                if response.status_code == 404:
                    return self._unknown(entity_type, "virustotal_not_found", timer.latency_ms)
                response.raise_for_status()
                attrs = response.json().get("data", {}).get("attributes", {})
                return self._signal_from_attributes(entity_type, attrs, timer.latency_ms)
            except Exception as exc:
                logger.debug("VirusTotal lookup failed for %s: %s", value, exc)
                return self._unknown(entity_type, "virustotal_error", timer.latency_ms)

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=None if self.is_configured else "VIRUSTOTAL_API_KEY is not set",
        )

    def _endpoint(self, entity_type: EntityType, value: str) -> str | None:
        if entity_type == EntityType.domain:
            return f"domains/{value}"
        if entity_type == EntityType.url:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"urls/{url_id}"
        if entity_type == EntityType.file:
            return f"files/{value}"
        return None

    def _signal_from_attributes(
        self,
        entity_type: EntityType,
        attrs: dict[str, Any],
        latency_ms: float,
    ) -> SourceSignal:
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        indicators: list[str] = []
        score_impact = 0
        verdict = Verdict.unknown
        severity = "info"
        confidence = 0.0
        minimum_score = None

        if malicious >= 3:
            verdict = Verdict.malicious
            score_impact = 70 if entity_type == EntityType.file else 50
            minimum_score = 85 if entity_type == EntityType.file else None
            severity = "high"
            confidence = 0.85
            indicators.append(f"vt_malicious:{malicious}/{total}")
        elif malicious >= 1:
            verdict = Verdict.suspicious
            score_impact = 40 if entity_type == EntityType.file else 25
            severity = "medium"
            confidence = 0.65
            indicators.append(f"vt_malicious:{malicious}/{total}")
        elif suspicious >= 2:
            verdict = Verdict.suspicious
            score_impact = 15
            severity = "medium"
            confidence = 0.55
            indicators.append(f"vt_suspicious:{suspicious}/{total}")
        elif harmless >= 10 and malicious == 0:
            verdict = Verdict.benign
            score_impact = -10
            severity = "info"
            confidence = 0.70
            indicators.append(f"vt_trusted:{harmless}_harmless")
        else:
            indicators.append("vt_no_actionable_signal")

        reputation_impact, reputation_indicator = _vt_reputation_adjustment(
            attrs.get("reputation"),
            malicious=malicious,
            harmless=harmless,
        )
        if reputation_indicator:
            indicators.append(reputation_indicator)
        score_impact += reputation_impact
        if reputation_impact > 0 and verdict == Verdict.unknown:
            verdict = Verdict.suspicious
            severity = "medium"
            confidence = 0.55

        if verdict == Verdict.unknown and not reputation_impact:
            return self._unknown(entity_type, "vt_no_actionable_signal", latency_ms)

        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=verdict,
            priority=self.config.priority,
            confidence=confidence,
            indicators=indicators,
            score_impact=score_impact,
            minimum_score=minimum_score,
            severity=severity,
            detail="VirusTotal reputation signal",
            raw={"last_analysis_stats": stats, "reputation": attrs.get("reputation")},
            latency_ms=latency_ms,
        )

    def _unknown(self, entity_type: EntityType, indicator: str, latency_ms: float) -> SourceSignal:
        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=Verdict.unknown,
            priority=self.config.priority,
            confidence=0.0,
            indicators=[indicator],
            detail="VirusTotal returned no actionable data",
            latency_ms=latency_ms,
        )


def _vt_reputation_adjustment(
    reputation: Any,
    *,
    malicious: int,
    harmless: int,
) -> tuple[int, str | None]:
    if reputation is None:
        return 0, None
    try:
        vt_rep = int(reputation)
    except (TypeError, ValueError):
        return 0, None
    if vt_rep >= -10:
        return 0, None
    if harmless > 0 and (malicious / harmless) <= 0.1:
        return 0, None
    return 20, f"vt_reputation:{vt_rep}"
