from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import httpx

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup

logger = logging.getLogger(__name__)


class AlienVaultAdapter(BaseAdapter):
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.api_key = settings.alienvault_otx_api_key

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
                        f"{self.base_url}/{endpoint}/general",
                        headers={"X-OTX-API-KEY": self.api_key or ""},
                    )
                if response.status_code == 404:
                    return self._unknown(entity_type, "otx_not_found", timer.latency_ms)
                response.raise_for_status()
                return self._signal_from_payload(entity_type, response.json(), timer.latency_ms)
            except Exception as exc:
                logger.debug("AlienVault OTX lookup failed for %s: %s", value, exc)
                return self._unknown(entity_type, "otx_error", timer.latency_ms)

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=None if self.is_configured else "ALIENVAULT_OTX_API_KEY is not set",
        )

    def _endpoint(self, entity_type: EntityType, value: str) -> str | None:
        encoded = urllib.parse.quote(value, safe="")
        if entity_type == EntityType.domain:
            return f"domain/{encoded}"
        if entity_type == EntityType.url:
            return f"url/{encoded}"
        if entity_type == EntityType.file:
            return f"file/{encoded}"
        return None

    def _signal_from_payload(
        self,
        entity_type: EntityType,
        payload: dict[str, Any],
        latency_ms: float,
    ) -> SourceSignal:
        pulse_info = payload.get("pulse_info", {}) or {}
        pulse_count = int(pulse_info.get("count", 0) or 0)

        if pulse_count >= 2:
            verdict = Verdict.malicious
            impact = 50 if entity_type in (EntityType.url, EntityType.file) else 35
            minimum = 80 if entity_type == EntityType.file else None
            severity = "high"
            confidence = 0.80
            indicator = f"otx_pulse_match:{pulse_count}"
        elif pulse_count == 1:
            verdict = Verdict.suspicious
            impact = 35 if entity_type in (EntityType.url, EntityType.file) else 25
            minimum = None
            severity = "medium"
            confidence = 0.60
            indicator = "otx_pulse_match:1"
        else:
            return self._unknown(entity_type, "otx_no_pulse", latency_ms)

        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=verdict,
            priority=self.config.priority,
            confidence=confidence,
            indicators=[indicator],
            score_impact=impact,
            minimum_score=minimum,
            severity=severity,
            detail="AlienVault OTX pulse reputation signal",
            raw={"pulse_count": pulse_count},
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
            detail="AlienVault OTX returned no actionable data",
            latency_ms=latency_ms,
        )
