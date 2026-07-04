from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import httpx

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal, TimedLookup

logger = logging.getLogger(__name__)


class UrlscanAdapter(BaseAdapter):
    base_url = "https://urlscan.io/api/v1"

    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.api_key = settings.urlscan_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        if not self.is_configured:
            return None

        malicious_params = self._malicious_params(entity_type, value)
        if malicious_params is None:
            return None

        observable_type, observable_value = malicious_params
        path_value = urllib.parse.quote(observable_value, safe="")

        with TimedLookup() as timer:
            try:
                async with httpx.AsyncClient(timeout=self.config.timeout_ms / 1000) as client:
                    headers = {"API-Key": self.api_key or ""}
                    response = await client.get(
                        f"{self.base_url}/malicious/{observable_type}/{path_value}",
                        headers=headers,
                    )

                    if response.status_code == 404:
                        return self._unknown(entity_type, "urlscan_not_found", timer.latency_ms)

                    if response.status_code in (401, 403):
                        return await self._search_fallback(
                            client,
                            headers,
                            entity_type,
                            value,
                            timer.latency_ms,
                        )

                    response.raise_for_status()
                    payload = response.json()
                    count = int(payload.get("count", 0) or 0)
                    if count <= 0:
                        return self._unknown(entity_type, "urlscan_no_malicious_hits", timer.latency_ms)
                    return self._signal_from_count(
                        entity_type,
                        count,
                        payload,
                        timer.latency_ms,
                        indicator_prefix="urlscan_malicious",
                    )
            except Exception as exc:
                logger.debug("urlscan lookup failed for %s: %s", value, exc)
                return self._unknown(entity_type, "urlscan_error", timer.latency_ms)

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=None if self.is_configured else "URLSCAN_API_KEY is not set",
        )

    async def _search_fallback(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        entity_type: EntityType,
        value: str,
        latency_ms: float,
    ) -> SourceSignal:
        query = self._search_query(entity_type, value)
        if not query:
            return self._unknown(entity_type, "urlscan_unsupported", latency_ms)

        try:
            response = await client.get(
                f"{self.base_url}/search/",
                params={"q": query, "size": 1},
                headers=headers,
            )
            if response.status_code == 404:
                return self._unknown(entity_type, "urlscan_not_found", latency_ms)
            response.raise_for_status()
            payload = response.json()
            total = int(payload.get("total", 0) or 0)
            if total <= 0:
                return self._unknown(entity_type, "urlscan_no_malicious_hits", latency_ms)
            return self._signal_from_count(
                entity_type,
                total,
                payload,
                latency_ms,
                indicator_prefix="urlscan_search_malicious",
            )
        except Exception as exc:
            logger.debug("urlscan search fallback failed for %s: %s", value, exc)
            return self._unknown(entity_type, "urlscan_error", latency_ms)

    def _malicious_params(self, entity_type: EntityType, value: str) -> tuple[str, str] | None:
        if entity_type == EntityType.domain:
            return "domain", value
        if entity_type == EntityType.url:
            return "url", value
        if entity_type == EntityType.ip:
            return "ip", value
        return None

    @staticmethod
    def _search_query(entity_type: EntityType, value: str) -> str | None:
        if entity_type == EntityType.domain:
            return f'domain:{value} AND labels:malicious'
        if entity_type == EntityType.url:
            escaped = value.replace('"', '\\"')
            return f'page.url:"{escaped}" AND labels:malicious'
        if entity_type == EntityType.ip:
            return f'ip:{value} AND labels:malicious'
        return None

    def _signal_from_count(
        self,
        entity_type: EntityType,
        count: int,
        payload: dict[str, Any],
        latency_ms: float,
        *,
        indicator_prefix: str,
    ) -> SourceSignal:
        if count >= 3:
            verdict = Verdict.malicious
            impact = 50
            minimum = None
            severity = "high"
            confidence = 0.85
        else:
            verdict = Verdict.suspicious
            impact = 25
            minimum = None
            severity = "medium"
            confidence = 0.65

        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=verdict,
            priority=self.config.priority,
            confidence=confidence,
            indicators=[f"{indicator_prefix}:{count}"],
            score_impact=impact,
            minimum_score=minimum,
            severity=severity,
            detail="urlscan.io observed malicious page content for this observable",
            raw={
                "count": count,
                "firstSeen": payload.get("firstSeen"),
                "lastSeen": payload.get("lastSeen"),
                "observable": payload.get("observable"),
            },
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
            detail="urlscan.io returned no actionable data",
            latency_ms=latency_ms,
        )
