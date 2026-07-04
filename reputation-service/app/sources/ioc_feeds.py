from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from typing import Any

from app.api.schemas import EntityType, Verdict
from app.config.settings import Settings
from app.sources.base import AdapterStatus, BaseAdapter, SourceConfig, SourceSignal

logger = logging.getLogger(__name__)

# Redis key layout matches sentinel-mail/backend/services/threat_feeds_service.py
# so Helios feed refresh workers and this adapter share the same IOC data.
FEED_PACKS: dict[str, dict[str, Any]] = {
    "ioc_urlhaus": {
        "type": "url",
        "strip_scheme": False,
    },
    "ioc_openphish": {
        "type": "url",
        "strip_scheme": True,
    },
    "ioc_ipsum": {
        "type": "ip",
    },
    "ioc_feodo": {
        "type": "ip",
    },
    "ioc_cins": {
        "type": "ip",
    },
    "ioc_spamhaus_drop": {
        "type": "cidr",
    },
}


def feed_entries_key(feed_id: str) -> str:
    return f"{feed_id}:entries"


class IocFeedsAdapter(BaseAdapter):
    def __init__(self, config: SourceConfig, settings: Settings) -> None:
        super().__init__(config)
        self.redis_url = settings.redis_url

    @property
    def is_configured(self) -> bool:
        return True

    async def health(self) -> AdapterStatus:
        detail = None
        status = "healthy"
        try:
            redis = await self._connect()
            try:
                await redis.ping()
            finally:
                await redis.aclose()
        except Exception as exc:
            status = "degraded"
            detail = f"Redis IOC feed lookup unavailable: {exc}"

        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=True,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
            detail=detail,
        )

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        if entity_type == EntityType.url:
            matching = await self._match_url(value)
            if not matching:
                return self._unknown(entity_type, "ioc_feed_no_url_match")
            return self._malicious_url_signal(entity_type, matching)

        if entity_type == EntityType.domain:
            matching = await self._match_domain(value)
            if not matching:
                return self._unknown(entity_type, "ioc_feed_no_domain_match")
            return self._malicious_domain_signal(entity_type, matching)

        if entity_type == EntityType.ip:
            matching = await self._match_ip(value)
            if not matching:
                return self._unknown(entity_type, "ioc_feed_no_ip_match")
            return self._malicious_ip_signal(entity_type, matching)

        return None

    async def _match_url(self, url: str) -> list[str]:
        redis = await self._connect()
        matching: list[str] = []
        try:
            for feed_id, pack_info in FEED_PACKS.items():
                if pack_info.get("type") != "url":
                    continue
                lookup_val = _url_lookup_value(url, strip_scheme=pack_info.get("strip_scheme", False))
                try:
                    if await redis.sismember(feed_entries_key(feed_id), lookup_val):
                        matching.append(feed_id)
                except Exception:
                    continue
        finally:
            await redis.aclose()
        return matching

    async def _match_domain(self, domain: str) -> list[str]:
        redis = await self._connect()
        domain_lower = domain.lower().strip()
        matching: list[str] = []
        try:
            for feed_id, pack_info in FEED_PACKS.items():
                if pack_info.get("type") != "url":
                    continue
                key = feed_entries_key(feed_id)
                cursor = 0
                found = False
                try:
                    while not found:
                        cursor, members = await redis.sscan(key, cursor=cursor, count=500)
                        for entry in members:
                            if domain_lower in entry.lower():
                                found = True
                                break
                        if cursor == 0:
                            break
                except Exception:
                    continue
                if found:
                    matching.append(feed_id)
        finally:
            await redis.aclose()
        return matching

    async def _match_ip(self, ip: str) -> list[str]:
        redis = await self._connect()
        matching: list[str] = []
        try:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return []

            for feed_id, pack_info in FEED_PACKS.items():
                feed_type = pack_info.get("type", "ip")
                key = feed_entries_key(feed_id)
                try:
                    if feed_type == "ip":
                        if await redis.sismember(key, str(ip_obj)):
                            matching.append(feed_id)
                    elif feed_type == "cidr" and isinstance(ip_obj, ipaddress.IPv4Address):
                        cursor = 0
                        found = False
                        while not found:
                            cursor, members = await redis.sscan(key, cursor=cursor, count=500)
                            for cidr_str in members:
                                try:
                                    if ip_obj in ipaddress.IPv4Network(cidr_str, strict=False):
                                        found = True
                                        break
                                except ValueError:
                                    continue
                            if cursor == 0:
                                break
                        if found:
                            matching.append(feed_id)
                except Exception:
                    continue
        finally:
            await redis.aclose()
        return matching

    async def _connect(self):
        import redis.asyncio as aioredis

        return aioredis.from_url(self.redis_url, decode_responses=True)

    def _malicious_url_signal(self, entity_type: EntityType, feeds: list[str]) -> SourceSignal:
        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=Verdict.malicious,
            priority=self.config.priority,
            confidence=0.90,
            indicators=[f"ioc_feed_url_match:{','.join(feeds)}"],
            score_impact=60,
            minimum_score=60,
            severity="high",
            detail="URL matched Helios IOC threat feed entries",
            raw={"matching_feeds": feeds},
        )

    def _malicious_domain_signal(self, entity_type: EntityType, feeds: list[str]) -> SourceSignal:
        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=Verdict.suspicious,
            priority=self.config.priority,
            confidence=0.75,
            indicators=[f"ioc_feed_domain_match:{','.join(feeds)}"],
            score_impact=40,
            severity="medium",
            detail="Domain appeared in Helios IOC URL feed entries",
            raw={"matching_feeds": feeds},
        )

    def _malicious_ip_signal(self, entity_type: EntityType, feeds: list[str]) -> SourceSignal:
        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=Verdict.malicious,
            priority=self.config.priority,
            confidence=0.90,
            indicators=[f"ioc_feed_ip_match:{','.join(feeds)}"],
            score_impact=30,
            minimum_score=30,
            severity="high",
            detail="IP matched Helios IOC threat feed entries",
            raw={"matching_feeds": feeds},
        )

    def _unknown(self, entity_type: EntityType, indicator: str) -> SourceSignal:
        return SourceSignal(
            source=self.name,
            entity_type=entity_type,
            verdict=Verdict.unknown,
            priority=self.config.priority,
            confidence=0.0,
            indicators=[indicator],
            detail="No IOC feed match found",
        )


def _url_lookup_value(url: str, *, strip_scheme: bool) -> str:
    if strip_scheme:
        parsed = urllib.parse.urlparse(url)
        return (parsed.netloc + parsed.path).rstrip("/").lower()
    return url
