"""
Threat Feeds Service — fetches and caches public IOC threat intelligence feeds in Redis.

Feeds are refreshed every hour by a background worker.
Policy engine and email processor consume these Redis sets for real-time IOC matching.

Supported feeds:
  - ioc_urlhaus        : URLhaus malware distribution URLs (abuse.ch)
  - ioc_openphish      : OpenPhish active phishing URLs
  - ioc_ipsum          : IPsum high-confidence malicious IPs (level 3+)
  - ioc_feodo          : Feodo Tracker botnet C2 IPs (abuse.ch)
  - ioc_cins           : CINS Army bad actor IPs
  - ioc_spamhaus_drop  : Spamhaus DROP hijacked netblocks (CIDR ranges)
"""
import asyncio
import ipaddress
import json
import logging
import time
import urllib.parse
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Feed definitions ───────────────────────────────────────────────────────────

FEED_PACKS = {
    "ioc_urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "label": "URLhaus Malware URLs",
        "description": "Malware distribution URLs actively serving payloads (abuse.ch URLhaus).",
        "type": "url",
        "comment_chars": ("#",),
    },
    "ioc_openphish": {
        "url": "https://openphish.com/feed.txt",
        "label": "OpenPhish Phishing URLs",
        "description": "Active phishing URLs (OpenPhish community feed).",
        "type": "url",
        "comment_chars": ("#",),
        "strip_scheme": True,  # Store domain+path for faster substring matching
    },
    "ioc_ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "label": "IPsum Malicious IPs (Level 3+)",
        "description": "IPs appearing on 3+ independent blacklists (high confidence malicious).",
        "type": "ip",
        "comment_chars": ("#",),
    },
    "ioc_feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "label": "Feodo Tracker C2 IPs",
        "description": "Botnet command-and-control server IPs (abuse.ch Feodo Tracker).",
        "type": "ip",
        "comment_chars": ("#",),
    },
    "ioc_cins": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "label": "CINS Army Bad IPs",
        "description": "Continuously updated bad actor IPs (CINS Score Army list).",
        "type": "ip",
        "comment_chars": ("#", ";"),
    },
    "ioc_spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "label": "Spamhaus DROP (CIDR)",
        "description": "Hijacked/leased netblocks used for spam and malware (Spamhaus DROP list).",
        "type": "cidr",
        "comment_chars": (";", "#"),
    },
}

# CERT-CN feeds are stored separately by cert_cn_service, but we register them here
# so check_ip_in_feeds / check_url_in_feeds can include them in policy matching.
CERT_CN_FEED_IDS = {"cert_cn_ips", "cert_cn_urls"}

REFRESH_INTERVAL_SECONDS = 3600       # 1 hour
TTL_SECONDS = 4 * 3600                # 4 hours — keep data across restarts
_CHUNK_SIZE = 1000                    # SADD chunk size to avoid huge single commands


def _redis_key(feed_id: str) -> str:
    return f"{feed_id}:entries"


def _redis_meta_key(feed_id: str) -> str:
    return f"{feed_id}:meta"


def _parse_url_entries(raw: str, strip_scheme: bool = False, comment_chars=("#",)) -> list[str]:
    """Parse plain-text URL feed, one entry per line. Returns list of URL strings."""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(c) for c in comment_chars):
            continue
        # Must look like a URL
        if not (line.startswith("http://") or line.startswith("https://")):
            continue
        if strip_scheme:
            # Remove scheme, keep domain+path for faster substring matching
            parsed = urllib.parse.urlparse(line)
            entry = parsed.netloc + parsed.path
            entry = entry.rstrip("/")
            if entry:
                entries.append(entry.lower())
        else:
            entries.append(line)
    return entries


def _parse_ip_entries(raw: str, comment_chars=("#",)) -> list[str]:
    """Parse plain-text IP feed, one IPv4 address per line (strips CIDR, port, etc.)."""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(c) for c in comment_chars):
            continue
        # Strip CIDR notation, port or trailing junk
        ip_candidate = line.split()[0].split("/")[0].split(":")[0]
        try:
            ipaddress.IPv4Address(ip_candidate)
            entries.append(ip_candidate)
        except ValueError:
            pass
    return entries


def _parse_cidr_entries(raw: str, comment_chars=(";", "#")) -> list[str]:
    """Parse plain-text CIDR feed, one network per line. Returns validated CIDR strings."""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(c) for c in comment_chars):
            continue
        # Spamhaus DROP format: "1.2.3.0/24 ; SBL12345" — take first token
        cidr_candidate = line.split()[0]
        if not cidr_candidate:
            continue
        try:
            net = ipaddress.IPv4Network(cidr_candidate, strict=False)
            entries.append(str(net))
        except ValueError:
            pass
    return entries


async def refresh_feed(feed_id: str, pack_info: dict, redis) -> int:
    """
    Fetch a single threat feed and store entries in Redis SET.
    Returns the count of entries cached (0 on failure).
    """
    url = pack_info["url"]
    feed_type = pack_info.get("type", "ip")
    comment_chars = pack_info.get("comment_chars", ("#",))
    strip_scheme = pack_info.get("strip_scheme", False)

    try:
        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "Himaya/1.0 threat-feed-sync"},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            raw = resp.text
    except Exception as e:
        logger.warning(f"threat_feeds: fetch failed for {feed_id} ({url}): {e}")
        return 0

    # Parse entries based on feed type
    if feed_type == "url":
        entries = _parse_url_entries(raw, strip_scheme=strip_scheme, comment_chars=comment_chars)
    elif feed_type == "cidr":
        entries = _parse_cidr_entries(raw, comment_chars=comment_chars)
    else:  # "ip"
        entries = _parse_ip_entries(raw, comment_chars=comment_chars)

    if not entries:
        logger.warning(f"threat_feeds: no entries parsed for {feed_id}")
        return 0

    key = _redis_key(feed_id)
    # Atomically replace the set
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(key)
        for i in range(0, len(entries), _CHUNK_SIZE):
            pipe.sadd(key, *entries[i:i + _CHUNK_SIZE])
        pipe.expire(key, TTL_SECONDS)
        await pipe.execute()

    # Write metadata
    meta = json.dumps({
        "feed_id": feed_id,
        "label": pack_info["label"],
        "entry_count": len(entries),
        "last_refresh": time.time(),
        "url": url,
        "type": feed_type,
    })
    await redis.set(_redis_meta_key(feed_id), meta, ex=TTL_SECONDS)

    logger.info(f"threat_feeds: cached {len(entries)} entries for {feed_id}")
    return len(entries)


async def refresh_all_feeds(redis) -> dict:
    """Refresh all threat feeds. Returns {feed_id: entry_count}."""
    results = {}
    for feed_id, pack_info in FEED_PACKS.items():
        try:
            count = await refresh_feed(feed_id, pack_info, redis)
            results[feed_id] = count
        except Exception as e:
            logger.error(f"threat_feeds: error refreshing {feed_id}: {e}")
            results[feed_id] = 0
    return results


# ── Query functions ────────────────────────────────────────────────────────────

async def check_url_in_feeds(url: str, redis=None) -> tuple[bool, list[str]]:
    """
    Check if a URL is present in any URL-type threat feeds.
    Returns (is_malicious, list_of_matching_feed_ids).
    """
    if not url:
        return False, []

    _redis = redis
    _owned = False
    if _redis is None:
        import os
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True

    matching = []
    try:
        url_feeds = [fid for fid, info in FEED_PACKS.items() if info["type"] == "url"]
        for feed_id in url_feeds:
            key = _redis_key(feed_id)
            pack_info = FEED_PACKS[feed_id]
            strip_scheme = pack_info.get("strip_scheme", False)

            if strip_scheme:
                # Compare domain+path (stored without scheme)
                try:
                    parsed = urllib.parse.urlparse(url)
                    lookup_val = (parsed.netloc + parsed.path).rstrip("/").lower()
                except Exception:
                    lookup_val = url.lower()
            else:
                lookup_val = url

            try:
                if await _redis.sismember(key, lookup_val):
                    matching.append(feed_id)
            except Exception:
                pass
        # Also check CERT-CN URLs
        try:
            from backend.services.cert_cn_service import check_url_in_cert_cn
            if await check_url_in_cert_cn(url, redis=_redis):
                matching.append("cert_cn_urls")
        except Exception:
            pass
        # Also check ANVA URL feeds
        try:
            from backend.services.anva_service import check_anva_url
            anva_hit, anva_feeds = await check_anva_url(url, redis=_redis)
            if anva_hit:
                matching.extend(anva_feeds)
        except Exception:
            pass
    finally:
        if _owned:
            await _redis.aclose()

    return bool(matching), matching


async def check_ip_in_feeds(ip: str, redis=None) -> tuple[bool, list[str]]:
    """
    Check if an IP address is present in any IP-type threat feeds (exact match).
    Also checks CIDR-type feeds via network containment.
    Returns (is_malicious, list_of_matching_feed_ids).
    """
    if not ip:
        return False, []

    _redis = redis
    _owned = False
    if _redis is None:
        import os
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True

    matching = []
    try:
        # Parse IP once for CIDR checks
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            return False, []

        for feed_id, pack_info in FEED_PACKS.items():
            feed_type = pack_info.get("type", "ip")
            key = _redis_key(feed_id)

            try:
                if feed_type == "ip":
                    if await _redis.sismember(key, ip):
                        matching.append(feed_id)

                elif feed_type == "cidr":
                    # For CIDR feeds we must scan all entries — use SSCAN to avoid blocking
                    cursor = 0
                    found = False
                    while not found:
                        cursor, members = await _redis.sscan(key, cursor=cursor, count=500)
                        for cidr_str in members:
                            try:
                                if ip_obj in ipaddress.IPv4Network(cidr_str, strict=False):
                                    found = True
                                    break
                            except ValueError:
                                pass
                        if cursor == 0:
                            break
                    if found:
                        matching.append(feed_id)
            except Exception:
                pass

        # Also check CERT-CN IPs
        try:
            from backend.services.cert_cn_service import check_ip_in_cert_cn
            if await check_ip_in_cert_cn(ip, redis=_redis):
                matching.append("cert_cn_ips")
        except Exception:
            pass
        # Also check ANVA IP feeds
        try:
            from backend.services.anva_service import check_anva_ip
            anva_hit, anva_feeds = await check_anva_ip(ip, redis=_redis)
            if anva_hit:
                matching.extend(anva_feeds)
        except Exception:
            pass
    finally:
        if _owned:
            await _redis.aclose()

    return bool(matching), matching


async def check_domain_in_feeds(domain: str, redis=None) -> tuple[bool, list[str]]:
    """
    Check if a domain appears in any URL-type threat feeds via substring match.
    Useful for domain-level blocking without needing exact URL match.
    Returns (is_malicious, list_of_matching_feed_ids).
    """
    if not domain:
        return False, []

    _redis = redis
    _owned = False
    if _redis is None:
        import os
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True

    domain_lower = domain.lower().strip()
    matching = []
    try:
        url_feeds = [fid for fid, info in FEED_PACKS.items() if info["type"] == "url"]
        for feed_id in url_feeds:
            key = _redis_key(feed_id)
            cursor = 0
            found = False
            try:
                while not found:
                    cursor, members = await _redis.sscan(key, cursor=cursor, count=500)
                    for entry in members:
                        if domain_lower in entry.lower():
                            found = True
                            break
                    if cursor == 0:
                        break
            except Exception:
                pass
            if found:
                matching.append(feed_id)
    finally:
        if _owned:
            await _redis.aclose()

    return bool(matching), matching


async def get_feed_meta(redis, feed_id: str) -> Optional[dict]:
    """Return cached metadata dict for a feed or None if not loaded yet."""
    raw = await redis.get(_redis_meta_key(feed_id))
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None


async def get_all_feed_meta(redis) -> dict:
    """Return metadata for all feeds (for admin/status endpoints)."""
    meta = {}
    for feed_id, info in FEED_PACKS.items():
        m = await get_feed_meta(redis, feed_id)
        meta[feed_id] = {
            "feed_id": feed_id,
            "label": info["label"],
            "description": info["description"],
            "url": info["url"],
            "type": info["type"],
            "entry_count": m["entry_count"] if m else 0,
            "last_refresh": m["last_refresh"] if m else None,
        }
    return meta


# ── Background worker ──────────────────────────────────────────────────────────

async def run_feeds_refresh_loop():
    """Long-running background task — refresh all threat feeds every hour."""
    import os
    import redis.asyncio as aioredis

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

    logger.info("Threat feeds refresh worker started (interval: 1h)")
    while True:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            results = await refresh_all_feeds(_redis)
            total = sum(results.values())
            logger.info(f"Threat feeds refresh complete: {results} (total {total} entries)")
        except Exception as e:
            logger.error(f"Threat feeds refresh error: {e}", exc_info=True)
        finally:
            await _redis.aclose()
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)
