"""
OpenDBL Service — fetches and caches OpenDBL IP blocklists in Redis.

Lists are refreshed every 6 hours by a background worker.
Policy engine consumes these Redis sets for real-time IP matching.

Supported packs:
  - emerging_threats : https://opendbl.net/lists/etknown.list
  - tor_exits        : https://opendbl.net/lists/tor-exit.list
  - brute_force      : https://opendbl.net/lists/bruteforce.list
  - blocklistde      : https://opendbl.net/lists/blocklistde-all.list
"""
import asyncio
import logging
import re
import socket
import urllib.parse
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OPENDBL_PACKS = {
    "emerging_threats": {
        "url": "https://opendbl.net/lists/etknown.list",
        "label": "Emerging Threats",
        "description": "Known malicious IPs from the Emerging Threats intelligence feed — continuously updated.",
    },
    "tor_exits": {
        "url": "https://opendbl.net/lists/tor-exit.list",
        "label": "TOR Exit Nodes",
        "description": "Active TOR exit node IPs. Blocks email relayed through anonymisation networks.",
    },
    "brute_force": {
        "url": "https://opendbl.net/lists/bruteforce.list",
        "label": "Brute Force Blocker",
        "description": "IPs observed in active brute-force and credential-stuffing attacks.",
    },
    "blocklistde": {
        "url": "https://opendbl.net/lists/blocklistde-all.list",
        "label": "Blocklist.de All",
        "description": "Comprehensive Blocklist.de combined feed — attacks, spam sources, and abuse IPs.",
    },
}

REDIS_KEY_PREFIX = "opendbl"
REFRESH_INTERVAL_SECONDS = 6 * 3600  # 6 hours
TTL_SECONDS = 7 * 3600               # 7 hours — slightly longer than refresh so no gap
_IP_RE = re.compile(r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d+)?\s*$")


def _redis_key(pack_id: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{pack_id}:ips"


def _redis_meta_key(pack_id: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{pack_id}:meta"


def _parse_ips(raw: str) -> list[str]:
    """Extract valid IPv4 addresses from raw text (skip comments, CIDR /mask stripped)."""
    ips = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        m = _IP_RE.match(line)
        if m:
            ips.append(m.group(1))
    return ips


async def fetch_and_cache_pack(redis, pack_id: str) -> int:
    """Fetch a single OpenDBL pack and store IPs in Redis. Returns count of IPs cached."""
    info = OPENDBL_PACKS.get(pack_id)
    if not info:
        logger.warning(f"opendbl: unknown pack_id={pack_id}")
        return 0

    url = info["url"]
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Himaya/1.0 opendbl-sync"})
            resp.raise_for_status()
            raw = resp.text
    except Exception as e:
        logger.warning(f"opendbl: fetch failed for {pack_id} ({url}): {e}")
        return 0

    ips = _parse_ips(raw)
    if not ips:
        logger.warning(f"opendbl: no IPs parsed for {pack_id}")
        return 0

    key = _redis_key(pack_id)
    # Replace the set atomically with a pipeline
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(key)
        # Redis SADD supports multiple values but we chunk to avoid huge commands
        chunk_size = 1000
        for i in range(0, len(ips), chunk_size):
            pipe.sadd(key, *ips[i:i + chunk_size])
        pipe.expire(key, TTL_SECONDS)
        await pipe.execute()

    # Write metadata
    import json, time
    meta = json.dumps({
        "pack_id": pack_id,
        "label": info["label"],
        "ip_count": len(ips),
        "last_refresh": time.time(),
        "url": url,
    })
    await redis.set(_redis_meta_key(pack_id), meta, ex=TTL_SECONDS)

    logger.info(f"opendbl: cached {len(ips)} IPs for {pack_id}")
    return len(ips)


async def refresh_all_packs(redis) -> dict:
    """Refresh all OpenDBL packs. Returns {pack_id: ip_count}."""
    results = {}
    for pack_id in OPENDBL_PACKS:
        count = await fetch_and_cache_pack(redis, pack_id)
        results[pack_id] = count
    return results


async def check_ip_in_pack(redis, ip: str, pack_id: str) -> bool:
    """Check if a single IP is present in a cached OpenDBL pack set."""
    if not ip:
        return False
    try:
        return bool(await redis.sismember(_redis_key(pack_id), ip))
    except Exception:
        return False


async def check_ip_in_any_pack(redis, ip: str, pack_ids: Optional[list[str]] = None) -> Optional[str]:
    """
    Check IP against one or more packs.
    Returns the first matching pack_id or None.
    """
    if not ip:
        return None
    packs_to_check = pack_ids or list(OPENDBL_PACKS.keys())
    for pid in packs_to_check:
        if await check_ip_in_pack(redis, ip, pid):
            return pid
    return None


async def get_pack_meta(redis, pack_id: str) -> Optional[dict]:
    """Return cached metadata dict for a pack or None if not loaded yet."""
    import json
    raw = await redis.get(_redis_meta_key(pack_id))
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None


async def get_all_pack_meta(redis) -> dict:
    """Return metadata for all packs."""
    meta = {}
    for pack_id in OPENDBL_PACKS:
        info = OPENDBL_PACKS[pack_id]
        m = await get_pack_meta(redis, pack_id)
        meta[pack_id] = {
            "pack_id": pack_id,
            "label": info["label"],
            "description": info["description"],
            "url": info["url"],
            "ip_count": m["ip_count"] if m else 0,
            "last_refresh": m["last_refresh"] if m else None,
        }
    return meta


def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Best-effort DNS resolution of a domain to its first IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def extract_ips_from_email(email_data: dict) -> list[str]:
    """
    Extract candidate IPs from an email for OpenDBL checking:
    1. Sender IP from Received headers (X-Originating-IP, etc.)
    2. Resolved IPs of domains found in email links
    """
    ips: list[str] = []

    # 1. Try X-Originating-IP or similar headers stored in email_data
    for field in ("sender_ip", "x_originating_ip", "originating_ip"):
        ip = email_data.get(field, "")
        if ip and _IP_RE.match(str(ip)):
            ips.append(str(ip).strip())

    # 2. Resolve sender domain → IP
    sender_domain = email_data.get("sender_domain") or ""
    if sender_domain:
        resolved = resolve_domain_to_ip(sender_domain)
        if resolved:
            ips.append(resolved)

    # 3. Extract links from body and resolve their domains
    body = email_data.get("body") or ""
    if body:
        urls = re.findall(r'https?://([^/\s"\'<>]+)', body)
        seen_domains: set[str] = set()
        for url_host in urls[:20]:  # cap at 20 links per email
            # Strip port if present
            host = url_host.split(":")[0].lower()
            if host in seen_domains:
                continue
            seen_domains.add(host)
            # If it's already an IP
            if _IP_RE.match(host):
                ips.append(host)
            else:
                resolved = resolve_domain_to_ip(host)
                if resolved:
                    ips.append(resolved)

    # Deduplicate
    return list(dict.fromkeys(ips))


# ── Background worker ──────────────────────────────────────────────────────────

async def run_opendbl_refresh_loop():
    """Long-running background task — refresh all OpenDBL packs every 6 hours."""
    import os
    import redis.asyncio as aioredis

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

    logger.info("OpenDBL refresh worker started (interval: 6h)")
    while True:
        redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            results = await refresh_all_packs(redis)
            total = sum(results.values())
            logger.info(f"OpenDBL refresh complete: {results} (total {total} IPs)")
        except Exception as e:
            logger.error(f"OpenDBL refresh error: {e}", exc_info=True)
        finally:
            await redis.aclose()
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)
