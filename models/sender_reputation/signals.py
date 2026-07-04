"""
Himaya Helios - MODEL-003: Sender Reputation Signal Collection
Async parallel collection of domain/email signals: WHOIS, DNS, HIBP.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp
import dns.resolver
import whois

from models.shared.config import HIBP_API_BASE, REDIS_URL, REDIS_TTL_SECONDS
from models.shared.schemas import DmarcResult, SpfResult, DkimResult

logger = logging.getLogger(__name__)

# In-memory cache fallback if Redis unavailable
_memory_cache: dict[str, tuple[Any, float]] = {}

# Try to import redis, fallback to in-memory
try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None  # type: ignore


class SignalCache:
    """
    Async cache layer with Redis + in-memory fallback.
    TTL: 24 hours.
    """

    def __init__(self, redis_url: str = REDIS_URL, ttl: int = REDIS_TTL_SECONDS) -> None:
        self.redis_url = redis_url
        self.ttl = ttl
        self._redis: Any = None
        self._redis_available = False

    async def _get_redis(self) -> Any:
        if not HAS_REDIS:
            return None
        if self._redis is None:
            try:
                self._redis = await aioredis.from_url(self.redis_url, decode_responses=True)
                await self._redis.ping()
                self._redis_available = True
            except Exception as e:
                logger.debug(f"Redis unavailable, using in-memory cache: {e}")
                self._redis_available = False
        return self._redis if self._redis_available else None

    async def get(self, key: str) -> Any | None:
        redis = await self._get_redis()
        if redis:
            try:
                val = await redis.get(key)
                if val:
                    import json
                    return json.loads(val)
            except Exception:
                pass

        # Fallback to memory
        if key in _memory_cache:
            val, ts = _memory_cache[key]
            if time.time() - ts < self.ttl:
                return val
            del _memory_cache[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        import json
        redis = await self._get_redis()
        if redis:
            try:
                await redis.setex(key, self.ttl, json.dumps(value))
                return
            except Exception:
                pass

        # Fallback to memory
        _memory_cache[key] = (value, time.time())


# Global cache instance
_cache = SignalCache()


async def check_domain_age(domain: str) -> int:
    """
    Check domain age via WHOIS lookup.

    Args:
        domain: Domain name to check

    Returns:
        Age in days, or -1 if lookup fails
    """
    cache_key = f"whois:{domain}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        # Run WHOIS in executor (blocking call)
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            result = -1
        else:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days
            result = max(age_days, 0)

        await _cache.set(cache_key, result)
        return result

    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return -1


async def check_dmarc(domain: str) -> DmarcResult:
    """
    Check DMARC DNS record for domain.

    Returns:
        DmarcResult with has_dmarc, policy, raw_record
    """
    cache_key = f"dmarc:{domain}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return DmarcResult(**cached)

    dmarc_domain = f"_dmarc.{domain}"
    result = DmarcResult(has_dmarc=False, policy=None, raw_record=None)

    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(dmarc_domain, "TXT")
        )

        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                result.has_dmarc = True
                result.raw_record = txt

                # Extract policy
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("p="):
                        result.policy = part.split("=", 1)[1].lower()
                        break
                break

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logger.debug(f"DMARC lookup failed for {domain}: {e}")

    await _cache.set(cache_key, result.model_dump())
    return result


async def check_spf(domain: str) -> SpfResult:
    """
    Check SPF DNS record for domain.

    Returns:
        SpfResult with has_spf, qualifier, raw_record
    """
    cache_key = f"spf:{domain}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return SpfResult(**cached)

    result = SpfResult(has_spf=False, qualifier=None, raw_record=None)

    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "TXT")
        )

        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                result.has_spf = True
                result.raw_record = txt

                # Extract all qualifier (default mechanism result)
                if " -all" in txt:
                    result.qualifier = "-"  # fail
                elif " ~all" in txt:
                    result.qualifier = "~"  # softfail
                elif " +all" in txt:
                    result.qualifier = "+"  # pass (dangerous!)
                elif " ?all" in txt:
                    result.qualifier = "?"  # neutral
                break

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logger.debug(f"SPF lookup failed for {domain}: {e}")

    await _cache.set(cache_key, result.model_dump())
    return result


async def check_dkim(domain: str, selector: str = "default") -> DkimResult:
    """
    Check DKIM DNS record for domain.

    Args:
        domain: Domain name
        selector: DKIM selector (common: default, google, selector1, selector2)

    Returns:
        DkimResult with has_dkim, selector, raw_record
    """
    cache_key = f"dkim:{selector}:{domain}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return DkimResult(**cached)

    dkim_domain = f"{selector}._domainkey.{domain}"
    result = DkimResult(has_dkim=False, selector=selector, raw_record=None)

    # Try multiple common selectors
    selectors_to_try = [selector]
    if selector == "default":
        selectors_to_try = ["default", "google", "selector1", "selector2", "k1", "mail"]

    for sel in selectors_to_try:
        dkim_domain = f"{sel}._domainkey.{domain}"
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda d=dkim_domain: dns.resolver.resolve(d, "TXT")
            )

            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=dkim1" in txt.lower() or "p=" in txt:
                    result.has_dkim = True
                    result.selector = sel
                    result.raw_record = txt[:200]  # Truncate long keys
                    break

            if result.has_dkim:
                break

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            logger.debug(f"DKIM lookup failed for {dkim_domain}: {e}")
            continue

    await _cache.set(cache_key, result.model_dump())
    return result


async def check_breach_db(email: str, api_key: str | None = None) -> bool:
    """
    Check if email has been involved in data breaches via HIBP API v3.

    Args:
        email: Email address to check
        api_key: HIBP API key (required for v3)

    Returns:
        True if email found in breaches, False otherwise
    """
    if not api_key:
        logger.warning("HIBP API key not provided, skipping breach check")
        return False

    cache_key = f"hibp:{hashlib.sha256(email.lower().encode()).hexdigest()}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return cached

    url = f"{HIBP_API_BASE}/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "HimayaHelios-SecurityScanner",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    result = True  # Found in breaches
                elif resp.status == 404:
                    result = False  # Not found
                else:
                    logger.debug(f"HIBP returned {resp.status} for {email}")
                    result = False

        await _cache.set(cache_key, result)
        return result

    except asyncio.TimeoutError:
        logger.debug(f"HIBP timeout for {email}")
        return False
    except Exception as e:
        logger.debug(f"HIBP check failed for {email}: {e}")
        return False


async def check_mx_valid(domain: str) -> bool:
    """
    Verify that MX records exist and resolve for domain.

    Returns:
        True if valid MX records found, False otherwise
    """
    cache_key = f"mx:{domain}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "MX")
        )

        # Verify at least one MX record exists
        result = len(answers) > 0

        # Optionally verify MX resolves to A/AAAA
        if result:
            mx_host = str(answers[0].exchange).rstrip(".")
            try:
                await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(mx_host, "A")
                )
            except Exception:
                # Try AAAA
                try:
                    await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(mx_host, "AAAA")
                    )
                except Exception:
                    result = False

        await _cache.set(cache_key, result)
        return result

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        await _cache.set(cache_key, False)
        return False
    except Exception as e:
        logger.debug(f"MX lookup failed for {domain}: {e}")
        return False


async def collect_all_signals(
    domain: str,
    email: str,
    hibp_api_key: str | None = None,
) -> dict[str, Any]:
    """
    Collect all sender reputation signals in parallel.

    Args:
        domain: Sender domain
        email: Full sender email address
        hibp_api_key: Optional HIBP API key

    Returns:
        Dict with all signal results
    """
    t0 = time.time()

    # Run all checks in parallel
    results = await asyncio.gather(
        check_domain_age(domain),
        check_dmarc(domain),
        check_spf(domain),
        check_dkim(domain),
        check_breach_db(email, hibp_api_key),
        check_mx_valid(domain),
        return_exceptions=True,
    )

    # Unpack with error handling
    def safe_get(idx: int, default: Any) -> Any:
        r = results[idx]
        return default if isinstance(r, Exception) else r

    domain_age = safe_get(0, -1)
    dmarc = safe_get(1, DmarcResult(has_dmarc=False))
    spf = safe_get(2, SpfResult(has_spf=False))
    dkim = safe_get(3, DkimResult(has_dkim=False))
    is_breached = safe_get(4, False)
    mx_valid = safe_get(5, False)

    latency_ms = (time.time() - t0) * 1000

    return {
        "domain": domain,
        "email": email,
        "domain_age_days": domain_age,
        "dmarc": dmarc.model_dump() if isinstance(dmarc, DmarcResult) else dmarc,
        "spf": spf.model_dump() if isinstance(spf, SpfResult) else spf,
        "dkim": dkim.model_dump() if isinstance(dkim, DkimResult) else dkim,
        "is_breached": is_breached,
        "mx_valid": mx_valid,
        "latency_ms": round(latency_ms, 2),
    }
