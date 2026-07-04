"""
CERT China (cert.org.cn) IOC Scraper Service
Scrapes daily threat intelligence reports from China's National Computer Network Emergency Response
Coordination Centre. Extracts IPs and URLs from report pages and stores them in Redis.

Feed IDs:
  cert_cn_ips    — malicious IPs extracted from CERT-CN reports
  cert_cn_urls   — malicious URLs/domains extracted from CERT-CN reports

Refresh interval: 6 hours (new reports published daily on China Standard Time)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

CERT_BASE = "https://www.cert.org.cn"
CERT_SECTION_URL = "https://www.cert.org.cn/publish/main/10/index.html"
REFRESH_INTERVAL_SECONDS = 6 * 3600   # 6 hours
TTL_SECONDS = 8 * 3600

REDIS_KEY_IPS = "cert_cn:ips"
REDIS_KEY_URLS = "cert_cn:urls"
REDIS_KEY_META = "cert_cn:meta"

DATE_RE = re.compile(r"\[(\d{4}-\d{2}-\d{2})\]")
WINDOW_OPEN_RE = re.compile(r'window\.open\(["\']([^"\']+)["\']\)')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_RE = re.compile(r'https?://[^\s<>"\']+')
DOMAIN_RE = re.compile(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Himaya-Himaya/1.0 threat-intel-collector)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "Referer": CERT_SECTION_URL,
}

# Private IP ranges to exclude
_PRIVATE_RANGES = [
    re.compile(r'^10\.'), re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'), re.compile(r'^0\.'),
    re.compile(r'^255\.'),
]


def _is_public_ip(ip: str) -> bool:
    return not any(p.match(ip) for p in _PRIVATE_RANGES)


async def _fetch_page(url: str, client: httpx.AsyncClient) -> str:
    try:
        r = await client.get(url, headers=HEADERS, timeout=20, follow_redirects=True)
        if r.status_code == 200:
            # Detect encoding
            content_type = r.headers.get("content-type", "")
            if "charset=" in content_type:
                enc = content_type.split("charset=")[-1].strip()
            else:
                enc = "utf-8"
            try:
                return r.content.decode(enc, errors="replace")
            except Exception:
                return r.text
    except Exception as e:
        logger.debug(f"cert_cn: fetch failed for {url}: {e}")
    return ""


def _parse_index_links(html: str) -> list[dict]:
    """Parse the cert.org.cn index page for report links."""
    from bs4 import BeautifulSoup
    results = []
    try:
        soup = BeautifulSoup(html, "lxml")
        # Try multiple selectors as the site structure may vary
        items = soup.select("ul.waring_con li") or soup.select("ul li") or soup.select(".list li")
        for li in items:
            span = li.select_one("span")
            a = li.select_one("a")
            if not a:
                continue
            # Extract date
            date_text = span.get_text(strip=True) if span else li.get_text(strip=True)
            m = DATE_RE.search(date_text)
            publish_date = m.group(1) if m else None
            # Extract URL
            onclick = a.get("onclick", "")
            url_match = WINDOW_OPEN_RE.search(onclick)
            if url_match:
                full_url = urljoin(CERT_BASE, url_match.group(1))
            else:
                href = a.get("href", "")
                if not href or href == "#":
                    continue
                full_url = urljoin(CERT_BASE, href)
            results.append({
                "publish_date": publish_date,
                "title": a.get_text(" ", strip=True),
                "url": full_url,
            })
    except Exception as e:
        logger.warning(f"cert_cn: index parse error: {e}")
    return results


def _extract_iocs_from_html(html: str) -> tuple[set[str], set[str]]:
    """Extract IPs and URLs/domains from a report page."""
    ips: set[str] = set()
    urls: set[str] = set()

    # Extract IPs
    for ip in IP_RE.findall(html):
        if _is_public_ip(ip):
            ips.add(ip)

    # Extract URLs
    for url in URL_RE.findall(html):
        # Clean up URL
        url = url.rstrip(".,;)\"'>")
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                urls.add(url.lower())
        except Exception:
            pass

    # Extract bare domains from text (common in Chinese threat reports)
    # Strip HTML tags first
    text = re.sub(r'<[^>]+>', ' ', html)
    for word in text.split():
        word = word.strip(".,;()'\"")
        if DOMAIN_RE.fullmatch(word) and '.' in word and len(word) < 100:
            # Exclude common non-threat domains
            if not any(safe in word for safe in ['cert.org.cn', 'cctga.org.cn', 'gov.cn', 'w3.org', 'schema.org']):
                urls.add(word.lower())

    return ips, urls


async def refresh_cert_cn_feeds(redis=None) -> dict:
    """
    Fetch CERT-CN index, scrape recent report pages, extract IOCs, store in Redis.
    Returns summary of what was collected.
    """
    _owned = False
    if redis is None:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True

    all_ips: set[str] = set()
    all_urls: set[str] = set()
    reports_scraped = 0

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            # Fetch index page
            index_html = await _fetch_page(CERT_SECTION_URL, client)
            if not index_html:
                logger.warning("cert_cn: failed to fetch index page")
                return {"ips": 0, "urls": 0, "reports": 0}

            links = _parse_index_links(index_html)
            logger.info(f"cert_cn: found {len(links)} report links on index")

            # Scrape the most recent reports (last 30 to build a meaningful feed)
            recent = links[:30]
            for item in recent:
                url = item.get("url", "")
                if not url:
                    continue
                report_html = await _fetch_page(url, client)
                if report_html:
                    ips, urls = _extract_iocs_from_html(report_html)
                    all_ips.update(ips)
                    all_urls.update(urls)
                    reports_scraped += 1
                # Small delay to be polite
                await asyncio.sleep(0.5)

        # Store in Redis
        if all_ips:
            await redis.delete(REDIS_KEY_IPS)
            await redis.sadd(REDIS_KEY_IPS, *list(all_ips))
            await redis.expire(REDIS_KEY_IPS, TTL_SECONDS)

        if all_urls:
            await redis.delete(REDIS_KEY_URLS)
            await redis.sadd(REDIS_KEY_URLS, *list(all_urls))
            await redis.expire(REDIS_KEY_URLS, TTL_SECONDS)

        meta = {
            "last_refresh": time.time(),
            "ip_count": len(all_ips),
            "url_count": len(all_urls),
            "reports_scraped": reports_scraped,
        }
        await redis.set(REDIS_KEY_META, json.dumps(meta), ex=TTL_SECONDS)

        logger.info(f"cert_cn: refreshed — {len(all_ips)} IPs, {len(all_urls)} URLs from {reports_scraped} reports")
        return {"ips": len(all_ips), "urls": len(all_urls), "reports": reports_scraped}

    except Exception as e:
        logger.error(f"cert_cn: refresh failed: {e}", exc_info=True)
        return {"ips": 0, "urls": 0, "reports": 0, "error": str(e)}
    finally:
        if _owned:
            await redis.aclose()


async def check_ip_in_cert_cn(ip: str, redis=None) -> bool:
    """Check if an IP is in the CERT-CN feed."""
    if not ip:
        return False
    _owned = False
    if redis is None:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True
    try:
        return bool(await redis.sismember(REDIS_KEY_IPS, ip))
    except Exception:
        return False
    finally:
        if _owned:
            await redis.aclose()


async def check_url_in_cert_cn(url: str, redis=None) -> bool:
    """Check if a URL or domain is in the CERT-CN feed."""
    if not url:
        return False
    _owned = False
    if redis is None:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True
    try:
        # Try exact URL match
        if await redis.sismember(REDIS_KEY_URLS, url.lower()):
            return True
        # Try domain extraction
        try:
            domain = urlparse(url).netloc.lower()
            if domain and await redis.sismember(REDIS_KEY_URLS, domain):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False
    finally:
        if _owned:
            await redis.aclose()


async def run_cert_cn_refresh_loop():
    """Long-running background loop — refreshes CERT-CN feeds every 6 hours."""
    logger.info("cert_cn: refresh worker started (interval: 6h)")
    # Initial delay to let service fully start
    await asyncio.sleep(300)
    while True:
        try:
            result = await refresh_cert_cn_feeds()
            logger.info(f"cert_cn: refresh complete — {result}")
        except Exception as e:
            logger.error(f"cert_cn: refresh loop error: {e}")
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)
