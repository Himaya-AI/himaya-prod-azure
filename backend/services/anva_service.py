"""
ANVA (China National Cybersecurity Threat Intelligence) Service
Fetches IOC data from share.anva.org.cn and caches in Redis.

Data is behind session authentication. Credentials are loaded from env:
  ANVA_USERNAME  — registered account username
  ANVA_PASSWORD  — account password

Packs fetched (every 24h):
  anva_phishing_ip    : Phishing server IPs       (ANVA-BL-PHISHINGIP)
  anva_phishing_url   : Phishing URLs/domains      (ANVA-BL-PHISHINGURL)
  anva_malware_ip     : Malware distribution IPs   (ANVA-BL-PMIP)
  anva_malware_url    : Malware distribution URLs   (ANVA-BL-PMURL)
  anva_email          : Malicious email addresses  (ANVA-BL-EMAIL)

IOC types stored in Redis:
  anva:{pack_id}:ips    → Redis Set of IPv4 addresses
  anva:{pack_id}:domains → Redis Set of domain strings
  anva:{pack_id}:emails → Redis Set of email addresses
  anva:{pack_id}:meta   → JSON metadata

Policy engine checks anva:*:ips / :domains / :emails against incoming emails.
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

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://share.anva.org.cn"
LOGIN_URL = f"{BASE_URL}/web/account/login.do"
REFRESH_INTERVAL_SECONDS = 24 * 3600   # 24 hours
TTL_SECONDS = 26 * 3600                # slightly longer than refresh

REDIS_KEY_PREFIX = "anva"

# Pack definitions: pack_id → {endpoint, type param, dataTypeCode, ioc_type}
ANVA_PACKS: dict[str, dict] = {
    "anva_phishing_ip": {
        "label": "ANVA Phishing IPs",
        "description": "China ANVA — phishing server IP addresses reported to CCTGA.",
        "endpoint": "/web/publicity/listPhishing",
        "method": "POST",
        "type": "phishing",
        "dataTypeCode": "ANVA-BL-PHISHINGIP",
        "ioc_type": "ip",
        "col_index": 2,
    },
    "anva_phishing_url": {
        "label": "ANVA Phishing URLs",
        "description": "China ANVA — phishing website URLs reported to CCTGA.",
        "endpoint": "/web/publicity/listPhishing",
        "method": "POST",
        "type": "phishing",
        "dataTypeCode": "ANVA-BL-PHISHINGURL",
        "ioc_type": "domain",
        "col_index": 2,
    },
    "anva_malware_ip": {
        "label": "ANVA Malware IPs",
        "description": "China ANVA — malware distribution server IPs.",
        "endpoint": "/web/publicity/listurl",
        "method": "POST",
        "type": "pm",
        "dataTypeCode": "ANVA-BL-PMIP",
        "ioc_type": "ip",
        "col_index": 2,
    },
    "anva_malware_url": {
        "label": "ANVA Malware URLs",
        "description": "China ANVA — malware distribution URLs/domains.",
        "endpoint": "/web/publicity/listurl",
        "method": "POST",
        "type": "pm",
        "dataTypeCode": "ANVA-BL-PMURL",
        "ioc_type": "domain",
        "col_index": 2,
    },
    # ── C2 / Trojan control server packs (GET endpoints) ──────────────────────
    # These appear under 控制地址 (Control Addresses) on the site and contain
    # trojan/RAT C2 infrastructure — the section the user described as having
    # "tons of attachments/IOCs".
    "anva_c2_ip": {
        "label": "ANVA C2 Server IPs",
        "description": "China ANVA — computer malicious control server IPs (C2/trojan infrastructure).",
        "endpoint": "/web/publicity/listurl",
        "method": "GET",
        "type": "pmcc",
        "dataTypeCode": "ANVA-BL-PMCCIP",
        "ioc_type": "ip",
        "col_index": 2,
    },
    "anva_c2_url": {
        "label": "ANVA C2 URLs",
        "description": "China ANVA — computer malicious control endpoint URLs (C2/trojan infrastructure).",
        "endpoint": "/web/publicity/listurl",
        "method": "GET",
        "type": "pmcc",
        "dataTypeCode": "ANVA-BL-PMCCURL",
        "ioc_type": "domain",
        "col_index": 2,
    },
    "anva_mobile_c2_ip": {
        "label": "ANVA Mobile C2 IPs",
        "description": "China ANVA — mobile malware control server IPs.",
        "endpoint": "/web/publicity/listurl",
        "method": "GET",
        "type": "pmcc",
        "dataTypeCode": "ANVA-BL-MMCCIP",
        "ioc_type": "ip",
        "col_index": 2,
    },
    # ── Email pack ────────────────────────────────────────────────────────────
    "anva_email": {
        "label": "ANVA Malicious Emails",
        "description": "China ANVA — malicious email accounts (direct sender block).",
        "endpoint": "/web/publicity/listEmail",
        "method": "POST",
        "type": "email",
        "dataTypeCode": "ANVA-BL-EMAIL",
        "ioc_type": "email",
        "col_index": 1,
    },
}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── HTML table parser ──────────────────────────────────────────────────────────

class _TableParser(HTMLParser):
    """Extract text rows from the first HTML table body found."""

    def __init__(self, target_col: int):
        super().__init__()
        self.target_col = target_col
        self.values: list[str] = []
        self._in_tbody = False
        self._in_tr = False
        self._in_td = False
        self._col = 0
        self._cell = ""
        self._total_records: int = 0

    def handle_starttag(self, tag, attrs):
        if tag == "tbody":
            self._in_tbody = True
        elif tag == "tr" and self._in_tbody:
            self._in_tr = True
            self._col = 0
        elif tag in ("td", "th") and self._in_tr:
            self._in_td = True
            self._cell = ""

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_tbody = False
        elif tag == "tr" and self._in_tbody:
            self._in_tr = False
        elif tag in ("td", "th") and self._in_tr:
            if self._col == self.target_col:
                val = self._cell.strip()
                if val:
                    self.values.append(val)
            self._col += 1
            self._in_td = False

    def handle_data(self, data):
        if self._in_td:
            self._cell += data

    def feed_total(self, html: str) -> int:
        """Extract total record count from pagination text (共 N 记录).
        The site uses &nbsp; between characters so we normalise before matching."""
        normalised = html.replace("&nbsp;", " ").replace("\xa0", " ")
        m = re.search(r"共\s*(\d+)\s*记录", normalised)
        if m:
            return int(m.group(1))
        return 0


def _parse_table_column(html: str, col_index: int) -> tuple[list[str], int]:
    """Return (values, total_count) parsed from HTML."""
    parser = _TableParser(target_col=col_index)
    parser.feed(html)
    total = parser.feed_total(html)
    return parser.values, total


# ── Session management ─────────────────────────────────────────────────────────

async def _login(client: httpx.AsyncClient) -> bool:
    """Authenticate with ANVA and set session cookie. Returns True on success."""
    username = os.getenv("ANVA_USERNAME", "")
    password = os.getenv("ANVA_PASSWORD", "")
    if not username or not password:
        logger.warning("anva: ANVA_USERNAME / ANVA_PASSWORD not set — skipping ANVA feed")
        return False

    try:
        # GET the login page first to get session cookie
        await client.get(f"{BASE_URL}/web/account/login", timeout=15)

        # SHA-256 the password (the site uses JS sha256 before submitting)
        import hashlib
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        resp = await client.post(
            LOGIN_URL,
            data={"username": username, "password": pw_hash},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
            follow_redirects=True,
        )
        # Success if redirected to non-login page or contains logged-in marker
        if resp.status_code in (200, 302) and "login" not in str(resp.url).lower():
            logger.info("anva: session login successful")
            return True
        # Also check response body for success markers
        if "logout" in resp.text.lower() or "退出" in resp.text:
            logger.info("anva: session login successful (body check)")
            return True
        logger.warning(f"anva: login may have failed (url={resp.url}, status={resp.status_code})")
        return True  # proceed anyway — let subsequent requests reveal auth state
    except Exception as e:
        logger.error(f"anva: login error: {e}")
        return False


async def _fetch_pack_page(
    client: httpx.AsyncClient,
    pack: dict,
    page: int = 1,
) -> tuple[list[str], int]:
    """Fetch one page of IOCs. Returns (values, total_count).
    Some packs use GET (e.g. C2/trojan endpoints), others use POST form submit.
    """
    method = pack.get("method", "POST").upper()
    params = {
        "type": pack["type"],
        "dataTypeCode": pack["dataTypeCode"],
        "page": str(page),
        "pageNow": str(page),
    }
    try:
        if method == "GET":
            resp = await client.get(
                f"{BASE_URL}{pack['endpoint']}",
                params=params,
                timeout=30,
                follow_redirects=True,
            )
        else:
            resp = await client.post(
                f"{BASE_URL}{pack['endpoint']}",
                data=params,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
                follow_redirects=True,
            )
        resp.raise_for_status()
        return _parse_table_column(resp.text, pack["col_index"])
    except Exception as e:
        logger.warning(f"anva: fetch error for {pack['dataTypeCode']} page {page}: {e}")
        return [], 0


async def fetch_and_cache_anva_pack(redis, pack_id: str) -> int:
    """Fetch ALL pages of an ANVA pack and store IOCs in Redis. Returns count stored.

    ANVA publicity endpoints are publicly accessible without authentication.
    Credentials (ANVA_USERNAME / ANVA_PASSWORD) are optional — if set they are
    used to establish a session first, which may expose additional/premium packs.
    If not set, we proceed unauthenticated (the public IOC lists are still available).
    """
    pack = ANVA_PACKS.get(pack_id)
    if not pack:
        logger.warning(f"anva: unknown pack_id={pack_id}")
        return 0

    username = os.getenv("ANVA_USERNAME", "")
    password = os.getenv("ANVA_PASSWORD", "")
    use_auth = bool(username and password)
    if not use_auth:
        logger.warning(
            f"anva: ANVA_USERNAME / ANVA_PASSWORD not set — {pack_id} will return 0 IOCs. "
            "The ANVA publicity endpoint requires a valid session to return data."
        )

    PAGE_SIZE = 20  # ANVA default page size
    all_values: list[str] = []

    async with httpx.AsyncClient(
        timeout=30,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Helios/1.0)"},
    ) as client:
        if use_auth:
            logged_in = await _login(client)
            if not logged_in:
                logger.warning(f"anva: auth failed, attempting unauthenticated fetch for {pack_id}")

        # Fetch page 1 to learn total count (works with or without auth)
        page1_values, total_count = await _fetch_pack_page(client, pack, page=1)
        all_values.extend(page1_values)

        if total_count > PAGE_SIZE:
            total_pages = (total_count + PAGE_SIZE - 1) // PAGE_SIZE
            # Fetch remaining pages (cap at 500 pages / 10,000 IOCs to be safe)
            for page_num in range(2, min(total_pages + 1, 501)):
                values, _ = await _fetch_pack_page(client, pack, page=page_num)
                if not values:
                    break
                all_values.extend(values)
                await asyncio.sleep(0.5)  # polite rate limit

    if not all_values:
        logger.info(f"anva: {pack_id} — 0 IOCs fetched (empty or blocked)")
        await redis.set(
            f"{REDIS_KEY_PREFIX}:{pack_id}:meta",
            json.dumps({
                "pack_id": pack_id,
                "label": pack["label"],
                "ioc_count": 0,
                "last_refresh": time.time(),
                "status": "empty",
            }),
            ex=TTL_SECONDS,
        )
        return 0

    # Deduplicate
    all_values = list(dict.fromkeys(v.strip() for v in all_values if v.strip()))

    # Store in Redis set
    redis_key = f"{REDIS_KEY_PREFIX}:{pack_id}:{pack['ioc_type']}s"  # :ips / :domains / :emails
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(redis_key)
        chunk_size = 1000
        for i in range(0, len(all_values), chunk_size):
            pipe.sadd(redis_key, *all_values[i:i + chunk_size])
        pipe.expire(redis_key, TTL_SECONDS)
        await pipe.execute()

    # Metadata
    meta = {
        "pack_id": pack_id,
        "label": pack["label"],
        "ioc_count": len(all_values),
        "ioc_type": pack["ioc_type"],
        "last_refresh": time.time(),
        "status": "ok",
    }
    await redis.set(f"{REDIS_KEY_PREFIX}:{pack_id}:meta", json.dumps(meta), ex=TTL_SECONDS)
    logger.info(f"anva: cached {len(all_values)} IOCs for {pack_id}")
    return len(all_values)


def _store_meta(redis, pack_id: str, pack: dict, count: int, status: str):
    """Fire-and-forget meta store helper (sync wrapper for use in non-async context)."""
    pass  # meta is stored inline in fetch_and_cache_anva_pack


async def refresh_all_anva_packs(redis) -> dict:
    """Refresh all ANVA packs sequentially. Returns {pack_id: ioc_count}."""
    results = {}
    for pack_id in ANVA_PACKS:
        count = await fetch_and_cache_anva_pack(redis, pack_id)
        results[pack_id] = count
        await asyncio.sleep(1)  # polite between packs
    return results


async def get_all_anva_pack_meta(redis) -> dict:
    """Return metadata for all ANVA packs from Redis."""
    meta = {}
    for pack_id, pack_info in ANVA_PACKS.items():
        raw = await redis.get(f"{REDIS_KEY_PREFIX}:{pack_id}:meta")
        if raw:
            try:
                m = json.loads(raw)
            except Exception:
                m = {}
        else:
            m = {}
        meta[pack_id] = {
            "pack_id": pack_id,
            "label": pack_info["label"],
            "description": pack_info["description"],
            "ioc_type": pack_info["ioc_type"],
            "ioc_count": m.get("ioc_count", 0),
            "last_refresh": m.get("last_refresh"),
            "status": m.get("status", "not_loaded"),
            "error": m.get("error"),
        }
    return meta


async def check_sender_in_anva(redis, sender_email: str, sender_domain: str, sender_ip: Optional[str] = None) -> Optional[str]:
    """
    Check an inbound email's sender against ANVA IOC packs.
    Returns the matching pack_id string or None.
    """
    # Check malicious email
    if sender_email:
        key = f"{REDIS_KEY_PREFIX}:anva_email:emails"
        if await redis.sismember(key, sender_email.lower()):
            return "anva_email"

    # Check sender domain against phishing/malware domain lists
    if sender_domain:
        for pack_id in ("anva_phishing_url", "anva_malware_url"):
            key = f"{REDIS_KEY_PREFIX}:{pack_id}:domains"
            if await redis.sismember(key, sender_domain.lower()):
                return pack_id

    # Check sender IP against phishing/malware IP lists
    if sender_ip and _IPV4_RE.match(sender_ip):
        for pack_id in ("anva_phishing_ip", "anva_malware_ip"):
            key = f"{REDIS_KEY_PREFIX}:{pack_id}:ips"
            if await redis.sismember(key, sender_ip):
                return pack_id

    return None


# ── Background refresh loop ────────────────────────────────────────────────────

async def run_anva_refresh_loop():
    """Long-running background task — refresh all ANVA packs every 24 hours."""
    import redis.asyncio as aioredis

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    logger.info("ANVA refresh worker started (interval: 24h)")

    # Initial delay — let other startup tasks complete first
    await asyncio.sleep(120)

    while True:
        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            results = await refresh_all_anva_packs(r)
            total = sum(results.values())
            logger.info(f"ANVA refresh complete: {results} (total {total} IOCs)")
        except Exception as e:
            logger.error(f"ANVA refresh error: {e}", exc_info=True)
        finally:
            await r.aclose()
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)


async def check_anva_ip(ip: str, redis=None) -> tuple[bool, list[str]]:
    """Check if an IP is in any ANVA feed. Returns (hit, [matching_feed_ids])."""
    if not ip:
        return False, []
    _owned = False
    if redis is None:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True
    matching = []
    try:
        ip_packs = [k for k, v in ANVA_PACKS.items() if v.get("ioc_type") in ("ip", "mixed")]
        for pack_id in ip_packs:
            key = f"{REDIS_KEY_PREFIX}:{pack_id}:ips"
            if await redis.sismember(key, ip):
                matching.append(pack_id)
    except Exception:
        pass
    finally:
        if _owned:
            await redis.aclose()
    return bool(matching), matching


async def check_anva_url(url: str, redis=None) -> tuple[bool, list[str]]:
    """Check if a URL/domain is in any ANVA feed. Returns (hit, [matching_feed_ids])."""
    if not url:
        return False, []
    from urllib.parse import urlparse as _up
    _owned = False
    if redis is None:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)
        _owned = True
    matching = []
    try:
        domain = _up(url).netloc.lower() if "://" in url else url.lower()
        url_packs = [k for k, v in ANVA_PACKS.items() if v.get("ioc_type") in ("url", "mixed")]
        for pack_id in url_packs:
            key = f"{REDIS_KEY_PREFIX}:{pack_id}:domains"
            if await redis.sismember(key, domain) or await redis.sismember(key, url.lower()):
                matching.append(pack_id)
    except Exception:
        pass
    finally:
        if _owned:
            await redis.aclose()
    return bool(matching), matching
