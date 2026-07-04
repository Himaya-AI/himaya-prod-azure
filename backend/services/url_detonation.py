"""
URL Detonation Service — Himaya

Visits suspicious URLs in a headless Playwright Chromium browser and captures:
  - Full-page screenshot (base64 PNG)
  - Complete redirect chain
  - Final URL after all redirects
  - Page title + meta description
  - Credential harvesting indicators (login forms, password fields, fake brand logos)
  - File download triggers
  - JavaScript redirects or suspicious page behaviour
  - Blob storage upload of screenshot (Azure Blob or S3 fallback)

Used both in the initial email processing pipeline (auto-detonation of suspicious links)
and in the on-demand sandbox analysis endpoint.
"""
import asyncio
import base64
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Domains that are always safe to skip detonation
SAFE_DOMAINS = frozenset([
    "google.com", "microsoft.com", "outlook.com", "office.com",
    "linkedin.com", "github.com", "amazon.com", "aws.amazon.com",
    "apple.com", "icloud.com", "dropbox.com", "zoom.us",
    "accounts.google.com", "login.microsoftonline.com",
])

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "unusual activity",
    "suspended", "click here to restore", "your password has expired",
    "update your payment", "billing information", "urgent action required",
]

BRAND_SPOOFING_PATTERNS = [
    r"(paypa1|payp4l|p4ypal)",
    r"(micros0ft|m1crosoft|microsofft)",
    r"(app1e|appl3|aap1e)",
    r"(g00gle|googl3|g0ogle)",
    r"(arnazon|amazn|amaz0n)",
    r"(netlfix|netfl1x)",
]


@dataclass
class DetonationResult:
    url: str
    final_url: str
    redirect_chain: list[str] = field(default_factory=list)
    page_title: str = ""
    page_text_snippet: str = ""
    screenshot_b64: Optional[str] = None
    screenshot_s3_url: Optional[str] = None
    has_login_form: bool = False
    has_password_field: bool = False
    requests_credentials: bool = False
    triggers_download: bool = False
    brand_spoofing_detected: list[str] = field(default_factory=list)
    phishing_keywords_found: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    detonation_risk_score: int = 0
    error: Optional[str] = None
    duration_ms: int = 0


def _is_safe_domain(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower().lstrip("www.")
        return any(host == d or host.endswith("." + d) for d in SAFE_DOMAINS)
    except Exception:
        return False


async def detonate_url(url: str, timeout_ms: int = 15000) -> DetonationResult:
    """
    Visit a URL in an isolated headless Chromium browser and capture its behaviour.
    Returns a DetonationResult with screenshot, redirect chain, and risk indicators.
    """
    result = DetonationResult(url=url, final_url=url)
    start = time.monotonic()

    if _is_safe_domain(url):
        result.error = "skipped_safe_domain"
        result.duration_ms = 0
        return result

    try:
        from playwright.async_api import async_playwright, Error as PlaywrightError

        async with async_playwright() as p:
            try:
                browser_exec = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")
                launch_kwargs = dict(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--no-first-run",
                        "--disable-background-networking",
                    ],
                )
                if browser_exec:
                    launch_kwargs["executable_path"] = browser_exec
                browser = await p.chromium.launch(**launch_kwargs)
            except Exception as _launch_err:
                logger.warning("Chromium launch failed (not installed?): %s", _launch_err)
                result.error = "browser_not_available"
                return result

            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    java_script_enabled=True,
                    accept_downloads=False,
                )

                page = await context.new_page()
                redirect_chain: list[str] = [url]
                download_triggered = False

                page.on("response", lambda r: redirect_chain.append(r.url)
                        if r.status in (301, 302, 303, 307, 308) else None)

                # Block media and ads to speed things up
                await page.route("**/*.{mp4,mp3,avi,mkv,webm,gif}", lambda r: r.abort())
                await page.route("**/ads/**", lambda r: r.abort())

                # Navigate
                try:
                    response = await page.goto(
                        url,
                        timeout=timeout_ms,
                        wait_until="domcontentloaded",
                    )
                except Exception as nav_err:
                    result.error = f"navigation_failed: {str(nav_err)[:200]}"
                    return result

                # Wait briefly for JS redirects
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                result.final_url = page.url
                result.redirect_chain = list(dict.fromkeys(redirect_chain))  # dedupe

                # Page content analysis
                result.page_title = await page.title() or ""
                try:
                    body_text = (await page.inner_text("body") or "")[:2000]
                    result.page_text_snippet = body_text[:500]
                except Exception:
                    body_text = ""

                # Detect login / credential harvesting forms
                try:
                    password_inputs = await page.query_selector_all('input[type="password"]')
                    email_inputs = await page.query_selector_all('input[type="email"], input[name*="user"], input[name*="email"]')
                    result.has_password_field = len(password_inputs) > 0
                    result.has_login_form = len(password_inputs) > 0 or len(email_inputs) > 0
                    if result.has_login_form:
                        result.requests_credentials = True
                        result.risk_indicators.append("credential_harvesting_form")
                except Exception:
                    pass

                # Phishing keyword detection
                text_lower = (result.page_title + " " + body_text).lower()
                for kw in PHISHING_KEYWORDS:
                    if kw in text_lower:
                        result.phishing_keywords_found.append(kw)
                        result.risk_indicators.append(f"phishing_keyword:{kw[:30]}")

                # Brand spoofing in URL or page content
                check_text = (result.final_url + " " + result.page_title + " " + body_text).lower()
                for pattern in BRAND_SPOOFING_PATTERNS:
                    m = re.search(pattern, check_text, re.I)
                    if m:
                        result.brand_spoofing_detected.append(m.group(0))
                        result.risk_indicators.append(f"brand_spoof:{m.group(0)}")

                # Check for suspicious redirect to different domain
                try:
                    from urllib.parse import urlparse
                    orig_domain = urlparse(url).netloc.lower()
                    final_domain = urlparse(result.final_url).netloc.lower()
                    if orig_domain and final_domain and orig_domain != final_domain:
                        result.risk_indicators.append(f"cross_domain_redirect:{orig_domain}->{final_domain}")
                except Exception:
                    pass

                # Take screenshot
                try:
                    screenshot_bytes = await page.screenshot(full_page=False, type="png")
                    result.screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

                    # Upload to blob storage if configured
                    storage_container = os.getenv("AZURE_STORAGE_CONTAINER", "himaya-evidence")
                    if (os.getenv("AZURE_STORAGE_ACCOUNT") or os.getenv("S3_BUCKET")) and result.screenshot_b64:
                        try:
                            from backend.services.storage_client import storage_client
                            key = f"sandbox-screenshots/{int(time.time())}_{hash(url) & 0xFFFFFF}.png"
                            url = await storage_client.upload(
                                container=storage_container,
                                key=key,
                                data=screenshot_bytes,
                                content_type="image/png",
                            )
                            result.screenshot_s3_url = url
                        except Exception as blob_err:
                            logger.debug(f"Blob screenshot upload failed (non-fatal): {blob_err}")
                except Exception as ss_err:
                    logger.warning(f"Screenshot failed for {url}: {ss_err}")

                await context.close()
            finally:
                await browser.close()

    except ImportError:
        logger.warning("Playwright not installed — falling back to httpx redirect chain check")
        result = await _fallback_httpx_check(url, result)
    except Exception as e:
        result.error = str(e)[:300]
        logger.warning(f"URL detonation failed for {url}: {e}")

    # Compute detonation risk score
    score = 0
    if result.requests_credentials:  score += 40
    if result.has_password_field:    score += 20
    if result.phishing_keywords_found: score += min(30, len(result.phishing_keywords_found) * 10)
    if result.brand_spoofing_detected: score += 35
    if "cross_domain_redirect" in " ".join(result.risk_indicators): score += 15
    if result.triggers_download: score += 20
    result.detonation_risk_score = min(100, score)
    result.duration_ms = int((time.monotonic() - start) * 1000)

    return result


async def _fallback_httpx_check(url: str, result: DetonationResult) -> DetonationResult:
    """Lightweight fallback when Playwright is unavailable — follow redirects with httpx."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Himaya/1.0)"},
        ) as client:
            resp = await client.get(url)
            result.final_url = str(resp.url)
            result.redirect_chain = [str(h.url) for h in resp.history] + [str(resp.url)]
            content = resp.text[:3000].lower()
            result.has_password_field = 'type="password"' in content or "type='password'" in content
            result.has_login_form = result.has_password_field or 'type="email"' in content
            if result.has_login_form:
                result.requests_credentials = True
                result.risk_indicators.append("credential_harvesting_form")
            for kw in PHISHING_KEYWORDS:
                if kw in content:
                    result.phishing_keywords_found.append(kw)
    except Exception as e:
        result.error = f"fallback_failed: {str(e)[:200]}"
    return result


async def detonate_email_urls(urls: list[str], max_urls: int = 5, timeout_ms: int = 12000) -> list[DetonationResult]:
    """
    Detonate up to max_urls from an email concurrently.
    Returns list of DetonationResult objects.
    """
    filtered = [u for u in urls if not _is_safe_domain(u)][:max_urls]
    if not filtered:
        return []
    tasks = [detonate_url(u, timeout_ms=timeout_ms) for u in filtered]
    return await asyncio.gather(*tasks, return_exceptions=False)
