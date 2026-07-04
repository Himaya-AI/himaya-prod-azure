"""
HTTP client for the Helios reputation microservice.

Builds entity batches from parsed email_data, calls POST /api/v1/reputation/lookup,
and maps per-entity results into the shapes expected by email_processor.py.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

REPUTATION_SERVICE_URL = os.getenv("REPUTATION_SERVICE_URL", "").rstrip("/")
REPUTATION_SERVICE_TIMEOUT_SECONDS = float(
    os.getenv("REPUTATION_SERVICE_TIMEOUT_SECONDS", "10")
)
MAX_ENTITIES_PER_REQUEST = 25
MAX_URLS = 20

_URL_RE = re.compile(r'https?://[^\s<>"\']+')
_DANGEROUS_EXTENSIONS = {
    ".exe", ".vbs", ".js", ".ps1", ".bat", ".cmd", ".msi",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".jar",
}


def is_configured() -> bool:
    return bool(REPUTATION_SERVICE_URL)


def extract_urls(email_data: dict) -> list[str]:
    body = (email_data.get("body", "") or "") + " " + (email_data.get("html_body", "") or "")
    return list(dict.fromkeys(_URL_RE.findall(body)))[:MAX_URLS]


def extract_attachment_filenames(email_data: dict) -> list[str]:
    filenames: list[str] = []
    for att in email_data.get("attachments", []) or []:
        if isinstance(att, str) and att:
            filenames.append(att)
        elif isinstance(att, dict):
            name = att.get("filename", "")
            if name:
                filenames.append(name)
    return filenames


def build_file_entities(email_data: dict) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    for att in email_data.get("attachments", []) or []:
        if not isinstance(att, dict):
            continue
        file_hash = att.get("sha256") or att.get("hash")
        filename = att.get("filename", "")
        if not file_hash or not isinstance(file_hash, str):
            continue
        digest = file_hash.strip().lower()
        if len(digest) not in (32, 40, 64):
            continue
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(digest)]
        entity: dict[str, Any] = {
            "type": "file",
            "value": digest,
            "hash_type": hash_type,
        }
        if filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            entity["context"] = {"filename": filename, "extension": ext or None}
        entities.append(entity)
    return entities


def build_entities(email_data: dict, auth_results: dict) -> list[dict[str, Any]]:
    sender = (email_data.get("sender") or "").strip()
    if not sender or "@" not in sender:
        return []

    entities: list[dict[str, Any]] = [
        {
            "type": "sender",
            "value": sender,
            "context": {"auth_results": auth_results},
        }
    ]

    sender_ip = (auth_results.get("sender_ip") or "").strip()
    if sender_ip:
        entities.append({"type": "ip", "value": sender_ip})

    file_entities = build_file_entities(email_data)
    remaining = MAX_ENTITIES_PER_REQUEST - len(entities) - len(file_entities)
    if remaining < 0:
        file_entities = file_entities[: max(0, MAX_ENTITIES_PER_REQUEST - len(entities))]

    for url in extract_urls(email_data)[: max(0, remaining)]:
        entities.append({"type": "url", "value": url})
        remaining -= 1
        if remaining <= 0:
            break

    entities.extend(file_entities)
    return entities[:MAX_ENTITIES_PER_REQUEST]


async def lookup_reputation(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not entities or not is_configured():
        return []

    url = f"{REPUTATION_SERVICE_URL}/api/v1/reputation/lookup"
    try:
        async with httpx.AsyncClient(timeout=REPUTATION_SERVICE_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json={"entities": entities})
            response.raise_for_status()
            return response.json().get("results", [])
    except httpx.HTTPError as exc:
        logger.warning("Reputation service lookup failed: %s", exc)
        return []
    except Exception as exc:
        logger.warning("Reputation service lookup error: %s", exc)
        return []


def map_sender_result(
    results: list[dict[str, Any]],
    auth_results: dict,
) -> dict[str, Any]:
    spf = str(auth_results.get("spf", "")).lower()
    dkim = str(auth_results.get("dkim", "")).lower()
    dmarc = str(auth_results.get("dmarc", "")).lower()

    sender_result = next((r for r in results if r.get("type") == "sender"), None)
    if sender_result is not None:
        return {
            "reputation_score": int(sender_result.get("score", 0)),
            "indicators": list(sender_result.get("indicators") or []),
            "spf_pass": spf == "pass",
            "dkim_pass": dkim == "pass",
            "dmarc_pass": dmarc == "pass",
        }

    return _fallback_sender_reputation(auth_results)


def map_link_result(
    results: list[dict[str, Any]],
    *,
    urls: list[str],
    att_filenames: list[str],
    file_entities: list[dict[str, Any]],
) -> dict[str, Any]:
    url_results = [r for r in results if r.get("type") == "url"]
    file_results = [r for r in results if r.get("type") == "file"]
    ip_results = [r for r in results if r.get("type") == "ip"]

    malicious_urls = [r["value"] for r in url_results if r.get("verdict") == "malicious"]
    suspicious_urls = [r["value"] for r in url_results if r.get("verdict") == "suspicious"]

    link_score = 0
    indicators: list[str] = []

    if malicious_urls:
        link_score += 60
        indicators.append(f"malicious_urls_detected:{len(malicious_urls)}")

    if any("ioc_feed" in ind for r in url_results for ind in (r.get("indicators") or [])):
        link_score = min(100, link_score + 20)

    if any("ioc_feed_ip_match" in ind for r in ip_results for ind in (r.get("indicators") or [])):
        link_score = min(100, link_score + 30)

    if any(
        "malwarebazaar_known_sample" in ind
        for r in file_results
        for ind in (r.get("indicators") or [])
    ):
        link_score = min(100, link_score + 40)

    if suspicious_urls:
        link_score += min(30, len(suspicious_urls) * 10)
        indicators.append(f"suspicious_urls:{len(suspicious_urls)}")

    suspicious_attachments = _suspicious_attachments_from_results(file_results, file_entities)
    if not suspicious_attachments:
        suspicious_attachments = _local_dangerous_attachments(att_filenames)

    if suspicious_attachments:
        link_score += min(40, len(suspicious_attachments) * 20)
        if not any(ind.startswith("dangerous_attachment:") for ind in indicators):
            indicators.append(f"dangerous_attachment:{','.join(suspicious_attachments)}")

    for r in file_results:
        if r.get("verdict") in ("suspicious", "malicious"):
            for ind in r.get("indicators") or []:
                if ind not in indicators:
                    indicators.append(ind)

    return {
        "link_score": min(link_score, 100),
        "indicators": indicators,
        "urls_found": len(urls),
        "suspicious_urls": suspicious_urls[:5],
        "malicious_urls": malicious_urls[:5],
        "suspicious_attachments": suspicious_attachments,
        "all_attachments": att_filenames[:10],
    }


async def analyze_email_reputation(
    email_data: dict,
    auth_results: dict,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Single entry point for email_processor.

    Returns (link_result, reputation_result) in the same shape as the legacy
    _analyze_links_and_attachments / _check_sender_reputation functions.
    """
    urls = extract_urls(email_data)
    att_filenames = extract_attachment_filenames(email_data)
    file_entities = build_file_entities(email_data)
    entities = build_entities(email_data, auth_results)

    results: list[dict[str, Any]] = []
    if entities and is_configured():
        results = await lookup_reputation(entities)
        if results:
            logger.debug(
                "Reputation lookup: %d entities → %d results",
                len(entities),
                len(results),
            )
    elif entities and not is_configured():
        logger.debug("REPUTATION_SERVICE_URL not set — using local reputation fallback")

    link_result = map_link_result(
        results,
        urls=urls,
        att_filenames=att_filenames,
        file_entities=file_entities,
    )
    reputation_result = map_sender_result(results, auth_results)

    if not results:
        link_result = _merge_local_link_fallback(link_result, urls, att_filenames)

    return link_result, reputation_result


def _suspicious_attachments_from_results(
    file_results: list[dict[str, Any]],
    file_entities: list[dict[str, Any]],
) -> list[str]:
    names: list[str] = []
    for entity in file_entities:
        filename = (entity.get("context") or {}).get("filename", "")
        value = entity.get("value", "")
        matched = next((r for r in file_results if r.get("value") == value), None)
        if matched and matched.get("verdict") in ("suspicious", "malicious") and filename:
            names.append(filename)
    return names


def _local_dangerous_attachments(filenames: list[str]) -> list[str]:
    suspicious: list[str] = []
    for fname in filenames:
        ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext in _DANGEROUS_EXTENSIONS:
            suspicious.append(fname)
    return suspicious


def _merge_local_link_fallback(
    link_result: dict[str, Any],
    urls: list[str],
    att_filenames: list[str],
) -> dict[str, Any]:
    """When the service is unavailable, preserve basic extension scoring."""
    if link_result["link_score"] > 0:
        return link_result

    suspicious_attachments = _local_dangerous_attachments(att_filenames)
    if suspicious_attachments:
        link_result = dict(link_result)
        link_result["suspicious_attachments"] = suspicious_attachments
        link_result["link_score"] = min(100, len(suspicious_attachments) * 20)
        link_result["indicators"] = [
            f"dangerous_attachment:{','.join(suspicious_attachments)}"
        ]
    link_result["urls_found"] = len(urls)
    link_result["all_attachments"] = att_filenames[:10]
    return link_result


def _fallback_sender_reputation(auth_results: dict) -> dict[str, Any]:
    """Auth-only scoring when the reputation service is down or unconfigured."""
    score = 0
    indicators: list[str] = []

    spf = str(auth_results.get("spf", "")).lower()
    dkim = str(auth_results.get("dkim", "")).lower()
    dmarc = str(auth_results.get("dmarc", "")).lower()

    if spf in ("fail", "softfail"):
        score += 15
        indicators.append(f"spf_{spf}")
    elif spf == "none":
        score += 5
        indicators.append("spf_none")

    if dkim == "fail":
        score += 15
        indicators.append("dkim_fail")
    elif dkim == "none":
        score += 5
        indicators.append("dkim_none")

    if dmarc == "fail":
        score += 20
        indicators.append("dmarc_fail")
    elif dmarc == "none":
        score += 10
        indicators.append("dmarc_none")

    return {
        "reputation_score": min(score, 100),
        "indicators": indicators,
        "spf_pass": spf == "pass",
        "dkim_pass": dkim == "pass",
        "dmarc_pass": dmarc == "pass",
    }
