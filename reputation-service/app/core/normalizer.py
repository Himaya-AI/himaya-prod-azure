from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

from app.api.schemas import EntityType, ReputationEntity


TRACKING_QUERY_PREFIXES = ("utm_",)
TRACKING_QUERY_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class NormalizedEntity:
    entity_type: EntityType
    original_value: str
    normalized_value: str
    lookup_type: EntityType
    lookup_value: str
    entity_key: str
    related_domain: str | None = None


def normalize_entity(entity: ReputationEntity) -> NormalizedEntity:
    if entity.type == EntityType.sender:
        normalized = normalize_sender(entity.value)
        domain = extract_sender_domain(normalized)
        lookup_type = EntityType.domain if domain else EntityType.sender
        lookup_value = domain or normalized
    elif entity.type == EntityType.domain:
        normalized = normalize_domain(entity.value)
        lookup_type = EntityType.domain
        lookup_value = normalized
        domain = normalized
    elif entity.type == EntityType.url:
        normalized = normalize_url(entity.value)
        lookup_type = EntityType.url
        lookup_value = normalized
        domain = extract_url_domain(normalized)
    elif entity.type == EntityType.ip:
        normalized = normalize_ip(entity.value)
        lookup_type = EntityType.ip
        lookup_value = normalized
        domain = None
    else:
        normalized = normalize_file_hash(entity.value)
        lookup_type = EntityType.file
        lookup_value = normalized
        domain = None

    return NormalizedEntity(
        entity_type=entity.type,
        original_value=entity.value,
        normalized_value=normalized,
        lookup_type=lookup_type,
        lookup_value=lookup_value,
        related_domain=domain,
        entity_key=build_cache_key(entity.type, normalized),
    )


def normalize_sender(value: str) -> str:
    return value.strip().lower()


def extract_sender_domain(sender: str) -> str | None:
    if "@" not in sender:
        return None
    domain = sender.rsplit("@", 1)[-1]
    return normalize_domain(domain) if domain else None


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if "://" in domain:
        parsed = urllib.parse.urlparse(domain)
        domain = parsed.hostname or domain
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return domain


def normalize_url(value: str) -> str:
    raw = value.strip()
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"http://{raw}")
    scheme = (parsed.scheme or "http").lower()
    if scheme in ("http", "https"):
        scheme = "https"
    host = normalize_domain(parsed.hostname or "")
    port = _normalized_port(scheme, parsed.port)
    netloc = f"{host}:{port}" if port else host
    path = urllib.parse.quote(urllib.parse.unquote(parsed.path or ""), safe="/:@")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = _normalize_query(parsed.query)
    rebuilt = urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
    return rebuilt.rstrip("/") if path in ("", "/") and not query else rebuilt


def extract_url_domain(url: str) -> str | None:
    parsed = urllib.parse.urlparse(url)
    return normalize_domain(parsed.hostname or "") or None


def normalize_file_hash(value: str) -> str:
    digest = value.strip().replace(" ", "").lower()
    if not HEX_RE.match(digest):
        raise ValueError("File hash must be hexadecimal")
    if len(digest) not in (32, 40, 64):
        raise ValueError("File hash must be MD5, SHA1, or SHA256 length")
    return digest


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def build_cache_key(entity_type: EntityType, normalized_value: str) -> str:
    digest = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
    return f"rep:v1:{entity_type.value}:{digest}"


def build_ti_cache_key(normalized: NormalizedEntity) -> str | None:
    """Threat-intel cache key. Sender lookups reuse the sender domain cache."""
    if normalized.entity_type == EntityType.sender:
        if normalized.lookup_type == EntityType.domain and normalized.lookup_value:
            return build_cache_key(EntityType.domain, normalized.lookup_value)
        return None
    return normalized.entity_key


def _normalized_port(scheme: str, port: int | None) -> int | None:
    if port is None:
        return None
    if scheme == "https" and port == 443:
        return None
    if scheme == "http" and port == 80:
        return None
    return port


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    filtered = [
        (key, value)
        for key, value in pairs
        if key not in TRACKING_QUERY_KEYS
        and not any(key.startswith(prefix) for prefix in TRACKING_QUERY_PREFIXES)
    ]
    return urllib.parse.urlencode(filtered, doseq=True)
