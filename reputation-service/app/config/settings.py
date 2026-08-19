from __future__ import annotations

import os
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


SERVICE_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    service_name: str
    environment: str
    log_level: str
    redis_url: str
    cache_ttl_seconds: int
    error_ttl_seconds: int
    admin_api_key: str | None
    sources_config_path: Path
    virustotal_api_key: str | None
    alienvault_otx_api_key: str | None
    urlscan_api_key: str | None
    abusech_api_key: str | None
    tranco_top1m_path: Path
    whois_record_ttl_seconds: int
    whois_negative_ttl_seconds: int
    whois_max_workers: int
    whois_socket_timeout_seconds: int


def _optional_env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_settings() -> Settings:
    load_dotenv(SERVICE_ROOT / ".env")
    return Settings(
        service_name=os.getenv("REPUTATION_SERVICE_NAME", "helios-reputation-service"),
        environment=os.getenv("REPUTATION_ENV", "local"),
        log_level=os.getenv("REPUTATION_LOG_LEVEL", "INFO"),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
        cache_ttl_seconds=_int_env("REPUTATION_CACHE_TTL_SECONDS", 72 * 60 * 60),
        error_ttl_seconds=_int_env("REPUTATION_ERROR_TTL_SECONDS", 15 * 60),
        admin_api_key=_optional_env("REPUTATION_ADMIN_API_KEY"),
        sources_config_path=Path(
            os.getenv(
                "REPUTATION_SOURCES_CONFIG",
                str(SERVICE_ROOT / "app" / "config" / "sources.yaml"),
            )
        ),
        virustotal_api_key=_optional_env("VIRUSTOTAL_API_KEY"),
        alienvault_otx_api_key=_optional_env("ALIENVAULT_OTX_API_KEY"),
        urlscan_api_key=_optional_env("URLSCAN_API_KEY"),
        abusech_api_key=_optional_env("ABUSECH_API_KEY"),
        tranco_top1m_path=Path(
            os.getenv(
                "REPUTATION_TRANCO_TOP1M_PATH",
                str(SERVICE_ROOT / "app" / "config" / "tranco_W37V9-1m.csv" / "top-1m.csv"),
            )
        ),
        # A domain's creation date never changes, so this can be long.
        whois_record_ttl_seconds=_int_env("WHOIS_RECORD_TTL_SECONDS", 30 * 24 * 60 * 60),
        # Short TTL for a failed/unanswered lookup so it self-heals quickly.
        whois_negative_ttl_seconds=_int_env("WHOIS_NEGATIVE_TTL_SECONDS", 30 * 60),
        whois_max_workers=_int_env("WHOIS_MAX_WORKERS", 4),
        whois_socket_timeout_seconds=_int_env("WHOIS_SOCKET_TIMEOUT_SECONDS", 5),
    )


@lru_cache(maxsize=2)
def load_tranco_rank_index(csv_path: str) -> dict[str, int]:
    """
    Load Tranco top-1m CSV into a {domain -> rank} lookup map.

    Expected format per line: rank,domain
    """
    path = Path(csv_path)
    ranks: dict[str, int] = {}

    if not path.exists():
        return ranks

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or "," not in raw:
                continue
            rank_part, domain_part = raw.split(",", 1)
            domain = domain_part.strip().lower().rstrip(".")
            if not domain:
                continue
            try:
                rank = int(rank_part)
            except ValueError:
                continue
            ranks[domain] = rank

    return ranks
