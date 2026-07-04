from __future__ import annotations

import os
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
    )
