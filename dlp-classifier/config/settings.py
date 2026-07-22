from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    LOG_LEVEL: str = "info"

    REDIS_URL: str
    REDIS_KEY_PREFIX: str = "dlp"
    LEXICON_TTL_SECONDS: int = 3600

    BETTERLEAKS_BINARY: str = "/usr/local/bin/betterleaks"
    BETTERLEAKS_TIMEOUT: int = 10

    SPACY_MODEL: str = "en_core_web_sm"
    TIER1_ENABLED: bool = True
    TIER2_ENABLED: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
