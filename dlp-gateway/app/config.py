from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dlp_env: str = "local"
    log_level: str = "INFO"

    smtp_host: str = "0.0.0.0"
    smtp_port: int = 2525
    health_host: str = "0.0.0.0"
    health_port: int = 8080

    spool_dir: Path = Path("/var/dlp/spool")
    data_dir: Path = Path("/var/dlp/data")
    queue_dir: Path = Path("/var/dlp/queues")
    tenant_config_path: Path = Path("/app/conf/tenants/local-tenant.json")

    force_allow: bool = True

    azure_storage_connection_string: str = Field(default="")
    blob_container: str = "dlp-mime"

    relay_host: str = "mailhog"
    relay_port: int = 1025
    relay_use_tls: bool = False

    max_message_bytes: int = 25 * 1024 * 1024
    max_recipients: int = 100

    @property
    def is_local(self) -> bool:
        return self.dlp_env.lower() == "local"


@lru_cache
def get_settings() -> Settings:
    return Settings()
