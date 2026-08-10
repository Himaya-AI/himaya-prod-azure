from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

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

    smtp_tls_cert_file: Path | None = None
    smtp_tls_key_file: Path | None = None
    smtp_require_starttls: bool = False

    spool_dir: Path = Path("/var/dlp/spool")
    data_dir: Path = Path("/var/dlp/data")
    queue_dir: Path = Path("/var/dlp/queues")
    queue_reclaim_seconds: int = 300
    tenant_config_path: Path = Path("/app/conf/tenants/local-tenant.json")
    message_bus: Literal["filesystem", "service_bus"] = "filesystem"
    service_bus_connection_string: str = ""
    service_bus_fully_qualified_namespace: str = ""
    capture_queue_name: str = "dlp-capture"
    command_queue_name: str = "dlp-commands"
    delivery_queue_name: str = "dlp-delivery"

    force_allow: bool = True

    azure_storage_connection_string: str = Field(default="")
    blob_container: str = "dlp-mime"

    relay_host: str = "mailhog"
    relay_port: int = 1025
    relay_use_tls: bool = False
    relay_max_attempts: int = Field(default=4, ge=1)

    max_message_bytes: int = 25 * 1024 * 1024
    max_recipients: int = 100

    @property
    def is_local(self) -> bool:
        return self.dlp_env.lower() == "local"


@lru_cache
def get_settings() -> Settings:
    return Settings()
