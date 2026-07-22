"""Module-local configuration for the DLP v2 bounded context."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class DlpSettings(BaseSettings):
    """Settings used only by ``backend.dlp`` APIs and workers."""

    model_config = SettingsConfigDict(
        env_prefix="DLP_",
        env_file=str(_REPOSITORY_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gateway_pipeline_enabled: bool = False
    tenant_mode: Literal["monitor", "enforce"] = "monitor"

    classifier_service_url: str = "http://127.0.0.1:8002"
    classifier_connect_timeout_seconds: float = 5.0
    classifier_read_timeout_seconds: float = 45.0
    classifier_max_attempts: int = 3
    classifier_circuit_failure_threshold: int = 5
    classifier_circuit_recovery_seconds: float = 30.0

    message_bus: Literal["filesystem", "service_bus"] = "filesystem"
    service_bus_connection_string: str = ""
    service_bus_fully_qualified_namespace: str = ""
    capture_queue_name: str = "dlp-capture"
    command_queue_name: str = "dlp-commands"
    local_queue_dir: Path = Path("/var/dlp/queues")
    local_queue_reclaim_seconds: int = 300

    azure_storage_connection_string: str = ""
    azure_storage_account: str = ""
    mime_blob_container: str = "dlp-mime"
    max_mime_bytes: int = 25 * 1024 * 1024
    max_classifier_text_bytes: int = 2 * 1024 * 1024


@lru_cache
def get_dlp_settings() -> DlpSettings:
    return DlpSettings()
