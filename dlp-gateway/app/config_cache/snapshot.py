from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from email.utils import parseaddr
from pathlib import Path

from app.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class TenantSnapshot:
    schema_version: int
    org_id: str
    provider_deployment_id: str
    provider: str
    routing_hostname: str
    status: str
    mode: str
    accepted_sender_domains: tuple[str, ...]
    relay_host: str
    relay_port: int
    relay_use_tls: bool
    config_version: int
    valid_from: datetime | None
    valid_until: datetime | None

    @property
    def is_enabled(self) -> bool:
        return self.status == "enabled"


class FileTenantConfigCache:
    """Local JSON tenant snapshot. Production will verify signatures."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._snapshot = self._load(path)

    def reload(self) -> None:
        self._snapshot = self._load(self.path)

    def resolve_for_sender(
        self, envelope_from: str, routing_hostname: str | None = None
    ) -> TenantSnapshot | None:
        snap = self._snapshot
        if snap is None or not snap.is_enabled:
            return None
        if routing_hostname and routing_hostname.lower() != snap.routing_hostname.lower():
            # Local mode may omit hostname; only enforce when provided.
            if routing_hostname not in ("localhost", "127.0.0.1"):
                log.warning(
                    "tenant.hostname_mismatch",
                    expected=snap.routing_hostname,
                    got=routing_hostname,
                )
        _, addr = parseaddr(envelope_from)
        addr = (addr or envelope_from or "").lower().strip()
        if "@" not in addr:
            return None
        domain = addr.split("@", 1)[1]
        if domain not in {d.lower() for d in snap.accepted_sender_domains}:
            return None
        return snap

    @staticmethod
    def _load(path: Path) -> TenantSnapshot | None:
        if not path.exists():
            log.error("tenant_config.missing", path=str(path))
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        relay = raw.get("relay") or {}
        return TenantSnapshot(
            schema_version=int(raw.get("schema_version", 1)),
            org_id=raw["org_id"],
            provider_deployment_id=raw["provider_deployment_id"],
            provider=raw["provider"],
            routing_hostname=raw["routing_hostname"],
            status=raw["status"],
            mode=raw.get("mode", "monitor"),
            accepted_sender_domains=tuple(raw.get("accepted_sender_domains") or ()),
            relay_host=relay.get("host", "mailhog"),
            relay_port=int(relay.get("port", 1025)),
            relay_use_tls=bool(relay.get("use_tls", False)),
            config_version=int(raw.get("config_version", 1)),
            valid_from=None,
            valid_until=None,
        )
