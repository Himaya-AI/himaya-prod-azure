from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from email.utils import parseaddr
from pathlib import Path
from typing import Any

from app.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class TenantRelayConfig:
    adapter: str
    host: str
    port: int
    use_tls: bool
    require_starttls: bool
    ehlo_hostname: str | None
    tls_sender_certificate_name: str | None
    client_cert_path: str | None
    client_key_path: str | None
    certificate_thumbprint: str | None
    connection_timeout_seconds: int
    command_timeout_seconds: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "host": self.host,
            "port": self.port,
            "use_tls": self.use_tls,
            "require_starttls": self.require_starttls,
            "ehlo_hostname": self.ehlo_hostname,
            "tls_sender_certificate_name": self.tls_sender_certificate_name,
            "client_cert_path": self.client_cert_path,
            "client_key_path": self.client_key_path,
            "certificate_thumbprint": self.certificate_thumbprint,
            "connection_timeout_seconds": self.connection_timeout_seconds,
            "command_timeout_seconds": self.command_timeout_seconds,
        }


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
    relay: TenantRelayConfig
    config_version: int
    valid_from: datetime | None
    valid_until: datetime | None

    # Back-compat helpers used by older call sites / health checks.
    @property
    def relay_host(self) -> str:
        return self.relay.host

    @property
    def relay_port(self) -> int:
        return self.relay.port

    @property
    def relay_use_tls(self) -> bool:
        return self.relay.use_tls

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

    def resolve_by_org_id(self, org_id: str) -> TenantSnapshot | None:
        snap = self._snapshot
        if snap is None or not snap.is_enabled:
            return None
        if snap.org_id != org_id:
            return None
        return snap

    @staticmethod
    def _load(path: Path) -> TenantSnapshot | None:
        if not path.exists():
            log.error("tenant_config.missing", path=str(path))
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        relay_raw = raw.get("relay") or {}
        adapter = str(
            relay_raw.get("adapter")
            or ("microsoft" if raw.get("provider") in {"m365", "microsoft"} else "local")
        ).lower()
        relay = TenantRelayConfig(
            adapter=adapter,
            host=str(
                relay_raw.get("mx_host")
                or relay_raw.get("host")
                or ("mailhog" if adapter == "local" else "")
            ),
            port=int(relay_raw.get("port", 1025 if adapter == "local" else 25)),
            use_tls=bool(relay_raw.get("use_tls", adapter != "local")),
            require_starttls=bool(
                relay_raw.get("require_starttls", adapter != "local")
            ),
            ehlo_hostname=relay_raw.get("ehlo_hostname"),
            tls_sender_certificate_name=relay_raw.get(
                "tls_sender_certificate_name"
            ),
            client_cert_path=relay_raw.get("client_cert_path"),
            client_key_path=relay_raw.get("client_key_path"),
            certificate_thumbprint=relay_raw.get("certificate_thumbprint"),
            connection_timeout_seconds=int(
                relay_raw.get("connection_timeout_seconds", 20)
            ),
            command_timeout_seconds=int(
                relay_raw.get("command_timeout_seconds", 60)
            ),
        )
        return TenantSnapshot(
            schema_version=int(raw.get("schema_version", 1)),
            org_id=raw["org_id"],
            provider_deployment_id=raw["provider_deployment_id"],
            provider=raw["provider"],
            routing_hostname=raw["routing_hostname"],
            status=raw["status"],
            mode=raw.get("mode", "monitor"),
            accepted_sender_domains=tuple(raw.get("accepted_sender_domains") or ()),
            relay=relay,
            config_version=int(raw.get("config_version", 1)),
            valid_from=None,
            valid_until=None,
        )
