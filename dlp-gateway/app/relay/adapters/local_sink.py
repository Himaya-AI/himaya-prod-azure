from __future__ import annotations

from app.domain.models import DeliveryOutcome, RelayRequest, RelayResult
from app.logging_setup import get_logger
from app.relay.smtp_transport import PhaseAwareSmtpTransport

log = get_logger(__name__)


class SmtpSinkRelayAdapter:
    """Local / generic SMTP relay (MailHog in Docker)."""

    def __init__(self, host: str, port: int, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self._transport = PhaseAwareSmtpTransport()

    def submit(self, request: RelayRequest) -> RelayResult:
        cfg = request.relay_config
        host = str(cfg.get("host") or self.host)
        port = int(cfg.get("port") or self.port)
        use_tls = bool(cfg.get("use_tls", self.use_tls))
        return self._transport.submit(
            host=host,
            port=port,
            envelope_from=request.envelope_from,
            envelope_to=request.envelope_to,
            mime_bytes=request.mime_bytes,
            ehlo_hostname=cfg.get("ehlo_hostname"),
            require_starttls=use_tls,
            client_certificate=None,
            connection_timeout_seconds=int(
                cfg.get("connection_timeout_seconds", 20)
            ),
            command_timeout_seconds=(
                int(cfg["command_timeout_seconds"])
                if cfg.get("command_timeout_seconds") is not None
                else None
            ),
        )
