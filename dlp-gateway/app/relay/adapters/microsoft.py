from __future__ import annotations

from app.domain.models import DeliveryOutcome, RelayRequest, RelayResult, SmtpStage
from app.logging_setup import get_logger
from app.relay.certificates import (
    CertificateLoadError,
    FilesystemRelayCertificateProvider,
)
from app.relay.smtp_transport import PhaseAwareSmtpTransport

log = get_logger(__name__)


class Microsoft365RelayAdapter:
    """Exchange Online provider-return relay via tenant MX + client cert."""

    def __init__(
        self,
        certificate_provider: FilesystemRelayCertificateProvider | None = None,
        transport: PhaseAwareSmtpTransport | None = None,
    ) -> None:
        self._certs = certificate_provider or FilesystemRelayCertificateProvider()
        self._transport = transport or PhaseAwareSmtpTransport()

    def submit(self, request: RelayRequest) -> RelayResult:
        cfg = request.relay_config
        host = str(cfg.get("host") or "").strip()
        port = int(cfg.get("port") or 25)
        cert_path = cfg.get("client_cert_path")
        key_path = cfg.get("client_key_path")
        ehlo = cfg.get("ehlo_hostname") or cfg.get("tls_sender_certificate_name")

        if not host:
            return RelayResult(
                outcome=DeliveryOutcome.FAILED,
                detail="microsoft relay mx_host/host is required",
                smtp_stage=SmtpStage.CONNECT,
            )
        if not cert_path or not key_path:
            return RelayResult(
                outcome=DeliveryOutcome.FAILED,
                detail="microsoft relay client_cert_path/client_key_path are required",
                smtp_stage=SmtpStage.STARTTLS,
                remote_host=host,
            )

        try:
            certificate = self._certs.get_certificate(
                org_id=request.org_id,
                cert_path=str(cert_path),
                key_path=str(key_path),
                expected_thumbprint=cfg.get("certificate_thumbprint"),
            )
        except CertificateLoadError as exc:
            log.error(
                "microsoft_relay.cert_load_failed",
                org_id=request.org_id,
                error=str(exc),
            )
            return RelayResult(
                outcome=DeliveryOutcome.FAILED,
                detail=str(exc),
                smtp_stage=SmtpStage.STARTTLS,
                remote_host=host,
            )

        log.info(
            "microsoft_relay.submit",
            message_id=str(request.message_id),
            org_id=request.org_id,
            host=host,
            port=port,
            recipients=len(request.envelope_to),
            thumbprint=certificate.thumbprint,
        )
        return self._transport.submit(
            host=host,
            port=port,
            envelope_from=request.envelope_from,
            envelope_to=request.envelope_to,
            mime_bytes=request.mime_bytes,
            ehlo_hostname=ehlo,
            require_starttls=bool(cfg.get("require_starttls", True)),
            client_certificate=certificate,
            connection_timeout_seconds=int(
                cfg.get("connection_timeout_seconds", 20)
            ),
            command_timeout_seconds=int(cfg.get("command_timeout_seconds", 60)),
        )
