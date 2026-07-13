from __future__ import annotations

import smtplib

from app.domain.models import DeliveryOutcome, RelayResult
from app.logging_setup import get_logger

log = get_logger(__name__)


class SmtpSinkRelayAdapter:
    """Local / generic SMTP relay (MailHog in Docker)."""

    def __init__(self, host: str, port: int, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls

    def submit(
        self, mime_bytes: bytes, envelope_from: str, envelope_to: list[str]
    ) -> RelayResult:
        try:
            with smtplib.SMTP(self.host, self.port, timeout=30) as client:
                if self.use_tls:
                    client.starttls()
                # Send original bytes; do not rebuild from fields.
                refused = client.sendmail(envelope_from, envelope_to, mime_bytes)
                if refused:
                    return RelayResult(
                        outcome=DeliveryOutcome.FAILED,
                        smtp_code=550,
                        detail=f"refused={refused}",
                    )
                return RelayResult(
                    outcome=DeliveryOutcome.ACCEPTED,
                    smtp_code=250,
                    smtp_message="accepted by sink",
                )
        except smtplib.SMTPResponseException as exc:
            code = int(exc.smtp_code)
            if 400 <= code < 500:
                outcome = DeliveryOutcome.DEFERRED
            else:
                outcome = DeliveryOutcome.FAILED
            return RelayResult(
                outcome=outcome,
                smtp_code=code,
                smtp_message=str(exc.smtp_error),
            )
        except (smtplib.SMTPServerDisconnected, TimeoutError, ConnectionError) as exc:
            # Ambiguous: may have been accepted after DATA.
            log.warning("relay.uncertain", error=str(exc))
            return RelayResult(
                outcome=DeliveryOutcome.UNCERTAIN,
                detail=str(exc),
            )
        except Exception as exc:
            log.exception("relay.failed")
            return RelayResult(outcome=DeliveryOutcome.FAILED, detail=str(exc))


class Microsoft365RelayAdapter:
    """Placeholder for production Exchange Online return path."""

    def submit(
        self, mime_bytes: bytes, envelope_from: str, envelope_to: list[str]
    ) -> RelayResult:
        return RelayResult(
            outcome=DeliveryOutcome.FAILED,
            detail="Microsoft365RelayAdapter not configured in local mode",
        )
