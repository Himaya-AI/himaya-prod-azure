from __future__ import annotations

import smtplib
import ssl
from datetime import datetime, timezone
from email.utils import parseaddr

from app.domain.models import DeliveryOutcome, RelayResult, SmtpStage
from app.logging_setup import get_logger
from app.relay.certificates import LoadedRelayCertificate
from app.relay.outcomes import classify_smtp_result

log = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _smtp_text(payload: object) -> str:
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return str(payload)


class PhaseAwareSmtpTransport:
    """SMTP submit with stage tracking and optional client certificate."""

    def submit(
        self,
        *,
        host: str,
        port: int,
        envelope_from: str,
        envelope_to: list[str],
        mime_bytes: bytes,
        ehlo_hostname: str | None = None,
        require_starttls: bool = True,
        client_certificate: LoadedRelayCertificate | None = None,
        connection_timeout_seconds: int = 20,
        command_timeout_seconds: int | None = None,
    ) -> RelayResult:
        started = _utcnow()
        stage = SmtpStage.CONNECT
        client: smtplib.SMTP | None = None
        accepted: list[str] = []
        refused: list[str] = []
        last_code: int | None = None
        last_message: str | None = None
        # smtplib uses one socket timeout for connect + SMTP commands.
        socket_timeout = connection_timeout_seconds
        if (
            command_timeout_seconds is not None
            and command_timeout_seconds > socket_timeout
        ):
            socket_timeout = command_timeout_seconds

        try:
            client = smtplib.SMTP(
                host=host,
                port=port,
                timeout=socket_timeout,
                local_hostname=ehlo_hostname,
            )
            stage = SmtpStage.EHLO
            code, message = client.ehlo(ehlo_hostname or "")
            last_code, last_message = int(code), _smtp_text(message)
            if last_code >= 400:
                return self._result(
                    classify_smtp_result(last_code, stage=stage),
                    stage,
                    last_code,
                    last_message,
                    host,
                    accepted,
                    refused,
                    started,
                    client_certificate,
                )

            if require_starttls:
                if not client.has_extn("starttls"):
                    return self._result(
                        DeliveryOutcome.FAILED,
                        stage,
                        last_code,
                        "STARTTLS not offered by remote SMTP server",
                        host,
                        accepted,
                        refused,
                        started,
                        client_certificate,
                        detail="STARTTLS required but unsupported",
                    )
                stage = SmtpStage.STARTTLS
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                if client_certificate is not None:
                    context.load_cert_chain(
                        certfile=str(client_certificate.cert_path),
                        keyfile=str(client_certificate.key_path),
                    )
                client.starttls(context=context)
                stage = SmtpStage.EHLO
                code, message = client.ehlo(ehlo_hostname or "")
                last_code, last_message = int(code), _smtp_text(message)
                if last_code >= 400:
                    return self._result(
                        classify_smtp_result(last_code, stage=stage),
                        stage,
                        last_code,
                        last_message,
                        host,
                        accepted,
                        refused,
                        started,
                        client_certificate,
                    )

            mail_from = parseaddr(envelope_from)[1] or envelope_from
            stage = SmtpStage.MAIL_FROM
            code, message = client.mail(mail_from)
            last_code, last_message = int(code), _smtp_text(message)
            if last_code >= 400:
                return self._result(
                    classify_smtp_result(last_code, stage=stage),
                    stage,
                    last_code,
                    last_message,
                    host,
                    accepted,
                    refused,
                    started,
                    client_certificate,
                )

            stage = SmtpStage.RCPT_TO
            for recipient in envelope_to:
                code, message = client.rcpt(recipient)
                code_i = int(code)
                last_code, last_message = code_i, _smtp_text(message)
                if 200 <= code_i < 300:
                    accepted.append(recipient)
                else:
                    refused.append(recipient)

            if not accepted:
                return self._result(
                    classify_smtp_result(last_code, stage=stage),
                    stage,
                    last_code,
                    last_message,
                    host,
                    accepted,
                    refused,
                    started,
                    client_certificate,
                    detail="all recipients refused",
                )

            stage = SmtpStage.DATA_STARTED
            code, message = client.data(mime_bytes)
            # data() returns after final response when successful
            stage = SmtpStage.FINAL_RESPONSE
            last_code, last_message = int(code), _smtp_text(message)
            data_outcome = classify_smtp_result(last_code, stage=stage)
            # PARTIAL only when DATA was accepted and some RCPT were refused.
            if refused and data_outcome == DeliveryOutcome.ACCEPTED:
                outcome = DeliveryOutcome.PARTIAL
            else:
                outcome = data_outcome
            return self._result(
                outcome,
                stage,
                last_code,
                last_message,
                host,
                accepted,
                refused,
                started,
                client_certificate,
            )
        except (smtplib.SMTPServerDisconnected, TimeoutError, ConnectionError) as exc:
            after_data = stage in {
                SmtpStage.DATA_STARTED,
                SmtpStage.DATA_SENT,
                SmtpStage.FINAL_RESPONSE,
            }
            outcome = classify_smtp_result(
                None,
                connection_lost_after_data=after_data,
                stage=SmtpStage.DATA_SENT if after_data else stage,
            )
            log.warning(
                "smtp_transport.connection_lost",
                stage=stage.value,
                host=host,
                error=str(exc),
                outcome=outcome.value,
            )
            return self._result(
                outcome,
                stage,
                last_code,
                last_message,
                host,
                accepted,
                refused,
                started,
                client_certificate,
                detail=str(exc),
            )
        except smtplib.SMTPResponseException as exc:
            code = int(exc.smtp_code)
            return self._result(
                classify_smtp_result(code, stage=stage),
                stage,
                code,
                _smtp_text(exc.smtp_error),
                host,
                accepted,
                refused,
                started,
                client_certificate,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("smtp_transport.failed", stage=stage.value, host=host)
            return self._result(
                DeliveryOutcome.FAILED,
                stage,
                last_code,
                last_message,
                host,
                accepted,
                refused,
                started,
                client_certificate,
                detail=str(exc),
            )
        finally:
            if client is not None:
                try:
                    client.quit()
                except Exception:  # noqa: BLE001
                    try:
                        client.close()
                    except Exception:  # noqa: BLE001
                        pass

    @staticmethod
    def _result(
        outcome: DeliveryOutcome,
        stage: SmtpStage,
        smtp_code: int | None,
        smtp_message: str | None,
        host: str,
        accepted: list[str],
        refused: list[str],
        started: datetime,
        client_certificate: LoadedRelayCertificate | None,
        detail: str | None = None,
    ) -> RelayResult:
        return RelayResult(
            outcome=outcome,
            smtp_code=smtp_code,
            smtp_message=smtp_message,
            detail=detail or smtp_message,
            smtp_stage=stage,
            accepted_recipients=accepted,
            refused_recipients=refused,
            remote_host=host,
            certificate_thumbprint=(
                client_certificate.thumbprint if client_certificate else None
            ),
            attempt_started_at=started,
            attempt_finished_at=_utcnow(),
        )
