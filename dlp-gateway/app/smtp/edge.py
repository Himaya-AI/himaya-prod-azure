from __future__ import annotations

import asyncio
import uuid
from email.utils import parseaddr

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

from app.config import Settings
from app.domain.models import SpoolRecord
from app.logging_setup import get_logger
from app.smtp.headers import strip_untrusted_himaya_headers
from app.smtp.tenant_resolver import TenantResolver
from app.smtp.trust import TrustPolicy
from app.spool.mta_spool import FilesystemSpoolStore, sha256_hex

log = get_logger(__name__)


class DlpSMTPHandler:
    """SMTP handler that accepts only after durable spool commit."""

    def __init__(
        self,
        settings: Settings,
        spool: FilesystemSpoolStore,
        resolver: TenantResolver,
        trust: TrustPolicy,
    ) -> None:
        self.settings = settings
        self.spool = spool
        self.resolver = resolver
        self.trust = trust

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        if len(envelope.rcpt_tos) >= self.settings.max_recipients:
            return "452 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        peer = None
        if session.peer:
            peer = session.peer[0] if isinstance(session.peer, tuple) else str(session.peer)
        if not self.trust.allow_peer(peer):
            return "550 Relay not permitted"

        mail_from = envelope.mail_from or ""
        _, sender = parseaddr(mail_from)
        sender = sender or mail_from
        tenant = self.resolver.resolve(sender)
        if tenant is None:
            log.warning("smtp.reject_unknown_tenant", mail_from=sender, peer=peer)
            return "550 Sender not authorized for DLP gateway"

        content = envelope.content or b""
        if isinstance(content, str):
            content = content.encode("utf-8", errors="replace")
        if len(content) > self.settings.max_message_bytes:
            return "552 Message size exceeds limit"

        mime_bytes = strip_untrusted_himaya_headers(content)
        message_id = uuid.uuid4()
        record = SpoolRecord(
            message_id=message_id,
            org_id=tenant.org_id,
            provider=tenant.provider,
            provider_deployment_id=tenant.provider_deployment_id,
            session_id=str(uuid.uuid4()),
            envelope_from=sender,
            envelope_to=list(envelope.rcpt_tos),
            mime_sha256=sha256_hex(mime_bytes),
            mime_size=len(mime_bytes),
            routing_hostname=tenant.routing_hostname,
            peer=peer,
            spool_mime_path="",
            metadata_path="",
        )

        try:
            # Spool commit is sync/fsync — run in thread to avoid blocking loop hard
            await asyncio.to_thread(self.spool.commit, record, mime_bytes)
        except Exception:
            log.exception("smtp.spool_failed", message_id=str(message_id))
            return "451 Temporary local error — try again later"

        log.info(
            "smtp.accepted",
            message_id=str(message_id),
            org_id=tenant.org_id,
            recipients=len(envelope.rcpt_tos),
        )
        return f"250 OK id={message_id}"


class SmtpEdge:
    def __init__(self, handler: DlpSMTPHandler, settings: Settings) -> None:
        self.handler = handler
        self.settings = settings
        self._controller: Controller | None = None

    def start(self) -> None:
        self._controller = Controller(
            self.handler,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            ready_timeout=10,
        )
        self._controller.start()
        log.info(
            "smtp.listening",
            host=self.settings.smtp_host,
            port=self.settings.smtp_port,
        )

    def stop(self) -> None:
        if self._controller is not None:
            self._controller.stop()
            self._controller = None
