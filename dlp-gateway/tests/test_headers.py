from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.smtp.edge import DlpSMTPHandler
from app.smtp.headers import (
    has_himaya_return_marker,
    strip_untrusted_himaya_headers,
)
from app.spool.mta_spool import FilesystemSpoolStore


def test_strip_untrusted_himaya_headers() -> None:
    msg = EmailMessage()
    msg["From"] = "alice@example.test"
    msg["To"] = "bob@external.test"
    msg["Subject"] = "hi"
    msg["X-Himaya-Org-Id"] = "evil"
    msg["X-Other"] = "keep"
    msg.set_content("body")
    cleaned = strip_untrusted_himaya_headers(msg.as_bytes())
    assert b"x-himaya-org-id" not in cleaned.lower()
    assert b"x-other" in cleaned.lower()
    assert b"body" in cleaned


def test_has_return_marker_in_headers() -> None:
    mime = (
        b"X-Himaya-DLP-Return: 1\r\n"
        b"From: a@x.test\r\n"
        b"Subject: hi\r\n"
        b"\r\nbody\r\n"
    )
    assert has_himaya_return_marker(mime) is True


def test_has_return_marker_ignores_body_text() -> None:
    mime = (
        b"From: a@x.test\r\n"
        b"Subject: hi\r\n"
        b"\r\n"
        b"Please set X-Himaya-DLP-Return: 1 in docs\r\n"
    )
    assert has_himaya_return_marker(mime) is False


def test_has_return_marker_any_value() -> None:
    mime = b"X-Himaya-DLP-Return: spoofed\r\nFrom: a@x.test\r\n\r\nbody\r\n"
    assert has_himaya_return_marker(mime) is True


@pytest.mark.asyncio
async def test_edge_rejects_return_marker_with_550(tmp_path: Path) -> None:
    spool = FilesystemSpoolStore(tmp_path / "spool")
    tenant = SimpleNamespace(
        org_id=str(uuid4()),
        provider="local",
        provider_deployment_id=str(uuid4()),
        routing_hostname="test.smtp.dlp.himaya.ai",
    )
    resolver = SimpleNamespace(resolve=lambda _sender: tenant)
    trust = SimpleNamespace(allow_peer=lambda _peer: True)
    settings = SimpleNamespace(
        max_message_bytes=1_000_000,
        max_recipients=100,
    )
    handler = DlpSMTPHandler(settings, spool, resolver, trust)  # type: ignore[arg-type]

    envelope = SimpleNamespace(
        mail_from="alice@example.test",
        rcpt_tos=["bob@external.test"],
        content=(
            b"X-Himaya-DLP-Return: 1\r\n"
            b"From: alice@example.test\r\n"
            b"To: bob@external.test\r\n"
            b"Subject: loop\r\n"
            b"\r\nbody\r\n"
        ),
    )
    session = SimpleNamespace(peer=("1.2.3.4", 25))

    reply = await handler.handle_DATA(None, session, envelope)  # type: ignore[arg-type]
    assert reply.startswith("550")
    assert "Loop detected" in reply
    assert spool.list_pending_capture() == []
