from __future__ import annotations

from email.message import EmailMessage

from app.smtp.headers import strip_untrusted_himaya_headers


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
