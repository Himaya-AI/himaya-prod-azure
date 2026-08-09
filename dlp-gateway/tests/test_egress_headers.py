from __future__ import annotations

from app.relay.dispatcher import build_egress_copy


def test_egress_stamps_return_marker() -> None:
    original = b"From: a@x.test\r\nTo: b@y.test\r\nSubject: hi\r\n\r\nhello\r\n"
    out = build_egress_copy(original)
    assert out.startswith(b"X-Himaya-DLP-Return: 1\r\n")
    assert b"\r\n\r\nhello\r\n" in out


def test_egress_removes_spoofed_marker_and_restamps() -> None:
    original = (
        b"X-Himaya-DLP-Return: 9\r\n"
        b"X-Himaya-Org-Id: evil\r\n"
        b"From: a@x.test\r\n"
        b"To: b@y.test\r\n"
        b"Subject: hi\r\n"
        b"\r\nhello\r\n"
    )
    out = build_egress_copy(original)
    # Exactly one marker, and the spoofed value/headers are gone.
    assert out.count(b"X-Himaya-DLP-Return") == 1
    assert b"X-Himaya-Org-Id" not in out
    assert b": 9\r\n" not in out.split(b"\r\n\r\n")[0]
    assert b"hello" in out


def test_egress_strips_folded_x_himaya_continuation() -> None:
    original = (
        b"X-Himaya-DLP-Return: 1\r\n\t(folded continuation)\r\n"
        b"Subject: hi\r\n"
        b"\r\nbody\r\n"
    )
    out = build_egress_copy(original)
    assert b"folded continuation" not in out
    assert out.count(b"X-Himaya-DLP-Return") == 1
    assert b"Subject: hi" in out


def test_egress_preserves_existing_headers_byte_for_byte() -> None:
    # Folded DKIM + encoded-word subject + base64 body must survive untouched.
    original = (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=x.test; s=s1;\r\n"
        b"\tb=AAAA" + b"A" * 80 + b"\r\n"
        b"Subject: =?utf-8?q?hello_=E2=82=AC?=\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8gd29ybGQg4oCsIHRoaXMgaXMgYSBsb25nIGxpbmUgdGhhdCBpcyBvdmVy\r\n"
    )
    out = build_egress_copy(original)
    # Strip just our marker; everything else must equal the original exactly.
    rest = out[len(b"X-Himaya-DLP-Return: 1\r\n"):]
    assert rest == original


def test_egress_fallback_prepends_marker_without_separator() -> None:
    garbage = b"no header separator at all \x00\xff"
    out = build_egress_copy(garbage)
    assert out.startswith(b"X-Himaya-DLP-Return: 1\r\n")
    assert out.endswith(garbage)
