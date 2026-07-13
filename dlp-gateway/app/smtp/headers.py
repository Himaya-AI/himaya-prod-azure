from __future__ import annotations

import re
from email import message_from_bytes
from email.policy import SMTP

_UNTRUSTED = re.compile(rb"(?im)^x-himaya-.*\r?\n")


def strip_untrusted_himaya_headers(mime_bytes: bytes) -> bytes:
    """Remove client-supplied X-Himaya-* headers before durable store."""
    # Fast path for simple cases; fall back to email parser if needed.
    if b"x-himaya-" not in mime_bytes.lower():
        return mime_bytes
    try:
        msg = message_from_bytes(mime_bytes, policy=SMTP)
        for key in list(msg.keys()):
            if key.lower().startswith("x-himaya-"):
                del msg[key]
        return msg.as_bytes(policy=SMTP)
    except Exception:
        return _UNTRUSTED.sub(b"", mime_bytes)
