from __future__ import annotations

import re
from email import message_from_bytes
from email.policy import SMTP

_UNTRUSTED = re.compile(rb"(?im)^x-himaya-.*\r?\n")
_HEADER_END = re.compile(rb"\r?\n\r?\n")
# Present anywhere in the header block (any value) means return/re-entry.
_RETURN_MARKER = re.compile(rb"(?im)^x-himaya-dlp-return\s*:")


def has_himaya_return_marker(mime_bytes: bytes) -> bool:
    """True if inbound MIME carries X-Himaya-DLP-Return in the header block.

    Used for loop re-entry rejection before stripping untrusted Himaya headers.
    Body text that happens to contain the string is ignored.
    """
    if b"x-himaya-dlp-return" not in mime_bytes.lower():
        return False
    match = _HEADER_END.search(mime_bytes)
    header_block = mime_bytes if match is None else mime_bytes[: match.start()]
    return _RETURN_MARKER.search(header_block) is not None


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
