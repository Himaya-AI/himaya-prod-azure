"""Shared helpers."""
from __future__ import annotations

import hashlib
import json
from typing import Any

_MESSAGE_ID_MAX = 128
MAX_QUEUE_BYTES = 240 * 1024
_ATTACHMENT_BLOB_KEYS = frozenset({"inline_data", "contentBytes", "content_base64"})


def parse_json_body(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
    return parsed if isinstance(parsed, dict) else {"raw": parsed}


def to_json(body: dict[str, Any]) -> str:
    return json.dumps(body, default=str)


def make_id(raw: str, max_length: int = _MESSAGE_ID_MAX) -> str:
    """Return raw if it fits; otherwise a SHA-256 hex id that fits Azure MessageId."""
    if len(raw) <= max_length:
        return raw
    return hashlib.sha256(raw.encode()).hexdigest()


def payload_bytes(data: dict[str, Any]) -> int:
    return len(to_json(data).encode("utf-8"))


def fit_queue_payload(data: dict[str, Any]) -> dict[str, Any]:
    if payload_bytes(data) <= MAX_QUEUE_BYTES:
        return data

    email = dict(data.get("email") or {})
    email.pop("html_body", None)
    attachments = email.get("attachments")
    if isinstance(attachments, list):
        email["attachments"] = [
            {k: v for k, v in item.items() if k not in _ATTACHMENT_BLOB_KEYS}
            if isinstance(item, dict)
            else item
            for item in attachments
        ]
    fitted = {**data, "email": email}
    if payload_bytes(fitted) <= MAX_QUEUE_BYTES:
        return fitted

    email["body"] = str(email.get("body") or "")[:8000]
    return {**data, "email": email}
