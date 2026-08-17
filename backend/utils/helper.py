"""Shared helpers."""
from __future__ import annotations

import hashlib
import json
from typing import Any

_MESSAGE_ID_MAX = 128


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
