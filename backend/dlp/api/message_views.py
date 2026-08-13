"""Pure helpers for DLP message list/detail presentation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.dlp.persistence.models import (
    DlpDecision,
    DlpMessage,
    DlpMessageEvent,
)

REVIEWABLE_STATES = frozenset({"decided", "held"})
PREVIEW_MAX_MIME_BYTES = 2 * 1024 * 1024
PREVIEW_MAX_TEXT_CHARS = 4000
DELIVERY_EVENT_TYPE = "dlp.message.delivery.v1"
DELIVERY_MAX_TEXT_CHARS = 500
DELIVERY_MAX_RECIPIENTS = 50


def is_reviewable(
    message: DlpMessage, decision: DlpDecision | None
) -> bool:
    return (
        decision is not None
        and decision.effective_action == "hold"
        and message.state in REVIEWABLE_STATES
    )


def sanitize_findings(
    finding_references: list[dict[str, Any]] | None,
    classification_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return detector/entity/confidence only — never raw match text."""
    source = finding_references or classification_findings or []
    sanitized: list[dict[str, Any]] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        detector = str(item.get("detector") or "").strip()
        entity_type = str(item.get("entity_type") or "").strip()
        if not detector or not entity_type:
            continue
        try:
            confidence = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        sanitized.append(
            {
                "detector": detector[:128],
                "entity_type": entity_type[:128],
                "confidence": max(0.0, min(confidence, 1.0)),
            }
        )
    return sanitized


def sanitize_preview_text(text: str, *, max_chars: int = PREVIEW_MAX_TEXT_CHARS) -> str:
    cleaned = " ".join(text.replace("\x00", " ").split())
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 1].rstrip() + "…"


def sanitize_limitations(
    limitations: list[dict[str, Any]] | None,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in limitations or []:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "").strip()
        detail = str(item.get("detail") or "").strip()
        if not code:
            continue
        result.append(
            {
                "code": code[:128],
                "detail": detail[:1000],
            }
        )
    return result


def _bounded_text(value: Any, max_chars: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_chars]


def _bounded_recipients(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    recipients: list[str] = []
    for item in value[:DELIVERY_MAX_RECIPIENTS]:
        text = str(item).strip()
        if text:
            recipients.append(text[:320])
    return recipients


def _payload_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _payload_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def sanitize_delivery_attempts(
    events: list[DlpMessageEvent],
) -> list[dict[str, Any]]:
    """Project stored delivery events into safe per-attempt records.

    Never exposes certificate thumbprints, command linkage, or any
    unbounded payload text.
    """
    attempts: list[dict[str, Any]] = []
    for event in events:
        payload = event.payload if isinstance(event.payload, dict) else {}
        attempts.append(
            {
                "outcome": (
                    _bounded_text(payload.get("outcome"), 32)
                    or "uncertain"
                ),
                "resulting_state": (
                    _bounded_text(payload.get("resulting_state"), 64)
                    or "unknown"
                ),
                "attempt_number": max(
                    _payload_int(payload.get("attempt_number")) or 0, 0
                ),
                "smtp_stage": _bounded_text(
                    payload.get("smtp_stage"), 64
                ),
                "smtp_code": _payload_int(payload.get("smtp_code")),
                "smtp_message": _bounded_text(
                    payload.get("smtp_message"), DELIVERY_MAX_TEXT_CHARS
                ),
                "detail": _bounded_text(
                    payload.get("detail"), DELIVERY_MAX_TEXT_CHARS
                ),
                "remote_host": _bounded_text(
                    payload.get("remote_host"), 255
                ),
                "accepted_recipients": _bounded_recipients(
                    payload.get("accepted_recipients")
                ),
                "refused_recipients": _bounded_recipients(
                    payload.get("refused_recipients")
                ),
                "attempt_started_at": _payload_datetime(
                    payload.get("attempt_started_at")
                ),
                "attempt_finished_at": _payload_datetime(
                    payload.get("attempt_finished_at")
                ),
                "occurred_at": event.occurred_at,
            }
        )
    return attempts
