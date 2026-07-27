"""Pure helpers for DLP message list/detail presentation."""

from __future__ import annotations

from typing import Any

from backend.dlp.persistence.models import DlpDecision, DlpMessage

REVIEWABLE_STATES = frozenset({"decided", "held"})
PREVIEW_MAX_MIME_BYTES = 2 * 1024 * 1024
PREVIEW_MAX_TEXT_CHARS = 4000


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
