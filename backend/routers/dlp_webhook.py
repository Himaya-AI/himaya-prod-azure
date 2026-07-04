"""
Himaya DLP Webhook Router
Receives outbound email from M365 transport rules and Gmail content compliance.
NOT enterprise-gated — called by transport layer, not by user UI.

Endpoints:
  POST /api/dlp/webhook/m365   — M365 transport rule (base64 MIME)
  POST /api/dlp/webhook/google — Gmail routing (base64 MIME)

Security: X-DLP-Secret header must match DLP_WEBHOOK_SECRET env var.
"""
from __future__ import annotations

import base64
import email as _email_lib
import json
import logging
import os
from email import policy as _email_policy
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dlp/webhook", tags=["dlp-webhook"])

DLP_WEBHOOK_SECRET = os.getenv("DLP_WEBHOOK_SECRET", "")


# ── Auth helper ───────────────────────────────────────────────────────────────

def _verify_secret(x_dlp_secret: Optional[str]):
    """Raise 401 if the shared secret header doesn't match."""
    if not DLP_WEBHOOK_SECRET:
        # Secret not configured — allow (dev mode, log warning)
        logger.warning("DLP_WEBHOOK_SECRET not set — webhook is unauthenticated!")
        return
    if x_dlp_secret != DLP_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid DLP webhook secret",
        )


# ── MIME parser ───────────────────────────────────────────────────────────────

def _parse_mime(raw_bytes: bytes) -> dict:
    """Parse a MIME email into a dict suitable for classify_email()."""
    try:
        msg = _email_lib.message_from_bytes(raw_bytes, policy=_email_policy.default)
    except Exception as exc:
        logger.warning(f"MIME parse failed: {exc}")
        return {}

    # Extract sender
    sender = msg.get("From", "")
    if "<" in sender and ">" in sender:
        sender = sender.split("<")[1].rstrip(">").strip()

    # Extract recipients (To + CC, not BCC — those are in the raw SMTP envelope)
    recipients = []
    for field in ("To", "Cc", "Bcc"):
        val = msg.get(field, "")
        for addr in val.split(","):
            addr = addr.strip()
            if "<" in addr and ">" in addr:
                addr = addr.split("<")[1].rstrip(">").strip()
            if "@" in addr:
                recipients.append(addr.lower())

    subject = msg.get("Subject", "")

    # Extract body (prefer plain text, fall back to HTML)
    body = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get("Content-Disposition", "")
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    body += part.get_content() or ""
                except Exception:
                    body += part.get_payload(decode=True).decode("utf-8", errors="replace")
            elif ct == "text/html" and not body and "attachment" not in cd:
                try:
                    body = part.get_content() or ""
                except Exception:
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
            elif "attachment" in cd or part.get_filename():
                fname = part.get_filename() or "unnamed"
                attachments.append(fname)
    else:
        try:
            body = msg.get_content() or ""
        except Exception:
            payload = msg.get_payload(decode=True)
            body = payload.decode("utf-8", errors="replace") if payload else ""

    return {
        "sender": sender,
        "recipients": recipients,
        "subject": subject,
        "body": body,
        "attachments": attachments,
    }


# ── Shared classification logic ───────────────────────────────────────────────

async def _run_webhook_classification(
    email_data: dict,
    org_id: str,
    db: AsyncSession,
    provider: str,
) -> dict:
    """Classify email and return verdict. Called by both M365 + Google webhooks."""
    from backend.services.dlp_service import classify_email
    email_data["provider"] = provider
    return await classify_email(email_data, org_id, db)


# ── Request model ─────────────────────────────────────────────────────────────

class WebhookPayload(BaseModel):
    mime_base64: Optional[str] = None   # base64-encoded raw MIME
    org_id: str                         # Himaya org ID (embedded by transport rule)
    # Optional pre-parsed fields (if transport rule extracts them)
    sender: Optional[str] = None
    recipients: Optional[list[str]] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    attachments: Optional[list[str]] = None


# ── M365 webhook ──────────────────────────────────────────────────────────────

@router.post("/m365")
async def webhook_m365(
    payload: WebhookPayload,
    x_dlp_secret: Optional[str] = Header(None, alias="X-DLP-Secret"),
    db: AsyncSession = Depends(get_db),
):
    """
    Receive outbound email from M365 transport rule.
    Transport rule should POST base64 MIME + org_id to this endpoint.

    Returns:
      - 200 OK (ALLOW/WARN)
      - 200 with X-DLP-Warning header (WARN)
      - 550 JSON (HOLD/BLOCK) → transport rule should NDR the sender
    """
    _verify_secret(x_dlp_secret)

    # Parse MIME if provided, else use pre-parsed fields
    if payload.mime_base64:
        try:
            raw = base64.b64decode(payload.mime_base64)
            email_data = _parse_mime(raw)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"MIME decode failed: {exc}")
    else:
        email_data = {
            "sender": payload.sender or "",
            "recipients": payload.recipients or [],
            "subject": payload.subject or "",
            "body": payload.body or "",
            "attachments": payload.attachments or [],
        }

    if not email_data.get("sender") and not email_data.get("body"):
        raise HTTPException(status_code=422, detail="Could not extract email content from MIME")

    verdict = await _run_webhook_classification(email_data, payload.org_id, db, "m365")
    action = verdict.get("action", "ALLOW")

    if action in ("HOLD", "BLOCK"):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=550,
            content={
                "error": "DLP_HOLD" if action == "HOLD" else "DLP_BLOCK",
                "message": (
                    "Email held for security review." if action == "HOLD"
                    else "Email blocked: sensitive content detected."
                ),
                "risk_level": verdict.get("risk_level"),
                "categories": verdict.get("categories", []),
                "explanation": verdict.get("explanation", ""),
                "event_id": verdict.get("event_id"),
            },
        )

    from fastapi.responses import JSONResponse
    headers = {}
    if action == "WARN":
        headers["X-DLP-Warning"] = (
            f"Sensitive content detected: {', '.join(verdict.get('categories', []))}"[:200]
        )

    return JSONResponse(
        status_code=200,
        content={"status": "ok", "action": action},
        headers=headers,
    )


# ── Google webhook ────────────────────────────────────────────────────────────

@router.post("/google")
async def webhook_google(
    payload: WebhookPayload,
    x_dlp_secret: Optional[str] = Header(None, alias="X-DLP-Secret"),
    db: AsyncSession = Depends(get_db),
):
    """
    Receive outbound email from Gmail content compliance rule.
    Same logic as M365 — Google Admin Console routes outbound SMTP through here.

    Returns:
      - 200 OK (ALLOW/WARN)
      - 200 with X-DLP-Warning header (WARN)
      - 550 JSON (HOLD/BLOCK)
    """
    _verify_secret(x_dlp_secret)

    if payload.mime_base64:
        try:
            raw = base64.b64decode(payload.mime_base64)
            email_data = _parse_mime(raw)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"MIME decode failed: {exc}")
    else:
        email_data = {
            "sender": payload.sender or "",
            "recipients": payload.recipients or [],
            "subject": payload.subject or "",
            "body": payload.body or "",
            "attachments": payload.attachments or [],
        }

    verdict = await _run_webhook_classification(email_data, payload.org_id, db, "google")
    action = verdict.get("action", "ALLOW")

    from fastapi.responses import JSONResponse

    if action in ("HOLD", "BLOCK"):
        return JSONResponse(
            status_code=550,
            content={
                "error": "DLP_HOLD" if action == "HOLD" else "DLP_BLOCK",
                "message": (
                    "Email held for security review." if action == "HOLD"
                    else "Email blocked: sensitive content detected."
                ),
                "risk_level": verdict.get("risk_level"),
                "categories": verdict.get("categories", []),
                "explanation": verdict.get("explanation", ""),
                "event_id": verdict.get("event_id"),
            },
        )

    headers = {}
    if action == "WARN":
        headers["X-DLP-Warning"] = (
            f"Sensitive content detected: {', '.join(verdict.get('categories', []))}"[:200]
        )

    return JSONResponse(
        status_code=200,
        content={"status": "ok", "action": action},
        headers=headers,
    )
