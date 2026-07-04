"""Attachment SHA-256 helpers for inbound email sync (Gmail + M365)."""
from __future__ import annotations

import base64
import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

MAX_ATTACHMENT_HASH_COUNT = 5
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def gmail_urlsafe_b64_to_std(raw_b64: str) -> str:
    std_b64 = raw_b64.replace("-", "+").replace("_", "/")
    padding = 4 - len(std_b64) % 4
    if padding != 4:
        std_b64 += "=" * padding
    return std_b64


def attachment_size_too_large(size: int | None) -> bool:
    if not size or size <= 0:
        return False
    return size > MAX_ATTACHMENT_BYTES


def public_attachment_dict(
    filename: str,
    *,
    mime_type: str = "",
    size: int = 0,
    sha256: str | None = None,
) -> dict:
    out = {
        "filename": filename,
        "mimeType": mime_type,
        "size": size,
    }
    if sha256:
        out["sha256"] = sha256
    return out


async def enrich_gmail_attachments_with_sha256(
    client: httpx.AsyncClient,
    user_email: str,
    msg_id: str,
    attachments: list[dict],
    headers: dict,
) -> list[dict]:
    """Download attachment bytes (when needed) and attach sha256 for file TI."""
    enriched: list[dict] = []
    for index, att in enumerate(attachments):
        filename = att.get("filename", "")
        if not filename:
            continue
        mime_type = att.get("mimeType", att.get("content_type", ""))
        size = att.get("size", 0) or 0
        digest: str | None = None

        if index < MAX_ATTACHMENT_HASH_COUNT and not attachment_size_too_large(size):
            raw_bytes: bytes | None = None
            inline_data = att.get("inline_data")
            attachment_id = att.get("attachment_id")
            try:
                if inline_data:
                    raw_bytes = base64.b64decode(gmail_urlsafe_b64_to_std(inline_data))
                elif attachment_id:
                    att_resp = await client.get(
                        f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}/attachments/{attachment_id}",
                        headers=headers,
                        timeout=15.0,
                    )
                    if att_resp.status_code == 200:
                        raw_b64 = att_resp.json().get("data", "")
                        if raw_b64:
                            raw_bytes = base64.b64decode(gmail_urlsafe_b64_to_std(raw_b64))
            except Exception as att_err:
                logger.debug(f"Gmail attachment hash failed for '{filename}': {att_err}")

            if raw_bytes is not None and len(raw_bytes) <= MAX_ATTACHMENT_BYTES:
                digest = sha256_hex(raw_bytes)
                if not size:
                    size = len(raw_bytes)

        enriched.append(
            public_attachment_dict(
                filename,
                mime_type=mime_type,
                size=size,
                sha256=digest,
            )
        )
    return enriched


async def fetch_m365_inbound_attachments(
    client: httpx.AsyncClient,
    user_email: str,
    message_id: str,
    access_token: str,
) -> list[dict]:
    """List all attachment names; hash up to MAX_ATTACHMENT_HASH_COUNT file attachments."""
    attachments: list[dict] = []
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        att_resp = await client.get(
            f"{GRAPH_API_BASE}/users/{user_email}/messages/{message_id}/attachments",
            headers=headers,
            params={"$select": "id,name,contentType,size,@odata.type"},
            timeout=15.0,
        )
        if att_resp.status_code != 200:
            return attachments

        value = att_resp.json().get("value", [])
        hashed_count = 0
        for a in value:
            name = a.get("name", "")
            if not name:
                continue
            mime_type = a.get("contentType", "")
            size = a.get("size", 0) or 0
            digest: str | None = None
            att_id = a.get("id")
            odata_type = a.get("@odata.type", "")
            is_file_attachment = not odata_type or "fileAttachment" in odata_type

            if (
                hashed_count < MAX_ATTACHMENT_HASH_COUNT
                and att_id
                and is_file_attachment
                and not attachment_size_too_large(size)
            ):
                try:
                    content_resp = await client.get(
                        f"{GRAPH_API_BASE}/users/{user_email}/messages/{message_id}/attachments/{att_id}",
                        headers=headers,
                        params={"$select": "contentBytes"},
                        timeout=15.0,
                    )
                    if content_resp.status_code == 200:
                        content_b64 = content_resp.json().get("contentBytes")
                        if content_b64:
                            raw_bytes = base64.b64decode(content_b64)
                            if len(raw_bytes) <= MAX_ATTACHMENT_BYTES:
                                digest = sha256_hex(raw_bytes)
                                hashed_count += 1
                except Exception as att_err:
                    logger.debug(f"M365 attachment hash failed for '{name}': {att_err}")

            attachments.append(
                public_attachment_dict(
                    name,
                    mime_type=mime_type,
                    size=size,
                    sha256=digest,
                )
            )
    except Exception as exc:
        logger.debug(f"M365 inbound attachment fetch failed for {message_id}: {exc}")
    return attachments
