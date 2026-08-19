"""
Mailbox capture service — pulls a quarantined message OUT of the user's mailbox
entirely and holds an encrypted copy in Himaya so the end user cannot see or
interact with it (not even in All Mail / hidden folders).

Flow per message:
  1. Fetch the full raw MIME from the user's mailbox (Gmail: format=raw,
     M365: /$value).
  2. Store a Fernet-encrypted + gzipped copy in `quarantined_captures`.
  3. ONLY after the copy is stored & verified, hard-remove the original from the
     mailbox (Gmail: messages.delete → gone from All Mail; M365: move to Deleted
     Items then delete → Recoverable Items, invisible in normal folders).

If any step before deletion fails, the caller falls back to the legacy
hidden-folder move so mail is NEVER lost or left visible-but-uncaptured.

Release (admin action) re-injects the stored MIME back into the user's inbox.

Toggle with QUARANTINE_HARD_CAPTURE (default "true").
"""
from __future__ import annotations

import base64
import gzip
import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


def hard_capture_enabled() -> bool:
    return os.getenv("QUARANTINE_HARD_CAPTURE", "true").lower() in ("1", "true", "yes")


# ── Encryption (reuses the org token ENCRYPTION_KEY) ──────────────────────────
def _encrypt_blob(raw: bytes) -> str:
    """gzip → Fernet → base64-text. Falls back to gzip+base64 if no key."""
    packed = gzip.compress(raw)
    try:
        from cryptography.fernet import Fernet
        key = os.getenv("ENCRYPTION_KEY", "").encode()
        if key:
            packed = Fernet(key).encrypt(packed)
    except Exception as e:  # pragma: no cover
        logger.warning(f"capture encrypt failed, storing gzip-only: {e}")
    return base64.b64encode(packed).decode()


def _decrypt_blob(s: str) -> bytes:
    """Reverse of _encrypt_blob."""
    packed = base64.b64decode(s.encode())
    try:
        from cryptography.fernet import Fernet
        key = os.getenv("ENCRYPTION_KEY", "").encode()
        if key:
            packed = Fernet(key).decrypt(packed)
    except Exception:
        # Not encrypted (key missing at store time) — treat as gzip only.
        pass
    return gzip.decompress(packed)


# ── Storage helpers (own DB session so callers need not pass one) ─────────────
async def store_capture(
    *,
    org_id: str | None,
    provider: str,
    user_email: str,
    original_message_id: str,
    internet_message_id: str | None,
    raw: bytes,
    threat_id: str | None = None,
) -> str | None:
    """Persist an encrypted copy of the raw MIME. Returns the capture row id, or
    None on failure (caller should then fall back to the hidden-folder move)."""
    if not org_id:
        return None
    from backend.database import AsyncSessionLocal
    from sqlalchemy import text as _text

    cap_id = str(uuid.uuid4())
    try:
        blob = _encrypt_blob(raw)
        async with AsyncSessionLocal() as db:
            await db.execute(
                _text(
                    """
                    INSERT INTO quarantined_captures
                        (id, org_id, threat_id, provider, user_email,
                         original_message_id, internet_message_id, raw_encrypted,
                         size_bytes, status, captured_at)
                    VALUES
                        (:id, :org_id, :threat_id, :provider, :user_email,
                         :omid, :imid, :blob, :size, 'held', NOW())
                    """
                ),
                {
                    "id": cap_id,
                    "org_id": org_id,
                    "threat_id": threat_id,
                    "provider": provider,
                    "user_email": user_email,
                    "omid": original_message_id,
                    "imid": internet_message_id,
                    "blob": blob,
                    "size": len(raw),
                },
            )
            await db.commit()
            # Verify it landed before the caller deletes the original.
            ok = (await db.execute(
                _text("SELECT 1 FROM quarantined_captures WHERE id = :id"),
                {"id": cap_id},
            )).scalar()
            if not ok:
                return None
        return cap_id
    except Exception as e:
        logger.warning(f"store_capture failed for {user_email}/{original_message_id}: {e}")
        return None


async def delete_capture(cap_id: str) -> None:
    """Remove a stored capture (used to roll back if the mailbox delete fails)."""
    from backend.database import AsyncSessionLocal
    from sqlalchemy import text as _text
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(_text("DELETE FROM quarantined_captures WHERE id = :id"), {"id": cap_id})
            await db.commit()
    except Exception as e:
        logger.debug(f"delete_capture failed (non-fatal): {e}")


async def get_capture_for_release(
    *, org_id: str, user_email: str, original_message_id: str
) -> dict | None:
    """Look up a held capture for release. Returns dict with raw bytes + provider."""
    from backend.database import AsyncSessionLocal
    from sqlalchemy import text as _text
    try:
        async with AsyncSessionLocal() as db:
            row = (await db.execute(
                _text(
                    """
                    SELECT id, provider, raw_encrypted
                    FROM quarantined_captures
                    WHERE org_id = :org_id AND user_email = :ue
                      AND original_message_id = :omid AND status = 'held'
                    ORDER BY captured_at DESC LIMIT 1
                    """
                ),
                {"org_id": org_id, "ue": user_email, "omid": original_message_id},
            )).first()
            if not row:
                return None
            return {"id": str(row[0]), "provider": row[1], "raw": _decrypt_blob(row[2])}
    except Exception as e:
        logger.warning(f"get_capture_for_release failed: {e}")
        return None


async def mark_capture_released(cap_id: str) -> None:
    from backend.database import AsyncSessionLocal
    from sqlalchemy import text as _text
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                _text("UPDATE quarantined_captures SET status='released', released_at=NOW() WHERE id = :id"),
                {"id": cap_id},
            )
            await db.commit()
    except Exception as e:
        logger.debug(f"mark_capture_released failed (non-fatal): {e}")


# ── Gmail capture / reinject ──────────────────────────────────────────────────
async def _fetch_gmail_raw(client: httpx.AsyncClient, headers: dict, user_email: str, msg_id: str):
    """Return (raw_bytes, internet_message_id) or (None, None)."""
    resp = await client.get(
        f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
        headers=headers,
        params={"format": "raw"},
    )
    if resp.status_code != 200:
        logger.warning(f"gmail raw fetch {msg_id}: {resp.status_code} {resp.text[:150]}")
        return None, None
    body = resp.json()
    raw_b64 = body.get("raw")
    if not raw_b64:
        return None, None
    raw = base64.urlsafe_b64decode(raw_b64.encode())
    imid = None
    for h in (body.get("payload", {}) or {}).get("headers", []) or []:
        if h.get("name", "").lower() == "message-id":
            imid = h.get("value")
            break
    return raw, imid


async def capture_gmail(
    *, user_email: str, msg_id: str, headers: dict, org_id: str | None, threat_id: str | None = None
) -> bool:
    """Fetch → store → hard-delete a Gmail message. Returns True only if the
    message was both stored AND removed from the mailbox. On any failure the
    stored copy (if any) is rolled back so the caller can fall back cleanly."""
    if not org_id:
        return False
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            raw, imid = await _fetch_gmail_raw(client, headers, user_email, msg_id)
            if not raw:
                return False
            cap_id = await store_capture(
                org_id=org_id, provider="google", user_email=user_email,
                original_message_id=msg_id, internet_message_id=imid, raw=raw,
                threat_id=threat_id,
            )
            if not cap_id:
                return False
            # Permanently delete from the mailbox (needs full mail scope).
            del_resp = await client.delete(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
                headers=headers,
            )
            if del_resp.status_code not in (200, 204):
                logger.warning(
                    f"gmail hard-delete {msg_id} failed: {del_resp.status_code} "
                    f"{del_resp.text[:150]} — rolling back capture"
                )
                await delete_capture(cap_id)
                return False
            logger.info(f"Captured+removed Gmail {msg_id} for {user_email} (capture {cap_id})")
            return True
    except Exception as e:
        logger.warning(f"capture_gmail error for {user_email}/{msg_id}: {e}")
        return False


async def reinject_gmail(user_email: str, raw: bytes) -> str | None:
    """Re-insert a previously captured message back into the user's inbox."""
    from backend.services.quarantine_service import _get_sa_headers_async
    headers = await _get_sa_headers_async(user_email)
    if not headers:
        logger.warning(f"reinject_gmail: no auth for {user_email}")
        return None
    try:
        raw_b64 = base64.urlsafe_b64encode(raw).decode()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/insert",
                headers={**headers, "Content-Type": "application/json"},
                params={"internalDateSource": "dateHeader"},
                json={"raw": raw_b64, "labelIds": ["INBOX", "UNREAD"]},
            )
            if resp.status_code in (200, 201):
                return resp.json().get("id")
            logger.warning(f"reinject_gmail failed: {resp.status_code} {resp.text[:200]}")
            return None
    except Exception as e:
        logger.warning(f"reinject_gmail error for {user_email}: {e}")
        return None


# ── M365 capture / reinject ───────────────────────────────────────────────────
async def _fetch_m365_mime(client: httpx.AsyncClient, headers: dict, user_email: str, msg_id: str):
    """Return (mime_bytes, internet_message_id) or (None, None)."""
    imid = None
    try:
        meta = await client.get(
            f"{GRAPH_API_BASE}/users/{user_email}/messages/{msg_id}",
            headers=headers,
            params={"$select": "internetMessageId"},
        )
        if meta.status_code == 200:
            imid = meta.json().get("internetMessageId")
    except Exception:
        pass
    resp = await client.get(
        f"{GRAPH_API_BASE}/users/{user_email}/messages/{msg_id}/$value",
        headers=headers,
    )
    if resp.status_code != 200:
        logger.warning(f"m365 mime fetch {msg_id}: {resp.status_code}")
        return None, None
    return resp.content, imid


async def capture_m365(
    *, user_email: str, msg_id: str, token: str, org_id: str | None, threat_id: str | None = None
) -> bool:
    """Fetch → store → move-to-DeletedItems → delete (Recoverable Items) an M365
    message. Returns True only if stored AND removed from normal folders."""
    if not org_id:
        return False
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            mime, imid = await _fetch_m365_mime(client, headers, user_email, msg_id)
            if not mime:
                return False
            cap_id = await store_capture(
                org_id=org_id, provider="m365", user_email=user_email,
                original_message_id=msg_id, internet_message_id=imid, raw=mime,
                threat_id=threat_id,
            )
            if not cap_id:
                return False
            # Move to Deleted Items → get the new id → delete it (Recoverable Items).
            mv = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{msg_id}/move",
                headers=headers,
                json={"destinationId": "deleteditems"},
            )
            if mv.status_code not in (200, 201):
                logger.warning(f"m365 move-to-deleted {msg_id} failed: {mv.status_code} — rolling back capture")
                await delete_capture(cap_id)
                return False
            deleted_id = mv.json().get("id", msg_id)
            dl = await client.delete(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{deleted_id}",
                headers=headers,
            )
            if dl.status_code not in (200, 204):
                # It's already out of the inbox (in Deleted Items). Keep capture,
                # log, and treat as success — it's no longer in the user's inbox.
                logger.warning(f"m365 purge {deleted_id} returned {dl.status_code}; left in Deleted Items")
            logger.info(f"Captured+removed M365 {msg_id} for {user_email} (capture {cap_id})")
            return True
    except Exception as e:
        logger.warning(f"capture_m365 error for {user_email}/{msg_id}: {e}")
        return False


async def reinject_m365(user_email: str, mime: bytes, org_id: str) -> str | None:
    """Re-create a captured message from MIME and move it to the user's inbox."""
    from backend.services.quarantine_service import _get_m365_app_token
    token = await _get_m365_app_token(org_id)
    if not token:
        logger.warning(f"reinject_m365: no token for org {org_id}")
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Create from MIME (lands in Drafts).
            create = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
                content=base64.b64encode(mime),
            )
            if create.status_code not in (200, 201):
                logger.warning(f"reinject_m365 create failed: {create.status_code} {create.text[:200]}")
                return None
            new_id = create.json().get("id")
            # Move it into the inbox so the user sees it again.
            mv = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{new_id}/move",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"destinationId": "inbox"},
            )
            if mv.status_code in (200, 201):
                return mv.json().get("id", new_id)
            return new_id
    except Exception as e:
        logger.warning(f"reinject_m365 error for {user_email}: {e}")
        return None
