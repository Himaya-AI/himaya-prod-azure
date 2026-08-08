"""
Shared attachment retrieval for sandboxing / detonation.

Fetches a threat's original email attachment bytes from the provider
(Gmail API via DWD service-account or OAuth, or Microsoft Graph), stages them
in Azure Blob Storage, and returns short-lived SAS download URLs.

Used by:
  - the interactive sandbox (routers/sandbox.py) to offer downloads to analysts
  - the automated detonator (auto_triage_service.py) to pull bytes into the
    ephemeral ACI analysis container.
"""
import base64 as _b64
import logging
import os

logger = logging.getLogger(__name__)

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024   # 10 MB cap for provider fetch
MAX_ATTACHMENTS = 8


async def fetch_threat_attachments(db, threat) -> list[dict]:
    """
    Return a list of dicts: {name, url (SAS or None), size, too_large}.

    - `url` is a short-lived (30 min) SAS download URL when the bytes were
      retrieved and staged to Blob; None when only metadata is available.
    - Never raises; returns [] on any failure so callers can degrade gracefully.
    """
    if not getattr(threat, "email_message_id", None):
        return []

    try:
        from sqlalchemy import select
        from backend.services.storage_client import storage_client
        from backend.models.db_models import OrgIntegration
        from backend.services.baseline_ingestion import (
            _decrypt as _dec,
            _refresh_m365_token,
            _get_service_account_headers_sync,
        )
        import asyncio
        import httpx
    except Exception as e:
        logger.warning(f"attachment_fetch: imports unavailable: {e}")
        return []

    headers = None
    provider = None

    # 1) Gmail domain-wide-delegation service account
    try:
        sa = await asyncio.to_thread(
            _get_service_account_headers_sync, threat.recipient_email
        )
        if sa:
            headers, provider = sa, "google"
    except Exception:
        pass

    # 2) Fall back to an active org OAuth integration (Google or M365)
    if not headers:
        try:
            res = await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == threat.org_id,
                    OrgIntegration.status == "active",
                )
            )
            for intg in res.scalars().all():
                if intg.provider == "google" and intg.access_token_enc and not headers:
                    try:
                        headers = {"Authorization": f"Bearer {_dec(intg.access_token_enc)}"}
                        provider = "google"
                    except Exception:
                        pass
                elif intg.provider == "m365" and not headers:
                    try:
                        tok = (await _refresh_m365_token(_dec(intg.refresh_token_enc))
                               if intg.refresh_token_enc
                               else (_dec(intg.access_token_enc) if intg.access_token_enc else None))
                        if tok:
                            headers = {"Authorization": f"Bearer {tok}"}
                            provider = "m365"
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"attachment_fetch: integration lookup failed: {e}")

    if not headers:
        logger.info("attachment_fetch: no provider credentials available")
        return []

    container = os.getenv("AZURE_STORAGE_CONTAINER", "himaya-evidence")

    async def _store(name: str, data: bytes) -> str:
        key = f"detonator-attachments/{threat.id}/{name}"
        await storage_client.upload(container=container, key=key, data=data)
        return await storage_client.generate_download_url(
            container, key, expires_seconds=1800, download_filename=name
        )

    out: list[dict] = []
    mid = threat.email_message_id
    try:
        async with httpx.AsyncClient(timeout=30) as hc:
            if provider == "google":
                mr = await hc.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/{threat.recipient_email}/messages/{mid}",
                    headers=headers, params={"format": "full"},
                )
                if mr.status_code == 200:
                    parts = []

                    def _walk(part):
                        fn = part.get("filename", "")
                        body = part.get("body", {})
                        if fn and (body.get("attachmentId") or body.get("data")):
                            parts.append({"name": fn, "aid": body.get("attachmentId"),
                                          "data": body.get("data"), "size": body.get("size", 0)})
                        for sub in part.get("parts", []):
                            _walk(sub)

                    _walk(mr.json().get("payload", {}))
                    for ap in parts[:MAX_ATTACHMENTS]:
                        name = ap["name"]
                        if ap["size"] and ap["size"] > MAX_ATTACHMENT_BYTES:
                            out.append({"name": name, "url": None, "size": ap["size"], "too_large": True})
                            continue
                        data = None
                        if ap.get("aid"):
                            ar = await hc.get(
                                f"https://gmail.googleapis.com/gmail/v1/users/{threat.recipient_email}/messages/{mid}/attachments/{ap['aid']}",
                                headers=headers,
                            )
                            if ar.status_code == 200:
                                d = ar.json().get("data", "")
                                if d:
                                    data = _b64.urlsafe_b64decode(d + "==")
                        elif ap.get("data"):
                            data = _b64.urlsafe_b64decode(ap["data"] + "==")
                        if data:
                            out.append({"name": name, "url": await _store(name, data),
                                        "size": len(data), "too_large": False})
                        else:
                            out.append({"name": name, "url": None, "size": ap["size"], "too_large": False})
            else:
                lr = await hc.get(
                    f"https://graph.microsoft.com/v1.0/users/{threat.recipient_email}/messages/{mid}/attachments",
                    headers=headers, params={"$select": "id,name,contentType,size"},
                )
                if lr.status_code == 200:
                    for att in lr.json().get("value", [])[:MAX_ATTACHMENTS]:
                        name = att.get("name", "attachment")
                        size = att.get("size", 0)
                        if size and size > MAX_ATTACHMENT_BYTES:
                            out.append({"name": name, "url": None, "size": size, "too_large": True})
                            continue
                        ar = await hc.get(
                            f"https://graph.microsoft.com/v1.0/users/{threat.recipient_email}/messages/{mid}/attachments/{att['id']}",
                            headers=headers,
                        )
                        if ar.status_code == 200:
                            cb = ar.json().get("contentBytes", "")
                            if cb:
                                data = _b64.b64decode(cb)
                                out.append({"name": name, "url": await _store(name, data),
                                            "size": len(data), "too_large": False})
    except Exception as e:
        logger.warning(f"attachment_fetch: provider fetch failed (non-fatal): {e}")

    logger.info(f"attachment_fetch: staged {sum(1 for a in out if a.get('url'))}/{len(out)} "
                f"attachments for threat {threat.id} (provider={provider})")
    return out
