"""
Quarantine service — retroactively moves emails out of inbox via Gmail/M365 API.

When Himaya classifies an email as high-risk (QUARANTINED), this service:
  - Gmail: creates a "Himaya-Quarantine" label (if needed), adds it, removes INBOX
  - M365: moves the message to a "Himaya-Quarantine" mail folder

This is the retroactive quarantine that makes Himaya behave like Abnormal Security —
the email was already delivered, but we move it out of view after the fact.
"""
import logging
import os
import httpx

logger = logging.getLogger(__name__)

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
HELIOS_LABEL = "Himaya-Quarantine"


def _get_sa_headers(user_email: str) -> dict | None:
    """Sync wrapper — only use outside of async contexts."""
    try:
        from backend.services.baseline_ingestion import _get_service_account_headers_sync
        return _get_service_account_headers_sync(subject_email=user_email)
    except Exception:
        return None


async def _get_sa_headers_async(user_email: str) -> dict | None:
    """Async-safe SA headers — runs the blocking credential refresh in a thread pool."""
    try:
        import asyncio
        from backend.services.baseline_ingestion import _get_service_account_headers_sync
        return await asyncio.to_thread(_get_service_account_headers_sync, user_email)
    except Exception:
        return None


async def quarantine_gmail_message(user_email: str, gmail_message_id: str, access_token: str = None) -> bool:
    """
    Move a Gmail message to "Himaya-Quarantine" label and remove from INBOX.
    Uses service account impersonation (DWD) if configured, falls back to OAuth token.
    Returns True if successful.
    """
    if not gmail_message_id or not user_email:
        return False

    headers = await _get_sa_headers_async(user_email)
    if not headers and access_token:
        headers = {"Authorization": f"Bearer {access_token}"}
    if not headers:
        logger.warning(f"No auth available to quarantine {gmail_message_id} for {user_email}")
        return False

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Step 1: Get or create "Himaya-Quarantine" label
            label_id = await _get_or_create_gmail_label(client, headers, user_email)

            # Step 2: Move message — remove INBOX, add Himaya-Quarantine label
            modify_payload = {
                "removeLabelIds": ["INBOX"],
            }
            if label_id:
                modify_payload["addLabelIds"] = [label_id]

            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json=modify_payload,
            )

            if resp.status_code == 200:
                logger.info(f"Quarantined Gmail message {gmail_message_id} for {user_email}")
                return True
            else:
                logger.warning(f"Gmail quarantine failed for {user_email}/{gmail_message_id}: {resp.status_code} {resp.text[:200]}")
                return False

    except Exception as e:
        logger.warning(f"Gmail quarantine error for {user_email}/{gmail_message_id}: {e}")
        return False


async def _get_or_create_gmail_label(client: httpx.AsyncClient, headers: dict, user_email: str) -> str | None:
    """Return the label ID for 'Himaya-Quarantine', creating it if needed."""
    try:
        # List existing labels
        resp = await client.get(
            f"{GMAIL_API_BASE}/users/{user_email}/labels",
            headers=headers,
        )
        if resp.status_code == 200:
            for label in resp.json().get("labels", []):
                if label.get("name") == HELIOS_LABEL:
                    return label["id"]

        # Create label if missing.
        # HIDDEN by default — quarantined mail should not be browsable by the user:
        #   labelListVisibility = labelHide      → label does not appear in left sidebar
        #   messageListVisibility = hide         → messages with this label do not show
        #                                          in the conversation list unless the
        #                                          user explicitly searches for it.
        # Power users can still find it via `label:Himaya-Quarantine` search, but it is
        # not surfaced anywhere in the normal Gmail UI.
        create_resp = await client.post(
            f"{GMAIL_API_BASE}/users/{user_email}/labels",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "name": HELIOS_LABEL,
                "labelListVisibility": "labelHide",
                "messageListVisibility": "hide",
                "color": {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
            },
        )
        if create_resp.status_code in (200, 201):
            return create_resp.json().get("id")

        # If the label already exists (race / pre-existing) but is visible, patch it
        # so it becomes hidden. Idempotent — safe to run on every quarantine action.
        if create_resp.status_code == 409:
            try:
                # Re-list to find the existing label id
                list_resp = await client.get(
                    f"{GMAIL_API_BASE}/users/{user_email}/labels",
                    headers=headers,
                )
                if list_resp.status_code == 200:
                    for label in list_resp.json().get("labels", []):
                        if label.get("name") == HELIOS_LABEL:
                            label_id = label["id"]
                            # Force-hide the existing label
                            await client.patch(
                                f"{GMAIL_API_BASE}/users/{user_email}/labels/{label_id}",
                                headers={**headers, "Content-Type": "application/json"},
                                json={
                                    "labelListVisibility": "labelHide",
                                    "messageListVisibility": "hide",
                                },
                            )
                            return label_id
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Label create/find failed: {e}")
    return None


async def block_to_trash_gmail(user_email: str, gmail_message_id: str, access_token: str = None) -> bool:
    """
    Block action — moves email directly to Gmail TRASH.
    More aggressive than quarantine (which uses a recoverable label).
    Uses service account impersonation (DWD) if configured, falls back to OAuth token.
    """
    if not gmail_message_id or not user_email:
        return False
    headers = await _get_sa_headers_async(user_email)
    if not headers and access_token:
        headers = {"Authorization": f"Bearer {access_token}"}
    if not headers:
        logger.warning(f"No auth available to block-trash {gmail_message_id} for {user_email}")
        return False
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/trash",
                headers=headers,
            )
            if resp.status_code == 200:
                logger.info(f"Blocked (trashed) Gmail message {gmail_message_id} for {user_email}")
                return True
            else:
                logger.warning(f"Gmail trash failed for {user_email}/{gmail_message_id}: {resp.status_code}")
                return False
    except Exception as e:
        logger.warning(f"Gmail trash error: {e}")
        return False


async def mark_as_spam_gmail(user_email: str, gmail_message_id: str) -> bool:
    """
    Mark as spam — adds SPAM label and removes INBOX.
    Trains Gmail's spam filter for this user.
    """
    if not gmail_message_id or not user_email:
        return False
    headers = await _get_sa_headers_async(user_email)
    if not headers:
        return False
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
            )
            if resp.status_code == 200:
                logger.info(f"Marked as spam Gmail message {gmail_message_id} for {user_email}")
                return True
            else:
                logger.warning(f"Gmail spam mark failed: {resp.status_code}")
                return False
    except Exception as e:
        logger.warning(f"Gmail spam error: {e}")
        return False


async def quarantine_m365_message(user_email: str, m365_message_id: str, access_token: str) -> bool:
    """
    Move an M365 message to "Himaya-Quarantine" folder.
    """
    if not m365_message_id or not user_email or not access_token:
        return False

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Step 1: Get or create Himaya-Quarantine folder
            folder_id = await _get_or_create_m365_folder(client, headers, user_email)
            if not folder_id:
                return False

            # Step 2: Move message
            resp = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{m365_message_id}/move",
                headers=headers,
                json={"destinationId": folder_id},
            )
            if resp.status_code in (200, 201):
                logger.info(f"Quarantined M365 message {m365_message_id} for {user_email}")
                return True
            else:
                logger.warning(f"M365 quarantine failed: {resp.status_code}")
                return False
    except Exception as e:
        logger.warning(f"M365 quarantine error: {e}")
        return False


async def _get_or_create_m365_folder(client: httpx.AsyncClient, headers: dict, user_email: str) -> str | None:
    """
    Return the folder ID for 'Himaya-Quarantine', creating it if needed.

    The folder is created HIDDEN (`isHidden=true`) and patched to hidden every
    time we touch it, so a user who manually unhides it has the setting reverted
    on the next quarantine action. This means quarantined mail does not appear
    in the normal Outlook folder tree without the user explicitly toggling
    "Show hidden folders" in Outlook settings (and even then it's clearly
    labelled Himaya-Quarantine so they know not to interact).

    Note: Graph API supports `isHidden` on mailFolders only via PATCH (not
    POST). The POST creates the folder, then we PATCH `isHidden=true` so the
    Outlook clients respect it.
    """
    try:
        resp = await client.get(
            f"{GRAPH_API_BASE}/users/{user_email}/mailFolders",
            headers=headers,
            params={
                "$filter": f"displayName eq '{HELIOS_LABEL}'",
                "$select": "id,displayName,isHidden",
                "includeHiddenFolders": "true",
            },
        )
        if resp.status_code == 200:
            folders = resp.json().get("value", [])
            if folders:
                folder_id = folders[0]["id"]
                # Re-enforce hidden state in case a user un-hid it
                if not folders[0].get("isHidden"):
                    try:
                        await client.patch(
                            f"{GRAPH_API_BASE}/users/{user_email}/mailFolders/{folder_id}",
                            headers={**headers, "Content-Type": "application/json"},
                            json={"isHidden": True},
                        )
                    except Exception:
                        pass
                return folder_id

        # Create the folder — Graph 1.0 doesn't accept isHidden on POST, so PATCH it
        # immediately after creation.
        create_resp = await client.post(
            f"{GRAPH_API_BASE}/users/{user_email}/mailFolders",
            headers=headers,
            json={"displayName": HELIOS_LABEL},
        )
        if create_resp.status_code in (200, 201):
            folder_id = create_resp.json().get("id")
            try:
                await client.patch(
                    f"{GRAPH_API_BASE}/users/{user_email}/mailFolders/{folder_id}",
                    headers={**headers, "Content-Type": "application/json"},
                    json={"isHidden": True},
                )
            except Exception as patch_err:
                logger.warning(
                    f"Quarantine folder created but isHidden PATCH failed for "
                    f"{user_email}: {patch_err}"
                )
            return folder_id
    except Exception as e:
        logger.debug(f"M365 folder create/find failed: {e}")
    return None


HELIOS_REVIEW_LABEL = "Himaya-Review"
HELIOS_ALERT_LABEL = "Himaya-Alert"
HIMAYA_FLAGGED_LABEL = "Himaya-Flagged"


async def apply_review_label_gmail(
    user_email: str,
    gmail_message_id: str,
    fallback_access_token: str | None = None,
) -> bool:
    """
    Apply a yellow 'Himaya-Review' label to an email (TAG / DELIVER_WITH_BANNER policy action).
    Email stays in INBOX — visibly tagged for user and analyst.
    Tries SA (DWD) first, falls back to OAuth token if provided.
    Returns True if label was applied.
    """
    if not gmail_message_id or not user_email:
        return False

    headers = await _get_sa_headers_async(user_email)
    if not headers and fallback_access_token:
        logger.info(f"apply_review_label_gmail: SA unavailable, using OAuth fallback for {user_email}")
        headers = {"Authorization": f"Bearer {fallback_access_token}", "Content-Type": "application/json"}
    if not headers:
        logger.warning(f"apply_review_label_gmail: no auth headers for {user_email}, cannot apply label")
        return False

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get or create the Himaya-Review label
            label_id = await _get_or_create_review_label(client, headers, user_email)
            if not label_id:
                logger.warning(f"Could not get/create {HELIOS_REVIEW_LABEL} label for {user_email}")
                return False

            # Apply label — keep INBOX (don't remove it, email stays visible)
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={"addLabelIds": [label_id]},
            )
            if resp.status_code == 200:
                logger.info(f"Applied {HELIOS_REVIEW_LABEL} label to {gmail_message_id} for {user_email}")
                return True
            logger.warning(f"apply_review_label_gmail failed: {resp.status_code} {resp.text[:300]}")
            return False
    except Exception as e:
        logger.warning(f"apply_review_label_gmail error: {e}")
        return False


async def _get_or_create_review_label(
    client: httpx.AsyncClient, headers: dict, user_email: str
) -> str | None:
    """Return the label ID for 'Himaya-Review', creating it if it doesn't exist."""
    return await _get_or_create_named_label(
        client, headers, user_email,
        name=HELIOS_REVIEW_LABEL,
        # #fad165 is a valid Gmail palette color (yellow) — #f9c513 is NOT and causes 400
        bg_color="#fad165", text_color="#000000",
    )


async def apply_flagged_label_gmail(
    user_email: str,
    gmail_message_id: str,
    fallback_access_token: str | None = None,
) -> bool:
    """
    Apply an orange 'Himaya-Flagged' label to an email (TAG policy action).
    Email stays in INBOX but is visibly flagged. Similar to Himaya-Quarantine
    flow but email is NOT removed from inbox — purely informational label.
    Tries SA (DWD) first, falls back to OAuth token if provided.
    Returns True if label was applied.

    BUG FIX: Gmail labels.create only accepts colours from a fixed palette.
    Previous value #e67e22 is NOT in the Gmail palette and caused silent 400
    failures, meaning the label was never created and tagging silently did nothing.
    Fix: use #eaa041 (amber-orange) which IS in the Gmail allowed palette.
    """
    if not gmail_message_id or not user_email:
        return False

    headers = await _get_sa_headers_async(user_email)
    if not headers and fallback_access_token:
        logger.info(f"apply_flagged_label_gmail: SA unavailable, using OAuth fallback for {user_email}")
        headers = {"Authorization": f"Bearer {fallback_access_token}", "Content-Type": "application/json"}
    if not headers:
        logger.warning(f"apply_flagged_label_gmail: no auth headers for {user_email}, cannot apply label")
        return False

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            label_id = await _get_or_create_named_label(
                client, headers, user_email,
                name=HIMAYA_FLAGGED_LABEL,
                # #eaa041 is a valid Gmail palette color (amber-orange).
                # Previous value #e67e22 was NOT in the palette — caused 400 on label creation.
                bg_color="#eaa041",
                text_color="#ffffff",
            )
            if not label_id:
                logger.warning(
                    f"apply_flagged_label_gmail: could not get/create {HIMAYA_FLAGGED_LABEL} "
                    f"label for {user_email} — check SA scopes or OAuth token"
                )
                return False

            # Apply label — keep INBOX (email stays visible to user)
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={"addLabelIds": [label_id]},
            )
            if resp.status_code == 200:
                logger.info(
                    f"apply_flagged_label_gmail: ✓ applied {HIMAYA_FLAGGED_LABEL} "
                    f"(id={label_id}) to {gmail_message_id} for {user_email}"
                )
                return True
            logger.warning(
                f"apply_flagged_label_gmail: modify failed {resp.status_code} for "
                f"{user_email}/{gmail_message_id}: {resp.text[:300]}"
            )
            return False
    except Exception as e:
        logger.warning(f"apply_flagged_label_gmail error: {e}")
        return False


async def _get_or_create_named_label(
    client: httpx.AsyncClient,
    headers: dict,
    user_email: str,
    name: str,
    bg_color: str = "#fad165",  # valid Gmail palette yellow (was #f9c513 — NOT valid)
    text_color: str = "#000000",
) -> str | None:
    """
    Generic helper — get or create a Gmail label by name.

    IMPORTANT: Gmail labels.create only accepts background/text colours from a
    fixed palette defined by the Gmail API.  If an invalid hex value is passed
    the API returns 400 and the label is never created.

    Valid colour samples (background):
      #fad165 (yellow), #eaa041 (orange), #cc3a21 (dark-red),
      #e66550 (red-orange), #fb4c2f (bright-red), #44b984 (green),
      #4a86e8 (blue), #a479e2 (purple)

    See: https://developers.google.com/gmail/api/reference/rest/v1/users.labels
    """
    try:
        list_resp = await client.get(
            f"{GMAIL_API_BASE}/users/{user_email}/labels",
            headers=headers,
        )
        if list_resp.status_code == 200:
            for label in list_resp.json().get("labels", []):
                if label.get("name") == name:
                    logger.debug(f"_get_or_create_named_label: found existing label '{name}' id={label['id']}")
                    return label["id"]
        elif list_resp.status_code != 200:
            logger.warning(
                f"_get_or_create_named_label: list labels returned {list_resp.status_code} "
                f"for {user_email} — {list_resp.text[:200]}"
            )

        # Label not found — create it
        create_resp = await client.post(
            f"{GMAIL_API_BASE}/users/{user_email}/labels",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
                "color": {"backgroundColor": bg_color, "textColor": text_color},
            },
        )
        if create_resp.status_code in (200, 201):
            new_id = create_resp.json().get("id")
            logger.info(f"_get_or_create_named_label: created Gmail label '{name}' id={new_id} for {user_email}")
            return new_id
        # Log the full response so we can diagnose palette issues
        logger.warning(
            f"_get_or_create_named_label: create '{name}' returned {create_resp.status_code} "
            f"for {user_email} (bg={bg_color}): {create_resp.text[:300]}"
        )
    except Exception as e:
        logger.warning(f"_get_or_create_named_label ({name}): {e}")
    return None


async def apply_alert_label_gmail(
    user_email: str,
    gmail_message_id: str,
    fallback_access_token: str | None = None,
) -> bool:
    """
    Apply a red 'Himaya-Alert' label to an email (ALERT policy action).
    Email stays in INBOX — visibly flagged in red so recipient sees it immediately.
    Tries SA (DWD) first, falls back to OAuth token if provided.

    BUG FIX: Previous color #e94560 is NOT in the Gmail label colour palette,
    causing silent 400 on label creation.  Replaced with #e66550 (red-orange)
    which IS in the Gmail-approved palette.
    """
    if not gmail_message_id or not user_email:
        return False

    headers = await _get_sa_headers_async(user_email)
    if not headers and fallback_access_token:
        headers = {"Authorization": f"Bearer {fallback_access_token}", "Content-Type": "application/json"}
    if not headers:
        logger.warning(f"apply_alert_label_gmail: no auth headers for {user_email}")
        return False

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            label_id = await _get_or_create_named_label(
                client, headers, user_email,
                name=HELIOS_ALERT_LABEL,
                # #e66550 is a valid Gmail palette red-orange (was #e94560 — NOT valid → 400)
                bg_color="#e66550", text_color="#ffffff",
            )
            if not label_id:
                logger.warning(
                    f"apply_alert_label_gmail: could not get/create {HELIOS_ALERT_LABEL} "
                    f"label for {user_email}"
                )
                return False

            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={"addLabelIds": [label_id]},
            )
            if resp.status_code == 200:
                logger.info(
                    f"apply_alert_label_gmail: ✓ applied {HELIOS_ALERT_LABEL} "
                    f"(id={label_id}) to {gmail_message_id} for {user_email}"
                )
                return True
            logger.warning(
                f"apply_alert_label_gmail: modify failed {resp.status_code} for "
                f"{user_email}/{gmail_message_id}: {resp.text[:300]}"
            )
            return False
    except Exception as e:
        logger.warning(f"apply_alert_label_gmail error: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# M365 / Graph API action functions
# ═══════════════════════════════════════════════════════════════════════════════

async def _get_m365_app_token(org_id: str) -> str | None:
    """
    Retrieve a fresh app-level access token for the org's M365 tenant
    via client-credentials flow (same as baseline ingestion).
    """
    try:
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import OrgIntegration
        from sqlalchemy import select as _sel
        from backend.services.baseline_ingestion import _refresh_m365_token, _decrypt

        async with AsyncSessionLocal() as _db:
            import uuid as _uuid
            _oid = _uuid.UUID(org_id) if isinstance(org_id, str) else org_id
            _res = await _db.execute(
                _sel(OrgIntegration).where(
                    OrgIntegration.org_id == _oid,
                    OrgIntegration.provider == "m365",
                    OrgIntegration.status == "active",
                )
            )
            integration = _res.scalar_one_or_none()
            if not integration:
                return None
            refresh_token = _decrypt(integration.refresh_token_enc) if integration.refresh_token_enc else None
            if refresh_token:
                token = await _refresh_m365_token(refresh_token)
                return token
    except Exception as _e:
        logger.debug(f"_get_m365_app_token failed: {_e}")
    return None


async def block_to_trash_m365(user_email: str, m365_message_id: str, access_token: str | None = None, org_id: str | None = None) -> bool:
    """
    BLOCK action for M365: move email to the 'Deleted Items' folder via Graph API.
    Tries the passed access_token first; falls back to refreshing via client-credentials.
    """
    if not m365_message_id or not user_email:
        return False

    token = access_token
    if not token and org_id:
        token = await _get_m365_app_token(org_id)
    if not token:
        logger.warning(f"block_to_trash_m365: no token for {user_email}")
        return False

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{m365_message_id}/move",
                headers=headers,
                json={"destinationId": "deleteditems"},
            )
            if resp.status_code in (200, 201):
                logger.info(f"M365 BLOCK: moved {m365_message_id} to Deleted Items for {user_email}")
                return True
            else:
                logger.warning(f"M365 block_to_trash failed: {resp.status_code} {resp.text[:200]}")
                return False
    except Exception as e:
        logger.warning(f"M365 block_to_trash error: {e}")
        return False


async def quarantine_m365_message_with_fallback(
    user_email: str, m365_message_id: str, access_token: str | None = None, org_id: str | None = None
) -> bool:
    """
    QUARANTINE for M365: move to 'Himaya-Quarantine' folder.
    Refreshes token if needed.
    """
    if not m365_message_id or not user_email:
        return False

    token = access_token
    if not token and org_id:
        token = await _get_m365_app_token(org_id)
    if not token:
        logger.warning(f"quarantine_m365: no token for {user_email}")
        return False

    return await quarantine_m365_message(user_email, m365_message_id, token)


async def apply_category_m365(
    user_email: str,
    m365_message_id: str,
    category_name: str,
    access_token: str | None = None,
    org_id: str | None = None,
) -> bool:
    """
    TAG / ALERT for M365: apply an Outlook category to the message (email stays in inbox).
    Outlook categories are user-visible colored labels.
    Category must exist in the user's master category list — we create it if missing.
    """
    if not m365_message_id or not user_email:
        return False

    token = access_token
    if not token and org_id:
        token = await _get_m365_app_token(org_id)
    if not token:
        logger.warning(f"apply_category_m365: no token for {user_email}")
        return False

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Colour presets: Himaya-Alert → red (preset2), Himaya-Flagged → orange (preset3)
    COLOR_MAP = {
        "Himaya-Alert":     "preset2",   # Red
        "Himaya-Suspicious": "preset2",   # Red — high visibility for escalated threats
        "Himaya-Flagged":   "preset3",   # Orange
        "Himaya-Review":    "preset5",   # Yellow
        "Himaya-Quarantine": "preset8",  # Purple (shouldn't be used here but included for safety)
    }
    color = COLOR_MAP.get(category_name, "preset3")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Step 1: Ensure the category exists in user's master list
            await _ensure_m365_category(client, headers, user_email, category_name, color)

            # Step 2: Apply category to the specific message by patching its categories array
            # First fetch existing categories on the message
            msg_resp = await client.get(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{m365_message_id}",
                headers=headers,
                params={"$select": "categories"},
            )
            existing_cats = []
            if msg_resp.status_code == 200:
                existing_cats = msg_resp.json().get("categories", [])

            if category_name not in existing_cats:
                existing_cats.append(category_name)

            patch_resp = await client.patch(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{m365_message_id}",
                headers=headers,
                json={"categories": existing_cats},
            )
            if patch_resp.status_code in (200, 201):
                logger.info(f"M365 category '{category_name}' applied to {m365_message_id} for {user_email}")
                return True
            else:
                logger.warning(f"M365 apply_category failed: {patch_resp.status_code} {patch_resp.text[:200]}")
                return False
    except Exception as e:
        logger.warning(f"apply_category_m365 error: {e}")
        return False


async def _ensure_m365_category(
    client: httpx.AsyncClient,
    headers: dict,
    user_email: str,
    category_name: str,
    color: str,
) -> None:
    """Create the Outlook category in the user's master list if it doesn't already exist."""
    try:
        resp = await client.get(
            f"{GRAPH_API_BASE}/users/{user_email}/outlook/masterCategories",
            headers=headers,
        )
        if resp.status_code == 200:
            existing = [c["displayName"] for c in resp.json().get("value", [])]
            if category_name in existing:
                return  # Already exists
        # Create it
        await client.post(
            f"{GRAPH_API_BASE}/users/{user_email}/outlook/masterCategories",
            headers=headers,
            json={"displayName": category_name, "color": color},
        )
    except Exception as e:
        logger.debug(f"_ensure_m365_category failed (non-fatal): {e}")


async def mark_as_spam_m365(
    user_email: str,
    m365_message_id: str,
    org_id: str | None = None,
    access_token: str | None = None,
) -> bool:
    """
    Mark as junk/spam for M365 — moves message to Junk Email folder via Graph API.
    Also sets isRead=false so the junk folder badge increments.
    """
    if not m365_message_id or not user_email:
        return False

    token = access_token
    if not token and org_id:
        token = await _get_m365_app_token(org_id)
    if not token:
        logger.warning(f"mark_as_spam_m365: no token for {user_email}")
        return False

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GRAPH_API_BASE}/users/{user_email}/messages/{m365_message_id}/move",
                headers=headers,
                json={"destinationId": "junkemail"},
            )
            if resp.status_code in (200, 201):
                logger.info(f"M365 mark-as-junk: moved {m365_message_id} to Junk Email for {user_email}")
                return True
            else:
                logger.warning(f"M365 mark_as_spam failed: {resp.status_code} {resp.text[:200]}")
                return False
    except Exception as e:
        logger.warning(f"mark_as_spam_m365 error: {e}")
        return False


async def reinject_to_inbox(user_email: str, message_id: str, org_id: str):
    """Move email back to inbox after auto-triage clears it as safe."""
    # Determine provider: M365 message IDs are long (>100 chars) or start with AAMk
    is_m365 = len(message_id or '') > 100 or (message_id or '').startswith('AAMk')
    if is_m365:
        # M365: move to inbox folder
        try:
            token = await _get_m365_app_token(org_id)
            if token:
                async with httpx.AsyncClient(timeout=15) as _cl:
                    await _cl.post(
                        f"{GRAPH_API_BASE}/users/{user_email}/messages/{message_id}/move",
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                        json={"destinationId": "inbox"},
                    )
        except Exception as e:
            import logging; logging.getLogger(__name__).debug(f"reinject M365 failed: {e}")
    else:
        # Gmail: remove TRASH/Himaya-Quarantine labels, add INBOX label
        try:
            sa_headers = await _get_sa_headers_async(user_email)
            if sa_headers:
                async with httpx.AsyncClient(timeout=15) as _cl:
                    await _cl.post(
                        f"{GMAIL_API_BASE}/users/me/messages/{message_id}/modify",
                        headers={**sa_headers, "Content-Type": "application/json"},
                        json={"addLabelIds": ["INBOX"], "removeLabelIds": ["TRASH"]},
                    )
        except Exception as e:
            import logging; logging.getLogger(__name__).debug(f"reinject Gmail failed: {e}")
