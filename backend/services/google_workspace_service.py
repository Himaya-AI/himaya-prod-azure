"""
Google Workspace / Gmail email ingestion service.

Flow:
  1. On org connect: set up Gmail Push Notifications via Google Pub/Sub → SQS bridge
  2. On each push notification: fetch email via Gmail API, enqueue to himaya-email-events SQS
  3. Falls back to polling for orgs without Pub/Sub setup

Scopes required:
  - https://www.googleapis.com/auth/gmail.readonly
  - https://www.googleapis.com/auth/gmail.modify     (for quarantine label)
  - https://www.googleapis.com/auth/admin.directory.user.readonly  (user listing)
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

EMAIL_QUEUE_NAME = os.getenv("EMAIL_QUEUE_NAME", "himaya-email-events")
SQS_EMAIL_QUEUE_URL = os.getenv("AWS_SQS_EMAIL_QUEUE_URL", "")

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
ADMIN_API_BASE = "https://admin.googleapis.com/admin/directory/v1"

# Gmail quarantine label — created during onboarding if absent
HELIOS_QUARANTINE_LABEL = "HELIOS_QUARANTINE"


class GoogleWorkspaceService:
    """
    Handles Gmail API interaction for a single org.
    Instantiated per-request with the org's decrypted tokens.
    """

    def __init__(self, access_token: str, refresh_token: str, org_id: str):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.org_id = org_id
        self._client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self._client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")

    # ─────────────────────────────────────────────
    # Token refresh
    # ─────────────────────────────────────────────

    async def refresh_access_token(self) -> bool:
        """Refresh the access token using the stored refresh token."""
        if not self.refresh_token or self.refresh_token == "demo_refresh_token":
            return False
        async with httpx.AsyncClient() as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            })
            if resp.status_code == 200:
                data = resp.json()
                self.access_token = data.get("access_token", self.access_token)
                return True
            logger.warning(f"Token refresh failed for org {self.org_id}: {resp.text}")
            return False

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}

    # ─────────────────────────────────────────────
    # User listing (for mailbox count + coverage)
    # ─────────────────────────────────────────────

    async def list_users(self, domain: str) -> list[dict]:
        """List all users in the Google Workspace domain."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{ADMIN_API_BASE}/users",
                headers=self._auth_headers(),
                params={"domain": domain, "maxResults": 500, "fields": "users(primaryEmail,name,suspended)"},
            )
            if resp.status_code == 401:
                await self.refresh_access_token()
                resp = await client.get(
                    f"{ADMIN_API_BASE}/users",
                    headers=self._auth_headers(),
                    params={"domain": domain, "maxResults": 500},
                )
            if resp.status_code == 200:
                return resp.json().get("users", [])
            logger.error(f"list_users failed: {resp.status_code} {resp.text}")
            return []

    async def list_group_members(self, group_email: str) -> list[str]:
        """Return list of member email addresses for a group (max 500)."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{ADMIN_API_BASE}/groups/{group_email}/members",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params={"maxResults": 500, "fields": "members(email,status,type)"},
            )
            if resp.status_code == 200:
                members = resp.json().get("members", [])
                return [
                    m["email"] for m in members
                    if m.get("email") and m.get("status") == "ACTIVE"
                ]
            logger.warning(f"list_group_members failed for {group_email}: {resp.status_code}")
            return []

    async def list_groups(self, domain: str) -> list[dict]:
        """List all Google Workspace groups (email groups / distribution lists) for the domain."""
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{ADMIN_API_BASE}/groups",
                headers=self._auth_headers(),
                params={
                    "domain": domain,
                    "maxResults": 200,
                    "fields": "groups(id,email,name,description,directMembersCount)",
                },
            )
            if resp.status_code == 401:
                await self.refresh_access_token()
                resp = await client.get(
                    f"{ADMIN_API_BASE}/groups",
                    headers=self._auth_headers(),
                    params={"domain": domain, "maxResults": 200},
                )
            if resp.status_code == 200:
                return resp.json().get("groups", [])
            logger.warning(f"list_groups failed: {resp.status_code} {resp.text[:300]}")
            return []

    # ─────────────────────────────────────────────
    # Gmail Push Notifications (Pub/Sub watch)
    # ─────────────────────────────────────────────

    async def setup_gmail_watch(self, user_email: str, pubsub_topic: str) -> Optional[dict]:
        """
        Set up Gmail push notification for a mailbox.
        pubsub_topic: 'projects/{project}/topics/{topic}'
        Returns watch expiration info.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/watch",
                headers=self._auth_headers(),
                json={
                    "topicName": pubsub_topic,
                    "labelIds": ["INBOX"],
                    "labelFilterAction": "include",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.info(f"Gmail watch set up for {user_email}, expires: {data.get('expiration')}")
                return data
            logger.warning(f"Gmail watch setup failed for {user_email}: {resp.status_code}")
            return None

    async def stop_gmail_watch(self, user_email: str):
        """Stop Gmail push notifications for a mailbox."""
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/stop",
                headers=self._auth_headers(),
            )

    # ─────────────────────────────────────────────
    # Email fetching
    # ─────────────────────────────────────────────

    async def get_message(self, user_email: str, message_id: str) -> Optional[dict]:
        """Fetch a full email message by ID."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{message_id}",
                headers=self._auth_headers(),
                params={"format": "full"},
            )
            if resp.status_code == 401:
                await self.refresh_access_token()
                resp = await client.get(
                    f"{GMAIL_API_BASE}/users/{user_email}/messages/{message_id}",
                    headers=self._auth_headers(),
                    params={"format": "full"},
                )
            if resp.status_code == 200:
                return resp.json()
            return None

    async def list_recent_messages(
        self,
        user_email: str,
        max_results: int = 50,
        query: str = "in:inbox newer_than:1d",
    ) -> list[dict]:
        """List recent messages for polling fallback."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/users/{user_email}/messages",
                headers=self._auth_headers(),
                params={"maxResults": max_results, "q": query},
            )
            if resp.status_code == 200:
                return resp.json().get("messages", [])
            return []

    # ─────────────────────────────────────────────
    # Message parsing
    # ─────────────────────────────────────────────

    @staticmethod
    def parse_gmail_message(raw_message: dict) -> dict:
        """
        Parse Gmail API message into our standard email_data format.
        Maps to the same schema used by the M365 processor.
        """
        headers = {
            h["name"].lower(): h["value"]
            for h in raw_message.get("payload", {}).get("headers", [])
        }

        sender = headers.get("from", "unknown@unknown.com")
        recipient = headers.get("to", "")
        subject = headers.get("subject", "(no subject)")
        message_id = headers.get("message-id", raw_message.get("id", ""))
        date_str = headers.get("date", "")

        # Extract body
        body = ""
        payload = raw_message.get("payload", {})
        body = GoogleWorkspaceService._extract_body(payload)

        # Authentication results (DMARC/SPF/DKIM from ARC headers)
        auth_results = headers.get("authentication-results", "")
        dmarc_pass = "dmarc=pass" in auth_results.lower()
        spf_pass = "spf=pass" in auth_results.lower()
        dkim_pass = "dkim=pass" in auth_results.lower()

        return {
            "message_id": message_id,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "body": body[:4000],  # Cap at 4k chars for LLM
            "received_at": date_str,
            "provider": "google",
            "raw_headers": dict(list(headers.items())[:20]),  # First 20 headers
            "authentication": {
                "dmarc_pass": dmarc_pass,
                "spf_pass": spf_pass,
                "dkim_pass": dkim_pass,
            },
            "attachments": GoogleWorkspaceService._extract_attachment_metadata(payload),
            "label_ids": raw_message.get("labelIds", []),
            "thread_id": raw_message.get("threadId", ""),
        }

    @staticmethod
    def _extract_body(payload: dict, depth: int = 0) -> str:
        if depth > 5:
            return ""
        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")

        if body_data and mime_type in ("text/plain", "text/html"):
            try:
                decoded = base64.urlsafe_b64decode(body_data + "==").decode("utf-8", errors="ignore")
                if mime_type == "text/plain":
                    return decoded
                # Strip HTML tags for plain text
                import re
                return re.sub(r"<[^>]+>", " ", decoded)
            except Exception:
                pass

        # Recurse into parts
        for part in payload.get("parts", []):
            result = GoogleWorkspaceService._extract_body(part, depth + 1)
            if result:
                return result
        return ""

    @staticmethod
    def _extract_attachment_metadata(payload: dict) -> list[dict]:
        attachments = []
        for part in payload.get("parts", []):
            if part.get("filename") and part.get("body", {}).get("attachmentId"):
                attachments.append({
                    "filename": part["filename"],
                    "mime_type": part.get("mimeType", ""),
                    "size": part.get("body", {}).get("size", 0),
                    "attachment_id": part["body"]["attachmentId"],
                })
        return attachments

    # ─────────────────────────────────────────────
    # Queue enqueue (Azure Service Bus or SQS fallback)
    # ─────────────────────────────────────────────

    async def enqueue_email_for_scanning(self, email_data: dict) -> bool:
        """Push parsed email to the himaya-email-events queue."""
        try:
            from backend.services.queue_client import queue_client
            await queue_client.send_message(
                queue_name=EMAIL_QUEUE_NAME,
                body={
                    "org_id": self.org_id,
                    "source": "google",
                    "email": email_data,
                    "enqueued_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            return True
        except Exception as e:
            logger.error(f"Queue enqueue failed: {e}")
            # Fallback to SQS if configured
            if SQS_EMAIL_QUEUE_URL:
                try:
                    import boto3
                    sqs = boto3.client("sqs", region_name=os.getenv("AWS_REGION", "us-east-1"))
                    sqs.send_message(
                        QueueUrl=SQS_EMAIL_QUEUE_URL,
                        MessageBody=json.dumps({
                            "org_id": self.org_id,
                            "source": "google",
                            "email": email_data,
                            "enqueued_at": datetime.now(timezone.utc).isoformat(),
                        }),
                    )
                    return True
                except Exception as sqs_e:
                    logger.error(f"SQS fallback enqueue failed: {sqs_e}")
            return False

    # ─────────────────────────────────────────────
    # Quarantine actions
    # ─────────────────────────────────────────────

    async def quarantine_message(self, user_email: str, message_id: str) -> bool:
        """Move email to quarantine by applying label and removing INBOX."""
        label_id = await self._ensure_quarantine_label(user_email)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{message_id}/modify",
                headers=self._auth_headers(),
                json={
                    "addLabelIds": [label_id] if label_id else [],
                    "removeLabelIds": ["INBOX"],
                },
            )
            return resp.status_code == 200

    async def delete_message(self, user_email: str, message_id: str) -> bool:
        """Permanently trash a message."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/messages/{message_id}/trash",
                headers=self._auth_headers(),
            )
            return resp.status_code == 200

    async def _ensure_quarantine_label(self, user_email: str) -> Optional[str]:
        """Get or create the HELIOS_QUARANTINE Gmail label."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/users/{user_email}/labels",
                headers=self._auth_headers(),
            )
            if resp.status_code == 200:
                for label in resp.json().get("labels", []):
                    if label.get("name") == HELIOS_QUARANTINE_LABEL:
                        return label["id"]
            # Create label
            resp = await client.post(
                f"{GMAIL_API_BASE}/users/{user_email}/labels",
                headers=self._auth_headers(),
                json={
                    "name": HELIOS_QUARANTINE_LABEL,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                    "color": {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
                },
            )
            if resp.status_code == 200:
                return resp.json().get("id")
        return None


# ─────────────────────────────────────────────
# Pub/Sub → SQS webhook handler
# ─────────────────────────────────────────────

async def handle_gmail_pubsub_notification(
    notification_data: dict,
    org_id: str,
    access_token: str,
    refresh_token: str,
):
    """
    Called by the /webhooks/google/pubsub endpoint when Gmail sends a push notification.
    Fetches new messages and enqueues them for scanning.
    """
    service = GoogleWorkspaceService(access_token, refresh_token, org_id)

    # Decode the Pub/Sub message
    message = notification_data.get("message", {})
    data_b64 = message.get("data", "")
    try:
        data = json.loads(base64.b64decode(data_b64).decode())
    except Exception:
        logger.warning("Failed to decode Pub/Sub notification data")
        return

    email_address = data.get("emailAddress", "")
    history_id = data.get("historyId")

    if not email_address or not history_id:
        return

    # Fetch new messages since last historyId
    # (In prod, store last processed historyId in Redis per-mailbox)
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GMAIL_API_BASE}/users/{email_address}/history",
            headers=service._auth_headers(),
            params={"startHistoryId": str(int(history_id) - 1), "historyTypes": "messageAdded"},
        )
        if resp.status_code != 200:
            await service.refresh_access_token()
            return

        history_data = resp.json()

    for record in history_data.get("history", []):
        for msg_added in record.get("messagesAdded", []):
            msg_id = msg_added.get("message", {}).get("id")
            if not msg_id:
                continue
            raw_msg = await service.get_message(email_address, msg_id)
            if raw_msg:
                email_data = GoogleWorkspaceService.parse_gmail_message(raw_msg)
                await service.enqueue_email_for_scanning(email_data)
                logger.info(f"Enqueued Gmail message {msg_id} from {email_address} for org {org_id}")
