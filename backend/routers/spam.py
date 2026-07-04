"""
Himaya Spam Center Router — enterprise tier only.
Manages spam inbox (sync/release/delete) and anti-spam rules.

DB tables created at startup via ensure_spam_tables().
"""
from __future__ import annotations

import base64
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization as _Org, OrgIntegration
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/spam", tags=["spam"])

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"


# ── Enterprise gate ───────────────────────────────────────────────────────────

async def _require_enterprise(current_user, db: AsyncSession):
    _org = (await db.execute(
        select(_Org).where(_Org.id == current_user.org_id)
    )).scalar_one_or_none()
    _tier = (getattr(_org, "tier", None) or "Launch").strip().lower()
    if _tier not in ("enterprise", "enterprise trial"):
        raise HTTPException(
            status_code=403,
            detail="Spam Center requires an Enterprise plan.",
        )


# ── Table creation ────────────────────────────────────────────────────────────

async def ensure_spam_tables(db: AsyncSession):
    """Create spam tables if they don't exist (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS spam_items (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            message_id VARCHAR(500) UNIQUE,
            provider VARCHAR(20),
            owner_email VARCHAR(255),
            subject TEXT,
            body_preview TEXT,
            sender VARCHAR(255),
            sender_domain VARCHAR(255),
            recipients TEXT[],
            has_attachment BOOLEAN DEFAULT FALSE,
            classification VARCHAR(50) DEFAULT 'SPAM',
            spam_score INTEGER DEFAULT 50,
            is_released BOOLEAN DEFAULT FALSE,
            released_at TIMESTAMPTZ,
            released_by VARCHAR(255),
            received_at TIMESTAMPTZ,
            synced_at TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_spam_items_org_id
        ON spam_items(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_spam_items_synced_at
        ON spam_items(synced_at DESC)
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS spam_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            enabled BOOLEAN DEFAULT TRUE,
            rule_type VARCHAR(50) NOT NULL,
            match_value TEXT NOT NULL,
            action VARCHAR(50) DEFAULT 'MOVE_TO_INBOX',
            hit_count INTEGER DEFAULT 0,
            last_hit_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_spam_rules_org_id
        ON spam_rules(org_id)
    """))
    await db.commit()


# ── Token helpers ─────────────────────────────────────────────────────────────

def _decrypt(enc: str) -> str:
    """Decrypt a Fernet-encrypted token using the same key as onboarding."""
    try:
        from backend.routers.onboarding import get_fernet
        return get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return enc


async def _get_org_integrations(org_id: str, db: AsyncSession):
    result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.status == "active",
        )
    )
    return result.scalars().all()


async def _get_access_token(integration: OrgIntegration) -> str:
    enc_at = integration.access_token_enc or ""
    enc_rt = integration.refresh_token_enc or ""
    access_token = _decrypt(enc_at) if enc_at else ""
    refresh_token = _decrypt(enc_rt) if enc_rt else ""
    if access_token in ("demo_access_token", ""):
        return ""
    provider = integration.provider or ""
    if provider in ("gmail", "google"):
        from backend.services.delta_sync import _refresh_google_token
        new_tok = await _refresh_google_token(refresh_token)
        if new_tok:
            access_token = new_tok
    elif provider == "m365":
        from backend.services.baseline_ingestion import _refresh_m365_token
        new_tok = await _refresh_m365_token(refresh_token)
        if new_tok:
            access_token = new_tok
    return access_token


# ── Spam classification helper ────────────────────────────────────────────────

def _classify_spam(subject: str, body: str, sender: str, headers: list[dict]) -> tuple[str, int]:
    """
    Returns (classification, spam_score).
    All items come from the spam/junk folder so they ARE confirmed spam.
    Classification determines subtype; score reflects severity within spam (all >= 50).
    """
    body_lower = body.lower()
    subject_lower = subject.lower()

    link_count = len(re.findall(r"https?://", body_lower))
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    link_domains = re.findall(r"https?://([^/\\s\"'>]+)", body_lower)
    mismatched = sum(1 for d in link_domains if sender_domain and sender_domain not in d)

    # --- Phishing indicators (highest risk) ---
    phishing_score = 0
    urgent_words = ["verify", "confirm", "suspended", "urgent", "account", "password",
                    "click here", "act now", "expire", "limited time", "signin", "login",
                    "validate", "update your", "unusual activity"]
    phishing_subject_words = ["verify", "suspended", "unusual", "confirm", "login", "alert",
                               "action required", "important", "security"]
    urgent_in_body = sum(1 for w in urgent_words if w in body_lower)
    urgent_in_subj = sum(1 for w in phishing_subject_words if w in subject_lower)
    if link_count > 5 and mismatched > 3:
        phishing_score += 30
    if urgent_in_body >= 3:
        phishing_score += 20
    if urgent_in_subj >= 2:
        phishing_score += 15
    if phishing_score >= 30 or (link_count > 3 and mismatched > 2 and urgent_in_body >= 2):
        return "PHISHING_SPAM", min(100, 70 + phishing_score)

    # --- Bulk indicators ---
    if link_count > 15:
        return "BULK", 75
    if link_count > 10:
        return "BULK", 70

    # --- Marketing indicators (lower severity) ---
    has_unsubscribe_body = "unsubscribe" in body_lower
    has_list_unsub = any(
        h.get("name", "").lower() == "list-unsubscribe"
        for h in headers
    )
    if has_unsubscribe_body or has_list_unsub:
        mkt_score = 50
        if link_count > 5:
            mkt_score = 60
        elif link_count > 2:
            mkt_score = 55
        return "MARKETING", mkt_score

    # --- Default: plain spam scored by content signals ---
    base = 60
    spam_words = ["free", "winner", "prize", "lottery", "casino", "xxx",
                  "bitcoin", "crypto", "investment", "million dollar", "nigerian",
                  "wire transfer", "bank account", "make money", "work from home",
                  "no cost", "100% free", "guaranteed", "risk free"]
    spam_hits = sum(1 for w in spam_words if w in body_lower or w in subject_lower)
    base += min(spam_hits * 3, 20)
    if link_count > 3:
        base += 5
    return "SPAM", min(base, 85)


def _extract_gmail_body_spam(payload: dict) -> str:
    mime = payload.get("mimeType", "")
    if mime == "text/plain":
        data = payload.get("body", {}).get("data", "")
        if data:
            try:
                return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            except Exception:
                return ""
    parts = payload.get("parts", [])
    for part in parts:
        text_body = _extract_gmail_body_spam(part)
        if text_body:
            return text_body
    return ""


def _match_rule(rule_type: str, match_value: str, item: dict) -> bool:
    """Check if a spam item matches a rule."""
    subject = (item.get("subject") or "").lower()
    sender = (item.get("sender") or "").lower()
    sender_domain = (item.get("sender_domain") or "").lower()
    body = (item.get("body_preview") or "").lower()
    val = match_value.lower()

    if rule_type == "SENDER_EMAIL":
        return val in sender
    elif rule_type == "SENDER_DOMAIN":
        return val in sender_domain
    elif rule_type == "SUBJECT_CONTAINS":
        return val in subject
    elif rule_type == "BODY_CONTAINS":
        return val in body
    elif rule_type == "CLASSIFICATION":
        return val.upper() == (item.get("classification") or "").upper()
    return False


# ── Pydantic models ───────────────────────────────────────────────────────────

class SpamRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str
    match_value: str
    action: str = "MOVE_TO_INBOX"
    enabled: bool = True


class SpamRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[str] = None
    match_value: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None


class RuleTestRequest(BaseModel):
    rule_type: str
    match_value: str


# ── Routes — Spam Items ───────────────────────────────────────────────────────

@router.get("/items")
async def list_spam_items(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    classification: Optional[str] = Query(None),
    owner_email: Optional[str] = Query(None),
    is_released: Optional[bool] = Query(None),
    sort_by: Optional[str] = Query("received_at"),
    sort_order: Optional[str] = Query("desc"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size

    # Validate sort params
    _allowed_sort_by = {"received_at", "synced_at"}
    _allowed_sort_order = {"asc", "desc"}
    _sort_col = sort_by if sort_by in _allowed_sort_by else "received_at"
    _sort_dir = sort_order.upper() if sort_order and sort_order.lower() in _allowed_sort_order else "DESC"

    where_clauses = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}

    if classification:
        where_clauses.append("classification = :classification")
        params["classification"] = classification
    if owner_email:
        where_clauses.append("owner_email ILIKE :owner_email")
        params["owner_email"] = f"%{owner_email}%"
    if is_released is not None:
        where_clauses.append("is_released = :is_released")
        params["is_released"] = is_released

    where_sql = " AND ".join(where_clauses)
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}

    total_row = await db.execute(
        text(f"SELECT COUNT(*) FROM spam_items WHERE {where_sql}"),
        count_params,
    )
    total = total_row.scalar() or 0

    rows = await db.execute(
        text(f"""
            SELECT id, message_id, provider, owner_email, subject, body_preview,
                   sender, sender_domain, recipients, has_attachment,
                   classification, spam_score, is_released, released_at,
                   released_by, received_at, synced_at
            FROM spam_items
            WHERE {where_sql}
            ORDER BY {_sort_col} {_sort_dir}
            LIMIT :limit OFFSET :offset
        """),
        params,
    )
    items = []
    for row in rows.mappings():
        items.append({
            "id": str(row["id"]),
            "message_id": row["message_id"],
            "provider": row["provider"],
            "owner_email": row["owner_email"],
            "subject": row["subject"],
            "body_preview": row["body_preview"],
            "sender": row["sender"],
            "sender_domain": row["sender_domain"],
            "recipients": row["recipients"] or [],
            "has_attachment": row["has_attachment"],
            "classification": row["classification"],
            "spam_score": row["spam_score"],
            "is_released": row["is_released"],
            "released_at": row["released_at"].isoformat() if row["released_at"] else None,
            "released_by": row["released_by"],
            "received_at": row["received_at"].isoformat() if row["received_at"] else None,
            "synced_at": row["synced_at"].isoformat() if row["synced_at"] else None,
        })

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def spam_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    row = await db.execute(
        text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE classification = 'SPAM') AS spam,
                COUNT(*) FILTER (WHERE classification = 'MARKETING') AS marketing,
                COUNT(*) FILTER (WHERE classification = 'BULK') AS bulk,
                COUNT(*) FILTER (WHERE classification = 'PHISHING_SPAM') AS phishing_spam,
                COUNT(*) FILTER (
                    WHERE is_released = TRUE
                    AND released_at >= NOW() - INTERVAL '1 day'
                ) AS released_today
            FROM spam_items
            WHERE org_id = :org_id
        """),
        {"org_id": org_id},
    )
    r = row.mappings().first()
    return {
        "total": r["total"] or 0,
        "spam": r["spam"] or 0,
        "marketing": r["marketing"] or 0,
        "bulk": r["bulk"] or 0,
        "phishing_spam": r["phishing_spam"] or 0,
        "released_today": r["released_today"] or 0,
    }


# ── Core sync helper (used by route + background service) ───────────────────

async def _sync_org_spam(org_id: str, db: AsyncSession) -> dict:
    """Sync spam folder for all mailboxes in one org. Returns {synced, auto_released}."""
    from backend.models.db_models import User

    integrations = await _get_org_integrations(org_id, db)
    if not integrations:
        return {"synced": 0, "auto_released": 0}

    integration_snaps = [
        {
            "provider": i.provider or "",
            "access_token_enc": i.access_token_enc or "",
            "refresh_token_enc": i.refresh_token_enc or "",
            "org_domain": i.org_domain or "",
        }
        for i in integrations
    ]

    users_result = await db.execute(
        select(User.email, User.directory_provider).where(
            User.org_id == org_id,
            User.is_active == True,
        )
    )
    user_rows = users_result.all()
    all_user_emails = [r.email for r in user_rows]

    rules_rows = await db.execute(
        text("SELECT id, rule_type, match_value, action, enabled FROM spam_rules WHERE org_id = :org_id AND enabled = TRUE"),
        {"org_id": org_id},
    )
    rules = [dict(r) for r in rules_rows.mappings()]

    synced = 0
    auto_released = 0

    for snap in integration_snaps:
        provider = snap["provider"]
        enc_at = snap["access_token_enc"]
        enc_rt = snap["refresh_token_enc"]
        access_token = _decrypt(enc_at) if enc_at else ""
        refresh_token = _decrypt(enc_rt) if enc_rt else ""

        if not access_token or access_token == "demo_access_token":
            continue

        org_domain = snap["org_domain"] or ""
        if provider in ("gmail", "google"):
            # Try to refresh — but keep original access_token if refresh fails/returns None
            if refresh_token:
                try:
                    from backend.services.delta_sync import _refresh_google_token
                    new_tok = await _refresh_google_token(refresh_token)
                    if new_tok:
                        access_token = new_tok
                except Exception as _e:
                    logger.debug(f"Gmail token refresh failed (using existing): {_e}")
            if not access_token:
                logger.warning(f"Gmail integration for org {org_id} has no usable access token, skipping spam sync")
                continue
            if org_domain:
                domain_users = [e for e in all_user_emails if e.endswith("@" + org_domain)]
                user_emails = domain_users if domain_users else all_user_emails
            else:
                user_emails = all_user_emails
        elif provider == "m365":
            try:
                from backend.services.baseline_ingestion import _refresh_m365_token
                new_tok = await _refresh_m365_token(refresh_token)
                if new_tok:
                    access_token = new_tok
            except Exception:
                pass
            if org_domain:
                domain_users = [e for e in all_user_emails if e.endswith("@" + org_domain)]
                m365_dp_users = [r.email for r in user_rows if r.directory_provider == "m365"]
                user_emails = list(set(domain_users + m365_dp_users)) or all_user_emails
            else:
                user_emails = [r.email for r in user_rows if r.directory_provider == "m365"] or all_user_emails
        else:
            continue

        for user_email in user_emails:
            spam_messages = []

            if provider == "m365":
                try:
                    async with httpx.AsyncClient(timeout=60) as client:
                        hdrs_req = {
                            "Authorization": f"Bearer {access_token}",
                            "Content-Type": "application/json",
                        }
                        next_link: Optional[str] = (
                            f"{GRAPH_API_BASE}/users/{user_email}/mailFolders/junkemail/messages"
                            f"?$top=100&$select=id,subject,sender,toRecipients,body,hasAttachments,receivedDateTime"
                        )
                        while next_link:
                            resp = await client.get(next_link, headers=hdrs_req)
                            if resp.status_code != 200:
                                logger.warning(f"M365 junk fetch failed for {user_email}: {resp.status_code}")
                                break
                            resp_json = resp.json()
                            next_link = resp_json.get("@odata.nextLink")
                            for msg in resp_json.get("value", []):
                                sender_addr = msg.get("sender", {}).get("emailAddress", {}).get("address", "")
                                sender_domain_v = sender_addr.split("@")[-1] if "@" in sender_addr else ""
                                body_content = msg.get("body", {}).get("content", "") or ""
                                body_plain = re.sub(r"<[^>]+>", " ", body_content).strip()
                                body_plain = re.sub(r"\s+", " ", body_plain)
                                received_str = msg.get("receivedDateTime", "")
                                received_at = None
                                if received_str:
                                    try:
                                        received_at = datetime.fromisoformat(received_str.replace("Z", "+00:00"))
                                    except Exception:
                                        pass
                                classification, score = _classify_spam(
                                    msg.get("subject", ""), body_plain, sender_addr, [],
                                )
                                spam_messages.append({
                                    "message_id": msg.get("id", ""),
                                    "provider": "m365",
                                    "owner_email": user_email,
                                    "subject": msg.get("subject", ""),
                                    "body_preview": body_plain[:500],
                                    "sender": sender_addr,
                                    "sender_domain": sender_domain_v,
                                    "recipients": [
                                        r.get("emailAddress", {}).get("address", "")
                                        for r in msg.get("toRecipients", [])
                                    ],
                                    "has_attachment": msg.get("hasAttachments", False),
                                    "classification": classification,
                                    "spam_score": score,
                                    "received_at": received_at,
                                })
                except Exception as e:
                    logger.error(f"M365 spam sync error for {user_email}: {e}")

            elif provider in ("gmail", "google"):
                # Use DWD SA impersonation via run_in_executor (most reliable)
                _gmail_tok = access_token  # OAuth fallback
                try:
                    import asyncio as _asyncio_spam
                    from backend.services.baseline_ingestion import _get_service_account_headers_sync as _sa_sync
                    _sa_result = await _asyncio_spam.get_running_loop().run_in_executor(
                        None, _sa_sync, user_email
                    )
                    if _sa_result:
                        _gmail_tok = _sa_result.get("Authorization", "").replace("Bearer ", "")
                        logger.info(f"Spam sync: SA DWD token obtained for {user_email}")
                    else:
                        logger.warning(f"Spam sync: SA returned None for {user_email}, using OAuth")
                except Exception as _sa_exc2:
                    logger.warning(f"Spam sync: SA failed for {user_email}: {_sa_exc2}, using OAuth")
                try:
                    async with httpx.AsyncClient(timeout=60) as client:
                        g_hdrs = {"Authorization": f"Bearer {_gmail_tok}"}
                        next_page_token: Optional[str] = None
                        while True:
                            g_params: dict = {"labelIds": "SPAM", "maxResults": "100"}
                            if next_page_token:
                                g_params["pageToken"] = next_page_token
                            list_resp = await client.get(
                                f"{GMAIL_API_BASE}/users/{user_email}/messages",
                                headers=g_hdrs,
                                params=g_params,
                            )
                            if list_resp.status_code != 200:
                                logger.warning(f"Gmail spam list failed for {user_email}: {list_resp.status_code} {list_resp.text[:200]}")
                                break
                            page_json = list_resp.json()
                            next_page_token = page_json.get("nextPageToken")
                            for m in page_json.get("messages", []):
                                msg_id = m.get("id", "")
                                det = await client.get(
                                    f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
                                    headers=g_hdrs,
                                    params={"format": "full"},
                                )
                                if det.status_code != 200:
                                    continue
                                msg_json = det.json()
                                payload = msg_json.get("payload", {})
                                hdrs_list = payload.get("headers", [])
                                hdrs = {h["name"].lower(): h["value"] for h in hdrs_list}
                                sender_addr = hdrs.get("from", "")
                                m_email = re.search(r"<([^>]+)>", sender_addr)
                                if m_email:
                                    sender_addr = m_email.group(1)
                                sender_domain_v = sender_addr.split("@")[-1] if "@" in sender_addr else ""
                                body = _extract_gmail_body_spam(payload)
                                internal_date_ms = msg_json.get("internalDate", "")
                                received_at = None
                                if internal_date_ms:
                                    try:
                                        received_at = datetime.fromtimestamp(
                                            int(internal_date_ms) / 1000, tz=timezone.utc
                                        )
                                    except Exception:
                                        pass
                                classification, score = _classify_spam(
                                    hdrs.get("subject", ""), body, sender_addr, hdrs_list,
                                )
                                spam_messages.append({
                                    "message_id": msg_id,
                                    "provider": "gmail",
                                    "owner_email": user_email,
                                    "subject": hdrs.get("subject", ""),
                                    "body_preview": body[:500],
                                    "sender": sender_addr,
                                    "sender_domain": sender_domain_v,
                                    "recipients": [r.strip() for r in hdrs.get("to", "").split(",") if r.strip()],
                                    "has_attachment": bool(payload.get("parts")),
                                    "classification": classification,
                                    "spam_score": score,
                                    "received_at": received_at,
                                })
                            if not next_page_token:
                                break
                except Exception as e:
                    logger.error(f"Gmail spam sync error for {user_email}: {e}")

            for item in spam_messages:
                try:
                    await db.execute(
                        text("""
                            INSERT INTO spam_items
                                (org_id, message_id, provider, owner_email, subject,
                                 body_preview, sender, sender_domain, recipients,
                                 has_attachment, classification, spam_score, received_at)
                            VALUES
                                (:org_id, :message_id, :provider, :owner_email, :subject,
                                 :body_preview, :sender, :sender_domain, :recipients,
                                 :has_attachment, :classification, :spam_score, :received_at)
                            ON CONFLICT (message_id) DO UPDATE SET
                                classification = EXCLUDED.classification,
                                spam_score = EXCLUDED.spam_score,
                                synced_at = NOW()
                        """),
                        {
                            "org_id": org_id,
                            "message_id": item["message_id"],
                            "provider": item["provider"],
                            "owner_email": item["owner_email"],
                            "subject": item["subject"],
                            "body_preview": item["body_preview"],
                            "sender": item["sender"],
                            "sender_domain": item["sender_domain"],
                            "recipients": item["recipients"],
                            "has_attachment": item["has_attachment"],
                            "classification": item["classification"],
                            "spam_score": item["spam_score"],
                            "received_at": item["received_at"],
                        },
                    )
                    synced += 1
                except Exception as e:
                    logger.warning(f"Failed to upsert spam_item {item['message_id']}: {e}")
                    continue

                for rule in rules:
                    if rule["action"] == "MOVE_TO_INBOX" and _match_rule(
                        rule["rule_type"], rule["match_value"], item
                    ):
                        # Mark as released in DB
                        await db.execute(
                            text("""
                                UPDATE spam_items
                                SET is_released = TRUE, released_at = NOW(), released_by = 'auto-rule'
                                WHERE message_id = :message_id AND org_id = :org_id
                            """),
                            {"message_id": item["message_id"], "org_id": org_id},
                        )
                        await db.execute(
                            text("""
                                UPDATE spam_rules SET hit_count = hit_count + 1, last_hit_at = NOW()
                                WHERE id = :rule_id
                            """),
                            {"rule_id": str(rule["id"])},
                        )
                        # Actually move message to inbox via mail API
                        try:
                            _item_msg_id = item["message_id"]
                            _item_provider = item["provider"]
                            _item_owner = item["owner_email"]
                            async with httpx.AsyncClient(timeout=15) as _ac:
                                _ah = {
                                    "Authorization": f"Bearer {access_token}",
                                    "Content-Type": "application/json",
                                }
                                if _item_provider == "m365":
                                    await _ac.post(
                                        f"{GRAPH_API_BASE}/users/{_item_owner}/messages/{_item_msg_id}/move",
                                        headers=_ah,
                                        json={"destinationId": "inbox"},
                                    )
                                else:  # gmail
                                    await _ac.post(
                                        f"{GMAIL_API_BASE}/users/{_item_owner}/messages/{_item_msg_id}/modify",
                                        headers=_ah,
                                        json={"addLabelIds": ["INBOX"], "removeLabelIds": ["SPAM"]},
                                    )
                        except Exception as _ae:
                            logger.debug(f"Auto-rule API move failed (non-fatal): {_ae}")
                        auto_released += 1
                        break

    return {"synced": synced, "auto_released": auto_released}
@router.post("/sync")
async def sync_spam(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    result = await _sync_org_spam(str(current_user.org_id), db)
    await db.commit()
    return result


@router.post("/items/{item_id}/release")
async def release_spam_item(
    item_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    row = await db.execute(
        text("SELECT * FROM spam_items WHERE id = :id AND org_id = :org_id"),
        {"id": item_id, "org_id": org_id},
    )
    item = row.mappings().first()
    if not item:
        raise HTTPException(status_code=404, detail="Spam item not found.")

    provider = item["provider"]
    owner_email = item["owner_email"]
    message_id = item["message_id"]

    # Integration provider: Gmail spam_items stored as 'gmail' but OrgIntegration uses 'google'
    _integ_provider = "google" if provider == "gmail" else provider

    # Get integration for this user
    integration_row = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == _integ_provider,
            OrgIntegration.status == "active",
        )
    )
    integration = integration_row.scalar_one_or_none()

    if integration:
        access_token = await _get_access_token(integration)
        if access_token:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    }
                    if provider == "m365":
                        await client.post(
                            f"{GRAPH_API_BASE}/users/{owner_email}/messages/{message_id}/move",
                            headers=headers,
                            json={"destinationId": "inbox"},
                        )
                    else:  # gmail
                        await client.post(
                            f"{GMAIL_API_BASE}/users/{owner_email}/messages/{message_id}/modify",
                            headers=headers,
                            json={"addLabelIds": ["INBOX"], "removeLabelIds": ["SPAM"]},
                        )
            except Exception as e:
                logger.error(f"Error releasing spam item {item_id}: {e}")

    await db.execute(
        text("""
            UPDATE spam_items
            SET is_released = TRUE, released_at = NOW(), released_by = :user_email
            WHERE id = :id AND org_id = :org_id
        """),
        {"id": item_id, "org_id": org_id, "user_email": current_user.email},
    )
    await db.commit()
    return {"success": True}


@router.post("/items/{item_id}/delete")
async def delete_spam_item(
    item_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    row = await db.execute(
        text("SELECT * FROM spam_items WHERE id = :id AND org_id = :org_id"),
        {"id": item_id, "org_id": org_id},
    )
    item = row.mappings().first()
    if not item:
        raise HTTPException(status_code=404, detail="Spam item not found.")

    provider = item["provider"]
    owner_email = item["owner_email"]
    message_id = item["message_id"]

    # Get integration and delete from provider
    # Integration provider: Gmail spam_items stored as 'gmail' but OrgIntegration uses 'google'
    _integ_provider_del = "google" if provider == "gmail" else provider

    integration_row = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == _integ_provider_del,
            OrgIntegration.status == "active",
        )
    )
    integration = integration_row.scalar_one_or_none()

    if integration:
        access_token = await _get_access_token(integration)
        if access_token:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    }
                    if provider == "m365":
                        await client.delete(
                            f"{GRAPH_API_BASE}/users/{owner_email}/messages/{message_id}",
                            headers=headers,
                        )
                    else:  # gmail
                        await client.post(
                            f"{GMAIL_API_BASE}/users/{owner_email}/messages/{message_id}/trash",
                            headers=headers,
                        )
            except Exception as e:
                logger.error(f"Error deleting spam item {item_id}: {e}")

    await db.execute(
        text("DELETE FROM spam_items WHERE id = :id AND org_id = :org_id"),
        {"id": item_id, "org_id": org_id},
    )
    await db.commit()
    return {"success": True}


# ── Routes — Spam Rules ───────────────────────────────────────────────────────

@router.get("/rules")
async def list_spam_rules(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    rows = await db.execute(
        text("""
            SELECT id, name, description, enabled, rule_type, match_value,
                   action, hit_count, last_hit_at, created_at, updated_at
            FROM spam_rules
            WHERE org_id = :org_id
            ORDER BY created_at DESC
        """),
        {"org_id": org_id},
    )
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "description": r["description"],
            "enabled": r["enabled"],
            "rule_type": r["rule_type"],
            "match_value": r["match_value"],
            "action": r["action"],
            "hit_count": r["hit_count"],
            "last_hit_at": r["last_hit_at"].isoformat() if r["last_hit_at"] else None,
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        }
        for r in rows.mappings()
    ]


@router.post("/rules")
async def create_spam_rule(
    body: SpamRuleCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    row = await db.execute(
        text("""
            INSERT INTO spam_rules (org_id, name, description, rule_type, match_value, action, enabled)
            VALUES (:org_id, :name, :description, :rule_type, :match_value, :action, :enabled)
            RETURNING id
        """),
        {
            "org_id": org_id,
            "name": body.name,
            "description": body.description,
            "rule_type": body.rule_type,
            "match_value": body.match_value,
            "action": body.action,
            "enabled": body.enabled,
        },
    )
    await db.commit()
    new_id = row.scalar()
    return {"id": str(new_id), "success": True}


@router.patch("/rules/{rule_id}")
async def update_spam_rule(
    rule_id: str,
    body: SpamRuleUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    updates = []
    params: dict = {"rule_id": rule_id, "org_id": org_id}

    if body.name is not None:
        updates.append("name = :name")
        params["name"] = body.name
    if body.description is not None:
        updates.append("description = :description")
        params["description"] = body.description
    if body.rule_type is not None:
        updates.append("rule_type = :rule_type")
        params["rule_type"] = body.rule_type
    if body.match_value is not None:
        updates.append("match_value = :match_value")
        params["match_value"] = body.match_value
    if body.action is not None:
        updates.append("action = :action")
        params["action"] = body.action
    if body.enabled is not None:
        updates.append("enabled = :enabled")
        params["enabled"] = body.enabled

    if not updates:
        return {"success": True, "message": "No changes."}

    updates.append("updated_at = NOW()")
    await db.execute(
        text(f"UPDATE spam_rules SET {', '.join(updates)} WHERE id = :rule_id AND org_id = :org_id"),
        params,
    )
    await db.commit()
    return {"success": True}


@router.delete("/rules/{rule_id}")
async def delete_spam_rule(
    rule_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    await db.execute(
        text("DELETE FROM spam_rules WHERE id = :rule_id AND org_id = :org_id"),
        {"rule_id": rule_id, "org_id": org_id},
    )
    await db.commit()
    return {"success": True}


@router.post("/rules/test")
async def test_spam_rule(
    body: RuleTestRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    # Fetch spam items to test against
    rows = await db.execute(
        text("""
            SELECT subject, sender, sender_domain, body_preview, classification
            FROM spam_items
            WHERE org_id = :org_id
            LIMIT 500
        """),
        {"org_id": org_id},
    )
    items = [dict(r) for r in rows.mappings()]

    matched = [
        item for item in items
        if _match_rule(body.rule_type, body.match_value, item)
    ]

    sample_subjects = [item["subject"] for item in matched[:5] if item.get("subject")]
    return {"matched_count": len(matched), "sample_subjects": sample_subjects}
