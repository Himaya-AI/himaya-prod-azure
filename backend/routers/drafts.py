"""
Himaya Draft Analysis Router — enterprise tier only.
Fetches drafts from M365/Gmail, runs DLP analysis, and stores results.

DB tables created at startup via ensure_draft_tables().
"""
from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization as _Org, OrgIntegration
from backend.routers.auth import get_current_user
from backend.services.dlp_service import classify_email

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/drafts", tags=["drafts"])

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


# ── Admin Email Notification for Sensitive Drafts ────────────────────────────

async def _send_draft_alert_email(
    org_id: str,
    user_email: str,
    subject: str,
    categories: list[str],
    flagged_types: list[str],
    score: int,
    explanation: str,
    db: AsyncSession,
):
    """
    Send email notification to org admins when a user creates a sensitive draft.
    Uses Himaya's branded email template.
    """
    import os
    import httpx
    
    try:
        # Get org name and admin emails
        org_result = await db.execute(
            text("SELECT name FROM organizations WHERE id = :org_id"),
            {"org_id": org_id}
        )
        org_row = org_result.mappings().first()
        org_name = org_row["name"] if org_row else "Your Organization"
        
        # Get admin users for this org
        admin_result = await db.execute(
            text("""
                SELECT email FROM users 
                WHERE org_id = :org_id AND role IN ('admin', 'owner') AND is_active = TRUE
                LIMIT 5
            """),
            {"org_id": org_id}
        )
        admin_emails = [row[0] for row in admin_result.fetchall()]
        
        if not admin_emails:
            logger.warning(f"No admin emails found for org {org_id}, skipping draft alert")
            return
        
        # Determine severity color and label
        if score >= 80:
            severity_color = "#dc2626"  # Red
            severity_label = "CRITICAL"
        elif score >= 60:
            severity_color = "#f97316"  # Orange
            severity_label = "HIGH"
        else:
            severity_color = "#f59e0b"  # Amber
            severity_label = "MEDIUM"
        
        # Build flagged types HTML
        types_html = "".join([f"<li style='margin: 4px 0;'>{t}</li>" for t in flagged_types]) if flagged_types else "<li>Sensitive content detected</li>"
        
        # Build email HTML with Himaya branding
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); padding: 30px 40px; border-radius: 12px 12px 0 0;">
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td>
                                        <img src="https://app.himaya.ai/himaya-logo-dark.png" alt="Himaya" width="120" style="display: block;">
                                    </td>
                                    <td align="right">
                                        <span style="color: {severity_color}; font-size: 12px; font-weight: 700; background: rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 20px; border: 1px solid {severity_color};">
                                            ⚠️ {severity_label} RISK
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Alert Banner -->
                    <tr>
                        <td style="background-color: {severity_color}; padding: 15px 40px;">
                            <p style="margin: 0; color: #ffffff; font-size: 16px; font-weight: 600;">
                                🚨 Sensitive Draft Detected
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <p style="margin: 0 0 20px 0; color: #374151; font-size: 15px; line-height: 1.6;">
                                A user in <strong>{org_name}</strong> has created a draft email containing potentially sensitive information.
                            </p>
                            
                            <!-- Details Card -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0; margin: 20px 0;">
                                <tr>
                                    <td style="padding: 20px;">
                                        <table width="100%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="40%" style="padding: 8px 0; color: #64748b; font-size: 13px;">User:</td>
                                                <td style="padding: 8px 0; color: #1e293b; font-size: 13px; font-weight: 600;">{user_email}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #64748b; font-size: 13px;">Subject:</td>
                                                <td style="padding: 8px 0; color: #1e293b; font-size: 13px; font-weight: 600;">{subject[:80]}{'...' if len(subject) > 80 else ''}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #64748b; font-size: 13px;">Risk Score:</td>
                                                <td style="padding: 8px 0;"><span style="color: {severity_color}; font-size: 14px; font-weight: 700;">{score}/100</span></td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Flagged Content Types -->
                            <p style="margin: 20px 0 10px 0; color: #374151; font-size: 14px; font-weight: 600;">
                                Flagged Content Types:
                            </p>
                            <ul style="margin: 0; padding-left: 20px; color: #475569; font-size: 13px;">
                                {types_html}
                            </ul>
                            
                            <!-- Analysis -->
                            <p style="margin: 20px 0 10px 0; color: #374151; font-size: 14px; font-weight: 600;">
                                AI Analysis:
                            </p>
                            <p style="margin: 0; padding: 15px; background-color: #fef3c7; border-left: 4px solid #f59e0b; color: #92400e; font-size: 13px; line-height: 1.5;">
                                {explanation[:500]}{'...' if len(explanation) > 500 else ''}
                            </p>
                            
                            <!-- CTA -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="margin-top: 30px;">
                                <tr>
                                    <td align="center">
                                        <a href="https://app.himaya.ai/drafts" style="display: inline-block; background: linear-gradient(135deg, #3b6ef6 0%, #2563eb 100%); color: #ffffff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 600;">
                                            Review in Himaya Dashboard →
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style="margin: 30px 0 0 0; color: #9ca3af; font-size: 12px; text-align: center;">
                                This alert was generated automatically by Himaya Draft Analysis.<br>
                                The draft has not been sent yet and remains in the user's mailbox.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8fafc; padding: 20px 40px; border-radius: 0 0 12px 12px; border-top: 1px solid #e2e8f0;">
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td>
                                        <p style="margin: 0; color: #64748b; font-size: 11px;">
                                            © 2026 Himaya Security • <a href="https://himaya.ai" style="color: #3b6ef6; text-decoration: none;">himaya.ai</a>
                                        </p>
                                    </td>
                                    <td align="right">
                                        <p style="margin: 0; color: #64748b; font-size: 11px;">
                                            Powered by Himaya
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
        
        # Send via Resend API
        resend_key = os.getenv("RESEND_API_KEY", "")
        if not resend_key:
            logger.warning("RESEND_API_KEY not set, skipping draft alert email")
            return
        
        async with httpx.AsyncClient(timeout=15) as client:
            for admin_email in admin_emails:
                try:
                    resp = await client.post(
                        "https://api.resend.com/emails",
                        headers={
                            "Authorization": f"Bearer {resend_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "from": "Himaya Security <alerts@app.himaya.ai>",
                            "to": admin_email,
                            "subject": f"🚨 [{severity_label}] Sensitive Draft Alert - {user_email}",
                            "html": html_body,
                        },
                    )
                    if resp.status_code == 200:
                        logger.info(f"Draft alert email sent to {admin_email}")
                    else:
                        logger.warning(f"Draft alert email failed for {admin_email}: {resp.status_code}")
                except Exception as e:
                    logger.warning(f"Failed to send draft alert to {admin_email}: {e}")
                    
    except Exception as e:
        logger.error(f"Draft alert email error: {e}")
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
            detail="Draft Analysis requires an Enterprise plan.",
        )


# ── Table creation ────────────────────────────────────────────────────────────

async def ensure_draft_tables(db: AsyncSession):
    """Create draft_events table if it doesn't exist (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS draft_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            message_id VARCHAR(500),
            provider VARCHAR(20),
            owner_email VARCHAR(255),
            subject TEXT,
            body_preview TEXT,
            recipients TEXT[],
            has_attachment BOOLEAN DEFAULT FALSE,
            attachment_names TEXT[],
            dlp_classification VARCHAR(50),
            dlp_categories TEXT[],
            dlp_score INTEGER DEFAULT 0,
            dlp_explanation TEXT,
            last_modified_at TIMESTAMPTZ,
            analyzed_at TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, message_id)
        )
    """))
    # Add unique constraint to existing tables (idempotent)
    await db.execute(text("""
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'draft_events_org_id_message_id_key'
                  AND conrelid = 'draft_events'::regclass
            ) THEN
                ALTER TABLE draft_events ADD CONSTRAINT draft_events_org_id_message_id_key UNIQUE (org_id, message_id);
            END IF;
        END $$;
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_draft_events_org_id
        ON draft_events(org_id)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_draft_events_analyzed_at
        ON draft_events(analyzed_at DESC)
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
    """Return list of active OrgIntegration rows for the org."""
    result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.status == "active",
        )
    )
    return result.scalars().all()


async def _get_access_token(integration: OrgIntegration) -> str:
    """Decrypt and refresh token as needed."""
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


# ── Draft fetching helpers ────────────────────────────────────────────────────

def _extract_gmail_body(payload: dict) -> str:
    """Recursively extract plain-text body from Gmail message payload."""
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
        text = _extract_gmail_body(part)
        if text:
            return text
    return ""


async def _fetch_gmail_drafts(user_email: str, access_token: str) -> list[dict]:
    """Fetch all draft messages from Gmail for a user using the Drafts API with pagination."""
    drafts = []
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            # Step 1: list all draft IDs via the Drafts API (supports pagination)
            next_page_token: Optional[str] = None
            draft_ids: list[str] = []
            while True:
                params: dict = {"maxResults": "100"}
                if next_page_token:
                    params["pageToken"] = next_page_token
                list_resp = await client.get(
                    f"{GMAIL_API_BASE}/users/{user_email}/drafts",
                    headers=headers,
                    params=params,
                )
                if list_resp.status_code != 200:
                    logger.warning(
                        f"Gmail drafts list failed for {user_email}: "
                        f"{list_resp.status_code} {list_resp.text[:200]}"
                    )
                    break
                page = list_resp.json()
                for d in page.get("drafts", []):
                    # Each entry has {"id": draft_id, "message": {"id": message_id}}
                    draft_ids.append(d.get("id", ""))
                next_page_token = page.get("nextPageToken")
                if not next_page_token:
                    break

            logger.info(f"Gmail drafts: found {len(draft_ids)} drafts for {user_email}")

            # Step 2: fetch full detail for each draft
            for draft_id in draft_ids:
                if not draft_id:
                    continue
                detail_resp = await client.get(
                    f"{GMAIL_API_BASE}/users/{user_email}/drafts/{draft_id}",
                    headers=headers,
                    params={"format": "full"},
                )
                if detail_resp.status_code != 200:
                    logger.warning(f"Gmail draft detail failed for {user_email}/{draft_id}: {detail_resp.status_code}")
                    continue
                draft_json = detail_resp.json()
                # Draft object: {"id": draft_id, "message": {...full message...}}
                msg_json = draft_json.get("message", {})
                msg_id = msg_json.get("id", draft_id)
                payload = msg_json.get("payload", {})
                hdrs = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                subject = hdrs.get("subject", "(No Subject)") or "(No Subject)"
                to_raw = hdrs.get("to", "")
                recipients = [r.strip() for r in to_raw.split(",") if r.strip()]
                body = _extract_gmail_body(payload)
                internal_date_ms = msg_json.get("internalDate", "")
                last_modified = None
                if internal_date_ms:
                    try:
                        last_modified = datetime.fromtimestamp(
                            int(internal_date_ms) / 1000, tz=timezone.utc
                        )
                    except Exception:
                        pass
                # Detect attachments: parts with filename set
                all_parts = payload.get("parts", [])
                att_names = [
                    p.get("filename", "") for p in all_parts
                    if p.get("filename") and p.get("mimeType", "") not in ("text/plain", "text/html")
                ]
                drafts.append({
                    "message_id": msg_id,
                    "provider": "gmail",
                    "owner_email": user_email,
                    "subject": subject,
                    "body": body,
                    "body_preview": body[:500] if body else "",
                    "recipients": recipients,
                    "has_attachment": len(att_names) > 0,
                    "attachment_names": att_names,
                    "last_modified_at": last_modified,
                })
    except Exception as e:
        logger.error(f"Error fetching Gmail drafts for {user_email}: {e}")
    return drafts


async def _fetch_m365_drafts(user_email: str, access_token: str) -> list[dict]:
    """Fetch all draft messages from M365 for a user with pagination."""
    drafts = []
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            next_link: Optional[str] = (
                f"{GRAPH_API_BASE}/users/{user_email}/mailFolders/drafts/messages"
                f"?$top=100&$select=id,subject,toRecipients,body,hasAttachments,lastModifiedDateTime"
            )
            all_msgs: list[dict] = []
            while next_link:
                resp = await client.get(next_link, headers=headers)
                if resp.status_code != 200:
                    logger.warning(f"M365 drafts failed for {user_email}: {resp.status_code} {resp.text[:200]}")
                    break
                resp_json = resp.json()
                all_msgs.extend(resp_json.get("value", []))
                next_link = resp_json.get("@odata.nextLink")
            logger.info(f"M365 drafts: found {len(all_msgs)} drafts for {user_email}")
            for msg in all_msgs:
                subject = msg.get("subject", "(No Subject)") or "(No Subject)"
                recipients = [
                    r.get("emailAddress", {}).get("address", "")
                    for r in msg.get("toRecipients", [])
                ]
                body_content = msg.get("body", {}).get("content", "") or ""
                # Strip HTML tags for plain text preview
                body_plain = re.sub(r"<[^>]+>", " ", body_content).strip()
                body_plain = re.sub(r"\s+", " ", body_plain)

                last_mod_str = msg.get("lastModifiedDateTime", "")
                last_modified = None
                if last_mod_str:
                    try:
                        last_modified = datetime.fromisoformat(last_mod_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                drafts.append({
                    "message_id": msg.get("id", ""),
                    "provider": "m365",
                    "owner_email": user_email,
                    "subject": subject,
                    "body": body_plain,
                    "body_preview": body_plain[:500],
                    "recipients": [r for r in recipients if r],
                    "has_attachment": msg.get("hasAttachments", False),
                    "attachment_names": [],
                    "last_modified_at": last_modified,
                })
    except Exception as e:
        logger.error(f"Error fetching M365 drafts for {user_email}: {e}")
    return drafts


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
async def list_drafts(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    classification: Optional[str] = Query(None),
    owner_email: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("analyzed_at"),
    sort_order: Optional[str] = Query("desc"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size

    # Validate sort params
    _allowed_sort_by = {"analyzed_at", "last_modified_at"}
    _allowed_sort_order = {"asc", "desc"}
    _sort_col = sort_by if sort_by in _allowed_sort_by else "analyzed_at"
    _sort_dir = sort_order.upper() if sort_order and sort_order.lower() in _allowed_sort_order else "DESC"

    where_clauses = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}

    if classification:
        where_clauses.append("dlp_classification = :classification")
        params["classification"] = classification
    if owner_email:
        where_clauses.append("owner_email ILIKE :owner_email")
        params["owner_email"] = f"%{owner_email}%"
    if provider:
        # Normalize: outlook → m365, google → gmail
        _prov = provider.lower()
        if _prov in ("outlook", "m365"):
            _prov = "m365"
        elif _prov in ("google", "gmail"):
            _prov = "gmail"
        where_clauses.append("provider = :provider")
        params["provider"] = _prov

    where_sql = " AND ".join(where_clauses)

    total_row = await db.execute(
        text(f"SELECT COUNT(*) FROM draft_events WHERE {where_sql}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")},
    )
    total = total_row.scalar() or 0

    rows = await db.execute(
        text(f"""
            SELECT id, message_id, provider, owner_email, subject, body_preview,
                   recipients, has_attachment, attachment_names,
                   dlp_classification, dlp_categories, dlp_score, dlp_explanation,
                   last_modified_at, analyzed_at, created_at
            FROM draft_events
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
            "recipients": row["recipients"] or [],
            "has_attachment": row["has_attachment"],
            "attachment_names": row["attachment_names"] or [],
            "dlp_classification": row["dlp_classification"],
            "dlp_categories": row["dlp_categories"] or [],
            "dlp_score": row["dlp_score"],
            "dlp_explanation": row["dlp_explanation"],
            "last_modified_at": row["last_modified_at"].isoformat() if row["last_modified_at"] else None,
            "analyzed_at": row["analyzed_at"].isoformat() if row["analyzed_at"] else None,
        })

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def draft_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    row = await db.execute(
        text("""
            SELECT
                COUNT(*) AS total_analyzed,
                COUNT(*) FILTER (WHERE dlp_classification = 'CLEAN') AS clean,
                COUNT(*) FILTER (WHERE dlp_classification = 'SENSITIVE') AS sensitive,
                COUNT(*) FILTER (WHERE dlp_classification = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE dlp_classification IS NULL OR dlp_classification = 'PENDING') AS pending,
                MAX(analyzed_at) AS last_scan_at
            FROM draft_events
            WHERE org_id = :org_id
        """),
        {"org_id": org_id},
    )
    r = row.mappings().first()
    return {
        "total_analyzed": r["total_analyzed"] or 0,
        "clean": r["clean"] or 0,
        "sensitive": r["sensitive"] or 0,
        "critical": r["critical"] or 0,
        "pending": r["pending"] or 0,
        "last_scan_at": r["last_scan_at"].isoformat() if r["last_scan_at"] else None,
    }


# ── Core scan helper (used by route + background service) ────────────────────

async def _scan_org_drafts(org_id: str, db: AsyncSession) -> dict:
    """Fetch + DLP-analyse drafts for one org. Returns {scanned, sensitive, critical}."""
    import hashlib as _hs
    from backend.models.db_models import Threat, User
    import uuid as _uuid_mod

    integrations = await _get_org_integrations(org_id, db)
    if not integrations:
        return {"scanned": 0, "sensitive": 0, "critical": 0}

    # Snapshot integration fields while session is open (avoid lazy-load issues)
    integration_snaps = [
        {
            "provider": i.provider or "",
            "access_token_enc": i.access_token_enc or "",
            "refresh_token_enc": i.refresh_token_enc or "",
            "org_domain": i.org_domain or "",
        }
        for i in integrations
    ]

    # Get all active user emails for this org from the users table
    users_result = await db.execute(
        select(User.email, User.directory_provider).where(
            User.org_id == org_id,
            User.is_active == True,
        )
    )
    user_rows = users_result.all()
    all_user_emails = [r.email for r in user_rows]
    # Release the read locks (organizations/users/org_integrations) taken above
    # BEFORE entering the slow per-draft loop (Gmail + Claude network calls).
    # Otherwise this session stays 'idle in transaction' for minutes holding an
    # AccessShareLock that blocks startup ALTER TABLE guards and stalls all reads.
    try:
        await db.commit()
    except Exception:
        await db.rollback()
    # For Gmail: users whose email domain matches the integration's org_domain,
    # OR whose directory_provider is null/google. Fall back to all users if no domain match.
    # For M365: users with directory_provider='m365', OR @<m365_tenant_domain> emails.
    # We resolve per-integration below using org_domain.

    org_uuid = _uuid_mod.UUID(org_id)
    scanned = 0
    sensitive_count = 0
    critical_count = 0

    for snap in integration_snaps:
        provider = snap["provider"]
        enc_at = snap["access_token_enc"]
        enc_rt = snap["refresh_token_enc"]
        access_token = _decrypt(enc_at) if enc_at else ""
        refresh_token = _decrypt(enc_rt) if enc_rt else ""

        logger.info(f"Draft scan: integration provider={provider} domain={snap['org_domain']} at_len={len(access_token)} rt_len={len(refresh_token)}")
        if not access_token or access_token == "demo_access_token":
            logger.warning(f"Draft scan: skipping integration provider={provider} - access_token empty/demo")
            continue

        # Refresh token if needed and resolve user list for this integration
        org_domain = snap["org_domain"] or ""
        if provider in ("gmail", "google"):
            try:
                from backend.services.delta_sync import _refresh_google_token
                new_tok = await _refresh_google_token(refresh_token)
                if new_tok:
                    access_token = new_tok
            except Exception:
                pass
            # Use users whose email matches this integration's org_domain, falling back to all users
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
            # Use users matching the M365 tenant domain, or directory_provider=m365
            if org_domain:
                domain_users = [e for e in all_user_emails if e.endswith("@" + org_domain)]
                m365_dp_users = [r.email for r in user_rows if r.directory_provider == "m365"]
                user_emails = list(set(domain_users + m365_dp_users)) or all_user_emails
            else:
                user_emails = [r.email for r in user_rows if r.directory_provider == "m365"] or all_user_emails
        else:
            continue

        for user_email in user_emails:
            # Fetch drafts for this user from their mailbox
            try:
                if provider in ("gmail", "google"):
                    # Use DWD service account impersonation via run_in_executor (most reliable)
                    gmail_token = access_token  # OAuth fallback
                    try:
                        import asyncio as _asyncio
                        from backend.services.baseline_ingestion import _get_service_account_headers_sync
                        sa_hdrs = await _asyncio.get_running_loop().run_in_executor(
                            None, _get_service_account_headers_sync, user_email
                        )
                        if sa_hdrs:
                            gmail_token = sa_hdrs.get("Authorization", "").replace("Bearer ", "")
                            logger.info(f"Draft scan: SA DWD token obtained for {user_email}")
                        else:
                            logger.warning(f"Draft scan: SA returned None for {user_email}, using OAuth")
                    except Exception as _sa_exc:
                        logger.warning(f"Draft scan: SA failed for {user_email}: {_sa_exc}, using OAuth")
                    logger.info(f"Draft scan: calling gmail for {user_email} with token_len={len(gmail_token) if gmail_token else 0}")
                    drafts = await _fetch_gmail_drafts(user_email, gmail_token)
                else:
                    drafts = await _fetch_m365_drafts(user_email, access_token)
            except Exception as e:
                logger.warning(f"Failed to fetch drafts for {user_email}: {e}")
                continue

            for draft in drafts:
                message_id = draft["message_id"]
                subject = draft["subject"]
                body_preview = draft["body_preview"]

                try:
                    # Run DLP classification in its OWN session to prevent poisoning the draft scan session
                    from backend.database import AsyncSessionLocal as _DraftDLPSession
                    async with _DraftDLPSession() as _dlp_db:
                        try:
                            dlp_result = await classify_email(
                                {
                                    "subject": subject,
                                    "body": draft["body"],
                                    "sender": user_email,
                                    "recipients": draft["recipients"],
                                },
                                org_id,
                                _dlp_db,
                                auto_commit=False,
                                prefer_claude=True,  # Use Claude directly for drafts - faster & more reliable
                            )
                        except Exception as _dlp_inner:
                            logger.warning(f"DLP classify inner error for {message_id}: {_dlp_inner}")
                            await _dlp_db.rollback()
                            dlp_result = {"risk_level": "low", "categories": [], "score": 0}
                    risk_level = dlp_result.get("risk_level", "low").upper()
                    if risk_level in ("HIGH", "CRITICAL"):
                        dlp_classification = "CRITICAL"
                        critical_count += 1
                    elif risk_level == "MEDIUM":
                        dlp_classification = "SENSITIVE"
                        sensitive_count += 1
                    else:
                        dlp_classification = "CLEAN"

                    categories = dlp_result.get("categories", [])
                    # Use explicit score from DeepSeek if provided, else derive from risk_level
                    if dlp_result.get("score") is not None:
                        score = int(dlp_result["score"])
                    else:
                        _risk_score_map = {"low": 5, "medium": 45, "high": 75, "critical": 95}
                        score = _risk_score_map.get((dlp_result.get("risk_level") or "low").lower(), 5)
                        # Blend confidence: only adjust if categories detected
                        if categories:
                            confidence = float(dlp_result.get("confidence") or 0.5)
                            score = min(100, max(0, int(score + (confidence - 0.5) * 20)))
                    explanation = dlp_result.get("explanation", "")

                except Exception as e:
                    logger.error(f"DLP classification failed for draft {message_id}: {e}")
                    dlp_classification = "PENDING"
                    categories = []
                    score = 0
                    explanation = ""

                # Upsert into draft_events
                try:
                    await db.execute(
                        text("""
                            INSERT INTO draft_events
                                (org_id, message_id, provider, owner_email, subject,
                                 body_preview, recipients, has_attachment, attachment_names,
                                 dlp_classification, dlp_categories, dlp_score, dlp_explanation,
                                 last_modified_at, analyzed_at)
                            VALUES
                                (:org_id, :message_id, :provider, :owner_email, :subject,
                                 :body_preview, :recipients, :has_attachment, :attachment_names,
                                 :dlp_classification, :dlp_categories, :dlp_score, :dlp_explanation,
                                 :last_modified_at, NOW())
                            ON CONFLICT (org_id, message_id) DO UPDATE SET
                                subject = EXCLUDED.subject,
                                body_preview = EXCLUDED.body_preview,
                                recipients = EXCLUDED.recipients,
                                has_attachment = EXCLUDED.has_attachment,
                                attachment_names = EXCLUDED.attachment_names,
                                dlp_classification = EXCLUDED.dlp_classification,
                                dlp_categories = EXCLUDED.dlp_categories,
                                dlp_score = EXCLUDED.dlp_score,
                                dlp_explanation = EXCLUDED.dlp_explanation,
                                last_modified_at = EXCLUDED.last_modified_at,
                                analyzed_at = NOW()
                        """),
                        {
                            "org_id": org_id,
                            "message_id": message_id,
                            "provider": provider,
                            "owner_email": user_email,
                            "subject": subject,
                            "body_preview": body_preview,
                            "recipients": draft["recipients"],
                            "has_attachment": draft["has_attachment"],
                            "attachment_names": draft["attachment_names"],
                            "dlp_classification": dlp_classification,
                            "dlp_categories": categories,
                            "dlp_score": score,
                            "dlp_explanation": explanation,
                            "last_modified_at": draft["last_modified_at"],
                        },
                    )
                    scanned += 1
                    # Commit each draft immediately so the session never holds
                    # an open transaction across the next draft's network calls.
                    await db.commit()
                except Exception as e:
                    logger.warning(f"Failed to upsert draft_event for {message_id}: {e}")
                    # CRITICAL: must rollback the aborted transaction or every
                    # subsequent query on this session will fail with
                    # InFailedSQLTransactionError. The loop processes 50+ drafts;
                    # one transient failure would otherwise cascade to all of them.
                    try:
                        await db.rollback()
                    except Exception as rb_exc:
                        logger.debug(f"rollback after draft upsert failure also failed (non-fatal): {rb_exc}")
                    continue

                # Funnel sensitive drafts to Threat Queue — use separate session to avoid poisoning draft scan
                # Mark as exclude_auto_triage=True so auto-triage engine skips it
                if score >= 60:
                    try:
                        from backend.database import AsyncSessionLocal as _ThreatSession
                        draft_subject = f"[DRAFT] {subject}"
                        subject_hash = _hs.sha256(draft_subject.encode()).hexdigest()[:64]
                        
                        # Build category description for alert
                        cat_descriptions = {
                            "credential_": "🔐 Credentials/API Keys",
                            "financial_": "💰 Financial Data",
                            "pii_": "👤 Personal Identifiable Information (PII)",
                            "hr_": "📁 HR/Employee Data",
                            "legal_": "⚖️ Legal/Confidential",
                            "hipaa_": "🏥 Healthcare (HIPAA)",
                            "bulk_exfil": "⚠️ Bulk Data Exfiltration",
                        }
                        flagged_types = []
                        for cat in categories:
                            for prefix, desc in cat_descriptions.items():
                                if cat.startswith(prefix) or cat == prefix.rstrip("_"):
                                    if desc not in flagged_types:
                                        flagged_types.append(desc)
                        
                        async with _ThreatSession() as _tdb:
                            try:
                                # Check if threat already exists
                                existing = await _tdb.execute(
                                    text("SELECT id FROM threats WHERE email_message_id = :msg_id AND org_id = :org_id"),
                                    {"msg_id": message_id, "org_id": str(org_uuid)}
                                )
                                is_new_threat = not existing.scalar()
                                
                                await _tdb.execute(
                                    text("""
                                        INSERT INTO threats
                                            (id, org_id, email_message_id, sender, sender_domain,
                                             recipient_email, subject, subject_hash,
                                             threat_type, risk_score, status, action_taken,
                                             ai_explanation_en, ai_explanation_ar,
                                             threat_indicators, detected_at, created_at, email_body_preview,
                                             exclude_auto_triage)
                                        VALUES
                                            (gen_random_uuid(), :org_id, :msg_id, :sender, :sender_domain,
                                             :recipient_email, :subject, :subject_hash,
                                             'DLP_DRAFT', :score, 'open', 'DRAFT_DLP_ALERT',
                                             :exp_en, :exp_ar,
                                             CAST(:indicators AS jsonb), NOW(), NOW(), :preview, TRUE)
                                        ON CONFLICT (email_message_id, org_id, recipient_email)
                                            WHERE email_message_id IS NOT NULL
                                              AND email_message_id != ''
                                              AND recipient_email IS NOT NULL
                                        DO UPDATE SET
                                            risk_score = EXCLUDED.risk_score,
                                            ai_explanation_en = EXCLUDED.ai_explanation_en,
                                            threat_indicators = EXCLUDED.threat_indicators,
                                            detected_at = NOW()
                                    """),
                                    {
                                        "org_id": str(org_uuid),
                                        "msg_id": message_id,
                                        "sender": user_email,
                                        "sender_domain": user_email.split("@")[-1] if "@" in user_email else "",
                                        "recipient_email": user_email,
                                        "subject": draft_subject,
                                        "subject_hash": subject_hash,
                                        "score": score,
                                        "exp_en": f"Sensitive content detected in draft: {explanation}",
                                        "exp_ar": f"تم اكتشاف محتوى حساس في المسودة: {explanation}",
                                        "indicators": json.dumps({"dlp_categories": categories}),
                                        "preview": (body_preview or "")[:500],
                                    }
                                )
                                await _tdb.commit()
                                
                                # Send admin email notification for new sensitive drafts
                                if is_new_threat:
                                    await _send_draft_alert_email(
                                        org_id=str(org_uuid),
                                        user_email=user_email,
                                        subject=subject,
                                        categories=categories,
                                        flagged_types=flagged_types,
                                        score=score,
                                        explanation=explanation,
                                        db=_tdb,
                                    )
                            except Exception as _te:
                                logger.warning(f"DLP_DRAFT threat insert failed (non-fatal): {_te}")
                                await _tdb.rollback()
                    except Exception as e:
                        logger.warning(f"Failed to create DLP_DRAFT threat for {message_id}: {e}")

    return {"scanned": scanned, "sensitive": sensitive_count, "critical": critical_count}
@router.post("/scan")
async def scan_drafts(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a draft scan. Runs in the background to avoid 504 timeout."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    async def _bg_scan():
        from backend.database import AsyncSessionLocal
        async with AsyncSessionLocal() as bg_db:
            try:
                await _scan_org_drafts(org_id, bg_db)
                await bg_db.commit()
            except Exception as e:
                logger.error(f"Background draft scan failed for org {org_id}: {e}")
                try:
                    await bg_db.rollback()
                except Exception:
                    pass

    import asyncio
    asyncio.create_task(_bg_scan())
    return {"status": "scanning", "message": "Draft scan started in background. Refresh in ~30s."}


@router.post("/dedup")
async def dedup_drafts(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove duplicate draft_events rows (keep latest per org+message_id) and apply UNIQUE constraint."""
    org_id = str(current_user.org_id)

    # Step 1: delete duplicates keeping the row with the latest analyzed_at
    result = await db.execute(text("""
        DELETE FROM draft_events
        WHERE id NOT IN (
            SELECT DISTINCT ON (org_id, message_id) id
            FROM draft_events
            ORDER BY org_id, message_id, analyzed_at DESC
        )
        AND org_id = :org_id
    """), {"org_id": org_id})
    deleted = result.rowcount
    await db.commit()

    # Step 2: try to add UNIQUE constraint (idempotent)
    try:
        await db.execute(text("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'draft_events_org_id_message_id_key'
                      AND conrelid = 'draft_events'::regclass
                ) THEN
                    ALTER TABLE draft_events
                    ADD CONSTRAINT draft_events_org_id_message_id_key UNIQUE (org_id, message_id);
                END IF;
            END $$;
        """))
        await db.commit()
        constraint_added = True
    except Exception as e:
        logger.warning(f"Could not add UNIQUE constraint (may already exist or still have violations): {e}")
        await db.rollback()
        constraint_added = False

    # Count remaining
    count_result = await db.execute(
        text("SELECT COUNT(*) FROM draft_events WHERE org_id = :org_id"),
        {"org_id": org_id}
    )
    remaining = count_result.scalar() or 0

    return {
        "deleted_duplicates": deleted,
        "remaining": remaining,
        "unique_constraint_applied": constraint_added,
    }
