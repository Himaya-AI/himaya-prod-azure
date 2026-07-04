"""
Inbox Posture Management — enterprise tier
Scans OAuth/delegated apps, inbox rules, and auto-forwarding rules across M365 and Google.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from backend.database import get_db
from backend.models.db_models import OrgIntegration
from backend.routers.auth import get_current_user
from backend.services.baseline_ingestion import _decrypt, _refresh_m365_token, _refresh_google_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/posture", tags=["posture"])


async def _require_enterprise(current_user, db: AsyncSession):
    """Raise 403 if org is not on Enterprise tier."""
    from backend.models.db_models import Organization as _Org
    _org = (await db.execute(
        select(_Org).where(_Org.id == current_user.org_id)
    )).scalar_one_or_none()
    _tier = (getattr(_org, "tier", None) or "Launch").strip().lower()
    if _tier not in ("enterprise", "enterprise trial"):
        raise HTTPException(
            status_code=403,
            detail="Inbox Posture Management requires an Enterprise plan. Upgrade to access this feature."
        )

GRAPH = "https://graph.microsoft.com/v1.0"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1"
ADMIN_API = "https://admin.googleapis.com/admin/directory/v1"

# ── Scope risk scoring ────────────────────────────────────────────────────────

# ── OAuth / Add-on scope risk definitions ─────────────────────────────────────

# Scopes that give write/send/delete power — immediate HIGH risk
_HIGH_RISK_SCOPES_M365 = {
    "Mail.ReadWrite", "Mail.ReadWrite.All",
    "Mail.Send", "Mail.Send.All",
    "MailboxSettings.ReadWrite",
    "full_access_as_user",
    "EWS.AccessAsUser.All",           # legacy EWS full access
    "Calendars.ReadWrite",            # calendar write can be used to plant meetings/phish
    "Contacts.ReadWrite",
    "User.ReadWrite.All",             # can modify user accounts
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",  # privilege escalation
    "AppRoleAssignment.ReadWrite.All",
    "offline_access",                 # flag: persistent token — always combine with other high
}
_HIGH_RISK_SCOPES_GOOGLE = {
    "https://mail.google.com/",                               # full Gmail access
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.settings.sharing",  # can set forwarding/delegates
    "https://www.googleapis.com/auth/gmail.settings.basic",    # can set filters/labels
    "https://www.googleapis.com/auth/admin.directory.user",    # full user admin
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/drive",                   # full Drive — exfil risk
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/contacts",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement",
}
_HIGH_RISK_SCOPES = _HIGH_RISK_SCOPES_M365 | _HIGH_RISK_SCOPES_GOOGLE

# Scopes that allow read-only or limited access — MEDIUM risk
_MEDIUM_RISK_SCOPES_M365 = {
    "Mail.Read", "Mail.Read.All",
    "MailboxSettings.Read",
    "Calendars.Read",
    "Contacts.Read",
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
}
_MEDIUM_RISK_SCOPES_GOOGLE = {
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.metadata",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
}
_MEDIUM_RISK_SCOPES = _MEDIUM_RISK_SCOPES_M365 | _MEDIUM_RISK_SCOPES_GOOGLE

# Scopes that are suspicious when combined with high-risk ones
_PERSISTENCE_SCOPES = {"offline_access", "https://www.googleapis.com/auth/gmail.settings.sharing"}

# Common personal email domains used in forwarding exfiltration
_PERSONAL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
    "protonmail.com", "proton.me", "icloud.com", "me.com", "aol.com",
    "yandex.com", "mail.com", "gmx.com", "tutanota.com", "fastmail.com",
    "zoho.com", "live.com", "msn.com",
}

# Security-related senders — rules that target these and delete/hide are high risk
_SECURITY_SENDERS = [
    "security", "alert", "noreply", "no-reply", "it@", "helpdesk", "support",
    "admin", "postmaster", "abuse", "compliance", "audit", "soc@", "siem",
    "helios", "himaya", "defender", "microsoft", "google", "okta", "duo",
    "mfa", "2fa", "authentication", "password", "login", "signin",
]

# Known legitimate security/productivity apps — lower suspicion
_KNOWN_SAFE_APPS = {
    "microsoft teams", "microsoft outlook", "microsoft onedrive", "microsoft sharepoint",
    "gmail", "google drive", "google calendar", "google meet",
    "slack", "zoom", "salesforce", "hubspot", "zendesk", "jira", "confluence",
    "dropbox", "box", "docusign", "adobe sign", "grammarly",
    "helios phish reporter", "himaya",
}


def _score_scopes(scopes: list[str]) -> tuple[str, list[str]]:
    """Comprehensive OAuth scope risk scoring with detailed reasons."""
    reasons: list[str] = []
    scope_set = set(scopes)

    # ── High-risk scope checks ─────────────────────────────────────────────
    if scope_set & {"Mail.Send", "Mail.Send.All"}:
        reasons.append("Can send email as any user in the org (phishing/impersonation risk)")
    if scope_set & {"https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.compose"}:
        reasons.append("Can compose and send email on behalf of users")
    if scope_set & {"Mail.ReadWrite", "Mail.ReadWrite.All"}:
        reasons.append("Can read, move, and permanently delete any email")
    if scope_set & {"https://mail.google.com/", "https://www.googleapis.com/auth/gmail.modify"}:
        reasons.append("Has full Gmail access — read, send, delete, label")
    if scope_set & {"MailboxSettings.ReadWrite"}:
        reasons.append("Can modify mailbox settings including auto-forwarding rules")
    if scope_set & {"https://www.googleapis.com/auth/gmail.settings.sharing"}:
        reasons.append("Can configure email forwarding and delegates on behalf of users")
    if scope_set & {"https://www.googleapis.com/auth/gmail.settings.basic"}:
        reasons.append("Can create/modify inbox filters and labels")
    if scope_set & {"EWS.AccessAsUser.All"}:
        reasons.append("Legacy EWS full mailbox access — broad and difficult to audit")
    if scope_set & {"full_access_as_user"}:
        reasons.append("Full delegated mailbox access — equivalent to user owning the inbox")
    if scope_set & {"User.ReadWrite.All", "Directory.ReadWrite.All"}:
        reasons.append("Can modify user accounts and directory — privilege escalation risk")
    if scope_set & {"RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All"}:
        reasons.append("Can assign admin roles — critical privilege escalation vector")
    if scope_set & {"https://www.googleapis.com/auth/admin.directory.rolemanagement"}:
        reasons.append("Can manage Google Workspace admin roles")
    if scope_set & {"https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file"}:
        reasons.append("Full Google Drive access — data exfiltration risk")
    if scope_set & {"https://www.googleapis.com/auth/admin.directory.user", "https://www.googleapis.com/auth/admin.directory.user.security"}:
        reasons.append("Can manage Workspace users and security settings")

    # ── Persistence / combinatorial risk ──────────────────────────────────
    has_high = bool(scope_set & _HIGH_RISK_SCOPES)
    has_persistence = bool(scope_set & _PERSISTENCE_SCOPES)
    if has_high and has_persistence:
        reasons.append("Holds a persistent refresh token combined with high-risk scopes — access survives password resets")
    elif has_persistence and not has_high:
        reasons.append("Has offline_access (persistent token) — review periodically")

    # ── Medium-risk checks (only add if not already high) ─────────────────
    if not has_high:
        if scope_set & {"Mail.Read", "Mail.Read.All"}:
            reasons.append("Can read all email content for any user")
        if scope_set & {"https://www.googleapis.com/auth/gmail.readonly"}:
            reasons.append("Read-only access to Gmail messages and metadata")
        if scope_set & {"https://www.googleapis.com/auth/gmail.metadata"}:
            reasons.append("Can read email headers and metadata (sender, subject, dates)")
        if scope_set & {"AuditLog.Read.All", "Reports.Read.All"}:
            reasons.append("Can read org audit logs and reports — useful for reconnaissance")
        if scope_set & {"User.Read.All", "Directory.Read.All"}:
            reasons.append("Can enumerate all users and org structure")
        if scope_set & {"Calendars.Read", "https://www.googleapis.com/auth/calendar.readonly"}:
            reasons.append("Can read calendar data — useful for targeted phishing")
        if scope_set & {"https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/drive.metadata.readonly"}:
            reasons.append("Read-only Drive access — can view file names and contents")

    has_medium = bool(scope_set & _MEDIUM_RISK_SCOPES)

    if has_high:
        return "high", reasons
    if has_medium:
        return "medium", reasons
    return "low", reasons


def _score_rule(rule_name: str, conditions: str, actions: str) -> tuple[str, list[str]]:
    """Comprehensive inbox rule risk scoring."""
    reasons: list[str] = []
    name_lower = rule_name.lower()
    lower_actions = actions.lower()
    lower_cond = conditions.lower()

    # ── HIGH: Forwarding / Redirect ────────────────────────────────────────
    is_forwarding = any(k in lower_actions for k in ["forward", "redirect"])
    if is_forwarding:
        reasons.append("Automatically forwards or redirects incoming email")
        # Extract destination domain if visible
        for personal_dom in _PERSONAL_DOMAINS:
            if personal_dom in lower_actions:
                reasons.append(f"Destination includes personal email domain ({personal_dom}) — classic exfiltration pattern")
                return "high", reasons
        # Generic external forwarding is still high
        reasons.append("All forwarding rules should be verified — common attacker persistence technique")
        return "high", reasons

    # ── HIGH: Deleting security/IT emails ──────────────────────────────────
    is_deleting = any(k in lower_actions for k in ["delete", "trash", "permanently delete"])
    targets_security = any(s in lower_cond for s in _SECURITY_SENDERS)
    if is_deleting and targets_security:
        reasons.append("Deletes emails from security/IT/auth senders — used to hide breach alerts, MFA codes, or password reset emails")
        return "high", reasons

    # ── HIGH: Scripting / macros ───────────────────────────────────────────
    if any(k in lower_actions for k in ["run script", "run a script", "execute"]):
        reasons.append("Executes a script or macro — advanced attacker persistence technique")
        return "high", reasons

    # ── HIGH: Suspicious rule names (attacker naming patterns) ─────────────
    _suspicious_names = [
        "...", "   ", "test", "temp", "tmp", "aaa", "zzz", "xxx",
        "rule1", "rule 1", "important", "do not delete",
    ]
    if any(name_lower == s or name_lower.startswith(s) for s in _suspicious_names):
        reasons.append(f"Rule name '{rule_name}' matches known attacker obfuscation patterns (blank, test, temp names)")
        # Downgrade to medium unless combined with bad actions
        if is_deleting or is_forwarding:
            return "high", reasons

    # ── HIGH: Move to obscure folder + mark read ───────────────────────────
    is_moving = "move" in lower_actions or "move to folder" in lower_actions
    is_marking_read = "mark as read" in lower_actions
    if is_moving and is_marking_read:
        reasons.append("Moves email to a folder AND marks as read — hides messages from the user without deleting them")
        return "high", reasons

    # ── MEDIUM: Deleting non-security emails ───────────────────────────────
    if is_deleting:
        reasons.append("Permanently deletes matched emails — verify this is intentional")
        return "medium", reasons

    # ── MEDIUM: Mark as read only ──────────────────────────────────────────
    if is_marking_read:
        reasons.append("Auto-marks emails as read — user may not see important messages")
        if targets_security:
            reasons.append("Targets security/auth senders — could hide MFA codes or alerts")
            return "high", reasons
        return "medium", reasons

    # ── MEDIUM: Archive/skip inbox ────────────────────────────────────────
    if "skip inbox" in lower_actions or "archive" in lower_actions:
        if targets_security:
            reasons.append("Archives emails from security senders — hides alerts from inbox")
            return "high", reasons
        reasons.append("Skips inbox (archives) — verify important emails aren't being hidden")
        return "medium", reasons

    # ── MEDIUM: Stop processing rules ─────────────────────────────────────
    if "stop processing" in lower_actions:
        reasons.append("Stops other rules from running — may be used to bypass security rules")
        return "medium", reasons

    # ── MEDIUM: Targets security senders even with mild actions ───────────
    if targets_security and (is_moving or "label" in lower_actions):
        reasons.append("Targets security/auth senders — moving or labeling these may hide alerts")
        return "medium", reasons

    return "low", []


def _score_forwarding(mailbox: str, forward_to: str, org_domain: str = "") -> tuple[str, list[str]]:
    """Score a direct auto-forwarding rule."""
    reasons: list[str] = []
    fwd_domain = forward_to.split("@")[1].lower() if "@" in forward_to else forward_to.lower()
    mailbox_domain = mailbox.split("@")[1].lower() if "@" in mailbox else ""

    is_external = fwd_domain != mailbox_domain and fwd_domain != org_domain

    if not is_external:
        return "low", ["Forwards to internal address — low risk"]

    if fwd_domain in _PERSONAL_DOMAINS:
        reasons.append(f"Forwards to personal email domain ({fwd_domain}) — high exfiltration risk")
        reasons.append("Personal email domains are not controlled by your org's security policies")
        return "high", reasons

    reasons.append(f"Forwards externally to {fwd_domain} — verify this is an authorized business destination")
    reasons.append("External forwarding bypasses your org's DLP and retention policies")
    return "high", reasons


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_m365_app_token() -> str:
    """Get an app-only M365 token via client credentials.
    Tries the app-registration tenant (M365_APP_TENANT_ID) first — this is where
    Application.Read.All and servicePrincipal permissions are granted.
    Falls back to the connected org tenant (M365_TENANT_ID) for email operations."""
    import os as _os
    import base64 as _b64, json as _jj
    client_id = _os.getenv("M365_CLIENT_ID", "")
    client_secret = _os.getenv("M365_CLIENT_SECRET", "")
    # Prefer the app's own tenant (where Application.Read.All is consented)
    # Fall back to the connected org tenant
    app_tenant = _os.getenv("M365_APP_TENANT_ID", "") or _os.getenv("M365_TENANT_ID", "")
    if not all([client_id, client_secret, app_tenant]):
        return ""
    try:
        async with httpx.AsyncClient(timeout=15) as _c:
            r = await _c.post(
                f"https://login.microsoftonline.com/{app_tenant}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            if r.status_code == 200:
                token = r.json().get("access_token", "")
                # Verify Application.Read.All is in the token before returning
                try:
                    payload = token.split(".")[1]
                    payload += "=" * (4 - len(payload) % 4)
                    roles = _jj.loads(_b64.urlsafe_b64decode(payload)).get("roles", [])
                    if "Application.Read.All" in roles or "Application.ReadWrite.All" in roles:
                        logger.info(f"posture: M365 app token has Application.Read.All ✓ (tenant={app_tenant[:8]}...)")
                        return token
                    else:
                        logger.debug(f"posture: M365 app token missing Application.Read.All, roles={roles}")
                        return token  # return anyway, may still work for other ops
                except Exception:
                    return token
            logger.warning(f"posture: M365 app token failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        logger.warning(f"posture: M365 app token error: {e}")
    return ""


async def _get_active_integration(db, org_id, provider: str) -> Optional[dict]:
    """Return a token-refreshed integration snapshot or None."""
    res = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == provider,
            OrgIntegration.status == "active",
        )
    )
    integ = res.scalar_one_or_none()
    if not integ:
        return None
    enc_at = integ.access_token_enc or ""
    enc_rt = integ.refresh_token_enc or ""
    at = _decrypt(enc_at) if enc_at else ""
    rt = _decrypt(enc_rt) if enc_rt else ""
    if provider == "m365":
        # Keep the delegated sana085 token for mailbox scanning (inbox rules, messages)
        # The app-only himayaai token is fetched separately in _run_posture_scan as _sp_headers
        new_at = await _refresh_m365_token(rt)
        if new_at:
            at = new_at
    elif provider == "google":
        new_at = await _refresh_google_token(rt)
        if new_at:
            at = new_at
    return {"access_token": at, "refresh_token": rt, "org_id": str(org_id)}


async def _get_m365_users(client: httpx.AsyncClient, headers: dict) -> list[str]:
    """Return list of user emails from Graph /users."""
    try:
        r = await client.get(
            f"{GRAPH}/users?$select=mail,userPrincipalName,accountEnabled&$top=200",
            headers=headers,
        )
        if r.status_code == 200:
            return [
                u.get("mail") or u.get("userPrincipalName", "")
                for u in r.json().get("value", [])
                if u.get("accountEnabled", True) and (u.get("mail") or u.get("userPrincipalName"))
            ]
    except Exception as e:
        logger.warning(f"posture: M365 user fetch failed: {e}")
    return []


async def _get_google_users(db, org_id) -> list[str]:
    """Return list of active user emails from our DB (Google users)."""
    from backend.models.db_models import User
    res = await db.execute(
        select(User.email).where(
            User.org_id == org_id,
            User.is_active.is_not(False),
            User.directory_provider == "google",
        )
    )
    return [r[0] for r in res.all() if r[0]]


# ── Summary ───────────────────────────────────────────────────────────────────

@router.get("/summary")
async def get_posture_summary(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return cached posture summary from DB/Redis if available, else compute from last scan."""
    await _require_enterprise(current_user, db)
    try:
        # Read from a lightweight posture_cache table or fall back to scanning key metrics
        # For now: read counts from DB-persisted posture data
        from sqlalchemy import text as _t
        # Apps
        apps_r = await db.execute(_t(
            "SELECT COUNT(*), SUM(CASE WHEN risk='high' THEN 1 ELSE 0 END) "
            "FROM posture_apps WHERE org_id=:oid"
        ), {"oid": str(current_user.org_id)})
        apps_row = apps_r.fetchone()
        total_apps = int(apps_row[0] or 0) if apps_row else 0
        high_apps = int(apps_row[1] or 0) if apps_row else 0

        # Rules
        rules_r = await db.execute(_t(
            "SELECT COUNT(*), SUM(CASE WHEN risk='high' THEN 1 ELSE 0 END) "
            "FROM posture_rules WHERE org_id=:oid"
        ), {"oid": str(current_user.org_id)})
        rules_row = rules_r.fetchone()
        total_rules = int(rules_row[0] or 0) if rules_row else 0
        high_rules = int(rules_row[1] or 0) if rules_row else 0

        # Forwards
        fwd_r = await db.execute(_t(
            "SELECT COUNT(*), SUM(CASE WHEN is_external=true THEN 1 ELSE 0 END) "
            "FROM posture_forwards WHERE org_id=:oid"
        ), {"oid": str(current_user.org_id)})
        fwd_row = fwd_r.fetchone()
        total_fwd = int(fwd_row[0] or 0) if fwd_row else 0
        ext_fwd = int(fwd_row[1] or 0) if fwd_row else 0

        # Last scanned
        scan_r = await db.execute(_t(
            "SELECT last_scanned_at FROM posture_scan_log WHERE org_id=:oid ORDER BY last_scanned_at DESC LIMIT 1"
        ), {"oid": str(current_user.org_id)})
        scan_row = scan_r.fetchone()
        last_scanned = scan_row[0].isoformat() if scan_row and scan_row[0] else None

        # Score: 100 - 20*high_apps - 15*high_rules - 25*ext_fwd, floor 0
        score = max(0, 100 - (20 * high_apps) - (15 * high_rules) - (25 * ext_fwd))

        return {
            "posture_score": score,
            "high_risk_apps": high_apps,
            "high_risk_rules": high_rules,
            "external_forwards": ext_fwd,
            "total_apps": total_apps,
            "total_rules": total_rules,
            "total_forwards": total_fwd,
            "last_scanned": last_scanned,
        }
    except Exception as e:
        logger.warning(f"posture summary: DB read failed (tables may not exist yet): {e}")
        return {
            "posture_score": 100,
            "high_risk_apps": 0, "high_risk_rules": 0, "external_forwards": 0,
            "total_apps": 0, "total_rules": 0, "total_forwards": 0,
            "last_scanned": None,
        }


# ── Apps ──────────────────────────────────────────────────────────────────────

@router.get("/apps")
async def get_posture_apps(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return OAuth/delegated apps from DB (populated by scan)."""
    await _require_enterprise(current_user, db)
    try:
        r = await db.execute(
            text(
                "SELECT id, app_name, description, provider, scopes, granted_by, granted_at, risk, risk_reasons, can_revoke "
                "FROM posture_apps WHERE org_id=:oid ORDER BY risk DESC, app_name"
            ),
            {"oid": str(current_user.org_id)},
        )
        rows = r.fetchall()
        import json as _j
        return [
            {
                "id": str(row[0]),
                "name": row[1],
                "description": row[2],
                "provider": row[3],
                "scopes": _j.loads(row[4]) if isinstance(row[4], str) else (row[4] or []),
                "granted_by": row[5],
                "granted_at": row[6].isoformat() if row[6] else None,
                "risk": row[7],
                "risk_reasons": _j.loads(row[8]) if isinstance(row[8], str) else (row[8] or []),
                "can_revoke": bool(row[9]),
            }
            for row in rows
        ]
    except Exception as e:
        logger.warning(f"posture apps: DB read failed: {e}")
        return []


@router.delete("/apps/{app_id}")
async def revoke_app(
    app_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an OAuth app's access via Graph API (M365) or Google Admin SDK."""
    row_r = await db.execute(
        text("SELECT provider, external_id FROM posture_apps WHERE id=:id AND org_id=:oid"),
        {"id": app_id, "oid": str(current_user.org_id)},
    )
    row = row_r.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="App not found")
    provider, external_id = row[0], row[1]

    integ = await _get_active_integration(db, current_user.org_id, provider)
    if not integ:
        raise HTTPException(status_code=400, detail=f"{provider} integration not connected")

    headers = {"Authorization": f"Bearer {integ['access_token']}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if provider == "m365":
                # Revoke service principal permission grant
                r = await client.delete(
                    f"{GRAPH}/oauth2PermissionGrants/{external_id}",
                    headers=headers,
                )
                if r.status_code not in (200, 204, 404):
                    raise HTTPException(status_code=502, detail=f"Graph revoke failed: {r.status_code}")
            else:
                # Google: revoke token via oauth2 endpoint
                r = await client.post(
                    f"https://oauth2.googleapis.com/revoke?token={external_id}",
                )
                if r.status_code not in (200, 204):
                    raise HTTPException(status_code=502, detail=f"Google revoke failed: {r.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    await db.execute(
        text("DELETE FROM posture_apps WHERE id=:id AND org_id=:oid"),
        {"id": app_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    return {"ok": True}


# ── Inbox Rules ───────────────────────────────────────────────────────────────

@router.get("/inbox-rules")
async def get_inbox_rules(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return inbox rules from DB (populated by scan)."""
    await _require_enterprise(current_user, db)
    try:
        r = await db.execute(
            text(
                "SELECT id, rule_name, mailbox, provider, enabled, conditions, actions, risk, risk_reasons, created_at "
                "FROM posture_rules WHERE org_id=:oid ORDER BY risk DESC, mailbox"
            ),
            {"oid": str(current_user.org_id)},
        )
        rows = r.fetchall()
        import json as _j
        return [
            {
                "id": str(row[0]),
                "name": row[1],
                "mailbox": row[2],
                "provider": row[3],
                "enabled": bool(row[4]),
                "conditions": row[5] or "",
                "actions": row[6] or "",
                "risk": row[7],
                "risk_reasons": _j.loads(row[8]) if isinstance(row[8], str) else (row[8] or []),
                "created_at": row[9].isoformat() if row[9] else None,
            }
            for row in rows
        ]
    except Exception as e:
        logger.warning(f"posture rules: DB read failed: {e}")
        return []


@router.delete("/inbox-rules/{rule_id}")
async def delete_inbox_rule(
    rule_id: str,
    mailbox: str,
    provider: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an inbox rule via Graph API (M365) or Gmail API (Google)."""
    integ = await _get_active_integration(db, current_user.org_id, provider)
    if not integ:
        raise HTTPException(status_code=400, detail=f"{provider} not connected")

    headers = {"Authorization": f"Bearer {integ['access_token']}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if provider == "m365":
                r = await client.delete(
                    f"{GRAPH}/users/{mailbox}/mailFolders/inbox/messageRules/{rule_id}",
                    headers=headers,
                )
                if r.status_code not in (200, 204, 404):
                    raise HTTPException(status_code=502, detail=f"Graph delete rule failed: {r.status_code}")
            else:
                # Gmail: delete filter
                from backend.services.baseline_ingestion import _get_sa_headers_async
                sa_hdrs = await _get_sa_headers_async(subject_email=mailbox)
                if sa_hdrs:
                    hdrs = sa_hdrs
                else:
                    hdrs = headers
                r = await client.delete(
                    f"{GMAIL_API}/users/{mailbox}/settings/filters/{rule_id}",
                    headers=hdrs,
                )
                if r.status_code not in (200, 204, 404):
                    raise HTTPException(status_code=502, detail=f"Gmail delete filter failed: {r.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    await db.execute(
        text("DELETE FROM posture_rules WHERE id=:id AND org_id=:oid"),
        {"id": rule_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    return {"ok": True}


# ── Forwards ──────────────────────────────────────────────────────────────────

@router.get("/forwards")
async def get_forwards(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return auto-forwarding rules from DB (populated by scan)."""
    await _require_enterprise(current_user, db)
    try:
        r = await db.execute(
            text(
                "SELECT id, mailbox, provider, forward_to, is_external, risk "
                "FROM posture_forwards WHERE org_id=:oid ORDER BY is_external DESC, mailbox"
            ),
            {"oid": str(current_user.org_id)},
        )
        rows = r.fetchall()
        return [
            {
                "id": str(row[0]),
                "mailbox": row[1],
                "provider": row[2],
                "forward_to": row[3],
                "is_external": bool(row[4]),
                "risk": row[5],
            }
            for row in rows
        ]
    except Exception as e:
        logger.warning(f"posture forwards: DB read failed: {e}")
        return []


# ── Scan (trigger) ────────────────────────────────────────────────────────────

# In-memory cache for AI score: org_id -> {score, label, reasoning, generated_at}
_ai_score_cache: dict = {}


@router.get("/ai-score")
async def get_posture_ai_score(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get an AI-generated posture score with natural language reasoning. Cached 6h."""
    await _require_enterprise(current_user, db)
    import os as _os, time as _time
    org_id = str(current_user.org_id)
    _now = _time.time()

    # Return cached score if < 6 hours old
    if org_id in _ai_score_cache:
        cached = _ai_score_cache[org_id]
        if _now - cached["generated_at"] < 6 * 3600:
            return cached

    # Gather posture data for Claude
    try:
        _sum = await get_posture_summary(current_user=current_user, db=db)
        apps_resp = await get_posture_apps(current_user=current_user, db=db)
        rules_resp = await get_inbox_rules(current_user=current_user, db=db)
        fwds_resp = await get_forwards(current_user=current_user, db=db)

        high_apps = [a for a in apps_resp if a["risk"] == "high"]
        high_rules = [r for r in rules_resp if r["risk"] == "high"]
        ext_fwds = [f for f in fwds_resp if f["is_external"]]
        total_apps = len(apps_resp)
        last_scan = _sum.get("last_scanned")

        if not last_scan:
            return {"score": None, "label": "Not scanned", "reasoning": "No posture scan has been run yet. Click Scan Now to generate your score.", "generated_at": _now}

        # Build prompt
        _prompt = (
            f"You are a security analyst scoring an organization's inbox posture on a scale of 0-100 "
            f"(100 = excellent, 0 = critical risk). Be precise and consistent — same data = same score.\n\n"
            f"Posture data:\n"
            f"- Total OAuth apps/add-ins: {total_apps}\n"
            f"- High-risk apps ({len(high_apps)}): {', '.join(a['name'] for a in high_apps[:5])}{'...' if len(high_apps)>5 else ''}\n"
            f"- High-risk inbox rules ({len(high_rules)}): {', '.join(r['name'] + ' @ ' + r['mailbox'].split('@')[0] for r in high_rules[:3])}\n"
            f"- External forwarding addresses: {len(ext_fwds)}\n"
            f"- Last scanned: {last_scan}\n\n"
            f"Respond with ONLY valid JSON: "
            f'{{"score": <0-100>, "label": "<Critical|Poor|Fair|Good|Excellent>", "reasoning": "<2-3 sentence explanation>"}}')

        _key = _os.getenv("ANTHROPIC_API_KEY", "")
        if not _key:
            score_val = max(0, 100 - len(high_apps)*5 - len(high_rules)*8 - len(ext_fwds)*12)
            return {"score": score_val, "label": "Fair" if score_val >= 50 else "Poor", "reasoning": "AI scoring unavailable.", "generated_at": _now}

        import httpx as _hx, json as _jj, re as _re
        async with _hx.AsyncClient(timeout=20) as _c:
            _r = await _c.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": _key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-haiku-4-5", "max_tokens": 256, "messages": [{"role": "user", "content": _prompt}]},
            )
            if _r.status_code == 200:
                _raw = _r.json()["content"][0]["text"]
                _m = _re.search(r'\{.*\}', _raw, _re.DOTALL)
                if _m:
                    _data = _jj.loads(_m.group())
                    result = {
                        "score": max(0, min(100, int(_data.get("score", 50)))),
                        "label": _data.get("label", "Fair"),
                        "reasoning": _data.get("reasoning", ""),
                        "generated_at": _now,
                    }
                    _ai_score_cache[org_id] = result
                    return result
    except Exception as _e:
        logger.warning(f"posture ai-score failed: {_e}")

    # Fallback if Claude fails
    fallback_score = max(0, 100 - _sum.get("high_risk_apps",0)*5 - _sum.get("high_risk_rules",0)*8 - _sum.get("external_forwards",0)*12)
    return {"score": fallback_score, "label": "Fair" if fallback_score >= 50 else "Poor", "reasoning": "Score calculated from posture metrics.", "generated_at": _now}


@router.post("/scan")
async def trigger_posture_scan(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Kick off a background posture scan for this org."""
    await _require_enterprise(current_user, db)
    import asyncio
    org_id = str(current_user.org_id)
    asyncio.create_task(_run_posture_scan(org_id))
    return {"ok": True, "message": "Posture scan started"}


async def _run_posture_scan(org_id: str):
    """Full posture scan: fetch apps, rules, forwards from M365 + Google and persist to DB."""
    from backend.database import AsyncSessionLocal
    from datetime import datetime as _datetime
    import json as _j
    import uuid as _uuid

    def _parse_dt(s):
        """Parse ISO datetime string to datetime object, or return None."""
        if not s:
            return None
        try:
            return _datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

    async with AsyncSessionLocal() as db:
        # Ensure tables exist
        try:
            await _ensure_posture_tables(db)
        except Exception as e:
            logger.error(f"posture scan: table creation failed: {e}")
            return

        # Get active integrations
        m365 = await _get_active_integration(db, org_id, "m365")
        google = await _get_active_integration(db, org_id, "google")

        apps_to_upsert = []
        rules_to_upsert = []
        forwards_to_upsert = []

        # ── M365 ──────────────────────────────────────────────────────────────
        if m365:
            at = m365["access_token"]
            headers = {"Authorization": f"Bearer {at}"}
            # App-only token for SP/OAuth grants (M365_APP_TENANT_ID if set, else M365_TENANT_ID)
            # For most customers these are the same tenant.
            # For Himaya's test setup: himayaai tenant has Application.Read.All, sana085 has mailboxes.
            _app_at = await _get_m365_app_token()
            _sp_headers = {"Authorization": f"Bearer {_app_at}"} if _app_at else headers

            # App-only token for mailbox operations (inbox rules, forwarding)
            # Always uses M365_TENANT_ID (the org's actual mailbox tenant)
            # This covers all mailboxes, unlike the delegated token which may only cover the connecting user
            import os as _posture_os
            _mb_tid = _posture_os.getenv("M365_TENANT_ID", "")
            _mb_cid = _posture_os.getenv("M365_CLIENT_ID", "")
            _mb_sec = _posture_os.getenv("M365_CLIENT_SECRET", "")
            _mb_app_at = ""
            if all([_mb_cid, _mb_sec, _mb_tid]):
                try:
                    async with httpx.AsyncClient(timeout=10) as _mtc:
                        _mtr = await _mtc.post(
                            f"https://login.microsoftonline.com/{_mb_tid}/oauth2/v2.0/token",
                            data={"client_id": _mb_cid, "client_secret": _mb_sec,
                                  "scope": "https://graph.microsoft.com/.default",
                                  "grant_type": "client_credentials"},
                        )
                        if _mtr.status_code == 200:
                            _mb_app_at = _mtr.json().get("access_token", "")
                except Exception:
                    pass
            # _mb_headers: app-only mailbox token (all users) or fall back to delegated
            _mb_headers = {"Authorization": f"Bearer {_mb_app_at}"} if _mb_app_at else headers
            async with httpx.AsyncClient(timeout=20) as client:

                # OAuth permission grants
                try:
                    r = await client.get(
                        f"{GRAPH}/oauth2PermissionGrants?$top=200",
                        headers=_sp_headers,
                    )
                    if r.status_code == 200:
                        grants = r.json().get("value", [])
                        # Resolve SP display names
                        sp_names: dict[str, str] = {}
                        sp_ids = list({g.get("clientId") for g in grants if g.get("clientId")})
                        for sp_id in sp_ids[:20]:  # limit to avoid rate limit
                            try:
                                sp_r = await client.get(f"{GRAPH}/servicePrincipals/{sp_id}", headers=headers)
                                if sp_r.status_code == 200:
                                    sp_names[sp_id] = sp_r.json().get("displayName", sp_id)
                            except Exception:
                                pass
                        for g in grants:
                            scopes = (g.get("scope") or "").split()
                            sp_id = g.get("clientId", "")
                            name = sp_names.get(sp_id, sp_id)
                            risk, reasons = _score_scopes(scopes)
                            # Known-safe apps get downgraded one level
                            if name.lower() in _KNOWN_SAFE_APPS and risk == "high":
                                risk = "medium"
                                reasons.insert(0, f"'{name}' is a known enterprise app — review scopes but likely legitimate")
                            elif name.lower() in _KNOWN_SAFE_APPS and risk == "medium":
                                risk = "low"
                            apps_to_upsert.append({
                                "id": str(_uuid.uuid4()),
                                "external_id": g.get("id", ""),
                                "app_name": name,
                                "description": None,
                                "provider": "m365",
                                "scopes": _j.dumps(scopes),
                                "granted_by": g.get("principalId"),
                                "granted_at": None,
                                "risk": risk,
                                "risk_reasons": _j.dumps(reasons),
                                "can_revoke": True,
                            })
                except Exception as e:
                    logger.warning(f"posture: M365 OAuth grants fetch failed: {e}")

                # ── Org-deployed Outlook add-ins via service principals ───────────────
                # Enumerate enterprise apps/service principals with exchange permissions
                # that indicate Outlook add-in functionality
                # Paginate through ALL service principals (tenant may have >100)
                try:
                    _sps: list = []
                    _sp_url: str | None = (
                        f"{GRAPH}/servicePrincipals?$top=200"
                        f"&$select=id,displayName,appId,createdDateTime,tags,oauth2PermissionScopes,appRoles"
                    )
                    while _sp_url:
                        _sp_resp = await client.get(_sp_url, headers=_sp_headers)
                        if _sp_resp.status_code != 200:
                            if _sp_resp.status_code == 403:
                                logger.debug("posture: servicePrincipals 403 — need Application.Read.All")
                            else:
                                logger.warning(f"posture: servicePrincipals {_sp_resp.status_code}")
                            break
                        _page = _sp_resp.json()
                        _sps.extend(_page.get("value", []))
                        _sp_url = _page.get("@odata.nextLink")
                        if len(_sps) > 500:  # safety cap
                            break
                    logger.info(f"posture: M365 fetched {len(_sps)} service principals")

                    _seen_addins: set = set()
                    # Also get delegated permission grants (oauth2PermissionGrants)
                    # maps clientId -> list of scope strings
                    _delegated_scopes: dict = {}
                    _pg_resp = await client.get(
                        f"{GRAPH}/oauth2PermissionGrants?$top=200",
                        headers=_sp_headers,
                    )
                    if _pg_resp.status_code == 200:
                        for _g in _pg_resp.json().get("value", []):
                            _cid = _g.get("clientId", "")
                            _scopes = (_g.get("scope") or "").split()
                            if _cid:
                                _delegated_scopes.setdefault(_cid, [])
                                _delegated_scopes[_cid].extend(_scopes)

                    for _sp in _sps:
                        _sp_id = _sp.get("id", "")
                        if _sp_id in _seen_addins:
                            continue
                        _seen_addins.add(_sp_id)
                        _name = _sp.get("displayName", "Unknown")
                        # Collect scopes: delegated grants + app role names from SP definition
                        _scope_names = list(_delegated_scopes.get(_sp_id, []))
                        # Also pull oauth2PermissionScopes defined on the SP itself
                        for _ps in _sp.get("oauth2PermissionScopes", []):
                            _sn = _ps.get("value", "")
                            if _sn and _sn not in _scope_names:
                                _scope_names.append(_sn)
                        # App roles granted to this SP (what it can DO)
                        _grants_resp = await client.get(
                            f"{GRAPH}/servicePrincipals/{_sp_id}/appRoleAssignments?$top=50",
                            headers=_sp_headers,
                        )
                        if _grants_resp.status_code == 200:
                            for _role in _grants_resp.json().get("value", []):
                                # appRoleId maps to a known scope — resolve via resource SP
                                # For now use the role display name as scope label
                                _rdn = _role.get("principalDisplayName", "")
                                if _rdn and _rdn not in _scope_names:
                                    _scope_names.append(_rdn)
                        _risk, _reasons = _score_scopes(_scope_names) if _scope_names else ("low", [])
                        if _name.lower() in _KNOWN_SAFE_APPS:
                            if _risk == "high": _risk = "medium"; _reasons.insert(0, f"'{_name}' is a known enterprise app")
                            elif _risk == "medium": _risk = "low"
                        apps_to_upsert.append({
                            "id": str(_uuid.uuid4()),
                            "external_id": _sp_id,
                            "app_name": _name,
                            "description": "Enterprise app / Outlook add-in",
                            "provider": "m365",
                            "scopes": _j.dumps(_scope_names),
                            "granted_by": None,
                            "granted_at": _parse_dt(_sp.get("createdDateTime")),
                            "risk": _risk,
                            "risk_reasons": _j.dumps(_reasons),
                            "can_revoke": False,
                        })
                except Exception as _spe:
                    logger.warning(f"posture: service principal scan failed: {_spe}")

                # Per-user inbox rules
                users = await _get_m365_users(client, _mb_headers)
                for email in users[:50]:  # cap at 50 to avoid timeout
                    try:
                        rr = await client.get(
                            f"{GRAPH}/users/{email}/mailFolders/inbox/messageRules?$top=50",
                            headers=_mb_headers,
                        )
                        if rr.status_code != 200:
                            continue
                        for rule in rr.json().get("value", []):
                            conds = _m365_rule_conds(rule.get("conditions", {}))
                            acts = _m365_rule_actions(rule.get("actions", {}))
                            risk, reasons = _score_rule(rule.get("displayName", ""), conds, acts)
                            rules_to_upsert.append({
                                "id": str(_uuid.uuid4()),
                                "rule_name": rule.get("displayName", "Unnamed"),
                                "mailbox": email,
                                "provider": "m365",
                                "enabled": rule.get("isEnabled", True),
                                "conditions": conds,
                                "actions": acts,
                                "risk": risk,
                                "risk_reasons": _j.dumps(reasons),
                                "created_at": None,
                            })
                    except Exception as e:
                        logger.debug(f"posture: M365 rules fetch for {email} failed: {e}")

                    # Auto-forwarding (mailbox settings)
                    try:
                        fwd_r = await client.get(
                            f"{GRAPH}/users/{email}/mailboxSettings",
                            headers=_mb_headers,
                        )
                        if fwd_r.status_code == 200:
                            fwd_data = fwd_r.json()
                            fwd_to = (fwd_data.get("automaticRepliesSetting") or {}).get("scheduledStartDateTime")
                            # Real forwarding is in the forwardingSmtpAddress field
                            fwd_addr = fwd_data.get("forwardingSmtpAddress") or fwd_data.get("forwardingAddress")
                            if fwd_addr:
                                mailbox_domain = email.split("@")[1] if "@" in email else ""
                                fwd_domain = fwd_addr.split("@")[1] if "@" in fwd_addr else ""
                                is_ext = mailbox_domain != fwd_domain
                                fwd_risk, _ = _score_forwarding(email, fwd_addr)
                                forwards_to_upsert.append({
                                    "id": str(_uuid.uuid4()),
                                    "mailbox": email,
                                    "provider": "m365",
                                    "forward_to": fwd_addr,
                                    "is_external": is_ext,
                                    "risk": fwd_risk,
                                })
                    except Exception as e:
                        logger.debug(f"posture: M365 forwarding check for {email} failed: {e}")

                # (forwarding from inbox rules extracted after all rules collected below)

        # ── Google ────────────────────────────────────────────────────────────
        if google:
            at = google["access_token"]
            headers = {"Authorization": f"Bearer {at}"}
            from backend.services.baseline_ingestion import _get_sa_headers_async

            async with httpx.AsyncClient(timeout=20) as client:
                # Google OAuth apps — Admin SDK tokens API per user
                # Requires admin.directory.user.security DWD scope
                google_users = await _get_google_users(db, org_id)
                # The Admin SDK tokens API requires a super admin context.
                # Use the first available user as the impersonation subject —
                # the SA must impersonate a Google Workspace admin account.
                # We try each user until one works (super admins can enumerate tokens).
                _seen_google_apps: dict = {}  # client_id -> app entry (dedup across users)

                for email in google_users[:50]:  # cap to avoid quota
                    # Get SA headers impersonating this user (needed for tokens API)
                    sa_hdrs = await _get_sa_headers_async(subject_email=email)
                    if not sa_hdrs:
                        break
                    # Tokens (OAuth apps) — requires admin.directory.user.security DWD
                    try:
                        tok_r = await client.get(
                            f"{ADMIN_API}/users/{email}/tokens",
                            headers=sa_hdrs,
                        )
                        if tok_r.status_code == 200:
                            for tok in tok_r.json().get("items", []):
                                client_id = tok.get("clientId", "")
                                scopes = tok.get("scopes") or []
                                name = tok.get("displayText") or client_id or "Unknown App"
                                risk, reasons = _score_scopes(scopes)
                                if name.lower() in _KNOWN_SAFE_APPS and risk == "high":
                                    risk = "medium"
                                    reasons.insert(0, f"'{name}' is a known enterprise app — review scopes but likely legitimate")
                                elif name.lower() in _KNOWN_SAFE_APPS and risk == "medium":
                                    risk = "low"
                                if client_id not in _seen_google_apps:
                                    # First time we see this app — add it
                                    _seen_google_apps[client_id] = {
                                        "id": str(_uuid.uuid4()),
                                        "external_id": client_id,
                                        "app_name": name,
                                        "description": f"Granted by: {email}",
                                        "provider": "google",
                                        "scopes": _j.dumps(scopes),
                                        "granted_by": email,
                                        "granted_at": None,
                                        "risk": risk,
                                        "risk_reasons": _j.dumps(reasons),
                                        "can_revoke": True,
                                    }
                                else:
                                    # App seen before — update description to show all grantors
                                    existing = _seen_google_apps[client_id]
                                    if email not in existing["description"]:
                                        existing["description"] += f", {email}"
                                    # Escalate risk if higher
                                    risk_order = {"low": 0, "medium": 1, "high": 2}
                                    if risk_order.get(risk, 0) > risk_order.get(existing["risk"], 0):
                                        existing["risk"] = risk
                                        existing["risk_reasons"] = _j.dumps(reasons)
                        elif tok_r.status_code == 403:
                            logger.debug(f"posture: Google tokens 403 for {email} — admin.directory.user.security may not be in DWD")
                    except Exception as e:
                        logger.debug(f"posture: Google tokens for {email} failed: {e}")

                    # Gmail filters (inbox rules) — use SA impersonation
                    try:
                        impersonate_hdrs = await _get_sa_headers_async(subject_email=email) or headers
                        fil_r = await client.get(
                            f"{GMAIL_API}/users/{email}/settings/filters",
                            headers=impersonate_hdrs,
                        )
                        if fil_r.status_code == 200:
                            for f in fil_r.json().get("filter", []):
                                crit = f.get("criteria", {})
                                act = f.get("action", {})
                                conds = _gmail_filter_conds(crit)
                                acts = _gmail_filter_actions(act)
                                risk, reasons = _score_rule("", conds, acts)
                                rules_to_upsert.append({
                                    "id": str(_uuid.uuid4()),
                                    "rule_name": f"Filter {f.get('id', '')}",
                                    "mailbox": email,
                                    "provider": "google",
                                    "enabled": True,
                                    "conditions": conds,
                                    "actions": acts,
                                    "risk": risk,
                                    "risk_reasons": _j.dumps(reasons),
                                    "created_at": None,
                                })
                    except Exception as e:
                        logger.debug(f"posture: Gmail filters for {email} failed: {e}")

                    # Gmail forwarding
                    try:
                        impersonate_hdrs = await _get_sa_headers_async(subject_email=email) or headers
                        fw_r = await client.get(
                            f"{GMAIL_API}/users/{email}/settings/forwardingAddresses",
                            headers=impersonate_hdrs,
                        )
                        if fw_r.status_code == 200:
                            for fwd in fw_r.json().get("forwardingAddresses", []):
                                if fwd.get("verificationStatus") in ("accepted", "pending"):  # include pending — attacker-created forwards may not be verified yet
                                    fwd_addr = fwd.get("forwardingEmail", "")
                                    mailbox_domain = email.split("@")[1] if "@" in email else ""
                                    fwd_domain = fwd_addr.split("@")[1] if "@" in fwd_addr else ""
                                    is_ext = mailbox_domain != fwd_domain
                                    fwd_risk, _ = _score_forwarding(email, fwd_addr)
                                    forwards_to_upsert.append({
                                        "id": str(_uuid.uuid4()),
                                        "mailbox": email,
                                        "provider": "google",
                                        "forward_to": fwd_addr,
                                        "is_external": is_ext,
                                        "risk": fwd_risk,
                                    })
                    except Exception as e:
                        logger.debug(f"posture: Gmail forwarding for {email} failed: {e}")

                # Add all unique Google apps to upsert list (deduplicated)
                apps_to_upsert.extend(_seen_google_apps.values())

        # Extract forwarding destinations from M365 + Google inbox rules
        # (mailbox-level forwardingSmtpAddress not settable via Graph API)
        import re as _fwd_re
        _seen_forwards: set = set()
        for _rule in rules_to_upsert:
            _acts = (_rule.get("actions") or "").lower()
            if "forward to:" in _acts or "redirect to:" in _acts:
                _fwd_matches = _fwd_re.findall(r'(?:forward|redirect) to: ([\w.@+%-]+)', _acts)
                for _fwd_addr in _fwd_matches:
                    _key = f"{_rule['mailbox']}:{_fwd_addr}"
                    if _key in _seen_forwards:
                        continue
                    _seen_forwards.add(_key)
                    _mb = _rule["mailbox"]
                    _mb_domain = _mb.split("@")[1].lower() if "@" in _mb else ""
                    _fwd_domain = _fwd_addr.split("@")[1].lower() if "@" in _fwd_addr else ""
                    _is_ext = _fwd_domain != _mb_domain and bool(_fwd_domain)
                    _frisk, _ = _score_forwarding(_mb, _fwd_addr)
                    forwards_to_upsert.append({
                        "id": str(_uuid.uuid4()),
                        "mailbox": _mb,
                        "provider": _rule["provider"],
                        "forward_to": _fwd_addr,
                        "is_external": _is_ext,
                        "risk": _frisk,
                    })
                    logger.info(f"posture: extracted forwarding {_mb} → {_fwd_addr} (ext={_is_ext}) from rule '{_rule['rule_name']}'")

        # ── Claude threat intelligence enrichment for apps ─────────────────────────────
        # Ask Claude about each app: known threat intel, public disclosures, CVEs
        if apps_to_upsert:
            try:
                import os as _os
                _anthropic_key = _os.getenv("ANTHROPIC_API_KEY", "")
                if _anthropic_key:
                    import httpx as _hx
                    import json as _jj
                    # Batch unique app names (cap at 20 to limit cost)
                    _unique_apps = list({a["app_name"]: a for a in apps_to_upsert}.values())[:20]
                    _app_names = [a["app_name"] for a in _unique_apps]
                    _prompt = (
                        "You are a security analyst reviewing OAuth/add-in apps installed in enterprise email environments.\n"
                        "For each app name below, answer:\n"
                        "1. Has this app had any publicly disclosed security incidents, data breaches, malware distribution, or CVEs?\n"
                        "2. Is this app known to be used in phishing campaigns or supply-chain attacks?\n"
                        "3. What is your overall threat assessment: clean | suspicious | compromised\n\n"
                        f"Apps to review:\n{chr(10).join(f'- {n}' for n in _app_names)}\n\n"
                        "Respond ONLY with a JSON array, one object per app, in the same order:\n"
                        '[{"name": "AppName", "verdict": "clean|suspicious|compromised", "note": "one sentence or empty string"}]'
                    )
                    async with _hx.AsyncClient(timeout=30) as _ac:
                        _resp = await _ac.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={"x-api-key": _anthropic_key, "anthropic-version": "2023-06-01",
                                     "content-type": "application/json"},
                            json={"model": "claude-haiku-4-5", "max_tokens": 1024,
                                  "messages": [{"role": "user", "content": _prompt}]},
                        )
                        if _resp.status_code == 200:
                            _raw = _resp.json()["content"][0]["text"]
                            # Extract JSON array from response
                            import re as _re
                            _match = _re.search(r'\[.*\]', _raw, _re.DOTALL)
                            if _match:
                                _intel = _jj.loads(_match.group())
                                _intel_map = {item["name"].lower(): item for item in _intel if "name" in item}
                                # Apply threat intel to apps
                                for _app in apps_to_upsert:
                                    _key = _app["app_name"].lower()
                                    if _key in _intel_map:
                                        _item = _intel_map[_key]
                                        _verdict = _item.get("verdict", "clean")
                                        _note = _item.get("note", "")
                                        if _verdict == "compromised":
                                            # Escalate to high, add threat intel note
                                            _app["risk"] = "high"
                                            _existing = _jj.loads(_app["risk_reasons"]) if isinstance(_app["risk_reasons"], str) else _app["risk_reasons"]
                                            _existing.insert(0, f"🚨 Threat Intel: {_note}" if _note else "🚨 Publicly disclosed security incident")
                                            _app["risk_reasons"] = _jj.dumps(_existing)
                                        elif _verdict == "suspicious" and _app["risk"] == "low":
                                            _app["risk"] = "medium"
                                            _existing = _jj.loads(_app["risk_reasons"]) if isinstance(_app["risk_reasons"], str) else _app["risk_reasons"]
                                            _existing.insert(0, f"⚠️ Threat Intel: {_note}" if _note else "⚠️ Flagged as suspicious by threat intelligence")
                                            _app["risk_reasons"] = _jj.dumps(_existing)
                                logger.info(f"posture: Claude threat intel enriched {len(_intel_map)} apps")
            except Exception as _ce:
                logger.warning(f"posture: Claude threat intel enrichment failed (non-fatal): {_ce}")

        # Persist to DB
        try:
            await db.execute(text("DELETE FROM posture_apps WHERE org_id=:oid"), {"oid": org_id})
            await db.execute(text("DELETE FROM posture_rules WHERE org_id=:oid"), {"oid": org_id})
            await db.execute(text("DELETE FROM posture_forwards WHERE org_id=:oid"), {"oid": org_id})

            for a in apps_to_upsert:
                await db.execute(text(
                    "INSERT INTO posture_apps (id, org_id, external_id, app_name, description, provider, scopes, "
                    "granted_by, granted_at, risk, risk_reasons, can_revoke) VALUES "
                    "(:id, :oid, :external_id, :app_name, :description, :provider, :scopes, "
                    ":granted_by, :granted_at, :risk, :risk_reasons, :can_revoke)"
                ), {**a, "oid": org_id})

            for r in rules_to_upsert:
                await db.execute(text(
                    "INSERT INTO posture_rules (id, org_id, rule_name, mailbox, provider, enabled, "
                    "conditions, actions, risk, risk_reasons, created_at) VALUES "
                    "(:id, :oid, :rule_name, :mailbox, :provider, :enabled, "
                    ":conditions, :actions, :risk, :risk_reasons, :created_at)"
                ), {**r, "oid": org_id})

            for f in forwards_to_upsert:
                await db.execute(text(
                    "INSERT INTO posture_forwards (id, org_id, mailbox, provider, forward_to, is_external, risk) "
                    "VALUES (:id, :oid, :mailbox, :provider, :forward_to, :is_external, :risk)"
                ), {**f, "oid": org_id})

            # Update scan log
            await db.execute(text(
                "INSERT INTO posture_scan_log (org_id, last_scanned_at) VALUES (:oid, NOW()) "
                "ON CONFLICT (org_id) DO UPDATE SET last_scanned_at=NOW()"
            ), {"oid": org_id})

            await db.commit()
            logger.info(
                f"posture scan: org {org_id} — {len(apps_to_upsert)} apps, "
                f"{len(rules_to_upsert)} rules, {len(forwards_to_upsert)} forwards"
            )
        except Exception as e:
            logger.error(f"posture scan: DB write failed: {e}")
            await db.rollback()


async def _ensure_posture_tables(db):
    """Create posture tables if they don't exist (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS posture_apps (
            id UUID PRIMARY KEY,
            org_id UUID NOT NULL,
            external_id TEXT,
            app_name TEXT NOT NULL,
            description TEXT,
            provider TEXT NOT NULL,
            scopes TEXT,
            granted_by TEXT,
            granted_at TIMESTAMPTZ,
            risk TEXT NOT NULL DEFAULT 'low',
            risk_reasons TEXT,
            can_revoke BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS posture_rules (
            id UUID PRIMARY KEY,
            org_id UUID NOT NULL,
            rule_name TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            provider TEXT NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            conditions TEXT,
            actions TEXT,
            risk TEXT NOT NULL DEFAULT 'low',
            risk_reasons TEXT,
            created_at TIMESTAMPTZ,
            scanned_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS posture_forwards (
            id UUID PRIMARY KEY,
            org_id UUID NOT NULL,
            mailbox TEXT NOT NULL,
            provider TEXT NOT NULL,
            forward_to TEXT NOT NULL,
            is_external BOOLEAN DEFAULT FALSE,
            risk TEXT NOT NULL DEFAULT 'low',
            scanned_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS posture_scan_log (
            org_id UUID PRIMARY KEY,
            last_scanned_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.commit()


def _m365_rule_conds(c: dict) -> str:
    parts = []
    if c.get("senderContains"):
        parts.append(f"from: {', '.join(c['senderContains'])}")
    if c.get("subjectContains"):
        parts.append(f"subject contains: {', '.join(c['subjectContains'])}")
    if c.get("bodyContains"):
        parts.append(f"body contains: {', '.join(c['bodyContains'])}")
    if c.get("hasAttachment"):
        parts.append("has attachment")
    if c.get("fromAddresses"):
        parts.append(f"from: {', '.join(a.get('emailAddress', {}).get('address', '') for a in c['fromAddresses'])}")
    return "; ".join(parts) if parts else "Any message"


def _m365_rule_actions(a: dict) -> str:
    parts = []
    if a.get("forwardTo"):
        parts.append(f"Forward to: {', '.join(x.get('emailAddress', {}).get('address', '') for x in a['forwardTo'])}")
    if a.get("forwardAsAttachmentTo"):
        parts.append(f"Forward as attachment to: {', '.join(x.get('emailAddress', {}).get('address', '') for x in a['forwardAsAttachmentTo'])}")
    if a.get("redirectTo"):
        parts.append(f"Redirect to: {', '.join(x.get('emailAddress', {}).get('address', '') for x in a['redirectTo'])}")
    if a.get("delete"):
        parts.append("Delete")
    if a.get("permanentDelete"):
        parts.append("Permanently delete")
    if a.get("moveToFolder"):
        parts.append(f"Move to folder: {a['moveToFolder']}")
    if a.get("markAsRead"):
        parts.append("Mark as read")
    if a.get("stopProcessingRules"):
        parts.append("Stop processing rules")
    return "; ".join(parts) if parts else "No action"


def _gmail_filter_conds(c: dict) -> str:
    parts = []
    if c.get("from"):
        parts.append(f"from: {c['from']}")
    if c.get("to"):
        parts.append(f"to: {c['to']}")
    if c.get("subject"):
        parts.append(f"subject: {c['subject']}")
    if c.get("query"):
        parts.append(f"query: {c['query']}")
    if c.get("hasAttachment"):
        parts.append("has attachment")
    return "; ".join(parts) if parts else "Any message"


def _gmail_filter_actions(a: dict) -> str:
    parts = []
    if a.get("forward"):
        parts.append(f"Forward to: {a['forward']}")
    if a.get("removeLabelIds") and "INBOX" in a["removeLabelIds"]:
        parts.append("Skip inbox (archive)")
    if a.get("addLabelIds") and "TRASH" in a["addLabelIds"]:
        parts.append("Move to trash")
    if a.get("removeLabelIds") and "UNREAD" in a["removeLabelIds"]:
        parts.append("Mark as read")
    if a.get("addLabelIds"):
        labels = [l for l in a["addLabelIds"] if l not in ("TRASH", "INBOX", "UNREAD")]
        if labels:
            parts.append(f"Apply label: {', '.join(labels)}")
    return "; ".join(parts) if parts else "No action"


# ── Dev Seed (remove after testing) ───────────────────────────────────────────
