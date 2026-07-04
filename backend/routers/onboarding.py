import os
import json
import uuid
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, BackgroundTasks, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from backend.database import get_db
from backend.models.db_models import OrgIntegration, Organization
from backend.routers.auth import get_current_user
from backend.schemas.api_schemas import M365ConnectRequest
from backend.services.baseline_ingestion import run_baseline_ingestion, get_baseline_status
import logging as _cb_log

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])
_logger = _cb_log.getLogger(__name__)


async def _stamp_m365_mailbox_count_async(org_id: str, access_token: str) -> None:
    """Called immediately after M365 connect/reconnect to stamp a real mailbox count
    before baseline ingestion finishes. Non-fatal on any error."""
    try:
        import httpx
        from sqlalchemy import text as _st
        from backend.database import AsyncSessionLocal
        GRAPH = "https://graph.microsoft.com/v1.0"
        async with httpx.AsyncClient(timeout=15) as _c:
            _r = await _c.get(
                f"{GRAPH}/users?$select=mail,userPrincipalName,accountEnabled&$top=999",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if _r.status_code == 200:
                _users = [u for u in _r.json().get("value", []) if u.get("accountEnabled", True) and (u.get("mail") or u.get("userPrincipalName"))]
                _mc = len(_users)
                async with AsyncSessionLocal() as _db:
                    await _db.execute(
                        _st("UPDATE org_integrations SET mailbox_count = :mc WHERE org_id = :oid AND provider = 'm365'"),
                        {"mc": _mc, "oid": org_id},
                    )
                    await _db.execute(
                        _st("UPDATE organizations SET mailbox_count = (SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations WHERE org_id = :oid AND status = 'active') WHERE id = :oid"),
                        {"oid": org_id},
                    )
                    await _db.commit()
                _logger.info(f"M365 connect: eagerly stamped mailbox_count={_mc} for org {org_id}")
            else:
                _logger.warning(f"M365 connect: eager user count returned {_r.status_code} — baseline will populate later")
    except Exception as _e:
        _logger.warning(f"M365 connect: eager mailbox_count stamp failed (non-fatal): {_e}")


async def _stamp_google_mailbox_count_async(org_id: str, access_token: str) -> None:
    """Called immediately after Google connect/reconnect to stamp a real mailbox count
    before baseline ingestion finishes. Non-fatal on any error."""
    try:
        from backend.services.baseline_ingestion import _google_list_users, _get_sa_headers_async
        from sqlalchemy import text as _st
        from backend.database import AsyncSessionLocal
        import httpx
        # Need the org domain
        async with AsyncSessionLocal() as _db:
            from sqlalchemy import select as _sel
            _org = (await _db.execute(_sel(Organization).where(Organization.id == org_id))).scalar_one_or_none()
            _domain = _org.domain if _org else ""
        if not _domain:
            _logger.warning(f"Google connect: no domain for org {org_id} — skipping eager count")
            return
        async with httpx.AsyncClient(timeout=15) as _c:
            _sa_hdrs = await _get_sa_headers_async() or {"Authorization": f"Bearer {access_token}"}
            _users = await _google_list_users(_c, _sa_hdrs, _domain)
            if not _users:  # fallback to OAuth
                _users = await _google_list_users(_c, {"Authorization": f"Bearer {access_token}"}, _domain)
            if _users:
                _mc = len([u for u in _users if not u.get("suspended")])
                async with AsyncSessionLocal() as _db:
                    await _db.execute(
                        _st("UPDATE org_integrations SET mailbox_count = :mc WHERE org_id = :oid AND provider = 'google'"),
                        {"mc": _mc, "oid": org_id},
                    )
                    await _db.execute(
                        _st("UPDATE organizations SET mailbox_count = (SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations WHERE org_id = :oid AND status = 'active') WHERE id = :oid"),
                        {"oid": org_id},
                    )
                    await _db.commit()
                _logger.info(f"Google connect: eagerly stamped mailbox_count={_mc} for org {org_id}")
    except Exception as _e:
        _logger.warning(f"Google connect: eager mailbox_count stamp failed (non-fatal): {_e}")

# --- OAuth Config ---
M365_CLIENT_ID = os.getenv("M365_CLIENT_ID", "demo-client-id")
M365_CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET", "demo-secret")
M365_REDIRECT_URI = os.getenv("M365_REDIRECT_URI", "http://localhost:8000/api/onboarding/callback/m365")
M365_TENANT_ID = os.getenv("M365_TENANT_ID", "common")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "demo-client-id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "demo-secret")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/onboarding/callback/google")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# --- Encryption ---
def get_fernet():
    from cryptography.fernet import Fernet
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        key = Fernet.generate_key().decode()
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)

def encrypt_token(token: str) -> str:
    if not token:
        return ""
    try:
        f = get_fernet()
        return f.encrypt(token.encode()).decode()
    except Exception:
        return token

def decrypt_token(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        f = get_fernet()
        return f.decrypt(encrypted.encode()).decode()
    except Exception:
        return encrypted


# --- Baseline endpoints ---

@router.post("/baseline/start")
async def start_baseline(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    org_id = str(current_user.org_id)
    background_tasks.add_task(run_baseline_ingestion, org_id, 50)
    return {"message": "Baseline ingestion started", "org_id": org_id, "status": "running"}


@router.get("/baseline/status")
async def baseline_status(current_user=Depends(get_current_user)):
    org_id = str(current_user.org_id)
    status = await get_baseline_status(org_id)
    return status


@router.get("/dwd/test")
async def test_dwd(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Test if Google Domain-Wide Delegation is configured.
    Returns { dwd_active: bool, admin_email: str | None, error: str | None }

    Strategy (in order of reliability):
    1. If we have >1 active users in DB for this org, DWD clearly works
       (we fetched the directory — without DWD we'd only see the admin)
    2. Live check: try to list users via SA, then try to access a non-admin Gmail
    3. If SA key is present but users = 1, DWD may not be configured for Gmail scope
    """
    from backend.services.baseline_ingestion import (
        _get_service_account_headers, _google_list_users, _decrypt,
        _refresh_google_token, _get_sa_headers_async,
    )
    from backend.models.db_models import OrgIntegration, Organization, User
    from sqlalchemy import func as _func

    org_id = current_user.org_id
    try:
        # Get org
        org_result = await db.execute(select(Organization).where(Organization.id == org_id))
        org = org_result.scalar_one_or_none()
        domain = org.domain if org else ""

        # Get integration
        int_result = await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_id == org_id,
                OrgIntegration.provider == "google",
                OrgIntegration.status == "active",
            )
        )
        integration = int_result.scalar_one_or_none()
        if not integration:
            return {"dwd_active": False, "admin_email": None, "error": "No active Google integration"}

        # ── Strategy 1: check DB user count ──────────────────────────────────
        # If DWD worked, we would have discovered all org users via the directory API
        # >1 user means the SA successfully listed the directory
        active_user_count = (await db.execute(
            select(_func.count(User.id)).where(
                User.org_id == org_id,
                User.is_active.is_(True),
            )
        )).scalar() or 0

        # Also count synced mailboxes — if we've synced >1 mailbox, DWD is definitely working
        synced_mailbox_count = integration.mailbox_count if hasattr(integration, "mailbox_count") else 0

        # ── Get admin email via OAuth ─────────────────────────────────────────
        access_token = _decrypt(integration.access_token_enc)
        refresh_token = _decrypt(integration.refresh_token_enc)
        refreshed = await _refresh_google_token(refresh_token)
        if refreshed:
            access_token = refreshed

        admin_email = None
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if r.status_code == 200:
                    admin_email = r.json().get("email")
        except Exception:
            pass

        # If we have more users than just the admin, DWD is working
        if active_user_count > 1 or synced_mailbox_count > 1:
            return {
                "dwd_active": True,
                "sa_key_present": True,
                "admin_email": admin_email,
                "domain": domain,
                "monitored_mailboxes": active_user_count,
                "client_id": "114733393163502940734",
                "error": None,
            }

        # ── Strategy 2: live SA test ─────────────────────────────────────────
        sa_ok = _get_service_account_headers() is not None
        dwd_active = False

        if sa_ok and domain:
            try:
                import httpx as _httpx
                async with _httpx.AsyncClient(timeout=10) as client:
                    sa_h = _get_service_account_headers()
                    if sa_h:
                        users = await _google_list_users(client, sa_h, domain)
                        if len(users) > 1:
                            dwd_active = True
                        elif len(users) == 1:
                            # Directory works — now test Gmail impersonation for that user
                            first_email = users[0].get("primaryEmail", "")
                            if first_email and first_email != admin_email:
                                imp_h = await _get_sa_headers_async(subject_email=first_email)
                                if imp_h:
                                    r = await client.get(
                                        f"https://gmail.googleapis.com/gmail/v1/users/{first_email}/profile",
                                        headers=imp_h,
                                    )
                                    dwd_active = r.status_code == 200
            except Exception:
                pass

        return {
            "dwd_active": dwd_active,
            "sa_key_present": sa_ok,
            "admin_email": admin_email,
            "domain": domain,
            "monitored_mailboxes": active_user_count,
            "client_id": "114733393163502940734",
            "required_scopes": "https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.user.readonly",
            "error": None if dwd_active else "DWD not yet enabled — only admin mailbox will be scanned. Follow setup instructions above.",
        }
    except Exception as e:
        return {"dwd_active": False, "admin_email": None, "error": str(e)}


@router.get("/status")
async def get_onboarding_status(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    integrations_result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
        )
    )
    integrations = integrations_result.scalars().all()
    connected_providers = {i.provider for i in integrations}

    steps = [
        {
            "id": "create_account",
            "title": "Create Account",
            "title_ar": "إنشاء حساب",
            "description": "Register your organization",
            "complete": True,
            "order": 1,
        },
        {
            "id": "connect_email",
            "title": "Connect Email Provider",
            "title_ar": "ربط موفر البريد الإلكتروني",
            "description": "Connect Microsoft 365 or Google Workspace",
            "complete": bool(connected_providers),
            "order": 2,
        },
        {
            "id": "configure_policies",
            "title": "Configure Policies",
            "title_ar": "تكوين السياسات",
            "description": "Set up your first threat response policy",
            "complete": False,
            "order": 3,
        },
        {
            "id": "invite_team",
            "title": "Invite Team",
            "title_ar": "دعوة الفريق",
            "description": "Add analysts and compliance officers",
            "complete": False,
            "order": 4,
        },
        {
            "id": "review_dashboard",
            "title": "Review Dashboard",
            "title_ar": "مراجعة لوحة التحكم",
            "description": "Review your security posture",
            "complete": False,
            "order": 5,
        },
    ]

    complete_count = sum(1 for s in steps if s["complete"])
    completion_pct = round(complete_count / len(steps) * 100, 1)
    overall_complete = completion_pct == 100.0

    return {
        "steps": steps,
        "overall_complete": overall_complete,
        "completion_pct": completion_pct,
    }


# --- OAuth URL endpoints ---

@router.get("/connect/m365/url")
async def get_m365_auth_url(current_user=Depends(get_current_user)):
    org_id = str(current_user.org_id)
    # Full delegated scope set — User.Read.All and Group.Read.All now registered
    # in Azure portal with admin consent granted tenant-wide.
    # prompt=select_account lets the admin pick their account without forcing re-consent every time.
    auth_url = (
        f"https://login.microsoftonline.com/{M365_TENANT_ID}/oauth2/v2.0/authorize"
        f"?client_id={M365_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={M365_REDIRECT_URI}"
        f"&scope=openid%20email%20profile%20offline_access"
        f"%20User.Read%20User.Read.All"
        f"%20Mail.Read%20Mail.ReadWrite%20MailboxSettings.Read"
        f"%20Group.Read.All"
        f"&state={org_id}"
        f"&response_mode=query"
        f"&prompt=select_account"
    )
    return {"auth_url": auth_url}


@router.get("/connect/google/url")
async def get_google_auth_url(current_user=Depends(get_current_user)):
    org_id = str(current_user.org_id)
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&scope=openid%20email%20https://www.googleapis.com/auth/gmail.modify%20https://www.googleapis.com/auth/admin.directory.user.readonly%20https://www.googleapis.com/auth/admin.directory.group.readonly"
        f"&state={org_id}"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return {"auth_url": auth_url}


# --- OAuth Callbacks ---

@router.get("/callback/m365")
async def m365_callback(
    background_tasks: BackgroundTasks,
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    if error:
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_denied")

    # Validate state (must be the org_id UUID)
    if not state:
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_invalid_state")
    org_id = state
    try:
        org_uuid = uuid.UUID(org_id)
    except ValueError:
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_invalid_state")

    access_token = ""
    refresh_token = ""
    real_domain = None

    if M365_CLIENT_ID != "demo-client-id" and code:
        import httpx
        token_url = f"https://login.microsoftonline.com/{M365_TENANT_ID}/oauth2/v2.0/token"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(token_url, data={
                    "client_id": M365_CLIENT_ID,
                    "client_secret": M365_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": M365_REDIRECT_URI,
                    "grant_type": "authorization_code",
                })
                token_data = resp.json()
                if resp.status_code != 200:
                    import logging as _log
                    _log.getLogger(__name__).error(f"M365 token exchange failed: {resp.status_code} {resp.text[:300]}")
                    return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_token_failed")
                access_token = token_data.get("access_token", "")
                refresh_token = token_data.get("refresh_token", "")

                # Fetch real domain from Graph /me
                if access_token:
                    me = await client.get(
                        "https://graph.microsoft.com/v1.0/me",
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    if me.status_code == 200:
                        me_data = me.json()
                        email = me_data.get("mail") or me_data.get("userPrincipalName", "")
                        real_domain = email.split("@")[1] if "@" in email else None
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).error(f"M365 callback exception: {exc}")
            return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_exception")

    if not access_token:
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_no_token")

    try:
        # Update org domain only if not already claimed by another provider
        if real_domain:
            org_result = await db.execute(
                select(Organization).where(Organization.id == org_uuid)
            )
            org = org_result.scalar_one_or_none()
            if org and not org.domain:
                org.domain = real_domain

        # Store encrypted tokens — always use Python uuid.UUID for UUID columns
        existing_result = await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_id == org_uuid,
                OrgIntegration.provider == "m365",
            )
        )
        existing = existing_result.scalar_one_or_none()

        if existing:
            existing.access_token_enc = encrypt_token(access_token)
            existing.refresh_token_enc = encrypt_token(refresh_token)
            existing.org_domain = real_domain  # always update per-provider domain
            existing.status = "active"
            existing.updated_at = datetime.utcnow()
        else:
            integration = OrgIntegration(
                org_id=org_uuid,
                provider="m365",
                access_token_enc=encrypt_token(access_token),
                refresh_token_enc=encrypt_token(refresh_token),
                org_domain=real_domain,
                scope="openid email profile offline_access User.Read User.Read.All Mail.Read Mail.ReadWrite Mail.ReadBasic.All MailboxSettings.Read MailboxSettings.ReadWrite Calendars.Read Directory.Read.All Group.Read.All",
                status="active",
            )
            db.add(integration)

        await db.commit()
    except Exception as exc:
        import logging as _log
        _log.getLogger(__name__).error(f"M365 DB save failed: {exc}")
        await db.rollback()
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=m365_db_error")

    # Eagerly fetch user count so mailbox_count is non-zero before baseline finishes
    background_tasks.add_task(_stamp_m365_mailbox_count_async, str(org_id), access_token)
    background_tasks.add_task(run_baseline_ingestion, str(org_id), 50)
    return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?connected=m365")


@router.get("/callback/google")
async def google_callback(
    background_tasks: BackgroundTasks,
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    if error:
        return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?error=google_denied")

    org_id = state
    access_token = "demo_access_token"
    refresh_token = "demo_refresh_token"

    real_domain = None
    if GOOGLE_CLIENT_ID != "demo-client-id" and code:
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post("https://oauth2.googleapis.com/token", data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                })
                token_data = resp.json()
                access_token = token_data.get("access_token", "")
                refresh_token = token_data.get("refresh_token", "")

                # Extract real domain from id_token JWT (no extra API call needed)
                id_token = token_data.get("id_token", "")
                if id_token:
                    try:
                        import base64
                        payload_b64 = id_token.split(".")[1]
                        # Pad base64 if needed
                        payload_b64 += "=" * (4 - len(payload_b64) % 4)
                        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                        hd = payload.get("hd")  # hosted domain for Workspace
                        email = payload.get("email", "")
                        real_domain = hd or (email.split("@")[1] if "@" in email else None)
                    except Exception:
                        pass
        except Exception:
            pass

    # Update org domain only if not already claimed by another provider
    _org_uuid = uuid.UUID(org_id) if isinstance(org_id, str) else org_id
    if real_domain:
        org_result = await db.execute(
            select(Organization).where(Organization.id == _org_uuid)
        )
        org = org_result.scalar_one_or_none()
        if org and not org.domain:
            org.domain = real_domain

    existing_result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == "google",
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.access_token_enc = encrypt_token(access_token)
        existing.refresh_token_enc = encrypt_token(refresh_token)
        existing.org_domain = real_domain  # always update per-provider domain
        existing.status = "active"
        existing.updated_at = datetime.utcnow()
    else:
        integration = OrgIntegration(
            org_id=org_id,
            provider="google",
            access_token_enc=encrypt_token(access_token),
            refresh_token_enc=encrypt_token(refresh_token),
            org_domain=real_domain,
            scope="gmail.modify admin.directory.user.readonly",
            status="active",
        )
        db.add(integration)

    await db.commit()
    # Eagerly fetch user count so mailbox_count is non-zero before baseline finishes
    background_tasks.add_task(_stamp_google_mailbox_count_async, str(org_id), access_token)
    # Trigger baseline ingestion in background
    background_tasks.add_task(run_baseline_ingestion, str(org_id), 50)
    return RedirectResponse(url=f"{FRONTEND_URL}/onboarding?connected=google")


# --- Connection Status ---

@router.get("/connections")
async def get_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()
    mailbox_count = org.mailbox_count if org else 0
    org_domain = org.domain if org else ""

    integrations_result = await db.execute(
        select(OrgIntegration).where(OrgIntegration.org_id == current_user.org_id)
    )
    integrations = integrations_result.scalars().all()
    integration_map = {i.provider: i for i in integrations}

    m365 = integration_map.get("m365")
    google = integration_map.get("google")

    def _int(val): return val if isinstance(val, int) else 0

    return {
        "m365": {
            "connected": m365 is not None and m365.status == "active",
            "mailbox_count": _int(getattr(m365, "mailbox_count", 0)) if m365 else 0,
            "groups_count": _int(getattr(m365, "groups_count", 0)) if m365 else 0,
            "aliases_count": _int(getattr(m365, "aliases_count", 0)) if m365 else 0,
            "shared_count": _int(getattr(m365, "shared_count", 0)) if m365 else 0,
            "last_baseline_at": m365.last_baseline_at.isoformat() if m365 and getattr(m365, "last_baseline_at", None) else None,
            "baseline_progress": _int(getattr(m365, "baseline_progress", 0)) if m365 else 0,
            "status": m365.status if m365 else "not_connected",
            "connected_at": m365.connected_at.isoformat() if m365 and m365.connected_at else None,
            "org_domain": (m365.org_domain if m365 and m365.org_domain else org_domain),
        },
        "google": {
            "connected": google is not None and google.status == "active",
            "mailbox_count": _int(getattr(google, "mailbox_count", 0)) if google else 0,
            "groups_count": _int(getattr(google, "groups_count", 0)) if google else 0,
            "aliases_count": _int(getattr(google, "aliases_count", 0)) if google else 0,
            "shared_count": _int(getattr(google, "shared_count", 0)) if google else 0,
            "last_baseline_at": google.last_baseline_at.isoformat() if google and getattr(google, "last_baseline_at", None) else None,
            "baseline_progress": _int(getattr(google, "baseline_progress", 0)) if google else 0,
            "status": google.status if google else "not_connected",
            "connected_at": google.connected_at.isoformat() if google and google.connected_at else None,
            "org_domain": (google.org_domain if google and google.org_domain else org_domain),
        },
    }


# --- Disconnect ---

@router.delete("/connect/{provider}")
async def disconnect_provider(
    provider: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if provider not in ("m365", "google"):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Unknown provider")

    await db.execute(
        delete(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.provider == provider,
        )
    )
    # Check if any other provider is still connected; if not, reset org.mailbox_count
    remaining_result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.status == "active",
        )
    )
    remaining = remaining_result.scalars().all()
    if not remaining:
        from sqlalchemy import text as _dctxt
        await db.execute(
            _dctxt("UPDATE organizations SET mailbox_count = 0 WHERE id = :oid"),
            {"oid": current_user.org_id},
        )
    await db.commit()

    # Clear Redis sync keys so next delta cycle does a full lookback (not just 1 min)
    try:
        import redis.asyncio as aioredis
        _redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        _redis = aioredis.from_url(_redis_url, decode_responses=True)
        _org_id = str(current_user.org_id)
        await _redis.delete(f"delta_sync:{_org_id}:{provider}:last_at")
        await _redis.delete(f"sync_history:{_org_id}")
        await _redis.aclose()
    except Exception as _re:
        import logging as _log
        _log.getLogger(__name__).warning(f"disconnect: redis key clear failed (non-fatal): {_re}")

    return {"message": f"{provider} disconnected successfully"}


# --- Legacy mock endpoint (kept for backward compat) ---

@router.post("/connect/m365")
async def connect_m365_legacy(
    req: M365ConnectRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    existing_result = await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.provider == "m365",
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.status = "active"
        existing.updated_at = datetime.utcnow()
        existing.access_token_enc = encrypt_token(f"mock_token_for_{req.tenant_id}")
        existing.scope = "openid email profile offline_access User.Read User.Read.All Mail.Read Mail.ReadWrite Mail.ReadBasic.All MailboxSettings.Read Directory.Read.All Group.Read.All"
        await db.flush()
        return {"message": "M365 integration updated", "status": "active"}

    integration = OrgIntegration(
        org_id=current_user.org_id,
        provider="m365",
        access_token_enc=encrypt_token(f"mock_token_for_{req.tenant_id}"),
        scope="Mail.Read Mail.ReadWrite",
        status="active",
    )
    db.add(integration)
    await db.flush()

    return {
        "message": "M365 connected successfully (mock mode)",
        "integration_id": str(integration.id),
        "status": "active",
    }


@router.get("/sync/history")
async def get_sync_history(
    current_user=Depends(get_current_user),
):
    """Return delta sync history for this org from Redis."""
    import redis.asyncio as aioredis
    from backend.config import settings
    org_id = str(current_user.org_id)
    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        history_raw = await redis.lrange(f"sync_history:{org_id}", 0, 19)
        history = []
        for item in history_raw:
            try:
                history.append(json.loads(item))
            except Exception:
                pass

        last_google = await redis.get(f"delta_sync:{org_id}:google:last_at")
        last_m365 = await redis.get(f"delta_sync:{org_id}:m365:last_at")
        baseline_progress = await redis.get(f"baseline:{org_id}:progress")
        baseline_status = await redis.get(f"baseline:{org_id}:status")
        emails_processed = await redis.get(f"baseline:{org_id}:emails_processed")

        # If Redis expired, fall back to DB to check completion
        baseline_prog_val = int(baseline_progress or 0)
        baseline_stat_val = baseline_status or "not_started"
        emails_proc_val = int(emails_processed or 0)

        # Fall back to DB truth if progress is low/stale — even if status says "running",
        # the DB is the authoritative source: if users exist, the system is operational.
        # "running" can mean a stale/interrupted baseline that never wrote 100%.
        if baseline_prog_val <= 10:
            try:
                from backend.database import AsyncSessionLocal
                from backend.models.db_models import User, Threat
                from sqlalchemy import select as _sel, func as _func
                async with AsyncSessionLocal() as db2:
                    uc = (await db2.execute(
                        _sel(_func.count(User.id)).where(
                            User.org_id == current_user.org_id,
                            User.is_active.is_(True),
                        )
                    )).scalar() or 0
                    tc = (await db2.execute(
                        _sel(_func.count(Threat.id)).where(Threat.org_id == current_user.org_id)
                    )).scalar() or 0
                    if uc > 0:
                        # DB has users — baseline is done regardless of Redis value
                        baseline_prog_val = 100
                        baseline_stat_val = "complete"
                        emails_proc_val = emails_proc_val or tc
                        # Fix the stale Redis key so it stops re-triggering
                        await redis.set(f"baseline:{org_id}:progress", 100, ex=86400)
                        await redis.set(f"baseline:{org_id}:status", "complete", ex=86400)
            except Exception:
                pass

        # Count live-monitored mailboxes from DB (includes shared mailboxes via org_integrations.shared_count)
        monitored_mailboxes = 0
        try:
            from backend.database import AsyncSessionLocal
            from backend.models.db_models import User as _User, OrgIntegration as _OI2
            from sqlalchemy import select as _sel2, func as _func2
            async with AsyncSessionLocal() as db3:
                # Active synced users (licensed mailboxes)
                licensed_count = (await db3.execute(
                    _sel2(_func2.count(_User.id)).where(
                        _User.org_id == current_user.org_id,
                        _User.is_active.is_(True),
                    )
                )).scalar() or 0
                # Shared mailboxes tracked in OrgIntegration
                _oi_rows = (await db3.execute(
                    _sel2(_OI2).where(
                        _OI2.org_id == current_user.org_id,
                        _OI2.status == "active",
                    )
                )).scalars().all()
                shared_total = sum(getattr(r, "shared_count", 0) or 0 for r in _oi_rows)
                monitored_mailboxes = licensed_count + shared_total
        except Exception:
            pass

        # Per-provider baseline data from Redis
        google_progress = int(await redis.get(f"baseline:{org_id}:google:progress") or 0)
        google_status   = await redis.get(f"baseline:{org_id}:google:status") or ("complete" if baseline_prog_val >= 100 else "not_started")
        google_emails   = int(await redis.get(f"baseline:{org_id}:google:emails_processed") or 0)
        google_mailboxes= int(await redis.get(f"baseline:{org_id}:google:mailboxes") or 0)
        m365_progress   = int(await redis.get(f"baseline:{org_id}:m365:progress") or 0)
        m365_status     = await redis.get(f"baseline:{org_id}:m365:status") or "not_started"
        m365_emails     = int(await redis.get(f"baseline:{org_id}:m365:emails_processed") or 0)
        m365_mailboxes  = int(await redis.get(f"baseline:{org_id}:m365:mailboxes") or 0)

        # Pull directory stats from OrgIntegration — fresh session to avoid aborted tx state
        _int_map: dict = {}
        try:
            from backend.database import AsyncSessionLocal as _ASL2
            from backend.models.db_models import OrgIntegration as _OIH
            from sqlalchemy import select as _selH
            async with _ASL2() as _db2:
                _ints = (await _db2.execute(_selH(_OIH).where(_OIH.org_id == current_user.org_id))).scalars().all()
                _int_map = {i.provider: i for i in _ints}
        except Exception as _die:
            pass
        def _iv(prov, attr): return getattr(_int_map.get(prov), attr, None) or 0

        return {
            "history": history,
            "last_sync": {
                "google": float(last_google) if last_google else None,
                "m365": float(last_m365) if last_m365 else None,
            },
            "baseline": {
                "progress": baseline_prog_val,
                "status": baseline_stat_val,
                "emails_processed": emails_proc_val,
            },
            "providers": {
                "google": {
                    # If Redis progress is 0 but we have mailboxes in DB, baseline is done — show 100
                    "progress": google_progress or (_iv("google", "baseline_progress")) or (100 if _iv("google", "mailbox_count") > 0 else 0),
                    "status": google_status if google_progress > 0 else ("complete" if _iv("google", "mailbox_count") > 0 else "not_started"),
                    "emails_processed": google_emails or baseline_prog_val,
                    "mailboxes": google_mailboxes or _iv("google", "mailbox_count"),
                    "groups": _iv("google", "groups_count"),
                    "aliases": _iv("google", "aliases_count"),
                    "shared": _iv("google", "shared_count"),
                    "last_baseline_at": _int_map["google"].last_baseline_at.isoformat() if "google" in _int_map and getattr(_int_map["google"], "last_baseline_at", None) else None,
                },
                "m365": {
                    # If status=complete or mailbox_count>0 in DB, always show 100 — Redis may have stale partial value
                    "progress": 100 if (m365_status == "complete" or _iv("m365", "mailbox_count") > 0) else (m365_progress or 0),
                    "status": m365_status if (m365_progress > 0 or _iv("m365", "mailbox_count") > 0) else ("complete" if _iv("m365", "mailbox_count") > 0 else "not_started"),
                    "emails_processed": m365_emails,
                    "mailboxes": m365_mailboxes or _iv("m365", "mailbox_count"),
                    "groups": _iv("m365", "groups_count"),
                    "aliases": _iv("m365", "aliases_count"),
                    "shared": _iv("m365", "shared_count"),
                    "last_baseline_at": _int_map["m365"].last_baseline_at.isoformat() if "m365" in _int_map and getattr(_int_map["m365"], "last_baseline_at", None) else None,
                },
            },
            "monitored_mailboxes": monitored_mailboxes,
            "delta_sync_note": "Delta sync automatically discovers new inboxes on every 1-minute run",
        }
    finally:
        await redis.aclose()


@router.delete("/baseline/reset")
async def reset_baseline(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear all threats for this org and reset baseline state so a fresh scan runs."""
    import redis.asyncio as aioredis
    from backend.config import settings
    org_id = str(current_user.org_id)
    org_uuid = current_user.org_id

    # Delete all threats for this org
    from sqlalchemy import delete
    from backend.models.db_models import Threat
    deleted = await db.execute(
        delete(Threat).where(Threat.org_id == org_uuid)
    )
    await db.commit()

    # Reset Redis baseline state
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await r.delete(
            f"baseline:{org_id}:status",
            f"baseline:{org_id}:progress",
            f"baseline:{org_id}:emails_processed",
            f"baseline:{org_id}:error",
        )
    finally:
        await r.aclose()

    return {"reset": True, "threats_deleted": deleted.rowcount, "org_id": org_id}


# ── Scoped Group Monitoring ────────────────────────────────────────────────────
class ScopeGroupRequest(BaseModel):
    provider: str          # "google" | "m365"
    group_id: str | None   # None = clear scope (monitor all users)
    group_name: str | None = None

@router.post("/scope-group")
async def set_scope_group(
    body: ScopeGroupRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Set or clear the scoped monitoring group for a provider.
    When set, only members of this group will be monitored (not the whole tenant).
    """
    from sqlalchemy import select as _sel
    from backend.models.db_models import OrgIntegration as _OI
    integration = (await db.execute(
        _sel(_OI).where(_OI.org_id == current_user.org_id, _OI.provider == body.provider)
    )).scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Provider not connected")
    integration.scope_group_id = body.group_id
    integration.scope_group_name = body.group_name

    # When setting a scope group, deactivate all current users for this org+provider so only
    # confirmed group members get re-activated on the next sync (prevents out-of-scope scanning)
    from backend.models.db_models import User as _User
    from sqlalchemy import update as _upd
    deactivated = 0
    if body.group_id:
        provider_to_dir = {"google": "google", "m365": "m365"}
        dir_prov = provider_to_dir.get(body.provider, body.provider)
        _upd_res = await db.execute(
            _upd(_User)
            .where(_User.org_id == current_user.org_id, _User.directory_provider == dir_prov)
            .values(is_active=False)
        )
        deactivated = _upd_res.rowcount

    await db.commit()
    action = "cleared" if not body.group_id else f"set to group '{body.group_name or body.group_id}'"
    return {"status": "ok", "provider": body.provider, "scope": action, "deactivated_users": deactivated}


@router.get("/scope-group/{provider}")
async def get_scope_group(
    provider: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current scope group for a provider."""
    from sqlalchemy import select as _sel
    from backend.models.db_models import OrgIntegration as _OI
    integration = (await db.execute(
        _sel(_OI).where(_OI.org_id == current_user.org_id, _OI.provider == provider)
    )).scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Provider not connected")
    return {
        "provider": provider,
        "scope_group_id": integration.scope_group_id,
        "scope_group_name": integration.scope_group_name,
    }


@router.get("/scope-group/{provider}/search")
async def search_groups_for_scope(
    provider: str,
    q: str = Query("", description="Search term for group name"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search groups in the provider directory for scope selection."""
    import httpx as _hx
    from sqlalchemy import select as _sel
    from backend.models.db_models import OrgIntegration as _OI
    from backend.services.baseline_ingestion import _refresh_m365_token, _refresh_google_token, _decrypt
    integration = (await db.execute(
        _sel(_OI).where(_OI.org_id == current_user.org_id, _OI.provider == provider)
    )).scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Provider not connected")

    access_token = _decrypt(integration.access_token_enc)
    refresh_token = _decrypt(integration.refresh_token_enc)

    results = []
    try:
        if provider == "m365":
            new_tok = await _refresh_m365_token(refresh_token)
            if new_tok: access_token = new_tok
            async with _hx.AsyncClient(timeout=10) as client:
                url = f"https://graph.microsoft.com/v1.0/groups?$select=id,mail,displayName,description"
                if q:
                    url += f"&$search=\"displayName:{q}\"&$filter=mailEnabled eq true"
                    headers = {"Authorization": f"Bearer {access_token}", "ConsistencyLevel": "eventual"}
                else:
                    headers = {"Authorization": f"Bearer {access_token}"}
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    results = [
                        {"id": g["id"], "name": g.get("displayName",""), "email": g.get("mail","")}
                        for g in resp.json().get("value", [])
                    ]
        elif provider == "google":
            from backend.services.baseline_ingestion import _get_sa_headers_async, _google_list_users
            new_tok = await _refresh_google_token(refresh_token)
            if new_tok: access_token = new_tok
            sa_headers = await _get_sa_headers_async()
            headers = sa_headers or {"Authorization": f"Bearer {access_token}"}
            async with _hx.AsyncClient(timeout=10) as client:
                url = f"https://admin.googleapis.com/admin/directory/v1/groups?domain={integration.org_domain or ''}&maxResults=50"
                if q:
                    url += f"&query={q}"
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    results = [
                        {"id": g["id"], "name": g.get("name",""), "email": g.get("email","")}
                        for g in resp.json().get("groups", [])
                    ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"groups": results}
