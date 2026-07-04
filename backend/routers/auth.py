import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional as OptionalHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from backend.database import get_db
from backend.config import settings
from backend.models.db_models import User, Organization
from backend.schemas.api_schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserOut, OrgOut
)

try:
    from jose import jwt, JWTError
except ImportError:
    from python_jose import jwt, JWTError

from backend.utils.hashing import (
    hash_password,
    verify_password,
    hash_password_async,
    verify_password_async,
)
import redis.asyncio as aioredis
import pyotp
import secrets

router = APIRouter(prefix="/api/auth", tags=["auth"])


bearer_scheme = HTTPBearer(auto_error=False)


async def _get_org_session_timeout(org_id, db) -> int:
    """
    Look up the org's configured session timeout (minutes). Falls back
    to the global JWT_EXPIRE_MINUTES if the org hasn't set one.
    Adnan 2026-06-17: configurable from Settings → Workspace Security.
    """
    try:
        from sqlalchemy import select as _select
        from backend.models.db_models import Organization
        row = (await db.execute(
            _select(Organization.org_metadata).where(Organization.id == org_id)
        )).first()
        if row and row[0]:
            meta = row[0]
            sec = (meta or {}).get("security") or {}
            v = sec.get("session_timeout_minutes")
            if v and isinstance(v, (int, float)) and 5 <= int(v) <= 24 * 60:
                return int(v)
    except Exception:
        pass
    return settings.JWT_EXPIRE_MINUTES


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def get_redis():
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield r
    finally:
        await r.aclose()


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.post("/register", response_model=TokenResponse)
async def register(
    req: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    if not settings.ALLOW_SELF_REGISTRATION:
        raise HTTPException(
            status_code=403,
            detail="Self-registration is disabled. Contact sales@himaya.ai to get onboarded.",
        )
    # Check if org domain already exists
    existing_org = await db.execute(select(Organization).where(Organization.domain == req.domain))
    if existing_org.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Domain already registered")

    # Check if user email exists
    existing_user = await db.execute(select(User).where(User.email == req.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create org
    org = Organization(
        name=req.org_name,
        domain=req.domain,
        country=req.country,
        plan="starter",
    )
    db.add(org)
    await db.flush()

    # Create admin user
    user = User(
        org_id=org.id,
        email=req.email,
        name=req.name or req.email.split("@")[0],
        role="admin",
        password_hash=await hash_password_async(req.password),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    token = create_access_token({"sub": str(user.id), "org_id": str(org.id), "role": user.role})
    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        user_id=str(user.id),
        org_id=str(org.id),
        role=user.role,
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not await verify_password_async(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    user.last_login = datetime.utcnow()
    await db.flush()

    # Per-org configurable session timeout (Adnan 2026-06-17).
    ttl_min = await _get_org_session_timeout(user.org_id, db)
    token = create_access_token(
        {"sub": str(user.id), "org_id": str(user.org_id), "role": user.role},
        expires_delta=timedelta(minutes=ttl_min),
    )
    return TokenResponse(
        access_token=token,
        expires_in=ttl_min * 60,
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    ttl_min = await _get_org_session_timeout(current_user.org_id, db)
    token = create_access_token(
        {
            "sub": str(current_user.id),
            "org_id": str(current_user.org_id),
            "role": current_user.role,
        },
        expires_delta=timedelta(minutes=ttl_min),
    )
    return TokenResponse(
        access_token=token,
        expires_in=ttl_min * 60,
        user_id=str(current_user.id),
        org_id=str(current_user.org_id),
        role=current_user.role,
    )


@router.post("/logout")
async def logout(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    # In a full impl, blacklist the token in Redis
    return {"message": "Logged out successfully"}


@router.get("/mfa/setup")
async def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=current_user.email, issuer_name="HimayaHimaya")

    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]

    # Store secret and backup codes on user record
    from sqlalchemy import text as sql_text
    await db.execute(
        sql_text("UPDATE users SET totp_secret = :secret, backup_codes = :codes WHERE id = :uid"),
        {"secret": secret, "codes": __import__('json').dumps(backup_codes), "uid": str(current_user.id)},
    )
    await db.flush()

    return {"qr_uri": qr_uri, "secret": secret, "backup_codes": backup_codes}


@router.post("/mfa/verify")
async def mfa_verify(
    body: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text as sql_text
    result = await db.execute(
        sql_text("SELECT totp_secret FROM users WHERE id = :uid"),
        {"uid": str(current_user.id)},
    )
    row = result.fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=400, detail="MFA not configured")

    totp = pyotp.TOTP(row[0])
    code = body.get("totp_code", "")
    if not totp.verify(code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # Mark MFA as enabled
    await db.execute(
        sql_text("UPDATE users SET mfa_enabled = TRUE WHERE id = :uid"),
        {"uid": str(current_user.id)},
    )
    await db.flush()
    return {"verified": True}


@router.post("/mfa/disable")
async def mfa_disable(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text as sql_text
    await db.execute(
        sql_text("UPDATE users SET totp_secret = NULL, mfa_enabled = FALSE, backup_codes = NULL WHERE id = :uid"),
        {"uid": str(current_user.id)},
    )
    await db.flush()
    return {"message": "MFA disabled"}


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from backend.models.db_models import Organization
    org_tier = "Launch"
    org_plan = None
    try:
        if current_user.org_id:
            _org_res = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
            _org = _org_res.scalar_one_or_none()
            if _org:
                org_tier = getattr(_org, 'tier', 'Launch') or 'Launch'
                org_plan = _org.plan
    except Exception:
        pass
    return {
        "id": str(current_user.id),
        "org_id": str(current_user.org_id) if current_user.org_id else None,
        "email": current_user.email,
        "name": current_user.name,
        "department": current_user.department,
        "job_title": current_user.job_title,
        "role": current_user.role,
        "is_vip": current_user.is_vip,
        "is_active": current_user.is_active,
        "risk_score": current_user.risk_score,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "tier": org_tier,
        "plan": org_plan,
    }


# ---------------------------------------------------------------------------
# Password set / reset flow
# ---------------------------------------------------------------------------
from pydantic import BaseModel as _BaseModel

class SetPasswordRequest(_BaseModel):
    token: str
    new_password: str

class ForgotPasswordRequest(_BaseModel):
    email: str

@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Send password reset link to user's email."""
    from backend.services.email_service import send_email
    import redis as sync_redis, secrets as sec
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()
    if not user:
        return {"message": "If that email exists, a reset link has been sent."}

    token = sec.token_urlsafe(32)
    r = sync_redis.from_url(settings.REDIS_URL)
    r.setex(f"pwd_reset:{token}", 3600, str(user.id))

    _frontend = os.getenv("FRONTEND_URL", "https://app.himaya.ai")
    reset_url = f"{_frontend}/set-password?token={token}"
    html = f"""<div style="font-family:sans-serif;padding:40px;background:#0a0a0f;color:#f9fafb;">
        <h2>Reset your password</h2>
        <p>Click the link below to set a new password. This link expires in 1 hour.</p>
        <a href="{reset_url}" style="background:#6d28d9;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin-top:16px;">Set New Password</a>
        <p style="color:#6b7280;margin-top:24px;font-size:12px;">If you didn't request this, ignore this email.</p>
    </div>"""
    send_email(user.email, "Reset your Himaya password", html)
    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/set-password")
async def set_password(req: SetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """Set a new password using a reset/activation token."""
    import redis as sync_redis
    r = sync_redis.from_url(settings.REDIS_URL)
    user_id = r.get(f"pwd_reset:{req.token}")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.id == user_id.decode()))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = await hash_password_async(req.new_password)
    user.is_active = True
    await db.commit()
    r.delete(f"pwd_reset:{req.token}")
    return {"message": "Password set successfully. You can now log in."}
