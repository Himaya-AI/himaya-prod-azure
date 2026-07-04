"""
Vendor Admin API — Himaya Helios
Protected by X-Admin-API-Key header or Admin JWT.
Allows provisioning tenants, viewing platform usage, and billing management.
"""
import logging
import os
import secrets
import uuid
import smtplib
import random
import string
from datetime import datetime, timedelta
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import redis as sync_redis
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from backend.utils.hashing import (
    hash_password,
    verify_password,
    hash_password_async,
    verify_password_async,
)
from pydantic import BaseModel
from sqlalchemy import func, select, text, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import get_db
from backend.models.db_models import Organization, User
from backend.services.email_service import send_admin_otp, send_welcome_email, send_email

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["vendor-admin"])



# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

async def verify_admin_token(authorization: str = Header(...)):
    """Verify admin JWT token."""
    from jose import jwt, JWTError
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, settings.JWT_SECRET + "_admin", algorithms=[settings.JWT_ALGORITHM])
        if payload.get("role") != "vendor_admin":
            raise HTTPException(status_code=403, detail="Not an admin token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid admin token")


async def verify_admin_key_or_token(
    x_admin_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Accept either API key (X-Admin-API-Key) or admin JWT (Authorization: Bearer ...)."""
    if x_admin_api_key and x_admin_api_key == settings.VENDOR_ADMIN_API_KEY:
        return True
    if authorization:
        from jose import jwt, JWTError
        try:
            token = authorization.replace("Bearer ", "")
            payload = jwt.decode(token, settings.JWT_SECRET + "_admin", algorithms=[settings.JWT_ALGORITHM])
            if payload.get("role") == "vendor_admin":
                return True
        except JWTError:
            pass
    raise HTTPException(status_code=403, detail="Invalid admin credentials")


# Keep old verify_admin_key as alias for backwards compat
verify_admin_key = verify_admin_key_or_token


async def send_admin_otp_email(to_email: str, otp: str):
    """Send OTP email. In dev mode just prints to console."""
    print(f"\n{'='*50}")
    print(f"HIMAYA HELIOS ADMIN OTP")
    print(f"To: {to_email}")
    print(f"OTP Code: {otp}")
    print(f"Valid for 10 minutes")
    print(f"{'='*50}\n")

    # Try sending via SMTP if configured
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"Himaya Helios Admin OTP: {otp}"
            msg["From"] = smtp_user
            msg["To"] = to_email

            html = f"""
            <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; padding: 40px;">
              <img src="https://himayahelios.io/himaya-logo.png" alt="Himaya Helios" style="height: 40px; margin-bottom: 24px;" />
              <h2 style="color: #1a1a2e;">Vendor Admin Login</h2>
              <p style="color: #666;">Your one-time login code:</p>
              <div style="font-size: 48px; font-weight: bold; letter-spacing: 12px; color: #7c3aed; margin: 24px 0; text-align: center;">
                {otp}
              </div>
              <p style="color: #999; font-size: 12px;">Valid for 10 minutes. Do not share this code.</p>
            </div>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP_SSL(smtp_host, 465) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, to_email, msg.as_string())
            print(f"OTP email sent successfully to {to_email}")
        except Exception as e:
            print(f"SMTP failed ({e}), OTP logged above")


@router.post("/auth/login")
async def admin_login(body: dict):
    """
    Step 1 of admin login: verify password, then send OTP to adnan@himaya.ai
    Body: {email, password}
    """
    if body.get("email") != settings.VENDOR_ADMIN_EMAIL:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if body.get("password") != settings.VENDOR_ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate 6-digit OTP
    otp = ''.join(random.choices(string.digits, k=6))

    # Store OTP in Redis with 10 min TTL
    r = sync_redis.from_url(settings.REDIS_URL)
    r.setex(f"admin_otp:{settings.VENDOR_ADMIN_EMAIL}", 600, otp)

    # Send OTP via Amazon SES
    send_admin_otp(settings.VENDOR_ADMIN_EMAIL, otp)

    return {"message": "OTP sent to your email", "email": settings.VENDOR_ADMIN_EMAIL}


@router.post("/auth/verify-otp")
async def admin_verify_otp(body: dict):
    """
    Step 2: verify OTP, issue admin JWT
    Body: {email, otp}
    """
    r = sync_redis.from_url(settings.REDIS_URL)
    stored_otp = r.get(f"admin_otp:{body.get('email')}")

    if not stored_otp or stored_otp.decode() != body.get("otp"):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

    # Delete OTP after use
    r.delete(f"admin_otp:{body.get('email')}")

    # Issue admin JWT (different secret/role from customer JWT)
    from jose import jwt
    token = jwt.encode(
        {
            "sub": body.get("email"),
            "role": "vendor_admin",
            "exp": datetime.utcnow() + timedelta(hours=8)
        },
        settings.JWT_SECRET + "_admin",
        algorithm=settings.JWT_ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer", "role": "vendor_admin"}


# ---------------------------------------------------------------------------
# Org schemas
# ---------------------------------------------------------------------------

class ProvisionOrgRequest(BaseModel):
    org_name: str
    domain: str
    plan: str = "starter"
    country: str = "Saudi Arabia"
    mailbox_limit: int = 100
    billing_rate_usd: float = 8.00
    contact_email: str
    contact_name: str


class UpdateOrgRequest(BaseModel):
    plan: Optional[str] = None
    mailbox_limit: Optional[int] = None
    billing_rate_usd: Optional[float] = None
    contact_email: Optional[str] = None
    contact_name: Optional[str] = None


# ---------------------------------------------------------------------------
# Org endpoints
# ---------------------------------------------------------------------------

@router.post("/orgs", dependencies=[Depends(verify_admin_key)])
async def provision_org(req: ProvisionOrgRequest, db: AsyncSession = Depends(get_db)):
    """Provision a new customer tenant."""
    # Check domain uniqueness
    existing = await db.execute(select(Organization).where(Organization.domain == req.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Domain already registered")

    org = Organization(
        name=req.org_name,
        domain=req.domain,
        plan=req.plan,
        country=req.country,
    )
    db.add(org)
    await db.flush()

    # Set new columns via raw SQL (they may not be in the ORM model yet)
    await db.execute(
        text("""
            UPDATE organizations SET
                mailbox_limit = :ml,
                billing_rate_usd = :br,
                contact_email = :ce,
                contact_name = :cn,
                status = 'active'
            WHERE id = :oid
        """),
        {"ml": req.mailbox_limit, "br": req.billing_rate_usd,
         "ce": req.contact_email, "cn": req.contact_name, "oid": str(org.id)},
    )

    # Create first admin user — no temp password, activation token flow
    import redis as sync_redis
    admin_email = req.contact_email  # use their real email as login
    user = User(
        org_id=org.id,
        email=admin_email,
        name=req.contact_name,
        role="admin",
        password_hash=await hash_password_async(secrets.token_urlsafe(32)),  # random unusable hash until they set password
        is_active=False,  # inactive until they set password via activation link
    )
    db.add(user)
    await db.flush()

    # Generate activation token (valid 72h)
    activation_token = secrets.token_urlsafe(32)
    r = sync_redis.from_url(settings.REDIS_URL)
    r.setex(f"pwd_reset:{activation_token}", 72 * 3600, str(user.id))

    cft_activation_url = f"https://app.himaya.ai/set-password?token={activation_token}"

    # Send branded welcome email via send_email with inline Himaya logo
    if req.contact_email:
        welcome_html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#0d1b2e;border-radius:16px;border:1px solid #1a2744;overflow:hidden;">
        <tr><td style="background:#0d1b2e;padding:36px 40px 28px;text-align:center;border-bottom:2px solid #3b6ef6;">
          <img src="cid:himaya-logo" alt="Himaya Helios" height="40"
               style="display:block;margin:0 auto;max-width:180px;border:0;" />
          <p style="margin:12px 0 0;color:#a1a1aa;font-size:11px;letter-spacing:2px;text-transform:uppercase;">Vendor Portal &mdash; New Account</p>
        </td></tr>
        <tr><td style="padding:36px 40px 32px;">
          <h1 style="margin:0 0 8px;color:#ffffff;font-size:22px;font-weight:700;">Welcome to Himaya Helios</h1>
          <p style="margin:0 0 24px;color:#a1a1aa;font-size:14px;line-height:1.75;">
            Your account for <strong style="color:#fff;">{req.org_name}</strong> has been provisioned by Himaya Technologies.
            Click below to set your password and gain access to the platform.
          </p>
          <div style="background:#0a0f1e;border:1px solid #1a2744;border-radius:10px;padding:20px;margin-bottom:28px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:8px 0;border-bottom:1px solid #1a2744;color:#a1a1aa;font-size:13px;width:140px;">Organization</td>
                <td style="padding:8px 0;border-bottom:1px solid #1a2744;color:#ffffff;font-size:13px;font-weight:600;">{req.org_name}</td>
              </tr>
              <tr>
                <td style="padding:8px 0;border-bottom:1px solid #1a2744;color:#a1a1aa;font-size:13px;">Admin Email</td>
                <td style="padding:8px 0;border-bottom:1px solid #1a2744;color:#ffffff;font-size:13px;font-weight:600;">{admin_email}</td>
              </tr>
              <tr>
                <td style="padding:8px 0;color:#a1a1aa;font-size:13px;">Plan</td>
                <td style="padding:8px 0;color:#3b6ef6;font-size:13px;font-weight:600;">{req.plan.capitalize()}</td>
              </tr>
            </table>
          </div>
          <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:12px;">
            <tr><td align="center">
              <a href="{cft_activation_url}"
                 style="display:inline-block;background:#3b6ef6;color:#ffffff;text-decoration:none;
                        padding:14px 44px;border-radius:10px;font-size:15px;font-weight:700;letter-spacing:0.2px;">
                Set Up Your Account &rarr;
              </a>
            </td></tr>
          </table>
          <p style="margin:0 0 24px;color:#a1a1aa;font-size:11px;text-align:center;">Link expires in 72 hours. Do not share this email.</p>
          <p style="margin:0;color:#a1a1aa;font-size:12px;text-align:center;">
            Questions? <a href="mailto:support@himaya.ai" style="color:#3b6ef6;text-decoration:none;">support@himaya.ai</a>
          </p>
        </td></tr>
        <tr><td style="background:#0a0f1e;padding:24px 40px;border-top:1px solid #1a2744;">
          <p style="margin:0;color:#a1a1aa;font-size:11px;text-align:center;">
            &copy; 2026 Himaya Technologies Group Inc. &mdash;
            <a href="https://app.himaya.ai" style="color:#3b6ef6;text-decoration:none;">app.himaya.ai</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
        send_email(
            req.contact_email,
            f"Welcome to Himaya Helios — {req.org_name}",
            welcome_html,
            f"Welcome to Himaya Helios\n\nHi {req.contact_name or req.org_name},\n\nYour account for {req.org_name} is ready.\nAdmin Email: {admin_email}\n\nSet up your account: {cft_activation_url}\n\nLink expires in 72 hours.\n\n© 2026 Himaya Technologies Group Inc.",
        )
    logger.info(f"Welcome email sent to {req.contact_email}: org={req.org_name}, login={admin_email}")

    return {
        "org_id": str(org.id),
        "org_name": req.org_name,
        "admin_email": admin_email,
        "activation_url": cft_activation_url,
        "onboarding_url": f"https://app.himaya.ai/onboarding?org={org.id}",
    }


@router.get("/orgs", dependencies=[Depends(verify_admin_key)])
async def list_orgs(
    db: AsyncSession = Depends(get_db),
    plan: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """List all customer orgs with usage and billing summary."""
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    rows = await db.execute(
        text("""
            SELECT
                o.id, o.name, o.domain, o.plan,
                COALESCE(o.status, 'active') AS status,
                COALESCE(o.mailbox_count, 0) AS mailbox_count,
                COALESCE(o.mailbox_limit, 100) AS mailbox_limit,
                COALESCE(o.billing_rate_usd, 8.00) AS billing_rate_usd,
                COALESCE(o.contact_email, '') AS contact_email,
                COALESCE(o.contact_name, '') AS contact_name,
                o.created_at,
                COALESCE(mu.emails_scanned, 0) AS emails_scanned_mtd,
                COALESCE(mu.threats_detected, 0) AS threats_detected_mtd,
                COALESCE(mu_all.total_scanned, 0) AS emails_scanned_total,
                COALESCE((
                    SELECT SUM(oi.mailbox_count)
                    FROM org_integrations oi
                    WHERE oi.org_id = o.id AND oi.status = 'active'
                ), 0) AS inboxes_onboarded,
                COALESCE((
                    SELECT COUNT(*)
                    FROM threats t
                    WHERE t.org_id = o.id AND t.detected_at >= :month_start
                ), 0) AS emails_processed_mtd
            FROM organizations o
            LEFT JOIN monthly_usage mu
                ON mu.org_id = o.id AND mu.year = :yr AND mu.month = :mo
            LEFT JOIN (
                SELECT org_id, SUM(emails_scanned) AS total_scanned
                FROM monthly_usage GROUP BY org_id
            ) mu_all ON mu_all.org_id = o.id
            ORDER BY o.created_at DESC
        """),
        {"yr": now.year, "mo": now.month, "month_start": month_start},
    )
    orgs = rows.fetchall()

    # Bulk-check auto_triage enabled from Redis
    r = sync_redis.from_url(settings.REDIS_URL)
    auto_triage_map: dict = {}
    try:
        pipe = r.pipeline()
        for row in orgs:
            pipe.get(f"auto_triage:enabled:{row.id}")
        results_at = pipe.execute()
        for row, val in zip(orgs, results_at):
            auto_triage_map[str(row.id)] = (val == b"true" or val == b"1" or val == "true")
    except Exception:
        pass

    result = []
    for row in orgs:
        if plan and row.plan != plan:
            continue
        if status and row.status != status:
            continue
        if search and search.lower() not in row.name.lower() and search.lower() not in row.domain.lower():
            continue

        monthly_bill = float(row.mailbox_count or 0) * float(row.billing_rate_usd or 8.0)
        emails_mtd = int(row.emails_processed_mtd or 0)
        result.append({
            "org_id": str(row.id),
            "name": row.name,
            "domain": row.domain,
            "plan": row.plan,
            "tier": getattr(row, 'tier', 'Launch') or 'Launch',
            "status": row.status,
            "mailbox_count": row.mailbox_count,
            "mailbox_limit": row.mailbox_limit,
            "contact_email": row.contact_email,
            "contact_name": row.contact_name,
            "emails_scanned_mtd": row.emails_scanned_mtd,
            "threats_detected_mtd": row.threats_detected_mtd,
            "emails_scanned_total": row.emails_scanned_total,
            "monthly_bill_usd": round(monthly_bill, 2),
            "billing_rate_usd": float(row.billing_rate_usd),
            "inboxes_onboarded": int(row.inboxes_onboarded or 0),
            "emails_processed_mtd": emails_mtd,
            "auto_triage_enabled": auto_triage_map.get(str(row.id), False),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })

    return result


@router.get("/orgs/{org_id}", dependencies=[Depends(verify_admin_key)])
async def get_org(org_id: str, db: AsyncSession = Depends(get_db)):
    """Full org detail with users and usage history."""
    org = await db.execute(select(Organization).where(Organization.id == uuid.UUID(org_id)))
    org = org.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    users_result = await db.execute(
        text("SELECT id, email, name, role, is_active, last_login, created_at FROM users WHERE org_id = :oid"),
        {"oid": org_id},
    )
    users = [
        {
            "id": str(r.id), "email": r.email, "name": r.name,
            "role": r.role, "is_active": r.is_active,
            "last_login": r.last_login.isoformat() if r.last_login else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in users_result.fetchall()
    ]

    usage_result = await db.execute(
        text("""
            SELECT year, month, emails_scanned, threats_detected,
                   emails_quarantined, emails_blocked, reports_generated
            FROM monthly_usage WHERE org_id = :oid ORDER BY year DESC, month DESC LIMIT 12
        """),
        {"oid": org_id},
    )
    usage_history = [dict(r._mapping) for r in usage_result.fetchall()]

    # Defensive query: only select columns guaranteed to exist; add missing ones via migration on first write
    try:
        billing_result = await db.execute(
            text("""
                SELECT billing_period,
                       COALESCE(total_amount_usd, 0) AS total_amount_usd,
                       status, invoice_id, created_at,
                       0 AS mailbox_count, 0 AS emails_scanned,
                       0 AS rate_per_mailbox_usd, 0 AS base_amount_usd,
                       0 AS overage_amount_usd, NULL AS paid_at
                FROM billing_records WHERE org_id = :oid ORDER BY billing_period DESC LIMIT 12
            """),
            {"oid": org_id},
        )
    except Exception:
        billing_result = None

    billing_history = []
    if billing_result:
      for r in billing_result.fetchall():
        d = dict(r._mapping)
        for k in ["rate_per_mailbox_usd", "base_amount_usd", "overage_amount_usd", "total_amount_usd"]:
            if d.get(k) is not None:
                d[k] = float(d[k])
        billing_history.append(d)

    try:
        extra_row = await db.execute(
            text("""SELECT COALESCE(mailbox_limit, 100) AS mailbox_limit,
                           COALESCE(billing_rate_usd, 8.00) AS billing_rate_usd,
                           COALESCE(status, 'active') AS status,
                           COALESCE(contact_email, '') AS contact_email,
                           COALESCE(contact_name, '') AS contact_name,
                           suspended_at
                    FROM organizations WHERE id = :oid"""),
            {"oid": org_id},
        )
        extra = extra_row.fetchone()
    except Exception:
        extra = None

    return {
        "org_id": org_id,
        "name": org.name,
        "domain": org.domain,
        "plan": org.plan,
        "tier": getattr(org, 'tier', 'Launch') or 'Launch',
        "country": org.country,
        "mailbox_count": org.mailbox_count,
        "mailbox_limit": extra.mailbox_limit if extra else 100,
        "billing_rate_usd": float(extra.billing_rate_usd) if extra and extra.billing_rate_usd else 8.0,
        "status": extra.status if extra else "active",
        "contact_email": extra.contact_email if extra else None,
        "contact_name": extra.contact_name if extra else None,
        "suspended_at": extra.suspended_at.isoformat() if extra and extra.suspended_at else None,
        "created_at": org.created_at.isoformat() if org.created_at else None,
        "users": users,
        "usage_history": usage_history,
        "billing_history": billing_history,
    }


@router.put("/orgs/{org_id}", dependencies=[Depends(verify_admin_key)])
async def update_org(org_id: str, req: UpdateOrgRequest, db: AsyncSession = Depends(get_db)):
    updates = {}
    if req.plan is not None:
        updates["plan"] = req.plan
    if req.mailbox_limit is not None:
        updates["mailbox_limit"] = req.mailbox_limit
    if req.billing_rate_usd is not None:
        updates["billing_rate_usd"] = req.billing_rate_usd
    if req.contact_email is not None:
        updates["contact_email"] = req.contact_email
    if req.contact_name is not None:
        updates["contact_name"] = req.contact_name

    if updates:
        set_clause = ", ".join(f"{k} = :{k}" for k in updates)
        updates["oid"] = org_id
        await db.execute(text(f"UPDATE organizations SET {set_clause} WHERE id = :oid"), updates)

    return {"updated": True, "org_id": org_id}


@router.post("/orgs/{org_id}/suspend", dependencies=[Depends(verify_admin_key)])
async def suspend_org(org_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(
        text("UPDATE organizations SET status = 'suspended', suspended_at = NOW() WHERE id = :oid"),
        {"oid": org_id},
    )
    # Deactivate all users
    await db.execute(text("UPDATE users SET is_active = FALSE WHERE org_id = :oid"), {"oid": org_id})
    return {"suspended": True, "org_id": org_id}


@router.post("/orgs/{org_id}/reactivate", dependencies=[Depends(verify_admin_key)])
async def reactivate_org(org_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(
        text("UPDATE organizations SET status = 'active', suspended_at = NULL WHERE id = :oid"),
        {"oid": org_id},
    )
    await db.execute(text("UPDATE users SET is_active = TRUE WHERE org_id = :oid"), {"oid": org_id})
    return {"reactivated": True, "org_id": org_id}


@router.delete("/orgs/{org_id}", dependencies=[Depends(verify_admin_key)])
async def offboard_org(org_id: str, db: AsyncSession = Depends(get_db)):
    """Soft delete — marks org as offboarded, keeps data for 90 days."""
    await db.execute(
        text("UPDATE organizations SET status = 'offboarded', suspended_at = NOW() WHERE id = :oid"),
        {"oid": org_id},
    )
    await db.execute(text("UPDATE users SET is_active = FALSE WHERE org_id = :oid"), {"oid": org_id})
    return {"offboarded": True, "org_id": org_id, "data_retained_until": (datetime.utcnow() + timedelta(days=90)).date().isoformat()}


@router.post("/orgs/{org_id}/resend-activation", dependencies=[Depends(verify_admin_key)])
async def resend_activation(org_id: str, db: AsyncSession = Depends(get_db)):
    """Resend activation email for an org's admin user (inactive account)."""
    import secrets
    import redis as sync_redis
    from backend.config import settings
    from backend.models.db_models import User
    from backend.services.email_service import send_welcome_email

    # Get the org
    org_result = await db.execute(
        select(Organization).where(Organization.id == uuid.UUID(org_id))
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Org not found")

    # Get the primary admin user for this org
    user_result = await db.execute(
        select(User).where(User.org_id == uuid.UUID(org_id), User.role == "admin")
        .order_by(User.created_at.asc()).limit(1)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="No admin user found for this org")

    # Generate fresh activation token
    activation_token = secrets.token_urlsafe(32)
    r = sync_redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    r.setex(f"pwd_reset:{activation_token}", 72 * 3600, str(user.id))

    activation_url = f"https://app.himaya.ai/set-password?token={activation_token}"
    onboarding_url = f"https://app.himaya.ai/onboarding"
    contact_name = getattr(org, 'contact_name', None) or user.name or user.email.split("@")[0]

    sent = send_welcome_email(
        to_email=user.email,
        org_name=org.name,
        contact_name=contact_name,
        activation_url=activation_url,
        onboarding_url=onboarding_url,
    )

    logger.info(f"Resent activation to {user.email} for org {org.name} (sent={sent})")
    return {"sent": sent, "email": user.email, "token_valid_hours": 72}


# ---------------------------------------------------------------------------
# Usage endpoints
# ---------------------------------------------------------------------------

@router.get("/usage", dependencies=[Depends(verify_admin_key)])
async def platform_usage(db: AsyncSession = Depends(get_db)):
    """Platform-wide usage stats."""
    now = datetime.utcnow()

    total_orgs_r = await db.execute(text("SELECT COUNT(*) FROM organizations WHERE COALESCE(status, 'active') = 'active'"))
    total_orgs = total_orgs_r.scalar() or 0

    mtd_r = await db.execute(
        text("SELECT COALESCE(SUM(emails_scanned),0), COALESCE(SUM(threats_detected),0) FROM monthly_usage WHERE year=:yr AND month=:mo"),
        {"yr": now.year, "mo": now.month},
    )
    mtd_row = mtd_r.fetchone()
    emails_mtd = int(mtd_row[0])
    threats_mtd = int(mtd_row[1])

    all_time_r = await db.execute(text("SELECT COALESCE(SUM(emails_scanned),0) FROM monthly_usage"))
    emails_all_time = int(all_time_r.scalar() or 0)

    mrr_r = await db.execute(
        text("SELECT COALESCE(SUM(mailbox_count * COALESCE(billing_rate_usd, 8.00)), 0) FROM organizations WHERE COALESCE(status, 'active') = 'active'")
    )
    total_mrr = float(mrr_r.scalar() or 0)

    top_orgs_r = await db.execute(
        text("""
            SELECT o.name, o.plan, COALESCE(mu.emails_scanned, 0) AS emails_mtd
            FROM organizations o
            LEFT JOIN monthly_usage mu ON mu.org_id = o.id AND mu.year = :yr AND mu.month = :mo
            ORDER BY emails_mtd DESC LIMIT 10
        """),
        {"yr": now.year, "mo": now.month},
    )
    top_orgs = [{"org_name": r.name, "plan": r.plan, "emails_mtd": r.emails_mtd} for r in top_orgs_r.fetchall()]

    # Daily volume last 30 days from usage_events
    daily_r = await db.execute(
        text("""
            SELECT
                DATE(recorded_at) AS day,
                SUM(CASE WHEN event_type = 'email_scanned' THEN count ELSE 0 END) AS emails_scanned,
                SUM(CASE WHEN event_type = 'threat_detected' THEN count ELSE 0 END) AS threats_detected
            FROM usage_events
            WHERE recorded_at >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(recorded_at) ORDER BY DATE(recorded_at)
        """)
    )
    daily_volume = [
        {"date": str(r.day), "emails_scanned": int(r.emails_scanned), "threats_detected": int(r.threats_detected)}
        for r in daily_r.fetchall()
    ]

    return {
        "total_orgs": total_orgs,
        "total_emails_scanned_mtd": emails_mtd,
        "total_emails_scanned_all_time": emails_all_time,
        "total_threats_detected_mtd": threats_mtd,
        "total_mrr_usd": round(total_mrr, 2),
        "top_orgs_by_volume": top_orgs,
        "daily_volume_30d": daily_volume,
    }


@router.get("/usage/{org_id}/history", dependencies=[Depends(verify_admin_key)])
async def org_usage_history(org_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        text("""
            SELECT year, month, emails_scanned, threats_detected,
                   emails_quarantined, emails_blocked, reports_generated
            FROM monthly_usage WHERE org_id = :oid
            ORDER BY year DESC, month DESC LIMIT 24
        """),
        {"oid": org_id},
    )
    rows = result.fetchall()

    # Also pull billing amount for each month
    billing_r = await db.execute(
        text("SELECT billing_period, total_amount_usd FROM billing_records WHERE org_id = :oid"),
        {"oid": org_id},
    )
    billing_map = {r.billing_period: float(r.total_amount_usd or 0) for r in billing_r.fetchall()}

    history = []
    for r in rows:
        period = f"{r.year}-{str(r.month).zfill(2)}"
        history.append({
            "month": period,
            "emails_scanned": r.emails_scanned,
            "threats_detected": r.threats_detected,
            "emails_quarantined": r.emails_quarantined,
            "emails_blocked": r.emails_blocked,
            "reports_generated": r.reports_generated,
            "amount_billed_usd": billing_map.get(period, 0.0),
        })
    return history


# ---------------------------------------------------------------------------
# Billing endpoints
# ---------------------------------------------------------------------------

@router.get("/billing", dependencies=[Depends(verify_admin_key)])
async def billing_summary(db: AsyncSession = Depends(get_db)):
    """Billing summary for all orgs this month."""
    now = datetime.utcnow()
    period = f"{now.year}-{str(now.month).zfill(2)}"

    rows = await db.execute(
        text("""
            SELECT
                o.id, o.name, o.plan,
                COALESCE(o.mailbox_count, 0) AS mailboxes,
                COALESCE(o.billing_rate_usd, 8.00) AS rate,
                COALESCE(mu.emails_scanned, 0) AS emails_scanned_mtd,
                COALESCE(br.total_amount_usd, 0) AS amount_due_usd,
                COALESCE(br.status, 'pending') AS billing_status
            FROM organizations o
            LEFT JOIN monthly_usage mu ON mu.org_id = o.id AND mu.year = :yr AND mu.month = :mo
            LEFT JOIN billing_records br ON br.org_id = o.id AND br.billing_period = :period
            WHERE COALESCE(o.status, 'active') != 'offboarded'
            ORDER BY amount_due_usd DESC
        """),
        {"yr": now.year, "mo": now.month, "period": period},
    )

    result = []
    for r in rows.fetchall():
        base = float(r.mailboxes) * float(r.rate)
        result.append({
            "org_id": str(r.id),
            "org_name": r.name,
            "plan": r.plan,
            "mailboxes": r.mailboxes,
            "emails_scanned_mtd": r.emails_scanned_mtd,
            "rate_per_mailbox_usd": float(r.rate),
            "base_amount_usd": round(base, 2),
            "amount_due_usd": float(r.amount_due_usd) if r.amount_due_usd else round(base, 2),
            "billing_status": r.billing_status,
            "billing_period": period,
        })
    return result


@router.post("/billing/{org_id}/invoice", dependencies=[Depends(verify_admin_key)])
async def generate_invoice(org_id: str, db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    period = f"{now.year}-{str(now.month).zfill(2)}"

    org_r = await db.execute(
        text("SELECT name, plan, mailbox_count, billing_rate_usd FROM organizations WHERE id = :oid"),
        {"oid": org_id},
    )
    org = org_r.fetchone()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    usage_r = await db.execute(
        text("SELECT emails_scanned FROM monthly_usage WHERE org_id = :oid AND year = :yr AND month = :mo"),
        {"oid": org_id, "yr": now.year, "mo": now.month},
    )
    usage = usage_r.fetchone()
    emails_scanned = usage.emails_scanned if usage else 0

    rate = float(org.billing_rate_usd or 8.0)
    mailboxes = org.mailbox_count or 0
    base_amount = mailboxes * rate
    invoice_id = f"INV-{now.year}{str(now.month).zfill(2)}-{org_id[:8].upper()}"

    await db.execute(
        text("""
            INSERT INTO billing_records (org_id, billing_period, plan, mailbox_count, emails_scanned,
                rate_per_mailbox_usd, base_amount_usd, overage_amount_usd, total_amount_usd, status, invoice_id)
            VALUES (:oid, :period, :plan, :mailboxes, :emails, :rate, :base, 0, :total, 'invoiced', :inv_id)
            ON CONFLICT (org_id, billing_period) DO UPDATE SET
                status = 'invoiced', invoice_id = EXCLUDED.invoice_id,
                total_amount_usd = EXCLUDED.total_amount_usd
        """),
        {
            "oid": org_id, "period": period, "plan": org.plan,
            "mailboxes": mailboxes, "emails": emails_scanned,
            "rate": rate, "base": base_amount, "total": base_amount,
            "inv_id": invoice_id,
        },
    )

    return {
        "invoice_id": invoice_id,
        "org_id": org_id,
        "org_name": org.name,
        "billing_period": period,
        "mailboxes": mailboxes,
        "emails_scanned": emails_scanned,
        "rate_per_mailbox_usd": rate,
        "total_amount_usd": round(base_amount, 2),
        "status": "invoiced",
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Internal ops: trigger baseline sync for any org
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/trigger-baseline")
async def trigger_baseline(
    org_id: str,
    background_tasks: BackgroundTasks,
    _auth=Depends(verify_admin_key_or_token),
):
    """Force-start a fresh baseline ingestion for the given org. Admin-key protected."""
    from backend.services.baseline_ingestion import run_baseline_ingestion
    background_tasks.add_task(run_baseline_ingestion, org_id, 50)
    return {"status": "started", "org_id": org_id}


# ---------------------------------------------------------------------------
# Emergency: force-reset a user's password (admin-key protected)
# ---------------------------------------------------------------------------

class ForcePasswordResetRequest(BaseModel):
    email: str
    new_password: str

@router.post("/maintenance/clean-triage-reasoning", dependencies=[Depends(verify_admin_key)])
async def clean_triage_reasoning(db: AsyncSession = Depends(get_db)):
    """
    One-time maintenance: replace legacy 'Claude unavailable' / 'Claude API error' strings
    in threat_indicators.auto_triage_reasoning with Helios Analysis branding.
    """
    from backend.models.db_models import Threat
    from sqlalchemy import select
    import copy

    result = await db.execute(
        select(Threat).where(
            Threat.threat_indicators["auto_triaged"].as_boolean() == True  # noqa: E712
        )
    )
    threats = result.scalars().all()
    updated = 0
    for t in threats:
        ti = dict(t.threat_indicators or {})
        reasoning = ti.get("auto_triage_reasoning", "")
        if reasoning and ("Claude" in reasoning or "claude" in reasoning):
            # Replace legacy Claude references
            new_reasoning = (
                reasoning
                .replace("Claude unavailable", "Helios Analysis fallback")
                .replace("Claude API error", "analysis engine error")
                .replace("Claude unavailable — verdict based on", "Helios Analysis fallback — verdict based on")
            )
            # Strip old exception text appended after the period
            import re
            new_reasoning = re.sub(r"\.\s*Claude API error: \d+", ".", new_reasoning)
            ti["auto_triage_reasoning"] = new_reasoning
            t.threat_indicators = ti
            updated += 1
    if updated:
        await db.commit()
    return {"updated": updated, "message": f"Patched {updated} threat records"}


@router.post("/users/force-reset-password", dependencies=[Depends(verify_admin_key)])
async def force_reset_password(
    req: ForcePasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    """Directly set a user's password. Admin-key protected. Use for emergency access recovery."""
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail=f"No user found with email: {req.email}")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user.password_hash = await hash_password_async(req.new_password)
    user.is_active = True
    await db.commit()
    return {"message": f"Password reset for {req.email}", "is_active": True}


@router.post("/orgs/{org_id}/inject-test-threats", dependencies=[Depends(verify_admin_key)])
async def inject_test_threats(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Dev/QA: inject simulated threat emails directly into the Helios processing pipeline
    for the given org. Bypasses email delivery — calls process_email() directly with
    crafted payloads simulating real attacker scenarios.
    Requires admin API key.
    """
    import uuid as _uuid
    from backend.services.email_processor import process_email
    from backend.models.db_models import User as _User
    from sqlalchemy import select as _sel

    # Get real recipient emails for this org
    users_res = await db.execute(
        _sel(_User.email).where(
            _User.org_id == _uuid.UUID(org_id),
            _User.is_active == True,  # noqa: E712
        ).limit(8)
    )
    recipients = [r[0] for r in users_res.fetchall()]
    if not recipients:
        return {"error": "No active users found for org", "org_id": org_id}

    # Pick 4 recipients (cycle if fewer available)
    def _pick(i):
        return recipients[i % len(recipients)]

    test_payloads = [
        {
            "label": "MALWARE — macro attachment lure",
            "data": {
                "message_id": f"test-malware-{_uuid.uuid4().hex[:8]}@gulf-capital-investments.co",
                "sender": "ahmed.alrashidi@gulf-capital-investments.co",
                "recipient": _pick(0),
                "subject": "Q1 2026 Financial Report — Please Review Before 9 AM",
                "body": (
                    "Dear Colleague, Please find attached the Q1 2026 Financial Report. "
                    "The document requires macros to be enabled for the interactive charts. "
                    "Kindly open and review Q1_Financial_Report_2026.xlsm before the 9 AM meeting. "
                    "The password to unlock the protected sections is: Qfin2026! "
                    "This message was sent from a secure external server."
                ),
                "html_body": "",
                "date": "Mon, 14 Apr 2026 04:30:00 +0000",
                "auth_results": {"spf": "fail", "dkim": "none", "dmarc": "fail", "sender_ip": "197.210.54.88"},
                "attachments": [
                    {"filename": "Q1_Financial_Report_2026.xlsm", "mimeType": "application/vnd.ms-excel.sheet.macroEnabled.12", "size": 89432}
                ],
            },
        },
        {
            "label": "ACCOUNT TAKEOVER — fake Microsoft security alert",
            "data": {
                "message_id": f"test-ato-{_uuid.uuid4().hex[:8]}@microsoftonline-alerts.net",
                "sender": "security-noreply@microsoftonline-alerts.net",
                "recipient": _pick(1),
                "subject": "URGENT: Unusual sign-in to your Microsoft 365 account from Nigeria",
                "body": (
                    "We detected a sign-in attempt to your Microsoft 365 account from an unrecognized device. "
                    "Location: Lagos, Nigeria. IP Address: 197.210.54.121. "
                    "If this was not you, your account may be compromised. You must verify your identity within 24 hours "
                    "or your account will be suspended. Click here to secure your account: "
                    "http://microsoft-secure-verify.account-protection-now.com/verify?token=eyJhbGciOiJSUzI1NiJ9 "
                    "Microsoft Corporation | One Microsoft Way, Redmond WA"
                ),
                "html_body": "",
                "date": "Mon, 14 Apr 2026 04:30:00 +0000",
                "auth_results": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "sender_ip": "185.220.101.42"},
                "attachments": [],
            },
        },
        {
            "label": "CREDENTIAL HARVESTING — fake Google storage warning",
            "data": {
                "message_id": f"test-cred-{_uuid.uuid4().hex[:8]}@accounts-google-portal.xyz",
                "sender": "no-reply@workspace-google-notification.com",
                "recipient": _pick(2),
                "subject": "Action Required: Your Google Workspace account storage is 95% full",
                "body": (
                    "Your Google Workspace account storage has reached 95% capacity. "
                    "To avoid email delivery failures and data loss, you must verify your account and expand your storage. "
                    "Accounts not verified within 48 hours will have incoming emails automatically rejected. "
                    "Verify your account here: "
                    "http://google-workspace-storage-verify.accounts-google-portal.xyz/auth?redirect=storage&email=user@himaya.ai "
                    "Action required by: April 16, 2026. Google LLC, 1600 Amphitheatre Parkway."
                ),
                "html_body": "",
                "date": "Mon, 14 Apr 2026 04:30:00 +0000",
                "auth_results": {"spf": "fail", "dkim": "none", "dmarc": "fail", "sender_ip": "91.108.4.200"},
                "attachments": [],
            },
        },
        {
            "label": "PHISHING / BEC — CEO impersonation wire fraud",
            "data": {
                "message_id": f"test-bec-{_uuid.uuid4().hex[:8]}@himaya-tech-group.com",
                "sender": "adnan.ahmed.ceo@himaya-tech-group.com",
                "recipient": _pick(3),
                "subject": "Urgent — Confidential Wire Transfer Request",
                "body": (
                    "Hi, I'm currently in an urgent board meeting and I need your help with something sensitive. "
                    "We are finalizing an acquisition deal and I need you to process a wire transfer "
                    "of USD $47,500 to our legal escrow account before market close today. "
                    "This is time-critical and must be kept confidential until the deal is announced. "
                    "Please initiate the transfer to: Bank: Emirates NBD, Account: Argent Legal Holdings Ltd, "
                    "IBAN: AE070331234567890123456, Reference: PROJ-ACQ-2026-Q2. "
                    "Confirm by reply once done. Do not discuss this with anyone else — legal compliance "
                    "requires strict confidentiality. Adnan Ahmed, CEO Himaya Technologies"
                ),
                "html_body": "",
                "date": "Mon, 14 Apr 2026 04:30:00 +0000",
                "auth_results": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "sender_ip": "104.21.34.56"},
                "attachments": [],
            },
        },
    ]

    results = []
    for tp in test_payloads:
        try:
            threat = await process_email(tp["data"], org_id=org_id, db=db)
            results.append({
                "label": tp["label"],
                "recipient": tp["data"]["recipient"],
                "threat_id": str(threat.id) if threat else None,
                "threat_type": threat.threat_type if threat else "SKIPPED",
                "risk_score": threat.risk_score if threat else 0,
                "action_taken": threat.action_taken if threat else "NONE",
                "status": threat.status if threat else "skipped",
            })
        except Exception as _e:
            results.append({"label": tp["label"], "error": str(_e)[:200]})

    return {"injected": len([r for r in results if "error" not in r and r.get("threat_id")]), "results": results}


@router.post("/orgs/{org_id}/inject-inbox-threats", dependencies=[Depends(verify_admin_key)])
async def inject_inbox_threats(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    E2E test: insert simulated threat emails directly into real Gmail and M365 inboxes
    using the provider APIs (Gmail messages.insert, M365 Graph createMessage).
    Delta-sync then picks them up naturally, runs the full threat pipeline,
    auto-triage fires, and quarantine labels/folder moves happen for real.
    Requires admin API key.
    """
    import uuid as _uuid
    import base64 as _b64
    import httpx as _httpx
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from backend.models.db_models import OrgIntegration as _OI
    from backend.services.baseline_ingestion import _decrypt
    from sqlalchemy import select as _sel

    ORG_UUID = _uuid.UUID(org_id)

    # ── Load integrations ───────────────────────────────────────────────────
    int_res = await db.execute(
        _sel(_OI).where(_OI.org_id == ORG_UUID, _OI.status == "active")
    )
    integrations = {i.provider: i for i in int_res.scalars().all()}

    results = []

    # ── Threat email templates ──────────────────────────────────────────────
    THREATS = [
        {
            "label": "MALWARE — macro lure (.xlsm + password)",
            "provider": "google",
            "target_email": "adnan@himaya.ai",
            "subject": "[TEST] Q1 2026 Financial Report — Enable Macros Required",
            "from_name": "Ahmed Al-Rashidi",
            "from_email": "ahmed.alrashidi@gulf-capital-inv.co",
            "body": (
                "Dear Adnan,\n\nPlease find attached the Q1 2026 Financial Report. "
                "The document requires macros to be enabled for the interactive charts.\n\n"
                "Kindly open Q1_Financial_Report_2026.xlsm before the 9 AM board meeting.\n"
                "Password to unlock protected sections: Qfin2026!\n\n"
                "Sent from a secure external server. Do not reply.\n\n"
                "Ahmed Al-Rashidi | CFO, Gulf Capital Investments LLC\n"
                "ahmed.alrashidi@gulf-capital-inv.co | +966 11 234 5678"
            ),
        },
        {
            "label": "ACCOUNT TAKEOVER — fake MS security alert",
            "provider": "google",
            "target_email": "info@himaya.ai",
            "subject": "[TEST] \u26a0 Microsoft 365: Unusual sign-in from Nigeria detected",
            "from_name": "Microsoft Security",
            "from_email": "security@microsoftonline-alerts.net",
            "body": (
                "MICROSOFT SECURITY ALERT\n\n"
                "We detected a sign-in attempt from an unrecognized device.\n"
                "Location: Lagos, Nigeria | IP: 197.210.54.121\n"
                "Device: Unknown Android | Time: Apr 14, 2026 03:47 UTC\n\n"
                "If this was not you, your account may be compromised.\n"
                "Verify your identity within 24 hours or your account will be suspended:\n"
                "http://microsoft-secure-verify.account-protection-now.com/verify?token=eyJhbGciOiJSUzI1NiJ9.aW52YWxpZA\n\n"
                "Microsoft Corporation | One Microsoft Way, Redmond WA 98052"
            ),
        },
        {
            "label": "CREDENTIAL HARVESTING — Google storage lure",
            "provider": "m365",
            "target_email": "adnanahmed@sana085.onmicrosoft.com",
            "subject": "[TEST] Action Required: Google Workspace storage 95% full",
            "from_name": "Google Workspace",
            "from_email": "no-reply@workspace-google-portal.xyz",
            "body": (
                "Hello,\n\nYour Google Workspace account storage has reached 95% capacity.\n"
                "To avoid email delivery failures, verify your account within 48 hours:\n\n"
                "http://google-workspace-storage-verify.accounts-google-portal.xyz/auth?email=adnanahmed@sana085.onmicrosoft.com\n\n"
                "Action required by: April 16, 2026 23:59 UTC\n\n"
                "Google LLC | 1600 Amphitheatre Parkway, Mountain View CA 94043"
            ),
        },
        {
            "label": "PHISHING / BEC — CEO impersonation wire fraud",
            "provider": "m365",
            "target_email": "faraz@sana085.onmicrosoft.com",
            "subject": "[TEST] Urgent — Confidential Wire Transfer",
            "from_name": "Adnan Ahmed",
            "from_email": "adnan.ahmed.ceo@himaya-tech-group.com",
            "body": (
                "Hi,\n\nI'm in an urgent board meeting and need your help with something confidential.\n\n"
                "We are finalising an acquisition and I need you to process a wire transfer of "
                "USD $47,500 to our legal escrow account before market close today.\n\n"
                "Bank: Emirates NBD\nAccount: Argent Legal Holdings Ltd\n"
                "IBAN: AE070331234567890123456\nReference: PROJ-ACQ-2026-Q2\n\n"
                "Confirm by reply. Keep this confidential — legal disclosure rules apply.\n\n"
                "Adnan Ahmed | CEO, Himaya Technologies\n"
                "adnan.ahmed.ceo@himaya-tech-group.com"
            ),
        },
        {
            # Hard phishing — no finance or urgency. Masquerades as IT team onboarding a new tool.
            # Low urgency language, no money, looks completely routine — designed to fool naive scanners.
            "label": "HARD PHISHING — IT tooling impersonation, credential harvest",
            "provider": "m365",
            "target_email": "adnanahmed@sana085.onmicrosoft.com",
            "subject": "[TEST] Action needed: Complete your Himaya IT portal setup",
            "from_name": "Himaya IT Support",
            "from_email": "it-support@himaya-employee-portal.net",
            "body": (
                "Hi Adnan,\n\n"
                "As part of our Q2 IT infrastructure refresh, we are migrating all staff to the new "
                "Himaya Employee Portal. This replaces the old intranet and consolidates your SSO, "
                "VPN access, and device management into a single platform.\n\n"
                "Please complete your account setup by end of the week:\n"
                "https://himaya-employee-portal.net/setup?token=eyJlbXBsb3llZSI6ImFkbmFuQGhpbWF5YS5haSIsInN0ZXAiOiJpbml0aWFsIn0\n\n"
                "You will be prompted to confirm your corporate credentials and set up MFA. "
                "The process takes about 3 minutes.\n\n"
                "If you have already completed setup, please disregard this message.\n\n"
                "IT Support Team\n"
                "Himaya Technologies\n"
                "it-support@himaya-employee-portal.net\n"
                "This is an automated message from the IT Helpdesk system."
            ),
        },
    ]

    # ── Gmail insert ────────────────────────────────────────────────────────
    async def _gmail_insert(integration, to_email: str, from_name: str, from_email: str,
                            subject: str, body: str, label: str):
        access_token = _decrypt(integration.access_token_enc)
        # Refresh token if needed
        try:
            test = await _httpx.AsyncClient().get(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=8,
            )
            if test.status_code == 401:
                # Refresh
                rt = _decrypt(integration.refresh_token_enc)
                import os as _os
                rr = await _httpx.AsyncClient().post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": _os.getenv("GOOGLE_CLIENT_ID", ""),
                        "client_secret": _os.getenv("GOOGLE_CLIENT_SECRET", ""),
                        "refresh_token": rt,
                        "grant_type": "refresh_token",
                    },
                    timeout=10,
                )
                if rr.status_code == 200:
                    access_token = rr.json().get("access_token", access_token)
        except Exception:
            pass

        # Build RFC 2822 message
        msg = MIMEMultipart("alternative")
        msg["To"] = to_email
        msg["From"] = f"{from_name} <{from_email}>"
        msg["Subject"] = subject
        msg["Reply-To"] = f"{from_name} <{from_email}>"
        # Fake auth failures to simulate external attacker
        msg["X-Forwarded-To"] = to_email
        msg["Authentication-Results"] = (
            f"mx.google.com; spf=fail smtp.mailfrom={from_email}; "
            f"dkim=fail header.d={from_email.split('@')[1]}; "
            f"dmarc=fail (p=REJECT) header.from={from_email.split('@')[1]}"
        )
        msg.attach(MIMEText(body, "plain"))

        raw = _b64.urlsafe_b64encode(msg.as_bytes()).decode()

        # Use DWD service account if available, else user OAuth
        import os as _os
        sa_b64 = _os.getenv("GOOGLE_SERVICE_ACCOUNT_B64", "")
        user_email = to_email
        if sa_b64:
            try:
                import json as _json
                import google.oauth2.service_account as _sa
                import google.auth.transport.requests as _gtr
                sa_info = _json.loads(_b64.b64decode(sa_b64).decode())
                creds = _sa.Credentials.from_service_account_info(
                    sa_info,
                    scopes=["https://mail.google.com/"],
                    subject=user_email,
                )
                creds.refresh(_gtr.Request())
                access_token = creds.token
            except Exception as _se:
                pass  # Fall back to OAuth token

        async with _httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://gmail.googleapis.com/gmail/v1/users/{user_email}/messages",
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json={"raw": raw, "labelIds": ["INBOX"]},
            )
            if resp.status_code in (200, 201):
                msg_id = resp.json().get("id", "?")
                return {"label": label, "provider": "google", "target": to_email,
                        "status": "inserted", "gmail_id": msg_id}
            else:
                return {"label": label, "provider": "google", "target": to_email,
                        "status": "failed", "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    # ── M365 Graph insert ───────────────────────────────────────────────────
    async def _m365_insert(integration, to_email: str, from_name: str, from_email: str,
                           subject: str, body: str, label: str):
        import os as _os
        # Always use client credentials (app-only) for inject — never stale delegated tokens
        tenant_id = _os.getenv("M365_TENANT_ID", "common")
        async with _httpx.AsyncClient(timeout=10) as _cl:
            tr = await _cl.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": _os.getenv("M365_CLIENT_ID", ""),
                    "client_secret": _os.getenv("M365_CLIENT_SECRET", ""),
                    "grant_type": "client_credentials",
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
        if tr.status_code != 200:
            return {"label": label, "provider": "m365", "target": to_email,
                    "status": "failed", "error": f"Token error {tr.status_code}: {tr.text[:100]}"}
        access_token = tr.json()["access_token"]

        # Create message via Graph API
        payload = {
            "subject": subject,
            "body": {"contentType": "text", "content": body},
            "from": {"emailAddress": {"name": from_name, "address": from_email}},
            "sender": {"emailAddress": {"name": from_name, "address": from_email}},
            "replyTo": [{"emailAddress": {"name": from_name, "address": from_email}}],
            "toRecipients": [{"emailAddress": {"address": to_email}}],
            "internetMessageHeaders": [
                {"name": "X-Simulated-Spf", "value": "fail"},
                {"name": "X-Simulated-Dmarc", "value": "fail"},
                {"name": "X-Helios-Threat-Test", "value": "inject-2026"},
            ],
            "isRead": False,
            "isDraft": False,
            "receivedDateTime": __import__('datetime').datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        async with _httpx.AsyncClient(timeout=20) as client:
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            # Step 1: Create message in inbox folder (arrives as draft — Graph limitation)
            resp = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{to_email}/mailFolders/inbox/messages",
                headers=headers,
                json=payload,
            )
            if resp.status_code not in (200, 201):
                return {"label": label, "provider": "m365", "target": to_email,
                        "status": "failed", "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
            msg_id = resp.json().get("id", "?")

            # Step 2: PATCH isDraft=false so it appears as received mail, not a draft
            # Graph ignores isDraft on create; must PATCH after creation.
            patch_resp = await client.patch(
                f"https://graph.microsoft.com/v1.0/users/{to_email}/messages/{msg_id}",
                headers=headers,
                json={"isDraft": False, "isRead": False},
            )
            if patch_resp.status_code not in (200, 201, 204):
                # Non-fatal — message still exists, just may show as draft
                import logging as _lg
                _lg.getLogger(__name__).warning(
                    f"inject: isDraft PATCH failed for {msg_id}: {patch_resp.status_code}"
                )

            return {"label": label, "provider": "m365", "target": to_email,
                    "status": "inserted", "graph_id": msg_id[:20] + "..."}

    # ── Fire all injections ─────────────────────────────────────────────────
    for t in THREATS:
        provider = t["provider"]
        integration = integrations.get(provider)
        if not integration:
            results.append({"label": t["label"], "status": "skipped",
                            "error": f"{provider} integration not connected"})
            continue
        try:
            if provider == "google":
                r = await _gmail_insert(
                    integration, t["target_email"], t["from_name"], t["from_email"],
                    t["subject"], t["body"], t["label"]
                )
            else:
                r = await _m365_insert(
                    integration, t["target_email"], t["from_name"], t["from_email"],
                    t["subject"], t["body"], t["label"]
                )
            results.append(r)
        except Exception as _e:
            results.append({"label": t["label"], "provider": provider,
                            "target": t["target_email"], "status": "error", "error": str(_e)[:200]})

    inserted = len([r for r in results if r.get("status") == "inserted"])
    return {
        "inserted_into_inboxes": inserted,
        "total": len(THREATS),
        "note": "Delta-sync will pick these up within ~60s. Auto-triage will fire within 2min.",
        "results": results,
    }


@router.post("/orgs/{org_id}/cleanup-loop-threats", dependencies=[Depends(verify_admin_key)])
async def cleanup_loop_threats(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Bulk-resolve all threats generated by Helios system notification emails
    (noreply@himaya.ai sender) to clear alert loop artifacts from the queue.
    """
    import uuid as _uuid
    from backend.models.db_models import Threat as _T
    from sqlalchemy import update as _upd
    from datetime import datetime as _dt

    _oid = _uuid.UUID(org_id)
    result = await db.execute(
        _upd(_T)
        .where(
            _T.org_id == _oid,
            _T.sender.in_(["noreply@himaya.ai", "no-reply@himaya.ai"]),
        )
        .values(
            status="resolved",
            action_taken="ALLOW",
            resolved_at=_dt.utcnow(),
            false_positive=True,
        )
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return {"cleaned": result.rowcount, "message": f"Resolved {result.rowcount} loop-generated threats"}


@router.post("/orgs/{org_id}/gmail-trash-loop-emails", dependencies=[Depends(verify_admin_key)])
async def gmail_trash_loop_emails(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Trash all Helios quarantine notification emails sitting in Gmail inboxes
    to stop delta-sync from re-ingesting them and triggering more loop threats.
    Uses DWD service account to access each Gmail mailbox.
    """
    import base64 as _b64
    import os as _os
    import json as _json
    import uuid as _uuid
    import httpx as _httpx
    from backend.models.db_models import OrgIntegration as _OI
    from backend.services.baseline_ingestion import _decrypt
    from sqlalchemy import select as _sel

    ORG_UUID = _uuid.UUID(org_id)
    int_res = await db.execute(
        _sel(_OI).where(_OI.org_id == ORG_UUID, _OI.provider == "google", _OI.status == "active")
    )
    integration = int_res.scalar_one_or_none()
    if not integration:
        return {"error": "Google integration not found"}

    # Get DWD token for each mailbox
    sa_b64 = _os.getenv("GOOGLE_SERVICE_ACCOUNT_B64", "")
    if not sa_b64:
        return {"error": "No service account configured"}

    results = {"trashed": 0, "mailboxes": [], "errors": []}

    # Get list of monitored mailboxes from OrgIntegration domain
    domain = integration.org_domain or "himaya.ai"
    access_token_enc = integration.access_token_enc
    oauth_token = _decrypt(access_token_enc) if access_token_enc else ""

    # Refresh OAuth token
    try:
        import google.oauth2.service_account as _sa
        import google.auth.transport.requests as _gtr
        sa_json = _json.loads(_b64.b64decode(sa_b64).decode())

        # Get list of users in domain
        async with _httpx.AsyncClient(timeout=10) as client:
            users_resp = await client.get(
                f"https://admin.googleapis.com/admin/directory/v1/users?domain={domain}&maxResults=50",
                headers={"Authorization": f"Bearer {oauth_token}"},
            )
            if users_resp.status_code != 200:
                # Refresh OAuth token
                rr = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": _os.getenv("GOOGLE_CLIENT_ID", ""),
                        "client_secret": _os.getenv("GOOGLE_CLIENT_SECRET", ""),
                        "refresh_token": _decrypt(integration.refresh_token_enc or ""),
                        "grant_type": "refresh_token",
                    },
                )
                if rr.status_code == 200:
                    oauth_token = rr.json().get("access_token", oauth_token)
                users_resp = await client.get(
                    f"https://admin.googleapis.com/admin/directory/v1/users?domain={domain}&maxResults=50",
                    headers={"Authorization": f"Bearer {oauth_token}"},
                )

            mailboxes = [u["primaryEmail"] for u in users_resp.json().get("users", [])]

        # For each mailbox, search and trash Helios notification emails
        for mailbox in mailboxes:
            try:
                # Get DWD token for this mailbox with gmail.modify scope
                creds = _sa.Credentials.from_service_account_info(
                    sa_json,
                    scopes=["https://www.googleapis.com/auth/gmail.modify"],
                    subject=mailbox,
                )
                creds.refresh(_gtr.Request())
                mb_token = creds.token

                # Search for notification emails from noreply@himaya.ai
                async with _httpx.AsyncClient(timeout=15) as client:
                    search = await client.get(
                        f"https://gmail.googleapis.com/gmail/v1/users/{mailbox}/messages",
                        headers={"Authorization": f"Bearer {mb_token}"},
                        params={"q": "from:noreply@himaya.ai subject:Quarantined OR subject:Threat OR subject:Email Quarantined", "maxResults": 500},
                    )
                    if search.status_code != 200:
                        results["errors"].append(f"{mailbox}: search failed {search.status_code}")
                        continue

                    msgs = search.json().get("messages", [])
                    trashed = 0
                    for msg in msgs:
                        trash_resp = await client.post(
                            f"https://gmail.googleapis.com/gmail/v1/users/{mailbox}/messages/{msg['id']}/trash",
                            headers={"Authorization": f"Bearer {mb_token}"},
                        )
                        if trash_resp.status_code == 200:
                            trashed += 1

                    results["mailboxes"].append({"email": mailbox, "trashed": trashed})
                    results["trashed"] += trashed

            except Exception as e:
                results["errors"].append(f"{mailbox}: {str(e)[:80]}")

    except Exception as e:
        return {"error": str(e)[:200]}

    return results


# ---------------------------------------------------------------------------
# New: Per-org live metrics
# ---------------------------------------------------------------------------

@router.get("/orgs/{org_id}/metrics", dependencies=[Depends(verify_admin_key)])
async def get_org_metrics(org_id: str, db: AsyncSession = Depends(get_db)):
    """Live metrics for a single org — inboxes, email counts, costs, auto-triage status."""
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # Get org base info
    org_row = await db.execute(
        text("""
            SELECT id, name, plan, COALESCE(status, 'active') AS status,
                   created_at, COALESCE(contact_email, '') AS contact_email
            FROM organizations WHERE id = :oid
        """),
        {"oid": org_id},
    )
    org = org_row.fetchone()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Integrations
    int_rows = await db.execute(
        text("""
            SELECT provider, status, COALESCE(mailbox_count, 0) AS mailbox_count,
                   COALESCE(groups_count, 0) AS groups_count,
                   COALESCE(shared_count, 0) AS shared_count,
                   last_baseline_at
            FROM org_integrations WHERE org_id = :oid
        """),
        {"oid": org_id},
    )
    integrations_raw = int_rows.fetchall()
    integrations = [
        {
            "provider": r.provider,
            "status": r.status,
            "mailbox_count": int(r.mailbox_count or 0),
            "last_sync_at": r.last_baseline_at.isoformat() if r.last_baseline_at else None,
        }
        for r in integrations_raw
    ]
    inboxes_onboarded = sum(int(r.mailbox_count or 0) for r in integrations_raw)
    groups_count = sum(int(r.groups_count or 0) for r in integrations_raw)
    shared_mailboxes_count = sum(int(r.shared_count or 0) for r in integrations_raw)

    # Threat counts from threats table
    counts_row = await db.execute(
        text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE detected_at >= :ms) AS mtd,
                COUNT(*) FILTER (WHERE detected_at >= :ms AND threat_type != 'CLEAN') AS threats_mtd,
                COUNT(*) FILTER (
                    WHERE detected_at >= :ms
                    AND action_taken IN ('QUARANTINED', 'QUARANTINE', 'BLOCK_DELETE')
                ) AS quarantined_mtd
            FROM threats WHERE org_id = :oid
        """),
        {"oid": org_id, "ms": month_start},
    )
    counts = counts_row.fetchone()
    emails_processed_total = int(counts.total or 0)
    emails_processed_mtd = int(counts.mtd or 0)
    threats_detected_mtd = int(counts.threats_mtd or 0)
    quarantined_mtd = int(counts.quarantined_mtd or 0)

    # Cost model
    cost_usd_mtd = round(
        emails_processed_mtd * 0.0008
        + threats_detected_mtd * 0.002
        + quarantined_mtd * 0.001,
        2,
    )

    # Redis auto-triage
    auto_triage_enabled = False
    auto_triage_last_run = None
    try:
        r = sync_redis.from_url(settings.REDIS_URL)
        at_enabled = r.get(f"auto_triage:enabled:{org_id}")
        auto_triage_enabled = at_enabled in (b"true", b"1", "true", "1")
        at_status = r.hgetall(f"auto_triage:status:{org_id}")
        if at_status:
            lr = at_status.get(b"last_run") or at_status.get("last_run")
            if lr:
                auto_triage_last_run = float(lr)
    except Exception:
        pass

    return {
        "org_id": org_id,
        "org_name": org.name,
        "plan": org.plan,
        "status": org.status,
        "contact_email": org.contact_email,
        "inboxes_onboarded": inboxes_onboarded,
        "groups_count": groups_count,
        "shared_mailboxes_count": shared_mailboxes_count,
        "emails_processed_total": emails_processed_total,
        "emails_processed_mtd": emails_processed_mtd,
        "threats_detected_mtd": threats_detected_mtd,
        "quarantined_mtd": quarantined_mtd,
        "auto_triage_enabled": auto_triage_enabled,
        "auto_triage_last_run": auto_triage_last_run,
        "integrations": integrations,
        "cost_usd_mtd": cost_usd_mtd,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


# ---------------------------------------------------------------------------
# New: Per-org audit trail
# ---------------------------------------------------------------------------

@router.get("/orgs/{org_id}/audit-trail", dependencies=[Depends(verify_admin_key)])
async def get_org_audit_trail(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
):
    """Audit trail of threat detection events for a specific org."""
    # Total count
    count_row = await db.execute(
        text("SELECT COUNT(*) FROM threats WHERE org_id = :oid"),
        {"oid": org_id},
    )
    total = int(count_row.scalar() or 0)

    rows = await db.execute(
        text("""
            SELECT
                id::text AS id,
                detected_at,
                sender,
                recipient_email,
                threat_type,
                risk_score,
                action_taken,
                status,
                COALESCE(threat_indicators->>'graph_score', '0') AS graph_score,
                threat_indicators->>'auto_triaged' AS auto_triaged,
                threat_indicators->>'auto_triage_verdict' AS auto_triage_verdict,
                threat_indicators->>'auto_triage_confidence' AS auto_triage_confidence,
                threat_indicators->>'auto_triage_at' AS auto_triage_at,
                threat_indicators AS threat_indicators_json
            FROM threats
            WHERE org_id = :oid
            ORDER BY detected_at DESC
            LIMIT :lim OFFSET :off
        """),
        {"oid": org_id, "lim": limit, "off": offset},
    )
    raw = rows.fetchall()

    items = []
    for r in raw:
        at_flag = (r.auto_triaged or "").lower() == "true"
        at_at = r.auto_triage_at
        action = (r.action_taken or "").upper()
        ttype = (r.threat_type or "").upper()

        if at_flag and at_at:
            etype = "AUTO_TRIAGE"
        elif action in ("QUARANTINED", "QUARANTINE", "BLOCK_DELETE"):
            etype = "QUARANTINE"
        elif action == "MARKED_SPAM":
            etype = "SPAM"
        elif ttype == "CLEAN":
            etype = "CLEAN_PASS"
        else:
            etype = "THREAT_DETECTED"

        # Filter by event_type if provided
        if event_type and etype != event_type.upper():
            continue

        try:
            gs = float(r.graph_score or 0)
        except (ValueError, TypeError):
            gs = 0.0
        neo4j_queried = gs > 0

        try:
            conf = float(r.auto_triage_confidence) if r.auto_triage_confidence else None
        except (ValueError, TypeError):
            conf = None

        items.append({
            "id": r.id,
            "event_type": etype,
            "timestamp": r.detected_at.isoformat() if r.detected_at else None,
            "sender": r.sender,
            "recipient": r.recipient_email,
            "threat_type": r.threat_type,
            "risk_score": r.risk_score,
            "action": r.action_taken,
            "auto_triage_verdict": r.auto_triage_verdict,
            "auto_triage_confidence": conf,
            "neo4j_queried": neo4j_queried,
            "details": r.threat_indicators_json if isinstance(r.threat_indicators_json, dict) else {},
        })

    return {"total": total, "items": items}


# ---------------------------------------------------------------------------
# New: AWS infrastructure costs via Cost Explorer
# ---------------------------------------------------------------------------

@router.get("/aws-costs", dependencies=[Depends(verify_admin_key)])
async def get_aws_costs():
    """Fetch MTD AWS costs from Cost Explorer. Graceful fallback on error."""
    now = datetime.utcnow()
    first_of_month = now.replace(day=1)
    # Cost Explorer end date must be today or future; if today == first, use tomorrow range
    end_date = now
    if end_date.date() == first_of_month.date():
        end_date = now + timedelta(days=1)

    try:
        import boto3 as _boto3
        ce = _boto3.client("ce", region_name="us-east-1")
        response = ce.get_cost_and_usage(
            TimePeriod={
                "Start": first_of_month.strftime("%Y-%m-%d"),
                "End": end_date.strftime("%Y-%m-%d"),
            },
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        by_service = []
        total = 0.0
        for result in response.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                svc = group["Keys"][0]
                amt = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if amt > 0:
                    by_service.append({"service": svc, "cost_usd": round(amt, 4)})
                    total += amt
        by_service.sort(key=lambda x: x["cost_usd"], reverse=True)
        return {
            "total_mtd_usd": round(total, 2),
            "period_start": first_of_month.strftime("%Y-%m-%d"),
            "period_end": now.strftime("%Y-%m-%d"),
            "by_service": by_service,
            "source": "aws_cost_explorer",
        }
    except Exception as e:
        logger.warning(f"Cost Explorer unavailable: {e}")
        return {
            "total_mtd_usd": None,
            "period_start": first_of_month.strftime("%Y-%m-%d"),
            "period_end": now.strftime("%Y-%m-%d"),
            "by_service": [],
            "error": "Cost Explorer not available",
            "source": "fallback",
        }


# ---------------------------------------------------------------------------
# New customer onboarding CLI endpoint
# ---------------------------------------------------------------------------

class NewOrgRequest(BaseModel):
    name: str
    domain: str
    contact_email: str
    contact_name: str
    tier: str = "Launch"
    send_activation: bool = True


@router.post("/setup/new-org", dependencies=[Depends(verify_admin_key)])
async def setup_new_org(req: NewOrgRequest, db: AsyncSession = Depends(get_db)):
    """
    Provision a new customer org with admin user and optional SES activation email.
    Returns org_id, user_id, temp_password, login_url.
    """
    import string as _string

    # Check domain uniqueness
    existing = await db.execute(select(Organization).where(Organization.domain == req.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Domain '{req.domain}' is already registered")

    # Create org
    org = Organization(
        name=req.name,
        domain=req.domain,
        plan="starter",
        contact_email=req.contact_email,
        contact_name=req.contact_name,
        status="active",
    )
    db.add(org)
    await db.flush()

    # Set tier via raw SQL (safe even if ORM column not yet reflected)
    await db.execute(
        text("UPDATE organizations SET tier = :tier WHERE id = :oid"),
        {"tier": req.tier, "oid": str(org.id)},
    )

    # Generate a 16-char temp password
    alphabet = _string.ascii_letters + _string.digits
    temp_password = ''.join(secrets.choice(alphabet) for _ in range(16))

    user = User(
        org_id=org.id,
        email=req.contact_email,
        name=req.contact_name,
        role="admin",
        password_hash=await hash_password_async(temp_password),
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()

    login_url = f"{os.getenv('FRONTEND_URL', 'https://app.himaya.ai')}/login"

    # Send activation email via SES if requested
    if req.send_activation:
        try:
            activation_html = f"""<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#0a0f1e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:48px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;background:#0d1b2e;border-radius:16px;border:1px solid #1a2744;overflow:hidden;">
        <tr><td style="background:#0d1b2e;padding:32px 40px 24px;text-align:center;border-bottom:2px solid #3b6ef6;">
          <h2 style="margin:0;color:#ffffff;font-size:22px;">Welcome to Himaya Helios</h2>
          <p style="margin:8px 0 0;color:#a1a1aa;font-size:12px;letter-spacing:1px;text-transform:uppercase;">Your account is ready</p>
        </td></tr>
        <tr><td style="padding:32px 40px;">
          <p style="margin:0 0 16px;color:#a1a1aa;font-size:14px;line-height:1.7;">
            Hi {req.contact_name}, your Helios account for <strong style="color:#fff;">{req.name}</strong> has been set up.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;border:1px solid #1a2744;border-radius:10px;padding:16px;margin-bottom:24px;">
            <tr><td style="padding:6px 0;color:#a1a1aa;font-size:13px;width:120px;">Login Email</td>
                <td style="padding:6px 0;color:#fff;font-size:13px;font-weight:600;">{req.contact_email}</td></tr>
            <tr><td style="padding:6px 0;color:#a1a1aa;font-size:13px;">Temp Password</td>
                <td style="padding:6px 0;color:#f59e0b;font-size:13px;font-weight:700;font-family:monospace;">{temp_password}</td></tr>
            <tr><td style="padding:6px 0;color:#a1a1aa;font-size:13px;">Tier</td>
                <td style="padding:6px 0;color:#fff;font-size:13px;">{req.tier}</td></tr>
          </table>
          <a href="{login_url}" style="display:inline-block;background:#3b6ef6;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;">Log In to Helios</a>
          <p style="margin:24px 0 0;color:#52525b;font-size:12px;">Please change your password after first login. If you did not request this account, contact support@himaya.ai</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
            send_email(req.contact_email, f"Your Himaya Helios account is ready — {req.name}", activation_html)
        except Exception as _e:
            logger.warning(f"new-org activation email failed (non-fatal): {_e}")

    return {
        "org_id": str(org.id),
        "user_id": str(user.id),
        "temp_password": temp_password,
        "login_url": login_url,
        "tier": req.tier,
        "message": f"Org '{req.name}' ({req.domain}) provisioned successfully.",
    }


# ---------------------------------------------------------------------------
# Export / Bulk Data
# ---------------------------------------------------------------------------

@router.get("/export/threats", dependencies=[Depends(verify_admin_key)])
async def export_threats(
    limit: int = Query(2000, ge=1, le=10000),
    org_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Export threats as JSON for Excel generation.
    Returns newest threats first, up to `limit` rows.
    If org_id is provided, filters to that org only.
    """
    from backend.models.db_models import Threat

    q = select(Threat).order_by(Threat.detected_at.desc()).limit(limit)
    if org_id:
        q = q.where(Threat.org_id == uuid.UUID(org_id))

    result = await db.execute(q)
    threats = result.scalars().all()

    return {
        "count": len(threats),
        "items": [
            {
                "id": str(t.id),
                "org_id": str(t.org_id),
                "subject": t.subject or "",
                "sender": t.sender or "",
                "recipient": t.recipient_email or "",
                "risk_score": t.risk_score,
                "threat_type": t.threat_type or "",
                "status": t.status or "",
                "action_taken": t.action_taken or "",
                "auto_triaged": getattr(t, "auto_triaged", False),
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
                "llm_classification": getattr(t, "llm_classification", None),
                "llm_confidence": getattr(t, "llm_confidence", None),
            }
            for t in threats
        ],
    }


@router.get("/export/threats/detailed", dependencies=[Depends(verify_admin_key)])
async def export_threats_detailed(
    limit: int = Query(2000, ge=1, le=10000),
    org_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Export threats with full details: body preview, attachments, links, verdicts.
    Returns newest threats first, up to `limit` rows.
    """
    from backend.models.db_models import Threat

    q = select(Threat).order_by(Threat.detected_at.desc()).limit(limit)
    if org_id:
        q = q.where(Threat.org_id == uuid.UUID(org_id))

    result = await db.execute(q)
    threats = result.scalars().all()

    items = []
    for t in threats:
        # Parse threat_indicators JSONB for attachments/links
        indicators = t.threat_indicators or {}
        attachments = []
        links = []
        
        # threat_indicators can be a list of strings or a dict
        if isinstance(indicators, list):
            for ind in indicators:
                if isinstance(ind, str):
                    if "attachment" in ind.lower():
                        attachments.append(ind)
                    elif "url" in ind.lower() or "link" in ind.lower():
                        links.append(ind)
        elif isinstance(indicators, dict):
            attachments = indicators.get("all_attachments", []) or indicators.get("suspicious_attachments", [])
            links = indicators.get("malicious_urls", []) or indicators.get("suspicious_urls", []) or indicators.get("urls_extracted", [])
        
        items.append({
            "id": str(t.id),
            "org_id": str(t.org_id),
            "subject": t.subject or "",
            "sender": t.sender or "",
            "sender_domain": t.sender_domain or "",
            "recipient": t.recipient_email or "",
            "risk_score": t.risk_score,
            "threat_type": t.threat_type or "",
            "status": t.status or "",
            "action_taken": t.action_taken or "",
            "auto_triaged": getattr(t, "auto_triaged", False),
            "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            "email_received_at": t.email_received_at.isoformat() if t.email_received_at else None,
            "llm_classification": getattr(t, "llm_classification", None),
            "llm_confidence": getattr(t, "llm_confidence", None),
            "llm_model": getattr(t, "llm_model", None),
            "body_preview": (t.email_body_preview or "")[:2000],  # First 2000 chars
            "ai_explanation_en": t.ai_explanation_en or "",
            "attachments": attachments if isinstance(attachments, list) else [],
            "links": links if isinstance(links, list) else [],
            "threat_indicators_raw": indicators,
            "auth_results": t.auth_results or {},
            "impersonation_detected": t.impersonation_detected,
            "impersonation_target": t.impersonation_target,
            "urgency_score": t.urgency_score,
            "analyst_verdict": t.analyst_verdict,
            "analyst_notes": t.analyst_notes,
        })

    return {
        "count": len(items),
        "items": items,
    }
