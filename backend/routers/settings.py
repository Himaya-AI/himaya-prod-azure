from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from backend.database import get_db
from backend.models.db_models import Organization, User
from backend.routers.auth import get_current_user

router = APIRouter(prefix="/api/settings", tags=["settings"])


class AlertPrefsUpdate(BaseModel):
    critical_threat: Optional[bool] = None
    daily_digest: Optional[bool] = None
    weekly_digest: Optional[bool] = None
    # Workspace Security alert toggles (Adnan 2026-06-17)
    saas_public_share: Optional[bool] = None
    saas_external_share: Optional[bool] = None
    saas_dlp_match: Optional[bool] = None
    saas_posture_drift: Optional[bool] = None
    cspm_critical: Optional[bool] = None
    cspm_high: Optional[bool] = None
    github_secret: Optional[bool] = None
    github_branch_protection: Optional[bool] = None
    # Added 2026-06-23 (Adnan) - sensitive upload + cross-region
    # access + malware / ransomware toggles consumed by the SaaS
    # alert sink (`_classify_and_create_alert`, `check_ransomware_burst`,
    # `_cross_region_access_monitor`).
    saas_sensitive_upload: Optional[bool] = None
    saas_cross_region_access: Optional[bool] = None
    saas_malware_upload: Optional[bool] = None
    saas_ransomware_indicator: Optional[bool] = None


class SecuritySettingsUpdate(BaseModel):
    # 2026-06-17: Adnan asked for auto-logout to default to 2h (was 1h)
    # and be configurable in settings.
    session_timeout_minutes: Optional[int] = None


class OrgSettingsUpdate(BaseModel):
    name: Optional[str] = None
    country: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    mfa_enforced: Optional[bool] = None
    plan: Optional[str] = None


@router.get("/org")
async def get_org_settings(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "id": str(org.id),
        "name": org.name,
        "domain": org.domain,
        "plan": org.plan,
        "country": org.country,
        "mailbox_count": org.mailbox_count,
        "risk_score": org.risk_score,
        "compliance_score": org.compliance_score,
        "timezone": org.timezone,
        "language": org.language,
        "mfa_enforced": org.mfa_enforced,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


@router.put("/org")
async def update_org_settings(
    req: OrgSettingsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    for field, value in req.model_dump(exclude_none=True).items():
        setattr(org, field, value)
    org.updated_at = datetime.utcnow()
    await db.flush()
    return {"message": "Settings updated", "org_id": str(org.id)}


@router.patch("/users/{user_id}")
async def update_org_user(
    user_id: str,
    body: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's role within the org (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    target = (await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found in your org")
    allowed_roles = {"admin", "analyst", "viewer", "user"}
    new_role = body.get("role")
    if new_role and new_role in allowed_roles:
        target.role = new_role
    await db.commit()
    return {"id": str(target.id), "email": target.email, "role": target.role}


@router.delete("/users/{user_id}")
async def remove_org_user(
    user_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Remove a portal user from the org (admin only).
    Cannot remove yourself. Soft-deactivates the account rather than hard-deleting.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    if str(current_user.id) == user_id:
        raise HTTPException(status_code=400, detail="You cannot remove your own account")

    target = (await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found in your org")

    # Soft-delete: deactivate and change role to revoke portal access
    target.is_active = False
    target.role = "revoked"
    target.updated_at = datetime.utcnow()
    await db.commit()
    return {"message": f"User {target.email} removed from org", "user_id": user_id}


@router.get("/users")
async def list_org_users(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return only admin/analyst portal users for this org — NOT synced mailbox accounts.
    Used by Settings > Users tab. Only users with role in (admin, analyst) are shown here;
    synced mailbox accounts live in People."""
    # Both admins AND analysts can see org users
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admins and analysts only")

    result = await db.execute(
        select(User).where(
            User.org_id == current_user.org_id,
            User.is_active == True,
            User.role.in_(["admin", "analyst", "viewer"]),  # portal users only; synced mailboxes are role=user
        ).order_by(User.created_at.asc())
    )
    users = result.scalars().all()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
            "role": u.role,
            "is_active": u.is_active,
            "is_vip": u.is_vip,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.get("/alerts")
async def get_alert_prefs(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return alert preferences for the current org."""
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Store prefs in org_metadata JSONB column
    meta = org.org_metadata or {}
    prefs = meta.get("alert_prefs", {})

    return {
        "critical_threat": prefs.get("critical_threat", True),
        "daily_digest": prefs.get("daily_digest", True),
        "weekly_digest": prefs.get("weekly_digest", True),
        "compliance_drift": prefs.get("compliance_drift", False),
        "new_user_added": prefs.get("new_user_added", False),
        # Workspace Security toggles — default ON (Adnan 2026-06-17).
        "saas_public_share": prefs.get("saas_public_share", True),
        "saas_external_share": prefs.get("saas_external_share", True),
        "saas_dlp_match": prefs.get("saas_dlp_match", True),
        "saas_posture_drift": prefs.get("saas_posture_drift", True),
        "cspm_critical": prefs.get("cspm_critical", True),
        "cspm_high": prefs.get("cspm_high", True),
        "github_secret": prefs.get("github_secret", True),
        "github_branch_protection": prefs.get("github_branch_protection", True),
        # Added 2026-06-23 (Adnan) — sensitive upload + cross-region
        # access + malware / ransomware toggles, default ON.
        "saas_sensitive_upload": prefs.get("saas_sensitive_upload", True),
        "saas_cross_region_access": prefs.get("saas_cross_region_access", True),
        "saas_malware_upload": prefs.get("saas_malware_upload", True),
        "saas_ransomware_indicator": prefs.get("saas_ransomware_indicator", True),
    }


@router.put("/alerts")
async def update_alert_prefs(
    req: AlertPrefsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Save alert preferences for the org. Also sends a test email to verify SES is working."""
    if current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Admins only")

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Merge into existing org_metadata
    import json as _json
    from sqlalchemy import text as _text
    meta = dict(org.org_metadata or {})
    current_prefs = meta.get("alert_prefs", {
        "critical_threat": True, "daily_digest": True, "weekly_digest": True,
    })

    updated = req.model_dump(exclude_none=True)
    current_prefs.update(updated)
    meta["alert_prefs"] = current_prefs

    await db.execute(
        _text("UPDATE organizations SET org_metadata = :m::jsonb, updated_at = NOW() WHERE id = :id"),
        {"m": _json.dumps(meta), "id": str(org.id)},
    )
    await db.flush()
    return {"message": "Alert preferences saved", "prefs": current_prefs}


# ── Workspace Security settings ───────────────────────────────────
# Adnan 2026-06-17: auto-logout was 1h; now defaults to 2h and is
# configurable from Settings → Workspace Security. The actual JWT TTL
# is read from `org_metadata.security.session_timeout_minutes` at
# token-mint time (see backend/routers/auth.py).

@router.get("/security")
async def get_security_settings(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return workspace-security settings for the org."""
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    meta = org.org_metadata or {}
    sec = meta.get("security", {})
    return {
        "session_timeout_minutes": int(sec.get("session_timeout_minutes", 120)),
    }


@router.patch("/security")
async def update_security_settings(
    req: SecuritySettingsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update workspace-security settings (session timeout, etc)."""
    if current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Admins only")
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    import json as _json
    from sqlalchemy import text as _text
    meta = dict(org.org_metadata or {})
    sec = dict(meta.get("security", {}))
    updated = req.model_dump(exclude_none=True)
    # Sanity-clamp the session timeout (5 min → 24h).
    if "session_timeout_minutes" in updated:
        v = int(updated["session_timeout_minutes"])
        if v < 5 or v > 24 * 60:
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be between 5 and 1440")
        sec["session_timeout_minutes"] = v
    meta["security"] = sec

    await db.execute(
        _text("UPDATE organizations SET org_metadata = :m::jsonb, updated_at = NOW() WHERE id = :id"),
        {"m": _json.dumps(meta), "id": str(org.id)},
    )
    await db.flush()
    return {
        "message": "Security settings saved",
        "session_timeout_minutes": int(sec.get("session_timeout_minutes", 120)),
    }


class InviteRequest(BaseModel):
    email: str
    role: str = "analyst"
    name: str = ""


@router.post("/invite")
async def invite_user(
    req: InviteRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invite a new admin/analyst to the org. Creates user account + sends welcome email."""
    from backend.models.db_models import User
    import uuid as _uuid
    import secrets as _secrets

    if current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Admins only")

    # Check not already a member — if they exist, resend invite with a new temp password
    existing = (await db.execute(
        select(User).where(User.email == req.email.lower(), User.org_id == current_user.org_id)
    )).scalar_one_or_none()
    if existing:
        # Re-invite: reset their password, update role, and resend email
        temp_password = _secrets.token_urlsafe(10)
        from backend.utils.hashing import hash_password_async as _hp_async
        existing.password_hash = await _hp_async(temp_password)
        existing.is_active = True
        # Update role if a valid portal role was requested
        if req.role in ("admin", "analyst", "viewer"):
            existing.role = req.role
        await db.flush()
        # Send reinvite email (falls through to email block below using existing user id)
        try:
            from backend.services.email_service import send_email as _se
            org_result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
            _org = org_result.scalar_one_or_none()
            org_name = _org.name if _org else "Your Organization"
            _se(to=req.email.lower(),
                subject=f"Your Himaya access credentials — {org_name}",
                html_body=f"""<div style="font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;background:#111117;border-radius:12px;padding:32px;border:1px solid #1e293b;">
                  <h2 style="color:#e2e8f0;">Access credentials resent</h2>
                  <p style="color:#64748b;">Your login details for <strong style="color:#e2e8f0;">{org_name}</strong> on Himaya:</p>
                  <div style="background:#0d1117;border-radius:8px;padding:16px;border:1px solid #1e293b;margin:16px 0;">
                    <div style="color:#e2e8f0;font-size:13px;">Email: <strong>{req.email.lower()}</strong></div>
                    <div style="color:#e2e8f0;font-size:13px;margin-top:4px;">Password: <strong style="font-family:monospace;background:#1e293b;padding:2px 6px;border-radius:4px;">{temp_password}</strong></div>
                  </div>
                  <a href="https://app.himaya.ai/login" style="display:inline-block;background:#3b6ef6;color:white;text-decoration:none;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;">Log in to Himaya →</a>
                </div>""")
        except Exception: pass
        await db.commit()
        return {"message": f"Invite resent to {req.email}", "user_id": str(existing.id), "temp_password": temp_password}

    # Generate temp password
    temp_password = _secrets.token_urlsafe(10)
    from backend.utils.hashing import hash_password_async as _hp_async
    pw_hash = await _hp_async(temp_password)

    new_user = User(
        id=_uuid.uuid4(),
        org_id=current_user.org_id,
        email=req.email.lower(),
        name=req.name or req.email.split("@")[0],
        role=req.role if req.role in ("admin", "analyst", "viewer") else "analyst",
        password_hash=pw_hash,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    await db.flush()

    # Send invite email
    try:
        from backend.services.email_service import send_email
        org_result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
        org = org_result.scalar_one_or_none()
        org_name = org.name if org else "Your Organization"
        html = f"""
        <div style="font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;background:#111117;border-radius:12px;padding:32px;border:1px solid #1e293b;">
          <div style="margin-bottom:24px;">
            <div style="width:40px;height:40px;background:linear-gradient(135deg,#3b6ef6,#8b5cf6);border-radius:8px;display:inline-flex;align-items:center;justify-content:center;margin-bottom:12px;">
              <span style="color:white;font-size:20px;font-weight:900;">H</span>
            </div>
            <h2 style="color:#e2e8f0;font-size:18px;margin:0;">You've been invited to Himaya</h2>
            <p style="color:#64748b;font-size:13px;margin-top:6px;">{org_name} has added you as a {req.role}.</p>
          </div>
          <div style="background:#0d1117;border-radius:8px;padding:16px;border:1px solid #1e293b;margin-bottom:20px;">
            <div style="color:#94a3b8;font-size:11px;text-transform:uppercase;margin-bottom:6px;">Your temporary credentials</div>
            <div style="color:#e2e8f0;font-size:13px;">Email: <strong>{req.email}</strong></div>
            <div style="color:#e2e8f0;font-size:13px;margin-top:4px;">Password: <strong style="font-family:monospace;background:#1e293b;padding:2px 6px;border-radius:4px;">{temp_password}</strong></div>
          </div>
          <a href="https://app.himaya.ai/login" style="display:inline-block;background:#3b6ef6;color:white;text-decoration:none;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;">Log in to Himaya →</a>
          <p style="color:#475569;font-size:11px;margin-top:20px;">Please change your password after first login. This invite was sent by {current_user.email}.</p>
        </div>"""
        send_email(to=req.email, subject=f"You've been invited to {org_name} on Himaya", html_body=html)
    except Exception as _e:
        import logging; logging.getLogger(__name__).warning(f"Invite email failed: {_e}")

    return {
        "message": f"Invitation sent to {req.email}",
        "user_id": str(new_user.id),
        "temp_password": temp_password,
    }


@router.post("/test-weekly-digest")
async def test_weekly_digest(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Immediately trigger a weekly digest for this org (admin only — for testing)."""
    if current_user.role not in ("admin", "superadmin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin only")
    from backend.services.weekly_digest import send_weekly_digest_now
    import asyncio
    asyncio.create_task(send_weekly_digest_now(org_id=current_user.org_id))
    return {"message": "Weekly digest queued — check admin inbox in a few seconds"}


@router.post("/test-daily-digest")
async def test_daily_digest(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Immediately trigger a daily digest for this org (admin only — for testing)."""
    if current_user.role not in ("admin", "superadmin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin only")
    from backend.services.daily_digest import send_daily_digest_now
    import asyncio
    asyncio.create_task(send_daily_digest_now(org_id=current_user.org_id))
    return {"message": "Daily digest queued — check admin inbox in a few seconds"}
