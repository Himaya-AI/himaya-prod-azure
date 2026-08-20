"""Authorization dependencies for DLP v2 control-plane APIs."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization, User
from backend.routers.auth import get_current_user

_ENTERPRISE_TIERS = frozenset({"enterprise", "enterprise trial"})
_ADMIN_ROLES = frozenset({"admin", "superadmin", "super_admin", "owner"})


async def require_dlp_enterprise(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Require an authenticated user whose organization is enterprise-tier."""
    if current_user.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Data Loss Prevention requires an Enterprise plan. "
                "Upgrade to access this feature."
            ),
        )
    org = await session.get(Organization, current_user.org_id)
    tier = (getattr(org, "tier", None) or "Launch").strip().lower()
    if tier not in _ENTERPRISE_TIERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Data Loss Prevention requires an Enterprise plan. "
                "Upgrade to access this feature."
            ),
        )
    return current_user


async def require_dlp_admin(
    current_user: User = Depends(require_dlp_enterprise),
) -> User:
    """Require enterprise entitlement plus a DLP administrator role."""
    if current_user.role not in _ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DLP administrator role required",
        )
    return current_user
