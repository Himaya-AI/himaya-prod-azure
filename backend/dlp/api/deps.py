"""Authorization dependencies for DLP v2 control-plane APIs."""

from fastapi import Depends, HTTPException, status

from backend.models.db_models import User
from backend.routers.auth import get_current_user


async def require_dlp_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role not in {
        "admin",
        "superadmin",
        "super_admin",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DLP administrator role required",
        )
    return current_user
