"""Endpoints for the permission-diff (ACL change) feature."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.services.permission_diff import compute_diff, snapshot_all

router = APIRouter(prefix="/api/permission-diff", tags=["permission-diff"])


@router.get("")
async def list_diffs(
    since_hours: int = Query(24, ge=1, le=720),
    limit: int = Query(500, ge=1, le=2000),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return ACL changes for the org over the given window."""
    org_id = str(current_user.org_id)
    diffs = await compute_diff(db, org_id, since_hours=since_hours, limit=limit)
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in diffs:
        by_sev[d["severity"]] = by_sev.get(d["severity"], 0) + 1
    return {"total": len(diffs), "by_severity": by_sev, "items": diffs}


@router.post("/snapshot")
async def take_snapshot(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force a snapshot now (UI button: 'Recompute baseline')."""
    org_id = str(current_user.org_id)
    n = await snapshot_all(db, org_id)
    return {"snapshotted": n}
