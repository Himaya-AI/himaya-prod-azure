"""Endpoint for GenAI shadow-IT discovery."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.services.genai_shadow_it import KNOWN_VENDORS, discover

router = APIRouter(prefix="/api/genai-shadow-it", tags=["genai-shadow-it"])


@router.get("")
async def list_genai_usage(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return GenAI usage findings across every connected source."""
    org_id = str(current_user.org_id)
    items = await discover(db, org_id)
    # Roll-up cards
    by_risk = {"high": 0, "medium": 0, "low": 0}
    by_category: dict[str, int] = {}
    for it in items:
        by_risk[it["risk"]] = by_risk.get(it["risk"], 0) + 1
        by_category[it["category"]] = by_category.get(it["category"], 0) + 1
    return {
        "total": len(items),
        "by_risk": by_risk,
        "by_category": by_category,
        "items": items,
    }


@router.get("/vendors")
async def list_known_vendors(
    current_user=Depends(get_current_user),
):
    """Return the vendor catalogue (for the UI's 'we look for these' help text)."""
    return {"vendors": KNOWN_VENDORS, "total": len(KNOWN_VENDORS)}
