from __future__ import annotations

from fastapi import APIRouter

from app.routes.health import router as health_router
from app.routes.evaluate import router as evaluate_router
from app.routes.write import router as write_router
from app.routes.retract import router as retract_router

router = APIRouter()

router.include_router(health_router)
router.include_router(evaluate_router)
router.include_router(write_router)
router.include_router(retract_router)
