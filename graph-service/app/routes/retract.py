from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.services.retract import retract_threat
from utils.schemas import RetractRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.delete("/retract")
async def retract(body: RetractRequest, req: Request) -> JSONResponse:
    removed = await retract_threat(
        req.app.state.neo4j,
        sender=body.sender,
        threat_type=body.threat_type,
    )
    return JSONResponse({"sender": body.sender, "threat_type": body.threat_type, "edges_removed": removed})
