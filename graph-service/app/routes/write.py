from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request

from app.services.write import record_communication
from utils.schemas import WriteRequest, WriteResponse

router = APIRouter()


@router.post("/write", status_code=202, response_model=WriteResponse)
async def write(
    body: WriteRequest,
    background_tasks: BackgroundTasks,
    req: Request,
) -> WriteResponse:
    background_tasks.add_task(
        record_communication,
        req.app.state.neo4j,
        body.to_write_dict(),
    )
    return WriteResponse(accepted=True)
