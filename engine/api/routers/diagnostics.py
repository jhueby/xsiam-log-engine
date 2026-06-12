from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from utils.diagnostics import DiagLevel, get_buffer

router = APIRouter(prefix="/api/diagnostics", tags=["diagnostics"])


class LevelUpdate(BaseModel):
    level: DiagLevel


@router.get("/logs")
async def get_diagnostic_logs(limit: int = 200) -> list[dict]:
    return get_buffer().get_recent(limit)


@router.get("/level")
async def get_level() -> dict:
    return {"level": get_buffer().level}


@router.put("/level")
async def set_level(body: LevelUpdate) -> dict:
    get_buffer().level = body.level
    return {"level": body.level}


@router.delete("/logs")
async def clear_logs() -> dict:
    get_buffer().clear()
    return {"ok": True}


async def _diag_generator(request: Request):
    buf = get_buffer()
    last_seq = buf.current_seq  # start from now; initial history loaded via REST
    while True:
        if await request.is_disconnected():
            break
        new_entries = buf.get_after(last_seq)
        for entry in new_entries:
            yield {"data": json.dumps(entry)}
        if new_entries:
            last_seq = buf.current_seq
        await asyncio.sleep(0.5)


@router.get("/stream")
async def stream_diagnostics(request: Request) -> EventSourceResponse:
    return EventSourceResponse(_diag_generator(request))
