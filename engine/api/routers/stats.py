from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from api.models import StatsResponse
from main import get_engine

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    engine = get_engine()
    data = engine.get_stats()
    return StatsResponse(**data)


@router.get("/sources")
async def get_source_stats() -> list[dict]:
    engine = get_engine()
    return engine.get_source_stats()


async def _stats_generator():
    engine = get_engine()
    while True:
        data = engine.get_stats()
        yield {"data": json.dumps(data)}
        await asyncio.sleep(1)


@router.get("/stream")
async def stream_stats() -> EventSourceResponse:
    return EventSourceResponse(_stats_generator())
