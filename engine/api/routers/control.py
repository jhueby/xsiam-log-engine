from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from api.models import ControlResponse, HealthResponse
from main import get_engine

router = APIRouter(prefix="/api", tags=["control"])


@router.post("/control/start-all", response_model=ControlResponse)
async def start_all() -> ControlResponse:
    engine = get_engine()
    await engine.start_all()
    return ControlResponse(ok=True, message="All sources started")


@router.post("/control/stop-all", response_model=ControlResponse)
async def stop_all() -> ControlResponse:
    engine = get_engine()
    await engine.stop_all()
    return ControlResponse(ok=True, message="All sources stopped")


@router.post("/control/reload", response_model=ControlResponse)
async def reload_config() -> ControlResponse:
    from config.settings import load_defaults
    engine = get_engine()
    defaults = load_defaults().get("sources", {})
    for sid, state in engine.sources.items():
        cfg = defaults.get(sid, {})
        if "eps" in cfg:
            state.set_eps(cfg["eps"])
        if "transport" in cfg:
            state.set_transport(cfg["transport"])
    return ControlResponse(ok=True, message="Config reloaded from disk")


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    engine = get_engine()
    transport_health = await engine.health()
    all_ok = all(transport_health.values())
    return HealthResponse(
        status="ok" if all_ok else "degraded",
        transports=transport_health,
    )


async def _log_generator(request: Request, source_id: str | None = None):
    engine = get_engine()
    last_len = 0
    while True:
        if await request.is_disconnected():
            break
        logs = engine.get_recent_logs(100)
        if source_id:
            logs = [l for l in logs if l.get("source_id") == source_id]
        if len(logs) > last_len:
            for entry in logs[last_len:]:
                yield {"data": json.dumps(entry)}
            last_len = len(logs)
        await asyncio.sleep(0.5)


@router.get("/logs/stream")
async def stream_logs(request: Request, source_id: str | None = None) -> EventSourceResponse:
    return EventSourceResponse(_log_generator(request, source_id))
