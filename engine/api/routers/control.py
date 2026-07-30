from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from pydantic import ValidationError

from api.models import ControlResponse, HealthResponse, SourceConfigPatch
from main import get_engine
from utils.logger import get_logger

logger = get_logger(__name__)

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
    skipped: list[str] = []
    for sid, state in engine.sources.items():
        cfg = defaults.get(sid, {})
        if "eps" in cfg or "transport" in cfg:
            try:
                # Route file-based config through the same bounds the PATCH
                # API enforces (SourceConfigPatch's eps ge=0.1/le=10000) —
                # defaults.yaml is hand-edited and shouldn't get a free pass
                # around validation the API doesn't allow.
                patch = SourceConfigPatch(eps=cfg.get("eps"), transport=cfg.get("transport"))
            except ValidationError as exc:
                skipped.append(sid)
                logger.error({"event": "reload_invalid_config", "source": sid, "error": str(exc)})
                continue
            if patch.eps is not None:
                state.set_eps(patch.eps)
            if patch.transport is not None:
                state.set_transport(patch.transport)
    # Scenario definitions are read from disk the same way source config is,
    # so "reload from disk" covers both -- otherwise a dropped-in scenario
    # YAML needs a full engine restart to become runnable.
    scenario_count = engine.scenarios.reload()

    message = f"Config reloaded from disk ({scenario_count} scenario(s))"
    if skipped:
        message += f" (skipped invalid entries: {', '.join(skipped)})"
    return ControlResponse(ok=True, message=message)


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
