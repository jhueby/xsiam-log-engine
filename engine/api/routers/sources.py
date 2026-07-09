from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.models import SourceInfo, SourceConfigPatch, ControlResponse
from config.settings import settings
from main import get_engine

router = APIRouter(prefix="/api/sources", tags=["sources"])


def _state_to_info(sid: str) -> SourceInfo:
    engine = get_engine()
    state = engine.sources.get(sid)
    if not state:
        raise HTTPException(status_code=404, detail=f"Source '{sid}' not found")
    src = state.source
    return SourceInfo(
        id=src.id,
        display_name=src.display_name,
        description=src.description,
        default_transport=src.default_transport,
        supported_transports=src.supported_transports,
        default_eps=src.default_eps,
        tags=src.tags,
        enabled=state.enabled,
        eps=state.eps,
        transport=state.transport_name,
        total_sent=state.total_sent,
        total_errors=state.total_errors,
        last_event_ts=state.last_event_ts,
        http_log_type=state.http_log_type,
        http_compression=state.http_compression,
        http_api_key="***" if state.http_api_key else "",
        auto_disabled_reason=state.auto_disabled_reason,
        xsiam_dataset=getattr(src, "xsiam_dataset", "") or settings.xsiam_dataset,
    )


@router.get("", response_model=list[SourceInfo])
async def list_sources() -> list[SourceInfo]:
    engine = get_engine()
    return [_state_to_info(sid) for sid in engine.sources]


@router.get("/{source_id}", response_model=SourceInfo)
async def get_source(source_id: str) -> SourceInfo:
    return _state_to_info(source_id)


@router.post("/{source_id}/start", response_model=ControlResponse)
async def start_source(source_id: str) -> ControlResponse:
    engine = get_engine()
    if source_id not in engine.sources:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found")
    await engine.start_source(source_id)
    return ControlResponse(ok=True, message=f"Source '{source_id}' started")


@router.post("/{source_id}/stop", response_model=ControlResponse)
async def stop_source(source_id: str) -> ControlResponse:
    engine = get_engine()
    if source_id not in engine.sources:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found")
    await engine.stop_source(source_id)
    return ControlResponse(ok=True, message=f"Source '{source_id}' stopped")


@router.patch("/{source_id}/config", response_model=SourceInfo)
async def patch_source_config(source_id: str, patch: SourceConfigPatch) -> SourceInfo:
    engine = get_engine()
    state = engine.sources.get(source_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found")

    if patch.eps is not None:
        state.set_eps(patch.eps)
    if patch.transport is not None:
        if patch.transport not in state.source.supported_transports:
            raise HTTPException(
                status_code=400,
                detail=f"Transport '{patch.transport}' not supported by '{source_id}'. Supported: {state.source.supported_transports}",
            )
        state.set_transport(patch.transport)
    if patch.http_log_type is not None:
        state.http_log_type = patch.http_log_type
    if patch.http_compression is not None:
        state.http_compression = patch.http_compression
    if patch.http_api_key is not None and patch.http_api_key != "***":
        state.http_api_key = patch.http_api_key
    if patch.enabled is not None:
        if patch.enabled and not state.enabled:
            await engine.start_source(source_id)
        elif not patch.enabled and state.enabled:
            await engine.stop_source(source_id)

    return _state_to_info(source_id)
