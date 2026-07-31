from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from api.models import DatasetInfo, SourceIngestionInfo
from config.settings import settings
from main import get_engine
from xsiam_api import XsiamApiError, XsiamApiNotConfigured, xsiam_api_client

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


def _iso(ms: int | None) -> str | None:
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


async def _tenant_datasets() -> list[dict]:
    try:
        return await xsiam_api_client.list_datasets()
    except XsiamApiNotConfigured as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except XsiamApiError as e:
        raise HTTPException(status_code=502, detail=e.detail)


@router.get("", response_model=list[DatasetInfo])
async def list_datasets() -> list[DatasetInfo]:
    return [
        DatasetInfo(
            name=d["name"],
            type=d["type"],
            total_events=d["total_events"],
            total_size_bytes=d["total_size_bytes"],
            last_updated=_iso(d["last_updated_ms"]),
        )
        for d in await _tenant_datasets()
    ]


@router.get("/ingestion", response_model=list[SourceIngestionInfo])
async def ingestion_status() -> list[SourceIngestionInfo]:
    """Join each source's target dataset to what the tenant actually holds.

    This closes the engine's blind spot: today it sends events and reports
    success the moment a transport accepts them, which says nothing about
    whether XSIAM parsed and stored anything. A source whose dataset is
    absent (no parsing rule routing `simulated_log_source` to it yet) has
    been "successfully sending" into nowhere.
    """
    engine = get_engine()
    by_name = {d["name"]: d for d in await _tenant_datasets()}

    out: list[SourceIngestionInfo] = []
    for source_id, state in engine.sources.items():
        dataset = getattr(state.source, "xsiam_dataset", "") or settings.xsiam_dataset
        found = by_name.get(dataset)
        out.append(SourceIngestionInfo(
            source_id=source_id,
            display_name=state.source.display_name,
            dataset=dataset,
            exists=found is not None,
            total_events=found["total_events"] if found else 0,
            last_updated=_iso(found["last_updated_ms"]) if found else None,
            sent_by_engine=state.total_sent,
        ))

    # Absent datasets first — those are the actionable rows.
    out.sort(key=lambda r: (r.exists, r.display_name.lower()))
    return out
