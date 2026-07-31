from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException

from api.models import ControlResponse, CorrelationApplyResponse, CorrelationRuleInfo
from main import get_engine
from utils.logger import get_logger
from xsiam_api import (
    XsiamApiError,
    XsiamApiNotConfigured,
    build_default_rule,
    rule_name,
    source_id_from_name,
    xsiam_api_client,
)

# Every mutation lists the tenant's rules first so the engine never blind-
# overwrites (XSIAM's insert is upsert) or blind-deletes. List-then-act is
# inherently racy against concurrent editors; that is the accepted contract.
router = APIRouter(prefix="/api/correlations", tags=["correlations"])
logger = get_logger(__name__)


def _to_info(rule: dict) -> CorrelationRuleInfo:
    sid = source_id_from_name(rule["name"])
    return CorrelationRuleInfo(
        name=rule["name"],
        source_id=sid,
        managed=sid is not None,
        severity=rule.get("severity", ""),
        dataset=rule.get("dataset", ""),
        xql_query=rule.get("xql_query", ""),
        description=rule.get("description", ""),
        enabled=rule.get("enabled", True),
    )


def _get_source(source_id: str):
    state = get_engine().sources.get(source_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found")
    return state.source


async def _list_rules() -> list[dict]:
    try:
        return await xsiam_api_client.list_rules()
    except XsiamApiNotConfigured as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except XsiamApiError as e:
        raise HTTPException(status_code=502, detail=e.detail)


@router.get("", response_model=list[CorrelationRuleInfo])
async def list_correlation_rules(all: bool = False) -> list[CorrelationRuleInfo]:
    rules = [_to_info(r) for r in await _list_rules()]
    return rules if all else [r for r in rules if r.managed]


@router.get("/{source_id}/preview", response_model=CorrelationRuleInfo)
async def preview_correlation_rule(source_id: str) -> CorrelationRuleInfo:
    return _to_info(build_default_rule(_get_source(source_id)))


@router.post("/{source_id}", response_model=CorrelationApplyResponse)
async def push_correlation_rule(source_id: str, overwrite: bool = False) -> CorrelationApplyResponse:
    source = _get_source(source_id)
    name = rule_name(source_id)

    existing = {r["name"] for r in await _list_rules()}
    if name in existing and not overwrite:
        raise HTTPException(
            status_code=409,
            detail=f"Rule '{name}' already exists on the tenant. Pass overwrite=true to replace it.",
        )

    rule = build_default_rule(source)
    try:
        await xsiam_api_client.upsert_rule(rule)
    except XsiamApiNotConfigured as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except XsiamApiError as e:
        # A 400 from the tenant means it rejected *this rule* (XQL validation,
        # bad enum), which is a client-side problem -- reporting it as 502 Bad
        # Gateway blames the upstream for a rule the operator can fix. The most
        # common cause: the target dataset exists but is populated by real
        # ingestion, so it has no simulated_log_source field for the generated
        # query to filter on.
        status = 400 if e.status == 400 else 502
        raise HTTPException(status_code=status, detail=e.detail)

    action = "updated" if name in existing else "created"
    logger.info({"event": "correlation_rule_pushed", "source": source_id, "action": action})
    return CorrelationApplyResponse(
        ok=True,
        message=f"Rule '{name}' {action}",
        rule=_to_info(rule),
        warning=await _dataset_warning(rule.get("dataset", "")),
    )


async def _dataset_warning(dataset: str) -> str | None:
    """Advisory note about the rule's target dataset.

    Sources aim at the canonical vendor dataset (okta_sso_raw,
    microsoft_windows_raw, ...) so that simulated traffic lands where a real
    deployment would put it and the tenant's built-in parsers and content
    packs apply. That makes an *absent* dataset the normal case on the empty
    tenants this engine is meant to fill — it appears on first ingest — and
    makes a *populated* one the case worth flagging:

      * the generated rule filters on simulated_log_source, a field only this
        engine's events carry, so against a dataset already holding real
        telemetry XSIAM rejects the query outright ("unknown field"); and
      * simulated events will be interleaved with that real data.

    Failing to check must never block the push that already succeeded, so any
    error here degrades to no warning.
    """
    if not dataset:
        return None
    try:
        datasets = {d["name"]: d for d in await xsiam_api_client.list_datasets()}
    except Exception as exc:  # noqa: BLE001 - advisory only, never fatal
        logger.warning({"event": "dataset_check_failed", "dataset": dataset, "error": str(exc)})
        return None

    found = datasets.get(dataset)
    if found is None:
        return None  # expected on an empty tenant; created on first ingest

    events = found.get("total_events") or 0
    if events <= 0:
        return None
    return (
        f"Dataset '{dataset}' already holds {events:,} events that did not come from "
        f"this engine. Simulated events will be mixed in with them, and because this "
        f"rule filters on simulated_log_source — a field only this engine's events "
        f"carry — XSIAM may reject it against that dataset's existing schema."
    )


@router.delete("/{source_id}", response_model=ControlResponse)
async def remove_correlation_rule(source_id: str) -> ControlResponse:
    _get_source(source_id)
    name = rule_name(source_id)

    existing = {r["name"] for r in await _list_rules()}
    if name not in existing:
        raise HTTPException(
            status_code=404,
            detail=f"Rule '{name}' not found on the tenant — nothing to remove.",
        )

    try:
        await xsiam_api_client.delete_rule(name)
    except XsiamApiNotConfigured as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except XsiamApiError as e:
        raise HTTPException(status_code=502, detail=e.detail)

    logger.info({"event": "correlation_rule_removed", "source": source_id})
    return ControlResponse(ok=True, message=f"Rule '{name}' removed")


@router.delete("", response_model=ControlResponse)
async def remove_all_correlation_rules() -> ControlResponse:
    managed = [r["name"] for r in await _list_rules() if source_id_from_name(r["name"]) is not None]
    if not managed:
        return ControlResponse(ok=True, message="No engine-managed rules on the tenant")

    results = await asyncio.gather(
        *(xsiam_api_client.delete_rule(name) for name in managed),
        return_exceptions=True,
    )

    # A config change mid-request surfaces as its own 400, not folded into
    # per-rule failures below (XsiamApiNotConfigured is itself an
    # XsiamApiError subclass, so it must be checked first or it's silently
    # misreported as an ordinary delivery failure).
    not_configured = next((r for r in results if isinstance(r, XsiamApiNotConfigured)), None)
    if not_configured:
        raise HTTPException(status_code=400, detail=not_configured.detail)

    failures = [f"{name}: {r}" for name, r in zip(managed, results) if isinstance(r, BaseException)]
    removed = len(managed) - len(failures)
    logger.info({"event": "correlation_rules_removed_all", "removed": removed, "failed": len(failures)})
    if failures:
        raise HTTPException(status_code=502, detail=f"Removed {removed}, failed {len(failures)}: {'; '.join(failures)}")
    return ControlResponse(ok=True, message=f"Removed {removed} engine-managed rule(s)")
