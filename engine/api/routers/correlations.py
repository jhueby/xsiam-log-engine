from __future__ import annotations

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
        raise HTTPException(status_code=502, detail=e.detail)

    action = "updated" if name in existing else "created"
    logger.info({"event": "correlation_rule_pushed", "source": source_id, "action": action})
    return CorrelationApplyResponse(ok=True, message=f"Rule '{name}' {action}", rule=_to_info(rule))


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

    failures: list[str] = []
    for name in managed:
        try:
            await xsiam_api_client.delete_rule(name)
        except (XsiamApiError, ValueError) as e:
            failures.append(f"{name}: {e}")

    removed = len(managed) - len(failures)
    logger.info({"event": "correlation_rules_removed_all", "removed": removed, "failed": len(failures)})
    if failures:
        raise HTTPException(status_code=502, detail=f"Removed {removed}, failed {len(failures)}: {'; '.join(failures)}")
    return ControlResponse(ok=True, message=f"Removed {removed} engine-managed rule(s)")
