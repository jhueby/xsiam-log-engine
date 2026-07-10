from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.models import (
    ScenarioEntitiesInfo,
    ScenarioInfo,
    ScenarioRunInfo,
    ScenarioStepInfo,
    ScenarioStepStatusInfo,
)
from main import get_engine
from scenarios.runner import ScenarioRun

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


def _scenario_to_info(defn: dict) -> ScenarioInfo:
    return ScenarioInfo(
        id=defn["id"],
        name=defn.get("name", defn["id"]),
        description=(defn.get("description") or "").strip(),
        steps=[
            ScenarioStepInfo(
                source=step["source"],
                delay=float(step.get("delay", 0)),
                jitter=float(step.get("jitter", 0)),
                overrides=step.get("overrides") or {},
            )
            for step in defn["steps"]
        ],
    )


def _run_to_info(run: ScenarioRun) -> ScenarioRunInfo:
    return ScenarioRunInfo(
        run_id=run.run_id,
        scenario_id=run.scenario_id,
        scenario_name=run.scenario_name,
        started_at=run.started_at,
        status=run.status,
        error=run.error,
        entities=ScenarioEntitiesInfo(
            username=run.entities.username,
            domain_user=run.entities.domain_user,
            host=run.entities.host,
            internal_ip=run.entities.internal_ip,
            external_ip=run.entities.external_ip,
        ),
        steps=[
            ScenarioStepStatusInfo(
                index=s.index,
                source=s.source,
                delay=s.delay,
                jitter=s.jitter,
                overrides=s.overrides,
                status=s.status,
                fired_at=s.fired_at,
                error=s.error,
            )
            for s in run.steps
        ],
    )


@router.get("", response_model=list[ScenarioInfo])
async def list_scenarios() -> list[ScenarioInfo]:
    runner = get_engine().scenarios
    return [_scenario_to_info(d) for d in runner.list_scenarios()]


@router.get("/runs", response_model=list[ScenarioRunInfo])
async def list_runs() -> list[ScenarioRunInfo]:
    runner = get_engine().scenarios
    return [_run_to_info(r) for r in runner.list_runs()]


@router.get("/runs/{run_id}", response_model=ScenarioRunInfo)
async def get_run(run_id: str) -> ScenarioRunInfo:
    runner = get_engine().scenarios
    run = runner.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Scenario run '{run_id}' not found")
    return _run_to_info(run)


@router.post("/runs/{run_id}/cancel", response_model=ScenarioRunInfo)
async def cancel_run(run_id: str) -> ScenarioRunInfo:
    runner = get_engine().scenarios
    run = runner.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Scenario run '{run_id}' not found")
    if not await runner.cancel(run_id):
        raise HTTPException(status_code=400, detail=f"Run '{run_id}' is not running (status: {run.status})")
    return _run_to_info(run)


@router.post("/{scenario_id}/run", response_model=ScenarioRunInfo)
async def run_scenario(scenario_id: str) -> ScenarioRunInfo:
    runner = get_engine().scenarios
    if not runner.get_scenario(scenario_id):
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")

    unknown = [
        step["source"] for step in runner.definitions[scenario_id]["steps"]
        if step["source"] not in get_engine().sources
    ]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Scenario '{scenario_id}' references unknown source(s): {', '.join(sorted(set(unknown)))}",
        )

    run = runner.start(scenario_id)
    return _run_to_info(run)
