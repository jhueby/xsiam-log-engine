from __future__ import annotations

import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, TYPE_CHECKING

from scenarios.loader import load_scenarios
from sources.base_source import ScenarioEntities
from utils.faker_helpers import DOMAIN, random_external_ip, random_internal_ip, random_user, random_windows_host
from utils.logger import get_logger

if TYPE_CHECKING:
    from main import Engine

logger = get_logger(__name__)

StepStatus = Literal["pending", "fired", "error"]
RunStatus = Literal["running", "completed", "cancelled", "failed"]

MAX_RUN_HISTORY = 20


@dataclass
class ScenarioStepState:
    index: int
    source: str
    delay: float
    jitter: float
    overrides: dict
    status: StepStatus = "pending"
    fired_at: str | None = None
    error: str | None = None


@dataclass
class ScenarioRun:
    run_id: str
    scenario_id: str
    scenario_name: str
    started_at: str
    entities: ScenarioEntities
    steps: list[ScenarioStepState]
    status: RunStatus = "running"
    error: str | None = None
    task: asyncio.Task | None = field(default=None, repr=False, compare=False)


def _resolve_entities() -> ScenarioEntities:
    username = random_user()
    return ScenarioEntities(
        username=username,
        domain_user=f"{username}@{DOMAIN}",
        host=random_windows_host(),
        internal_ip=random_internal_ip(),
        external_ip=random_external_ip(),
    )


class ScenarioRunner:
    """Fires timed, entity-correlated event sequences across sources so
    XSIAM correlation rules have a real multi-vendor story to fire on,
    independent of each source's own steady-state EPS loop."""

    def __init__(self, engine: "Engine") -> None:
        self.engine = engine
        self.definitions: dict[str, dict] = load_scenarios()
        # dict preserves insertion order (Python 3.7+); that ordering is all
        # list_runs()/_prune_history() need, so there's no separate index to
        # keep in sync.
        self.runs: dict[str, ScenarioRun] = {}

    def list_scenarios(self) -> list[dict]:
        return list(self.definitions.values())

    def get_scenario(self, scenario_id: str) -> dict | None:
        return self.definitions.get(scenario_id)

    def list_runs(self) -> list[ScenarioRun]:
        return list(reversed(self.runs.values()))

    def get_run(self, run_id: str) -> ScenarioRun | None:
        return self.runs.get(run_id)

    def start(self, scenario_id: str) -> ScenarioRun:
        defn = self.definitions.get(scenario_id)
        if not defn:
            raise KeyError(scenario_id)

        entities = _resolve_entities()
        steps = [
            ScenarioStepState(
                index=i,
                source=step["source"],
                delay=float(step.get("delay", 0)),
                jitter=float(step.get("jitter", 0)),
                overrides=step.get("overrides") or {},
            )
            for i, step in enumerate(defn["steps"])
        ]
        run = ScenarioRun(
            run_id=uuid.uuid4().hex,
            scenario_id=scenario_id,
            scenario_name=defn.get("name", scenario_id),
            started_at=datetime.now(timezone.utc).isoformat(),
            entities=entities,
            steps=steps,
        )
        run.task = asyncio.create_task(self._execute(run))
        self.runs[run.run_id] = run
        self._prune_history()
        return run

    def _prune_history(self) -> None:
        # Only evict finished runs (completed/cancelled/failed), oldest first.
        # A still-running scenario is never evicted just because newer runs
        # started -- if everything in history happens to be running, history
        # simply grows past MAX_RUN_HISTORY rather than killing user-visible work.
        while len(self.runs) > MAX_RUN_HISTORY:
            evictable_id = next((rid for rid, r in self.runs.items() if r.status != "running"), None)
            if evictable_id is None:
                break
            del self.runs[evictable_id]

    async def cancel(self, run_id: str) -> bool:
        run = self.runs.get(run_id)
        if not run or run.status != "running":
            return False
        if run.task:
            run.task.cancel()
            try:
                await asyncio.wait_for(run.task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.error({"event": "scenario_cancel_timeout", "run_id": run_id})
        return True

    async def cancel_all(self) -> None:
        tasks = [run.task for run in self.runs.values() if run.status == "running" and run.task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _execute(self, run: ScenarioRun) -> None:
        start = time.monotonic()
        try:
            for step in run.steps:
                target_offset = step.delay + random.uniform(0, step.jitter)
                remaining = target_offset - (time.monotonic() - start)
                if remaining > 0:
                    await asyncio.sleep(remaining)

                try:
                    delivered = await self.engine.fire_scenario_event(step.source, run.entities, step.overrides)
                    step.fired_at = datetime.now(timezone.utc).isoformat()
                    if delivered:
                        step.status = "fired"
                    else:
                        step.status = "error"
                        step.error = "Event generated but the transport failed to deliver it — check Diagnostics/Log Viewer"
                except Exception as exc:
                    # One misconfigured/failing step doesn't abort the story —
                    # matches how the normal per-source loop tolerates errors.
                    step.status = "error"
                    step.error = str(exc)
                    logger.error({
                        "event": "scenario_step_failed",
                        "scenario": run.scenario_id,
                        "run_id": run.run_id,
                        "source": step.source,
                        "error": str(exc),
                    })
            run.status = "completed"
        except asyncio.CancelledError:
            run.status = "cancelled"
        except Exception as exc:
            run.status = "failed"
            run.error = str(exc)
            logger.error({"event": "scenario_run_failed", "run_id": run.run_id, "error": str(exc)})
