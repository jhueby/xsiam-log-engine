"""Tests for ScenarioRunner's sequencing/status tracking, isolated from the
real transport layer with a fake engine double."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from scenarios.runner import ScenarioRunner


class FakeEngine:
    def __init__(self):
        self.sources = {"okta": object(), "crowdstrike_falcon": object(), "bad_source": object()}
        self.calls: list[tuple] = []
        self.fail_sources: set[str] = set()      # raise inside fire_scenario_event
        self.undelivered_sources: set[str] = set()  # return False (no exception)

    async def fire_scenario_event(self, source_id, entities, overrides=None):
        self.calls.append((source_id, entities, overrides))
        if source_id in self.fail_sources:
            raise RuntimeError(f"boom: {source_id}")
        return source_id not in self.undelivered_sources


def _fast_scenario(**overrides_by_step):
    return {
        "id": "_test",
        "name": "Test Scenario",
        "description": "fast, deterministic, for tests",
        "steps": [
            {"source": "okta", "delay": 0, "jitter": 0, "overrides": {"event_type": "user.session.start"}},
            {"source": "crowdstrike_falcon", "delay": 0.05, "jitter": 0, "overrides": {"event_type": "Detection"}},
        ],
    }


@pytest.fixture
def runner():
    r = ScenarioRunner(FakeEngine())
    r.definitions = {"_test": _fast_scenario()}
    return r


@pytest.mark.asyncio
async def test_start_fires_all_steps_in_order(runner):
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)

    assert run.status == "completed"
    assert [s.status for s in run.steps] == ["fired", "fired"]
    assert [c[0] for c in runner.engine.calls] == ["okta", "crowdstrike_falcon"]


@pytest.mark.asyncio
async def test_all_steps_share_the_same_resolved_entities(runner):
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)

    entities_seen = {c[1] for c in runner.engine.calls}
    assert len(entities_seen) == 1
    assert run.entities in entities_seen


@pytest.mark.asyncio
async def test_step_overrides_are_passed_through(runner):
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)

    overrides_by_source = {c[0]: c[2] for c in runner.engine.calls}
    assert overrides_by_source["okta"] == {"event_type": "user.session.start"}
    assert overrides_by_source["crowdstrike_falcon"] == {"event_type": "Detection"}


@pytest.mark.asyncio
async def test_unknown_scenario_raises_keyerror(runner):
    with pytest.raises(KeyError):
        runner.start("does_not_exist")


@pytest.mark.asyncio
async def test_one_failing_step_does_not_abort_the_run(runner):
    runner.engine.fail_sources.add("okta")
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)

    assert run.status == "completed"
    assert run.steps[0].status == "error"
    assert "boom" in run.steps[0].error
    assert run.steps[1].status == "fired"


@pytest.mark.asyncio
async def test_undelivered_event_marks_step_error_without_raising(runner):
    # fire_scenario_event returning False (transport failed, no exception) —
    # the step must NOT show as "fired" just because nothing raised.
    runner.engine.undelivered_sources.add("okta")
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)

    assert run.status == "completed"
    assert run.steps[0].status == "error"
    assert "transport failed to deliver" in run.steps[0].error
    assert run.steps[0].fired_at is not None  # we did attempt it
    assert run.steps[1].status == "fired"


@pytest.mark.asyncio
async def test_cancel_stops_a_running_scenario():
    slow = {
        "id": "_slow",
        "name": "Slow",
        "description": "",
        "steps": [
            {"source": "okta", "delay": 0, "jitter": 0},
            {"source": "crowdstrike_falcon", "delay": 10, "jitter": 0},
        ],
    }
    runner = ScenarioRunner(FakeEngine())
    runner.definitions = {"_slow": slow}

    run = runner.start("_slow")
    await asyncio.sleep(0.05)  # let step 1 fire, then we're waiting out the 10s delay
    assert runner.cancel(run.run_id) is True

    await asyncio.wait_for(run.task, timeout=2)
    assert run.status == "cancelled"
    assert run.steps[1].status == "pending"


@pytest.mark.asyncio
async def test_cancel_on_non_running_run_returns_false(runner):
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)
    assert runner.cancel(run.run_id) is False


def test_cancel_unknown_run_returns_false(runner):
    assert runner.cancel("nonexistent-run-id") is False


@pytest.mark.asyncio
async def test_run_history_is_capped(runner):
    from scenarios.runner import MAX_RUN_HISTORY

    for _ in range(MAX_RUN_HISTORY + 5):
        run = runner.start("_test")
        await asyncio.wait_for(run.task, timeout=2)

    assert len(runner.list_runs()) == MAX_RUN_HISTORY
