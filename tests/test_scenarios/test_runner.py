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
    assert await runner.cancel(run.run_id) is True

    assert run.status == "cancelled"
    assert run.steps[1].status == "pending"


@pytest.mark.asyncio
async def test_cancel_returns_only_after_status_actually_updates(runner):
    # Regression: cancel() previously returned immediately after calling
    # task.cancel(), so the caller's response could still say "running"
    # even though cancellation had been requested successfully.
    slow = {
        "id": "_slow2",
        "name": "Slow",
        "description": "",
        "steps": [{"source": "okta", "delay": 30, "jitter": 0}],
    }
    runner.definitions["_slow2"] = slow
    run = runner.start("_slow2")
    await asyncio.sleep(0.01)

    assert await runner.cancel(run.run_id) is True
    assert run.status == "cancelled"  # already updated, not stale, by the time cancel() returns


@pytest.mark.asyncio
async def test_cancel_on_non_running_run_returns_false(runner):
    run = runner.start("_test")
    await asyncio.wait_for(run.task, timeout=2)
    assert await runner.cancel(run.run_id) is False


@pytest.mark.asyncio
async def test_cancel_unknown_run_returns_false(runner):
    assert await runner.cancel("nonexistent-run-id") is False


@pytest.mark.asyncio
async def test_run_history_is_capped(runner):
    from scenarios.runner import MAX_RUN_HISTORY

    for _ in range(MAX_RUN_HISTORY + 5):
        run = runner.start("_test")
        await asyncio.wait_for(run.task, timeout=2)

    assert len(runner.list_runs()) == MAX_RUN_HISTORY


@pytest.mark.asyncio
async def test_prune_history_never_evicts_or_cancels_a_running_scenario(runner):
    # Regression: history pruning previously evicted purely by insertion
    # count, cancelling a still-in-progress run just because MAX_RUN_HISTORY
    # newer runs had started.
    from scenarios.runner import MAX_RUN_HISTORY

    long_running = {
        "id": "_long",
        "name": "Long",
        "description": "",
        "steps": [{"source": "okta", "delay": 30, "jitter": 0}],
    }
    runner.definitions["_long"] = long_running
    first = runner.start("_long")

    for _ in range(MAX_RUN_HISTORY + 5):
        run = runner.start("_test")
        await asyncio.wait_for(run.task, timeout=2)

    # The cap still holds -- pruning evicted enough *completed* runs to fit --
    # but it held by leaving the running one alone, not by killing it.
    assert len(runner.runs) == MAX_RUN_HISTORY
    assert runner.get_run(first.run_id) is not None
    assert first.status == "running"
    assert not first.task.done()

    await runner.cancel(first.run_id)  # clean up the background task

    # If literally everything in history is still running, there's nothing
    # left to evict -- history grows past the cap rather than killing work.
    runner2 = ScenarioRunner(FakeEngine())
    runner2.definitions = {"_long": long_running}
    running_runs = [runner2.start("_long") for _ in range(MAX_RUN_HISTORY + 3)]
    assert len(runner2.runs) == MAX_RUN_HISTORY + 3
    assert all(r.status == "running" for r in running_runs)
    await asyncio.gather(*(runner2.cancel(r.run_id) for r in running_runs))


@pytest.mark.asyncio
async def test_cancel_all_awaits_tasks_before_returning():
    slow = {
        "id": "_slow3",
        "name": "Slow",
        "description": "",
        "steps": [{"source": "okta", "delay": 30, "jitter": 0}],
    }
    runner = ScenarioRunner(FakeEngine())
    runner.definitions = {"_slow3": slow}
    run = runner.start("_slow3")
    await asyncio.sleep(0.01)

    await runner.cancel_all()

    assert run.task.done()
    assert run.status == "cancelled"
