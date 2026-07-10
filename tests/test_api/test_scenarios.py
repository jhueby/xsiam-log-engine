"""API tests for the scenarios router. The engine's fire_scenario_event is
monkeypatched so these tests never touch the real transport layer."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from httpx import AsyncClient, ASGITransport
from api.app import app
from main import get_engine


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fast_scenario(monkeypatch):
    """Swap in a near-instant scenario and stub out real event firing so
    these tests don't hit the transport layer or wait out real delays."""
    engine = get_engine()
    calls = []

    async def fake_fire(source_id, entities, overrides=None):
        calls.append((source_id, overrides))
        return True

    monkeypatch.setattr(engine, "fire_scenario_event", fake_fire)
    engine.scenarios.definitions = {
        **engine.scenarios.definitions,
        "_test_fast": {
            "id": "_test_fast",
            "name": "Fast Test Scenario",
            "description": "for API tests",
            "steps": [
                {"source": "okta", "delay": 0, "jitter": 0, "overrides": {"event_type": "user.session.start"}},
                {"source": "crowdstrike_falcon", "delay": 0, "jitter": 0},
            ],
        },
    }
    yield calls


@pytest.mark.asyncio
async def test_list_scenarios_includes_shipped_and_test_defs(client):
    resp = await client.get("/api/scenarios")
    assert resp.status_code == 200
    ids = {s["id"] for s in resp.json()}
    assert "phishing_to_exfiltration" in ids
    assert "insider_privilege_escalation" in ids
    assert "_test_fast" in ids


@pytest.mark.asyncio
async def test_run_scenario_returns_running_then_completes(client):
    resp = await client.post("/api/scenarios/_test_fast/run")
    assert resp.status_code == 200
    run = resp.json()
    assert run["scenario_id"] == "_test_fast"
    assert run["status"] in ("running", "completed")
    assert len(run["steps"]) == 2
    assert run["entities"]["domain_user"].endswith("@corp.local")

    run_id = run["run_id"]
    for _ in range(20):
        detail = (await client.get(f"/api/scenarios/runs/{run_id}")).json()
        if detail["status"] == "completed":
            break
        await asyncio.sleep(0.05)
    assert detail["status"] == "completed"
    assert all(s["status"] == "fired" for s in detail["steps"])


@pytest.mark.asyncio
async def test_run_unknown_scenario_404s(client):
    resp = await client.post("/api/scenarios/does_not_exist/run")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_run_scenario_with_unknown_source_400s(client):
    engine = get_engine()
    engine.scenarios.definitions["_bad_source"] = {
        "id": "_bad_source",
        "name": "Bad",
        "description": "",
        "steps": [{"source": "not_a_real_source", "delay": 0, "jitter": 0}],
    }
    resp = await client.post("/api/scenarios/_bad_source/run")
    assert resp.status_code == 400
    assert "not_a_real_source" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_get_unknown_run_404s(client):
    resp = await client.get("/api/scenarios/runs/nonexistent-run-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cancel_run(client):
    engine = get_engine()
    engine.scenarios.definitions["_slow_for_cancel"] = {
        "id": "_slow_for_cancel",
        "name": "Slow",
        "description": "",
        "steps": [
            {"source": "okta", "delay": 0, "jitter": 0},
            {"source": "crowdstrike_falcon", "delay": 30, "jitter": 0},
        ],
    }
    run = (await client.post("/api/scenarios/_slow_for_cancel/run")).json()
    resp = await client.post(f"/api/scenarios/runs/{run['run_id']}/cancel")
    assert resp.status_code == 200
    # The cancel response itself must already reflect the final status --
    # regression check for cancel() returning before the task had actually
    # finished unwinding.
    assert resp.json()["status"] == "cancelled"

    detail = (await client.get(f"/api/scenarios/runs/{run['run_id']}")).json()
    assert detail["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_already_completed_run_400s(client):
    run = (await client.post("/api/scenarios/_test_fast/run")).json()
    run_id = run["run_id"]
    for _ in range(20):
        detail = (await client.get(f"/api/scenarios/runs/{run_id}")).json()
        if detail["status"] == "completed":
            break
        await asyncio.sleep(0.05)

    resp = await client.post(f"/api/scenarios/runs/{run_id}/cancel")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cancel_unknown_run_404s(client):
    resp = await client.post("/api/scenarios/runs/nonexistent-run-id/cancel")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_runs_reflects_started_run(client):
    run = (await client.post("/api/scenarios/_test_fast/run")).json()
    resp = await client.get("/api/scenarios/runs")
    assert resp.status_code == 200
    run_ids = [r["run_id"] for r in resp.json()]
    assert run["run_id"] in run_ids
