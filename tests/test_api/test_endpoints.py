"""Smoke tests for the FastAPI endpoints."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from httpx import AsyncClient, ASGITransport
from api.app import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_root(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "xsiam-log-engine"


@pytest.mark.asyncio
async def test_list_sources(client):
    resp = await client.get("/api/sources")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 21


@pytest.mark.asyncio
async def test_get_source(client):
    resp = await client.get("/api/sources/okta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "okta"
    assert "display_name" in data


@pytest.mark.asyncio
async def test_get_source_not_found(client):
    resp = await client.get("/api/sources/nonexistent_source_xyz")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_stats(client):
    resp = await client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_sent" in data
    assert "eps_actual" in data


@pytest.mark.asyncio
async def test_get_config(client):
    resp = await client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "xsiam_url" in data
    assert "brokervm_host" in data


@pytest.mark.asyncio
async def test_update_config(client):
    resp = await client.put("/api/config", json={"xsiam_dataset": "test_dataset"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["xsiam_dataset"] == "test_dataset"


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "transports" in data
    assert "http" in data["transports"]


@pytest.mark.asyncio
async def test_patch_source_eps(client):
    resp = await client.patch("/api/sources/okta/config", json={"eps": 25.0})
    assert resp.status_code == 200
    data = resp.json()
    assert data["eps"] == 25.0


@pytest.mark.asyncio
async def test_start_stop_source(client):
    start_resp = await client.post("/api/sources/okta/start")
    assert start_resp.status_code == 200
    assert start_resp.json()["ok"] is True

    stop_resp = await client.post("/api/sources/okta/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["ok"] is True


@pytest.mark.asyncio
async def test_control_start_stop_all(client):
    start_resp = await client.post("/api/control/start-all")
    assert start_resp.status_code == 200

    stop_resp = await client.post("/api/control/stop-all")
    assert stop_resp.status_code == 200


@pytest.mark.asyncio
async def test_control_reload(client):
    resp = await client.post("/api/control/reload")
    assert resp.status_code == 200
