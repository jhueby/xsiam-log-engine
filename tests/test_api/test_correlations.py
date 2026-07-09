"""Tests for the correlation-rules router, the XSIAM API client, and config validation.

Outbound XSIAM public-API calls are mocked with respx. The load-bearing cases
assert that the list-first contract prevents any mutation call from going out
on 409/404 paths.
"""
import sys
import os
import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from api.app import app
from config.settings import settings
from xsiam_api import xsiam_api_client
from xsiam_api.client import CORRELATIONS_PATH, INCIDENTS_PATH

API_BASE = "https://api-test.example.com"
CORR_URL = API_BASE + CORRELATIONS_PATH
INCIDENTS_URL = API_BASE + INCIDENTS_PATH

OKTA_RULE = {
    "name": "[LogSim] okta",
    "description": "existing",
    "xql_query": "dataset = okta_system_log_raw",
    "severity": "informational",
    "enabled": True,
    "dataset": "okta_system_log_raw",
}
USER_RULE = {"name": "My custom rule", "xql_query": "dataset = foo"}


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def xsiam_api_settings(monkeypatch):
    monkeypatch.setattr(settings, "xsiam_api_url", API_BASE)
    monkeypatch.setattr(settings, "xsiam_api_key_id", "1")
    monkeypatch.setattr(settings, "xsiam_api_secret", "secret")
    xsiam_api_client.reset()
    yield
    xsiam_api_client.reset()


def _mock_list(rules):
    return respx.get(CORR_URL).mock(return_value=Response(200, json={"reply": rules}))


@pytest.mark.asyncio
@respx.mock
async def test_push_to_empty_tenant(client):
    _mock_list([])
    post_route = respx.post(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["rule"]["name"] == "[LogSim] okta"
    assert data["rule"]["managed"] is True
    assert data["rule"]["source_id"] == "okta"

    assert post_route.called
    body = post_route.calls.last.request.content.decode()
    assert "[LogSim] okta" in body
    assert "simulated_log_source" in body
    # both auth headers present
    req = post_route.calls.last.request
    assert req.headers["Authorization"] == "secret"
    assert req.headers["x-xdr-auth-id"] == "1"


@pytest.mark.asyncio
@respx.mock
async def test_push_conflict_never_calls_post(client):
    _mock_list([OKTA_RULE])
    post_route = respx.post(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 409
    assert "overwrite=true" in resp.json()["detail"]
    assert not post_route.called


@pytest.mark.asyncio
@respx.mock
async def test_push_with_overwrite(client):
    _mock_list([OKTA_RULE])
    post_route = respx.post(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.post("/api/correlations/okta?overwrite=true")
    assert resp.status_code == 200
    assert "updated" in resp.json()["message"]
    assert post_route.called


@pytest.mark.asyncio
@respx.mock
async def test_push_unknown_source(client):
    resp = await client.post("/api/correlations/nonexistent_source_xyz")
    assert resp.status_code == 404


@pytest.mark.asyncio
@respx.mock
async def test_delete_missing_never_calls_delete(client):
    _mock_list([])
    delete_route = respx.delete(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.delete("/api/correlations/okta")
    assert resp.status_code == 404
    assert "nothing to remove" in resp.json()["detail"]
    assert not delete_route.called


@pytest.mark.asyncio
@respx.mock
async def test_delete_existing(client):
    _mock_list([OKTA_RULE])
    delete_route = respx.delete(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.delete("/api/correlations/okta")
    assert resp.status_code == 200
    assert delete_route.called
    assert "[LogSim] okta" in delete_route.calls.last.request.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_list_filters_to_managed(client):
    _mock_list([OKTA_RULE, USER_RULE])

    resp = await client.get("/api/correlations")
    assert resp.status_code == 200
    names = [r["name"] for r in resp.json()]
    assert names == ["[LogSim] okta"]

    resp = await client.get("/api/correlations?all=true")
    names = [r["name"] for r in resp.json()]
    assert set(names) == {"[LogSim] okta", "My custom rule"}


@pytest.mark.asyncio
@respx.mock
async def test_remove_all_only_touches_managed(client):
    _mock_list([OKTA_RULE, USER_RULE])
    delete_route = respx.delete(CORR_URL).mock(return_value=Response(200, json={"reply": True}))

    resp = await client.delete("/api/correlations")
    assert resp.status_code == 200
    assert "1" in resp.json()["message"]
    assert delete_route.call_count == 1
    assert "[LogSim] okta" in delete_route.calls.last.request.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_upstream_403_maps_to_502(client):
    respx.get(CORR_URL).mock(return_value=Response(403, json={"reply": {"err_msg": "forbidden"}}))

    resp = await client.get("/api/correlations")
    assert resp.status_code == 502
    assert "Instance Administrator" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_unconfigured_returns_400(client, monkeypatch):
    monkeypatch.setattr(settings, "xsiam_api_url", "")
    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 400
    assert "Configuration" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_preview_is_local(client):
    resp = await client.get("/api/correlations/okta/preview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "[LogSim] okta"
    assert 'simulated_log_source = "okta"' in data["xql_query"]
    assert data["dataset"] == "okta_system_log_raw"


@pytest.mark.asyncio
async def test_delete_rule_refuses_unmanaged_name():
    with pytest.raises(ValueError):
        await xsiam_api_client.delete_rule("My custom rule")


@pytest.mark.asyncio
async def test_source_info_exposes_dataset(client):
    resp = await client.get("/api/sources/okta")
    assert resp.status_code == 200
    assert resp.json()["xsiam_dataset"] == "okta_system_log_raw"


# ── POST /api/config/validate ──────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_validate_all_green(client):
    respx.get(API_BASE + "/").mock(return_value=Response(200))
    respx.post(INCIDENTS_URL).mock(return_value=Response(200, json={"reply": {}}))
    _mock_list([OKTA_RULE])

    resp = await client.post("/api/config/validate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert [c["name"] for c in data["checks"]] == ["configured", "reachable", "authenticated", "correlations_access"]
    assert all(c["ok"] for c in data["checks"])


@pytest.mark.asyncio
@respx.mock
async def test_validate_bad_credentials_skips_correlations(client):
    respx.get(API_BASE + "/").mock(return_value=Response(200))
    respx.post(INCIDENTS_URL).mock(return_value=Response(403, json={}))
    corr_route = _mock_list([])

    resp = await client.post("/api/config/validate")
    data = resp.json()
    assert data["ok"] is False
    auth = next(c for c in data["checks"] if c["name"] == "authenticated")
    assert auth["ok"] is False
    assert "rejected" in auth["detail"]
    assert not any(c["name"] == "correlations_access" for c in data["checks"])
    assert not corr_route.called


@pytest.mark.asyncio
@respx.mock
async def test_validate_role_gate_detected(client):
    respx.get(API_BASE + "/").mock(return_value=Response(200))
    respx.post(INCIDENTS_URL).mock(return_value=Response(200, json={"reply": {}}))
    respx.get(CORR_URL).mock(return_value=Response(403, json={}))

    resp = await client.post("/api/config/validate")
    data = resp.json()
    assert data["ok"] is False
    corr = next(c for c in data["checks"] if c["name"] == "correlations_access")
    assert corr["ok"] is False
    assert "Instance Administrator" in corr["detail"]


@pytest.mark.asyncio
async def test_validate_unconfigured(client, monkeypatch):
    monkeypatch.setattr(settings, "xsiam_api_secret", "")
    resp = await client.post("/api/config/validate")
    data = resp.json()
    assert data["ok"] is False
    assert len(data["checks"]) == 1
    assert data["checks"][0]["name"] == "configured"
    assert data["checks"][0]["ok"] is False
