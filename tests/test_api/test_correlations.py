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
from xsiam_api.client import (
    CORRELATIONS_DELETE_PATH,
    CORRELATIONS_GET_PATH,
    CORRELATIONS_INSERT_PATH,
    INCIDENTS_PATH,
)

API_BASE = "https://api-test.example.com"
CORR_GET_URL = API_BASE + CORRELATIONS_GET_PATH
CORR_INSERT_URL = API_BASE + CORRELATIONS_INSERT_PATH
CORR_DELETE_URL = API_BASE + CORRELATIONS_DELETE_PATH
INCIDENTS_URL = API_BASE + INCIDENTS_PATH

OKTA_RULE = {
    "name": "[LogSim] okta",
    "description": "existing",
    "xql_query": "dataset = okta_system_log_raw",
    "severity": "informational",
    "is_enabled": True,
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
    # Real tenant shape (confirmed live): POST .../correlations/get with a
    # {"request_data": {...}} body, response un-wrapped (no "reply" key) as
    # {"objects_count": N, "objects": [...]}.
    return respx.post(CORR_GET_URL).mock(
        return_value=Response(200, json={"objects_count": len(rules), "objects": rules})
    )


@pytest.mark.asyncio
@respx.mock
async def test_push_to_empty_tenant(client):
    _mock_list([])
    post_route = respx.post(CORR_INSERT_URL).mock(return_value=Response(200, json={"added_objects": [{"id": 1}], "errors": []}))
    # upsert is delete-then-insert (there is no update endpoint), so the
    # pre-delete goes out even against an empty tenant -- a no-op there.
    respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 0, "objects": []}))

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
    post_route = respx.post(CORR_INSERT_URL).mock(return_value=Response(200, json={"added_objects": [{"id": 1}], "errors": []}))

    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 409
    assert "overwrite=true" in resp.json()["detail"]
    assert not post_route.called


@pytest.mark.asyncio
@respx.mock
async def test_push_with_overwrite(client):
    _mock_list([OKTA_RULE])
    post_route = respx.post(CORR_INSERT_URL).mock(return_value=Response(200, json={"added_objects": [{"id": 1}], "errors": []}))
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

    resp = await client.post("/api/correlations/okta?overwrite=true")
    assert resp.status_code == 200
    assert "updated" in resp.json()["message"]
    assert post_route.called
    # /insert always creates -- pushing over an existing name without first
    # deleting produced duplicate same-named rules on a real tenant, so an
    # overwrite must delete first.
    assert delete_route.called
    assert "[LogSim] okta" in delete_route.calls.last.request.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_push_unknown_source(client):
    resp = await client.post("/api/correlations/nonexistent_source_xyz")
    assert resp.status_code == 404


@pytest.mark.asyncio
@respx.mock
async def test_delete_missing_never_calls_delete(client):
    _mock_list([])
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

    resp = await client.delete("/api/correlations/okta")
    assert resp.status_code == 404
    assert "nothing to remove" in resp.json()["detail"]
    assert not delete_route.called


@pytest.mark.asyncio
@respx.mock
async def test_delete_existing(client):
    _mock_list([OKTA_RULE])
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

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
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

    resp = await client.delete("/api/correlations")
    assert resp.status_code == 200
    assert "1" in resp.json()["message"]
    assert delete_route.call_count == 1
    assert "[LogSim] okta" in delete_route.calls.last.request.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_remove_all_deletes_concurrently_not_sequentially(client):
    okta2 = {**OKTA_RULE, "name": "[LogSim] crowdstrike_falcon"}
    _mock_list([OKTA_RULE, okta2, USER_RULE])
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

    resp = await client.delete("/api/correlations")
    assert resp.status_code == 200
    assert delete_route.call_count == 2
    deleted_names = {c.request.content.decode() for c in delete_route.calls}
    assert any("[LogSim] okta" in n for n in deleted_names)
    assert any("[LogSim] crowdstrike_falcon" in n for n in deleted_names)


@pytest.mark.asyncio
@respx.mock
async def test_remove_all_config_cleared_midflight_returns_400_not_502(client, monkeypatch):
    # XsiamApiNotConfigured is a subclass of XsiamApiError -- if the generic
    # except clause catches it first, this would misreport as an ordinary
    # per-rule delivery failure (502) instead of the distinct 400 every other
    # endpoint uses for "not configured".
    from xsiam_api.client import XsiamApiNotConfigured

    okta2 = {**OKTA_RULE, "name": "[LogSim] crowdstrike_falcon"}
    _mock_list([OKTA_RULE, okta2])

    async def fake_delete_rule(name):
        raise XsiamApiNotConfigured()

    monkeypatch.setattr(xsiam_api_client, "delete_rule", fake_delete_rule)

    resp = await client.delete("/api/correlations")
    assert resp.status_code == 400
    assert "not configured" in resp.json()["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_bodyless_request_carries_no_content_type_header():
    """Regression: some tenant-side deployments eagerly parse the request
    body as JSON whenever Content-Type: application/json is present, even on
    a request with no body -- crashing their WSGI app with an empty-body JSON
    parse error and returning an opaque 500 with no useful detail. Every
    current caller happens to send a body (list_rules() now does too, since
    it moved to POST .../correlations/get), so this exercises _request()
    directly rather than via a specific endpoint -- the header logic itself
    is still load-bearing for any future bodyless call."""
    route = respx.get(API_BASE + "/no-body-path").mock(return_value=Response(200, json={}))

    await xsiam_api_client._request("GET", "/no-body-path")

    assert route.called
    assert "content-type" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_request_with_body_still_carries_content_type_header():
    """The bodyless-request fix must not regress requests that do have a body."""
    route = respx.post(API_BASE + "/with-body-path").mock(return_value=Response(200, json={}))

    await xsiam_api_client._request("POST", "/with-body-path", {"foo": "bar"})

    assert route.called
    assert route.calls.last.request.headers["content-type"] == "application/json"


@pytest.mark.asyncio
@respx.mock
async def test_list_rules_posts_to_get_path_with_request_data(client):
    """Regression: the original guess (GET /public_api/v1/correlations/) isn't
    a real endpoint on an actual tenant -- it 500s exactly like any other
    unroutable path there. The real endpoint is POST .../correlations/get
    with a {"request_data": {...}} body, confirmed live."""
    list_route = _mock_list([])

    resp = await client.get("/api/correlations")
    assert resp.status_code == 200
    assert list_route.called
    req = list_route.calls.last.request
    assert req.method == "POST"
    assert "request_data" in req.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_list_rules_maps_is_enabled_not_enabled(client):
    """Regression: the real field is is_enabled, not enabled -- the original
    guess meant every rule silently read back as enabled=True regardless of
    its actual state on the tenant."""
    disabled_rule = {**OKTA_RULE, "is_enabled": False}
    _mock_list([disabled_rule])

    resp = await client.get("/api/correlations?all=true")
    assert resp.status_code == 200
    assert resp.json()[0]["enabled"] is False


@pytest.mark.asyncio
@respx.mock
async def test_insert_payload_matches_tenant_required_schema(client):
    """Regression: /insert rejects a partial object -- it requires the full
    field set, a SEV_0N0_* severity enum (not the plain word the engine used
    to send), is_enabled (not enabled), and mapping_strategy CUSTOM ("AUTO"
    is advertised as valid but rejected in practice). All confirmed live."""
    import json as _json

    _mock_list([])
    respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 0, "objects": []}))
    post_route = respx.post(CORR_INSERT_URL).mock(return_value=Response(200, json={"added_objects": [{"id": 1}], "errors": []}))

    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 200

    sent = _json.loads(post_route.calls.last.request.content.decode())
    assert isinstance(sent["request_data"], list)  # "should contain only a list of JSONs"
    obj = sent["request_data"][0]

    required = {
        "name", "alert_domain", "drilldown_query_timeframe", "severity", "alert_name",
        "mitre_defs", "user_defined_category", "action", "dataset", "lookup_mapping",
        "execution_mode", "user_defined_severity", "suppression_fields",
        "suppression_duration", "mapping_strategy", "simple_schedule", "search_window",
        "alert_category", "crontab", "timezone", "suppression_enabled",
        "alert_description", "description", "alert_fields", "investigation_query_link",
        "xql_query", "is_enabled", "alert_type",
    }
    assert required <= set(obj), f"missing required fields: {required - set(obj)}"
    assert obj["severity"].startswith("SEV_")
    assert obj["mapping_strategy"] == "CUSTOM"
    assert "enabled" not in obj  # the real field is is_enabled


@pytest.mark.asyncio
@respx.mock
async def test_insert_partial_failure_is_not_reported_as_success(client):
    """Regression: /insert returns HTTP 200 with a populated "errors" list
    when some items fail, so a status-only check would report a rule that was
    never created as successfully pushed."""
    _mock_list([])
    respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 0, "objects": []}))
    respx.post(CORR_INSERT_URL).mock(return_value=Response(200, json={
        "added_objects": [],
        "updated_objects": [],
        "errors": [{"index": 0, "status": "Failed to create correlation rule due to: Invalid severity: NOPE"}],
    }))

    resp = await client.post("/api/correlations/okta")
    assert resp.status_code == 502
    assert "Invalid severity" in resp.json()["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_delete_uses_scoped_name_filter(client):
    """Regression: delete takes filters, not {"names": [...]}. An unfiltered
    delete is rejected by the API ("At least one filter is required"), and the
    filter must be scoped to the one engine-managed name."""
    import json as _json

    _mock_list([OKTA_RULE])
    delete_route = respx.post(CORR_DELETE_URL).mock(return_value=Response(200, json={"objects_count": 1, "objects": [1]}))

    resp = await client.delete("/api/correlations/okta")
    assert resp.status_code == 200

    sent = _json.loads(delete_route.calls.last.request.content.decode())
    filters = sent["request_data"]["filters"]
    assert filters == [{"field": "name", "operator": "eq", "value": "[LogSim] okta"}]


@pytest.mark.asyncio
@respx.mock
async def test_upstream_403_maps_to_502(client):
    respx.post(CORR_GET_URL).mock(return_value=Response(403, json={"reply": {"err_msg": "forbidden"}}))

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
    respx.post(CORR_GET_URL).mock(return_value=Response(403, json={}))

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
