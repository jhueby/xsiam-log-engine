"""Tests for the datasets router: the tenant dataset list and the per-source
ingestion join. Outbound XSIAM calls are mocked with respx."""
import os
import sys

import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from api.app import app
from config.settings import settings
from xsiam_api import xsiam_api_client
from xsiam_api.client import DATASETS_PATH

API_BASE = "https://api-test.example.com"
DATASETS_URL = API_BASE + DATASETS_PATH

# Day-granular midnight timestamp, as the real tenant reports it.
LAST_UPDATED_MS = 1785369600000

ROWS = [
    {"Dataset Name": "okta_sso_raw", "Type": "USER", "Total Events": 4211,
     "Total Size Stored": 8192, "Last Updated": LAST_UPDATED_MS},
    {"Dataset Name": "xdr_data", "Type": "SYSTEM", "Total Events": 2149346,
     "Total Size Stored": 2821454186, "Last Updated": LAST_UPDATED_MS},
]


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


def _mock_datasets(rows=ROWS):
    # The tenant returns a bare list under "reply", not an {objects: [...]}
    # wrapper like correlations/get.
    return respx.post(DATASETS_URL).mock(return_value=Response(200, json={"reply": rows}))


@pytest.mark.asyncio
@respx.mock
async def test_list_datasets_normalizes_display_cased_keys(client):
    """The tenant uses display-cased, space-separated keys ("Dataset Name",
    "Total Events") unlike the rest of the API."""
    _mock_datasets()

    resp = await client.get("/api/datasets")
    assert resp.status_code == 200
    by_name = {d["name"]: d for d in resp.json()}
    assert by_name["okta_sso_raw"]["total_events"] == 4211
    assert by_name["okta_sso_raw"]["type"] == "USER"
    assert by_name["okta_sso_raw"]["last_updated"].startswith("2026-07-30T00:00:00")


@pytest.mark.asyncio
@respx.mock
async def test_ingestion_flags_sources_whose_dataset_is_absent(client):
    """The engine's blind spot: a transport reports success as soon as XSIAM
    accepts the request, even when no parsing rule routes the events into a
    dataset -- so the source is 'sending' into nowhere."""
    _mock_datasets()

    resp = await client.get("/api/datasets/ingestion")
    assert resp.status_code == 200
    rows = resp.json()
    by_source = {r["source_id"]: r for r in rows}

    okta = by_source["okta"]
    assert okta["dataset"] == "okta_sso_raw"
    assert okta["exists"] is True
    assert okta["total_events"] == 4211

    # aws_cloudtrail resolves to amazon_aws_raw, which isn't in ROWS
    aws = by_source["aws_cloudtrail"]
    assert aws["exists"] is False
    assert aws["total_events"] == 0
    assert aws["last_updated"] is None


@pytest.mark.asyncio
@respx.mock
async def test_ingestion_lists_missing_datasets_first(client):
    """Absent datasets are the actionable rows, so they sort to the top."""
    _mock_datasets()

    rows = (await client.get("/api/datasets/ingestion")).json()
    exists_flags = [r["exists"] for r in rows]
    assert exists_flags == sorted(exists_flags), "missing datasets should sort first"


@pytest.mark.asyncio
@respx.mock
async def test_ingestion_covers_every_source(client):
    _mock_datasets()

    rows = (await client.get("/api/datasets/ingestion")).json()
    from main import get_engine
    assert len(rows) == len(get_engine().sources)


@pytest.mark.asyncio
async def test_datasets_unconfigured_returns_400(client, monkeypatch):
    monkeypatch.setattr(settings, "xsiam_api_url", "")
    resp = await client.get("/api/datasets")
    assert resp.status_code == 400
    assert "Configuration" in resp.json()["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_datasets_upstream_error_maps_to_502(client):
    respx.post(DATASETS_URL).mock(return_value=Response(500, text="boom"))
    resp = await client.get("/api/datasets")
    assert resp.status_code == 502
