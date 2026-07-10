"""Tests that /docs, /redoc, and /openapi.json are gated by ENGINE_API_TOKEN
the same way /api/* already is — previously they were reachable unauthenticated
regardless of the token, exposing the full route/schema surface."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from httpx import AsyncClient, ASGITransport
from api.app import app
from config.settings import settings

DOC_PATHS = ["/docs", "/redoc", "/openapi.json"]


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_docs_open_when_no_token_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "engine_api_token", "")
    for path in DOC_PATHS:
        resp = await client.get(path)
        assert resp.status_code == 200, path


@pytest.mark.asyncio
async def test_docs_require_token_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "engine_api_token", "s3cret")
    for path in DOC_PATHS:
        resp = await client.get(path)
        assert resp.status_code == 401, path


@pytest.mark.asyncio
async def test_docs_accessible_with_correct_token(client, monkeypatch):
    monkeypatch.setattr(settings, "engine_api_token", "s3cret")
    for path in DOC_PATHS:
        resp = await client.get(path, headers={"X-Engine-Token": "s3cret"})
        assert resp.status_code == 200, path


@pytest.mark.asyncio
async def test_docs_rejected_with_wrong_token(client, monkeypatch):
    monkeypatch.setattr(settings, "engine_api_token", "s3cret")
    resp = await client.get("/docs", headers={"X-Engine-Token": "nope"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_docs_via_query_token_embeds_token_for_the_browsers_own_fetch(client, monkeypatch):
    # Regression: Swagger UI/ReDoc's generated HTML makes its own browser-side
    # fetch to openapi_url. A header can authenticate the /docs page load
    # itself, but can't be attached to that follow-up fetch — only a token
    # baked into the URL (the realistic way a human reaches /docs at all,
    # since browsers can't set custom headers by navigating) survives it.
    monkeypatch.setattr(settings, "engine_api_token", "s3cret")

    swagger = await client.get("/docs?token=s3cret")
    assert swagger.status_code == 200
    assert "/openapi.json?token=s3cret" in swagger.text

    redoc = await client.get("/redoc?token=s3cret")
    assert redoc.status_code == 200
    assert "/openapi.json?token=s3cret" in redoc.text


@pytest.mark.asyncio
async def test_docs_embedded_openapi_url_actually_works(client, monkeypatch):
    """End-to-end: extract the embedded openapi_url from /docs and fetch it,
    proving the browser's own follow-up request would succeed, not just that
    the HTML contains the right-looking substring."""
    import re

    monkeypatch.setattr(settings, "engine_api_token", "s3cret")
    swagger = await client.get("/docs?token=s3cret")
    match = re.search(r"url:\s*'([^']+)'", swagger.text)
    assert match, "could not find the embedded openapi_url in the Swagger UI HTML"

    resp = await client.get(match.group(1))
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "XSIAM Log Engine"


@pytest.mark.asyncio
async def test_docs_with_no_token_configured_has_plain_openapi_url(client, monkeypatch):
    monkeypatch.setattr(settings, "engine_api_token", "")
    resp = await client.get("/docs")
    assert "url: '/openapi.json'" in resp.text
    assert "token=" not in resp.text
