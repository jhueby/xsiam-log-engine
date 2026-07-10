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
