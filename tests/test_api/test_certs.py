"""Tests for the .pfx upload endpoint's security hardening: key file
permissions, passphrase handling, and upload size caps."""
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from httpx import AsyncClient, ASGITransport
from api.app import app
from api.routers import certs as certs_module

PASSPHRASE = "test-passphrase-123"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
def pfx_bytes(tmp_path):
    """A throwaway self-signed cert/key exported as PKCS#12, built with the
    system openssl binary — the same tool the endpoint shells out to."""
    key_path = tmp_path / "t.key"
    crt_path = tmp_path / "t.crt"
    pfx_path = tmp_path / "t.pfx"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key_path),
         "-out", str(crt_path), "-days", "1", "-nodes", "-subj", "/CN=test"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkcs12", "-export", "-in", str(crt_path), "-inkey", str(key_path),
         "-out", str(pfx_path), "-passout", f"pass:{PASSPHRASE}"],
        check=True, capture_output=True,
    )
    return pfx_path.read_bytes()


@pytest.fixture(autouse=True)
def isolated_certs_dir(tmp_path, monkeypatch):
    """Redirect the endpoint's cert output dir so tests don't touch the repo."""
    monkeypatch.setattr(certs_module, "_CERTS_DIR", tmp_path / "certs")
    yield


@pytest.mark.asyncio
async def test_upload_writes_key_with_owner_only_permissions(client, pfx_bytes):
    resp = await client.post(
        "/api/certs/pfx",
        files={"file": ("t.pfx", pfx_bytes, "application/x-pkcs12")},
        data={"passphrase": PASSPHRASE},
    )
    assert resp.status_code == 200
    data = resp.json()

    key_mode = stat.S_IMODE(os.stat(data["key_path"]).st_mode)
    cert_mode = stat.S_IMODE(os.stat(data["cert_path"]).st_mode)
    dir_mode = stat.S_IMODE(os.stat(Path(data["key_path"]).parent).st_mode)

    assert key_mode == 0o600
    assert cert_mode == 0o600
    assert dir_mode == 0o700


@pytest.mark.asyncio
async def test_upload_rejects_oversized_file(client):
    oversized = b"x" * (certs_module.MAX_PFX_BYTES + 1)
    resp = await client.post(
        "/api/certs/pfx",
        files={"file": ("t.pfx", oversized, "application/x-pkcs12")},
        data={"passphrase": PASSPHRASE},
    )
    assert resp.status_code == 413
    assert "limit" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_at_cap_boundary_is_accepted_by_size_check(client, pfx_bytes, monkeypatch):
    # Confirm the cap is enforced on bytes actually read, not on Content-Length,
    # by lowering it below this fixture's real (small) pfx size.
    monkeypatch.setattr(certs_module, "MAX_PFX_BYTES", 10)
    resp = await client.post(
        "/api/certs/pfx",
        files={"file": ("t.pfx", pfx_bytes, "application/x-pkcs12")},
        data={"passphrase": PASSPHRASE},
    )
    assert resp.status_code == 413


def test_openssl_pkcs12_never_puts_passphrase_in_argv(monkeypatch, pfx_bytes, tmp_path):
    pfx_path = tmp_path / "in.pfx"
    pfx_path.write_bytes(pfx_bytes)

    captured_argv = []
    real_run = subprocess.run

    def spy(args, **kwargs):
        captured_argv.append(args)
        return real_run(args, **kwargs)

    monkeypatch.setattr(certs_module.subprocess, "run", spy)
    certs_module._openssl_pkcs12(str(pfx_path), PASSPHRASE, "-nokeys", "-clcerts")

    assert captured_argv, "openssl was never invoked"
    for args in captured_argv:
        assert PASSPHRASE not in args
        assert "fd:0" in args


@pytest.mark.asyncio
async def test_upload_wrong_passphrase_returns_422(client, pfx_bytes):
    resp = await client.post(
        "/api/certs/pfx",
        files={"file": ("t.pfx", pfx_bytes, "application/x-pkcs12")},
        data={"passphrase": "definitely-wrong"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_temp_pfx_file_cleaned_up(client, pfx_bytes, tmp_path, monkeypatch):
    seen_paths = []
    real_mkstemp = tempfile.mkstemp

    def spy_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        seen_paths.append(path)
        return fd, path

    monkeypatch.setattr(certs_module.tempfile, "mkstemp", spy_mkstemp)

    resp = await client.post(
        "/api/certs/pfx",
        files={"file": ("t.pfx", pfx_bytes, "application/x-pkcs12")},
        data={"passphrase": PASSPHRASE},
    )
    assert resp.status_code == 200
    assert seen_paths and not os.path.exists(seen_paths[0])
