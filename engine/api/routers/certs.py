from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate
from dotenv import set_key
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from config.settings import settings

router = APIRouter(prefix="/api/certs", tags=["certs"])

_ENV_FILE = Path(os.environ.get("ENGINE_ENV_FILE") or str(
    Path(__file__).parent.parent.parent / "config" / ".env"
))
_CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


class PfxUploadResult(BaseModel):
    cert_path: str
    key_path: str
    subject: str
    expires: str


def _openssl_pkcs12(pfx_path: str, passphrase: str, *extra_args: str) -> bytes:
    """Run openssl pkcs12 with the given extra args, trying -legacy first for
    Windows-generated files that use RC2/3DES ciphers (OpenSSL 3.x provider)."""
    pass_arg = f"pass:{passphrase}"
    for variant in (["-legacy"], []):
        try:
            return subprocess.check_output(
                ["openssl", "pkcs12", "-in", pfx_path, "-passin", pass_arg, *variant, *extra_args],
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            continue
    raise HTTPException(
        status_code=422,
        detail="Failed to parse .pfx — verify the passphrase and that the file is a valid PKCS#12 certificate",
    )


@router.post("/pfx", response_model=PfxUploadResult)
async def upload_pfx(
    file: UploadFile = File(...),
    passphrase: str = Form(""),
) -> PfxUploadResult:
    data = await file.read()

    with tempfile.NamedTemporaryFile(suffix=".pfx", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        cert_pem = _openssl_pkcs12(tmp_path, passphrase, "-nokeys", "-clcerts")
        key_pem = _openssl_pkcs12(tmp_path, passphrase, "-nocerts", "-nodes")
    finally:
        os.unlink(tmp_path)

    _CERTS_DIR.mkdir(exist_ok=True)
    cert_path = _CERTS_DIR / "wec.crt"
    key_path = _CERTS_DIR / "wec.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    try:
        cert = load_pem_x509_certificate(cert_pem)
        subject = cert.subject.rfc4514_string()
        expires = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        subject = "(unknown)"
        expires = "(unknown)"

    settings.tls_client_cert_path = str(cert_path)
    settings.tls_client_key_path = str(key_path)
    try:
        set_key(str(_ENV_FILE), "TLS_CLIENT_CERT_PATH", str(cert_path))
        set_key(str(_ENV_FILE), "TLS_CLIENT_KEY_PATH", str(key_path))
    except Exception:
        pass

    from main import get_engine
    get_engine()._wec.reset()

    return PfxUploadResult(
        cert_path=str(cert_path),
        key_path=str(key_path),
        subject=subject,
        expires=expires,
    )
