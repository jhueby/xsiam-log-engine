from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization import pkcs12
from dotenv import set_key
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from config.settings import settings

router = APIRouter(prefix="/api/certs", tags=["certs"])

_ENV_FILE = Path(".env")
_CERTS_DIR = Path("certs")


class PfxUploadResult(BaseModel):
    cert_path: str
    key_path: str
    subject: str
    expires: str


@router.post("/pfx", response_model=PfxUploadResult)
async def upload_pfx(
    file: UploadFile = File(...),
    passphrase: str = Form(""),
) -> PfxUploadResult:
    data = await file.read()
    passphrase_bytes = passphrase.encode() if passphrase else None

    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(data, passphrase_bytes)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse .pfx: {e}")

    if certificate is None:
        raise HTTPException(status_code=422, detail="No certificate found in .pfx")
    if private_key is None:
        raise HTTPException(status_code=422, detail="No private key found in .pfx")

    _CERTS_DIR.mkdir(exist_ok=True)
    cert_path = _CERTS_DIR / "wec.crt"
    key_path = _CERTS_DIR / "wec.key"

    cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )

    settings.tls_client_cert_path = str(cert_path)
    settings.tls_client_key_path = str(key_path)
    if _ENV_FILE.exists():
        set_key(str(_ENV_FILE), "TLS_CLIENT_CERT_PATH", str(cert_path))
        set_key(str(_ENV_FILE), "TLS_CLIENT_KEY_PATH", str(key_path))

    from main import get_engine
    get_engine()._wec.reset()

    subject = certificate.subject.rfc4514_string()
    expires = certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")

    return PfxUploadResult(
        cert_path=str(cert_path),
        key_path=str(key_path),
        subject=subject,
        expires=expires,
    )
