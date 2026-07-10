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

# A PKCS#12 bundle holding one leaf cert + key is a few KB; this leaves
# generous headroom for chains/intermediates while still bounding memory use
# against an oversized or malicious upload.
MAX_PFX_BYTES = 256 * 1024


class PfxUploadResult(BaseModel):
    cert_path: str
    key_path: str
    subject: str
    expires: str


def _write_private(path: Path, data: bytes) -> None:
    """Create/overwrite a file at 0600. For a new file, os.open's mode is
    applied by the OS at creation, so it's never briefly observable at a
    wider (umask-controlled) permission the way write_bytes()-then-chmod()
    would be. os.open's mode argument is silently ignored if the path
    already exists though (POSIX open(2) only honors it on creation), so
    fchmod right after open covers that case too -- before any new data is
    written, not after, keeping the exposure window a single syscall wide
    instead of a full write."""
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
    finally:
        os.close(fd)


async def _read_capped(file: UploadFile, max_bytes: int) -> bytes:
    """Read an upload in chunks, aborting before buffering past max_bytes —
    the declared Content-Length can't be trusted, so this caps actual reads."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Upload exceeds the {max_bytes // 1024} KiB limit for a .pfx certificate bundle",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _openssl_pkcs12(pfx_path: str, passphrase: str, *extra_args: str) -> bytes:
    """Run openssl pkcs12 with the given extra args, trying -legacy first for
    Windows-generated files that use RC2/3DES ciphers (OpenSSL 3.x provider).

    The passphrase is sent over the child's stdin (-passin fd:0) rather than
    as a `pass:...` argv value, which any local user could read off `ps`.
    """
    passin = passphrase.encode() + b"\n"
    for variant in (["-legacy"], []):
        try:
            return subprocess.run(
                ["openssl", "pkcs12", "-in", pfx_path, "-passin", "fd:0", *variant, *extra_args],
                input=passin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
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
    data = await _read_capped(file, MAX_PFX_BYTES)

    # mkstemp() already creates the file at 0600 (owner-only) by default, so
    # no separate chmod is needed here -- one less syscall and one less
    # exception window between creating the fd and closing it.
    fd, tmp_path = tempfile.mkstemp(suffix=".pfx")
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)

        cert_pem = _openssl_pkcs12(tmp_path, passphrase, "-nokeys", "-clcerts")
        key_pem = _openssl_pkcs12(tmp_path, passphrase, "-nocerts", "-nodes")
    finally:
        os.unlink(tmp_path)

    _CERTS_DIR.mkdir(exist_ok=True, mode=0o700)
    os.chmod(_CERTS_DIR, 0o700)  # mkdir's mode is masked by umask; enforce it
    cert_path = _CERTS_DIR / "wec.crt"
    key_path = _CERTS_DIR / "wec.key"

    _write_private(cert_path, cert_pem)
    _write_private(key_path, key_pem)  # private key material

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
