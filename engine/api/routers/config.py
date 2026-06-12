from __future__ import annotations

from pathlib import Path

from dotenv import set_key
from fastapi import APIRouter

from api.models import TransportConfig, TransportConfigUpdate
from config.settings import settings

router = APIRouter(prefix="/api/config", tags=["config"])

_ENV_FILE = Path(".env")


@router.get("", response_model=TransportConfig)
async def get_config() -> TransportConfig:
    return TransportConfig(
        xsiam_url=settings.xsiam_url,
        xsiam_api_key="***" if settings.xsiam_api_key else "",
        xsiam_dataset=settings.xsiam_dataset,
        brokervm_host=settings.brokervm_host,
        brokervm_syslog_port=settings.brokervm_syslog_port,
        brokervm_syslog_proto=settings.brokervm_syslog_proto,
        brokervm_wec_port=settings.brokervm_wec_port,
        brokervm_wec_use_tls=settings.brokervm_wec_use_tls,
        brokervm_wec_user=settings.brokervm_wec_user,
        brokervm_wec_password="***" if settings.brokervm_wec_password else "",
        tls_ca_cert_path=settings.tls_ca_cert_path,
        tls_client_cert_path=settings.tls_client_cert_path,
        tls_client_key_path=settings.tls_client_key_path,
    )


@router.put("", response_model=TransportConfig)
async def update_config(update: TransportConfigUpdate) -> TransportConfig:
    env_updates: dict[str, str] = {}

    if update.xsiam_url is not None:
        settings.xsiam_url = update.xsiam_url
        env_updates["XSIAM_URL"] = update.xsiam_url
    if update.xsiam_api_key is not None and update.xsiam_api_key != "***":
        settings.xsiam_api_key = update.xsiam_api_key
        env_updates["XSIAM_API_KEY"] = update.xsiam_api_key
    if update.xsiam_dataset is not None:
        settings.xsiam_dataset = update.xsiam_dataset
        env_updates["XSIAM_DATASET"] = update.xsiam_dataset
    if update.brokervm_host is not None:
        settings.brokervm_host = update.brokervm_host
        env_updates["BROKERVM_HOST"] = update.brokervm_host
    if update.brokervm_syslog_port is not None:
        settings.brokervm_syslog_port = update.brokervm_syslog_port
        env_updates["BROKERVM_SYSLOG_PORT"] = str(update.brokervm_syslog_port)
    if update.brokervm_syslog_proto is not None:
        settings.brokervm_syslog_proto = update.brokervm_syslog_proto
        env_updates["BROKERVM_SYSLOG_PROTO"] = update.brokervm_syslog_proto
    if update.brokervm_wec_port is not None:
        settings.brokervm_wec_port = update.brokervm_wec_port
        env_updates["BROKERVM_WEC_PORT"] = str(update.brokervm_wec_port)
    if update.brokervm_wec_use_tls is not None:
        settings.brokervm_wec_use_tls = update.brokervm_wec_use_tls
        env_updates["BROKERVM_WEC_USE_TLS"] = str(update.brokervm_wec_use_tls).lower()
    if update.brokervm_wec_user is not None:
        settings.brokervm_wec_user = update.brokervm_wec_user
        env_updates["BROKERVM_WEC_USER"] = update.brokervm_wec_user
    if update.brokervm_wec_password is not None and update.brokervm_wec_password != "***":
        settings.brokervm_wec_password = update.brokervm_wec_password
        env_updates["BROKERVM_WEC_PASSWORD"] = update.brokervm_wec_password
    if update.tls_ca_cert_path is not None:
        settings.tls_ca_cert_path = update.tls_ca_cert_path
        env_updates["TLS_CA_CERT_PATH"] = update.tls_ca_cert_path
    if update.tls_client_cert_path is not None:
        settings.tls_client_cert_path = update.tls_client_cert_path
        env_updates["TLS_CLIENT_CERT_PATH"] = update.tls_client_cert_path
    if update.tls_client_key_path is not None:
        settings.tls_client_key_path = update.tls_client_key_path
        env_updates["TLS_CLIENT_KEY_PATH"] = update.tls_client_key_path

    if env_updates and _ENV_FILE.exists():
        for env_key, env_val in env_updates.items():
            set_key(str(_ENV_FILE), env_key, env_val)

    from main import get_engine
    engine = get_engine()
    engine._http.reset()
    engine._syslog.reset()
    engine._wec.reset()

    return await get_config()
