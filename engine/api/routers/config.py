from __future__ import annotations

from fastapi import APIRouter

from api.models import TransportConfig, TransportConfigUpdate
from config.settings import settings

router = APIRouter(prefix="/api/config", tags=["config"])


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
        tls_ca_cert_path=settings.tls_ca_cert_path,
        tls_client_cert_path=settings.tls_client_cert_path,
        tls_client_key_path=settings.tls_client_key_path,
    )


@router.put("", response_model=TransportConfig)
async def update_config(update: TransportConfigUpdate) -> TransportConfig:
    # Live reload: mutate the settings singleton and reconnect transports
    if update.xsiam_url is not None:
        settings.xsiam_url = update.xsiam_url
    if update.xsiam_api_key is not None:
        settings.xsiam_api_key = update.xsiam_api_key
    if update.xsiam_dataset is not None:
        settings.xsiam_dataset = update.xsiam_dataset
    if update.brokervm_host is not None:
        settings.brokervm_host = update.brokervm_host
    if update.brokervm_syslog_port is not None:
        settings.brokervm_syslog_port = update.brokervm_syslog_port
    if update.brokervm_syslog_proto is not None:
        settings.brokervm_syslog_proto = update.brokervm_syslog_proto
    if update.brokervm_wec_port is not None:
        settings.brokervm_wec_port = update.brokervm_wec_port
    if update.brokervm_wec_use_tls is not None:
        settings.brokervm_wec_use_tls = update.brokervm_wec_use_tls
    if update.tls_ca_cert_path is not None:
        settings.tls_ca_cert_path = update.tls_ca_cert_path
    if update.tls_client_cert_path is not None:
        settings.tls_client_cert_path = update.tls_client_cert_path
    if update.tls_client_key_path is not None:
        settings.tls_client_key_path = update.tls_client_key_path

    # Force transport reconnection on next send
    from main import get_engine
    engine = get_engine()
    engine._http._client = None
    engine._syslog._tcp_writer = None
    engine._syslog._udp_transport = None
    engine._wec._client = None

    return await get_config()
