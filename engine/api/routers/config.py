from __future__ import annotations

import os
from pathlib import Path

from dotenv import set_key
from fastapi import APIRouter

from api.models import (
    ConfigValidationResponse,
    TransportConfig,
    TransportConfigUpdate,
    ValidationCheck,
)
from config.settings import settings
from utils.logger import get_logger
from xsiam_api import XsiamApiError, xsiam_api_client

router = APIRouter(prefix="/api/config", tags=["config"])
logger = get_logger(__name__)

_ENV_FILE = Path(os.environ.get("ENGINE_ENV_FILE") or str(
    Path(__file__).parent.parent.parent / "config" / ".env"
))


@router.get("", response_model=TransportConfig)
async def get_config() -> TransportConfig:
    return TransportConfig(
        xsiam_url=settings.xsiam_url,
        xsiam_api_key="***" if settings.xsiam_api_key else "",
        xsiam_dataset=settings.xsiam_dataset,
        xsiam_api_url=settings.xsiam_api_url,
        xsiam_api_key_id=settings.xsiam_api_key_id,
        xsiam_api_secret="***" if settings.xsiam_api_secret else "",
        brokervm_host=settings.brokervm_host,
        brokervm_syslog_port=settings.brokervm_syslog_port,
        brokervm_syslog_proto=settings.brokervm_syslog_proto,
        brokervm_wec_port=settings.brokervm_wec_port,
        wec_subscription_url=settings.wec_subscription_url,
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
    if update.xsiam_api_url is not None:
        settings.xsiam_api_url = update.xsiam_api_url
        env_updates["XSIAM_API_URL"] = update.xsiam_api_url
    if update.xsiam_api_key_id is not None:
        settings.xsiam_api_key_id = update.xsiam_api_key_id
        env_updates["XSIAM_API_KEY_ID"] = update.xsiam_api_key_id
    if update.xsiam_api_secret is not None and update.xsiam_api_secret != "***":
        settings.xsiam_api_secret = update.xsiam_api_secret
        env_updates["XSIAM_API_SECRET"] = update.xsiam_api_secret
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
    if update.wec_subscription_url is not None:
        settings.wec_subscription_url = update.wec_subscription_url
        env_updates["WEC_SUBSCRIPTION_URL"] = update.wec_subscription_url

    if env_updates:
        try:
            for env_key, env_val in env_updates.items():
                set_key(str(_ENV_FILE), env_key, env_val)
            logger.info({"event": "config_saved", "path": str(_ENV_FILE), "keys": list(env_updates)})
        except Exception as e:
            logger.warning({"event": "config_save_failed", "path": str(_ENV_FILE), "error": str(e)})

    from main import get_engine
    engine = get_engine()
    engine._http.reset()
    engine._syslog.reset()
    engine._wec.reset()
    xsiam_api_client.reset()

    return await get_config()


@router.post("/validate", response_model=ConfigValidationResponse)
async def validate_config() -> ConfigValidationResponse:
    """Staged probe of the XSIAM Public API settings. Each stage pinpoints a
    different misconfiguration; later stages are skipped once one fails."""
    checks: list[ValidationCheck] = []

    configured = xsiam_api_client.is_configured()
    checks.append(ValidationCheck(
        name="configured",
        ok=configured,
        detail="API URL, key ID, and key are set" if configured
        else "Set the XSIAM API URL, key ID, and key under Configuration",
    ))
    if not configured:
        return ConfigValidationResponse(ok=False, checks=checks)

    try:
        await xsiam_api_client.check_reachable()
        checks.append(ValidationCheck(name="reachable", ok=True, detail=f"{settings.xsiam_api_url} responded"))
    except XsiamApiError as e:
        checks.append(ValidationCheck(name="reachable", ok=False, detail=e.detail))
        return ConfigValidationResponse(ok=False, checks=checks)

    try:
        await xsiam_api_client.probe_incidents()
        checks.append(ValidationCheck(name="authenticated", ok=True, detail="API key and key ID accepted"))
    except XsiamApiError as e:
        detail = "API key or key ID rejected" if e.status in (401, 403) else e.detail
        checks.append(ValidationCheck(name="authenticated", ok=False, detail=detail))
        return ConfigValidationResponse(ok=False, checks=checks)

    try:
        rules = await xsiam_api_client.list_rules()
        checks.append(ValidationCheck(
            name="correlations_access",
            ok=True,
            detail=f"Correlations API accessible ({len(rules)} rules visible)",
        ))
    except XsiamApiError as e:
        detail = (
            "Key is valid but lacks the Instance Administrator role, or the "
            "correlations API feature flag is disabled on this tenant (contact support)."
        ) if e.status in (401, 403) else e.detail
        checks.append(ValidationCheck(name="correlations_access", ok=False, detail=detail))
        return ConfigValidationResponse(ok=False, checks=checks)

    return ConfigValidationResponse(ok=True, checks=checks)
