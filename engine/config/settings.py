from __future__ import annotations

import os
import yaml
from pathlib import Path
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ENGINE_ENV_FILE lets Docker point to /app/data/.env (named volume with only
# data files, never code) so rebuilds don't get shadowed by a stale volume.
# Local dev falls back to config/.env next to this file.
ENV_FILE = Path(os.environ.get("ENGINE_ENV_FILE") or str(Path(__file__).parent / ".env"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # XSIAM HTTP Log Collector
    xsiam_url: str = "http://localhost:9999/logs/v1/event"
    xsiam_api_key: str = "changeme"
    xsiam_dataset: str = "xsiam_log_engine"

    # BrokerVM
    brokervm_host: str = "127.0.0.1"
    brokervm_syslog_port: int = 514
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"] = "udp"
    brokervm_wec_port: int = 5985

    # TLS
    tls_ca_cert_path: str = ""
    tls_client_cert_path: str = ""
    tls_client_key_path: str = ""

    # Engine
    engine_api_port: int = 8080
    engine_default_eps: float = 10.0
    engine_log_level: str = "INFO"
    engine_api_token: str = ""  # when set, all /api/* requests must present it


def load_defaults() -> dict:
    defaults_path = Path(__file__).parent / "defaults.yaml"
    if defaults_path.exists():
        with open(defaults_path) as f:
            return yaml.safe_load(f) or {}
    return {}


settings = Settings()
