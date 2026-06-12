from __future__ import annotations

import yaml
from pathlib import Path
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # XSIAM HTTP
    xsiam_url: str = "http://localhost:9999/logs/v1/event"
    xsiam_api_key: str = "changeme"
    xsiam_dataset: str = "xsiam_log_engine"

    # BrokerVM
    brokervm_host: str = "127.0.0.1"
    brokervm_syslog_port: int = 514
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"] = "udp"
    brokervm_wec_port: int = 5985
    brokervm_wec_use_tls: bool = False

    # TLS
    tls_ca_cert_path: str = ""
    tls_client_cert_path: str = ""
    tls_client_key_path: str = ""

    # Engine
    engine_api_port: int = 8080
    engine_default_eps: float = 10.0
    engine_log_level: str = "INFO"


def load_defaults() -> dict:
    defaults_path = Path(__file__).parent / "defaults.yaml"
    if defaults_path.exists():
        with open(defaults_path) as f:
            return yaml.safe_load(f) or {}
    return {}


settings = Settings()
