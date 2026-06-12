from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class SourceInfo(BaseModel):
    id: str
    display_name: str
    description: str
    default_transport: str
    supported_transports: list[str]
    default_eps: float
    tags: list[str]
    enabled: bool
    eps: float
    transport: str
    total_sent: int
    total_errors: int
    last_event_ts: str | None


class SourceConfigPatch(BaseModel):
    eps: float | None = Field(None, ge=0.1, le=10000)
    transport: str | None = None
    enabled: bool | None = None


class TransportConfig(BaseModel):
    xsiam_url: str
    xsiam_api_key: str
    xsiam_dataset: str
    brokervm_host: str
    brokervm_syslog_port: int
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"]
    brokervm_wec_port: int
    brokervm_wec_use_tls: bool
    brokervm_wec_user: str
    brokervm_wec_password: str
    tls_ca_cert_path: str
    tls_client_cert_path: str
    tls_client_key_path: str


class TransportConfigUpdate(BaseModel):
    xsiam_url: str | None = None
    xsiam_api_key: str | None = None
    xsiam_dataset: str | None = None
    brokervm_host: str | None = None
    brokervm_syslog_port: int | None = None
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"] | None = None
    brokervm_wec_port: int | None = None
    brokervm_wec_use_tls: bool | None = None
    brokervm_wec_user: str | None = None
    brokervm_wec_password: str | None = None
    tls_ca_cert_path: str | None = None
    tls_client_cert_path: str | None = None
    tls_client_key_path: str | None = None


class StatsResponse(BaseModel):
    total_sent: int
    total_errors: int
    eps_actual: float
    per_transport: dict[str, int]
    active_sources: int
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    transports: dict[str, bool]


class ControlResponse(BaseModel):
    ok: bool
    message: str
