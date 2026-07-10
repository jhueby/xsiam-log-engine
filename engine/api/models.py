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
    http_log_type: str
    http_compression: str
    http_api_key: str  # "***" if set, "" if using global key
    auto_disabled_reason: str | None
    xsiam_dataset: str  # effective dataset (source override or global default)


class SourceConfigPatch(BaseModel):
    eps: float | None = Field(None, ge=0.1, le=10000)
    transport: str | None = None
    enabled: bool | None = None
    http_log_type: Literal["raw", "json", "cef", "leef"] | None = None
    http_compression: Literal["none", "gzip"] | None = None
    http_api_key: str | None = None


class TransportConfig(BaseModel):
    xsiam_url: str
    xsiam_api_key: str
    xsiam_dataset: str
    xsiam_api_url: str
    xsiam_api_key_id: str
    xsiam_api_secret: str  # masked as "***" on GET
    brokervm_host: str
    brokervm_syslog_port: int
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"]
    brokervm_wec_port: int
    wec_subscription_url: str
    tls_client_cert_path: str  # read-only; populated by /api/certs/pfx
    tls_client_key_path: str


class TransportConfigUpdate(BaseModel):
    xsiam_url: str | None = None
    xsiam_api_key: str | None = None
    xsiam_dataset: str | None = None
    xsiam_api_url: str | None = None
    xsiam_api_key_id: str | None = None
    xsiam_api_secret: str | None = None
    brokervm_host: str | None = None
    brokervm_syslog_port: int | None = None
    brokervm_syslog_proto: Literal["udp", "tcp", "tls"] | None = None
    brokervm_wec_port: int | None = None
    wec_subscription_url: str | None = None



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


class CorrelationRuleInfo(BaseModel):
    name: str
    source_id: str | None  # parsed from the [LogSim] prefix; None for unmanaged
    managed: bool
    severity: str = ""
    dataset: str = ""
    xql_query: str = ""
    description: str = ""
    enabled: bool = True


class CorrelationApplyResponse(BaseModel):
    ok: bool
    message: str
    rule: CorrelationRuleInfo


class ValidationCheck(BaseModel):
    name: Literal["configured", "reachable", "authenticated", "correlations_access"]
    ok: bool
    detail: str


class ConfigValidationResponse(BaseModel):
    ok: bool
    checks: list[ValidationCheck]


class ScenarioStepInfo(BaseModel):
    source: str
    delay: float
    jitter: float
    overrides: dict


class ScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    steps: list[ScenarioStepInfo]


class ScenarioEntitiesInfo(BaseModel):
    username: str
    domain_user: str
    host: str
    internal_ip: str
    external_ip: str


class ScenarioStepStatusInfo(BaseModel):
    index: int
    source: str
    delay: float
    jitter: float
    overrides: dict
    status: Literal["pending", "fired", "error"]
    fired_at: str | None
    error: str | None


class ScenarioRunInfo(BaseModel):
    run_id: str
    scenario_id: str
    scenario_name: str
    started_at: str
    status: Literal["running", "completed", "cancelled", "failed"]
    error: str | None
    entities: ScenarioEntitiesInfo
    steps: list[ScenarioStepStatusInfo]
