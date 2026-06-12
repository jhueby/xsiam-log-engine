from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SourceMeta:
    source_id: str
    source_name: str
    format: str
    transport: str
    hostname: str = ""
    facility: int = 1
    severity: int = 6
    dataset: str = ""
    http_log_type: str = "raw"      # raw | json | cef | leef
    http_compression: str = "none"  # none | gzip
    http_api_key: str = ""          # empty = use global settings.xsiam_api_key


@dataclass
class SendResult:
    success: bool
    bytes_sent: int = 0
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Transport(ABC):
    @abstractmethod
    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult: ...

    @abstractmethod
    async def health_check(self) -> bool: ...

    async def close(self) -> None:
        pass
