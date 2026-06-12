from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


@dataclass
class LogEvent:
    raw: str
    structured: dict
    format: str
    source_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


TransportName = Literal["http", "syslog", "wec"]


class LogSource(ABC):
    id: str
    display_name: str
    description: str
    default_transport: TransportName
    supported_transports: list[TransportName]
    default_eps: float
    tags: list[str]

    @abstractmethod
    async def generate(self) -> LogEvent: ...

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "description": self.description,
            "default_transport": self.default_transport,
            "supported_transports": self.supported_transports,
            "default_eps": self.default_eps,
            "tags": self.tags,
        }
