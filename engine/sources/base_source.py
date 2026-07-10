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


@dataclass(frozen=True)
class ScenarioEntities:
    """A shared identity/host resolved once per scenario run, so every step
    that opts in produces events about the same person/machine."""
    username: str       # bare form, e.g. "jsmith"
    domain_user: str     # e.g. "jsmith@corp.local"
    host: str
    internal_ip: str
    external_ip: str


TransportName = Literal["http", "syslog", "wec"]


class LogSource(ABC):
    id: str
    display_name: str
    description: str
    default_transport: TransportName
    supported_transports: list[TransportName]
    default_eps: float
    tags: list[str]
    syslog_facility: int = 1   # RFC 5424 facility for non-pre-framed syslog sources
    syslog_severity: int = 6   # RFC 5424 severity for non-pre-framed syslog sources
    xsiam_dataset: str = ""    # XSIAM dataset name; empty falls back to settings.xsiam_dataset

    @abstractmethod
    async def generate(self) -> LogEvent: ...

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario-mode generation: substitute a shared identity/host/IP so
        events from different sources tell one correlated story. Default
        implementation ignores entities/overrides and falls back to normal
        random generation — only sources that opt in produce correlated
        output; every other source is safe to use in a scenario as-is.
        """
        return await self.generate()

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
