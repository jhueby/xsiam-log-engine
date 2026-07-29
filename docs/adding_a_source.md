# Adding a New Log Source

Adding a source requires creating exactly one file. No other files need modification.

## Steps

### 1. Create `engine/sources/my_new_source.py`

```python
from __future__ import annotations

import json
import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource


class MyNewSource(LogSource):
    id = "my_new_source"                           # snake_case, unique
    display_name = "My New Source"                 # shown in GUI
    description = "What this source simulates"
    default_transport: str = "syslog"              # "http" | "syslog" | "wec"
    supported_transports = ["syslog", "http"]      # all valid options
    default_eps = 5.0
    tags = ["network", "vendor"]                   # used for GUI filtering

    async def generate(self) -> LogEvent:
        ts = datetime.now(timezone.utc).isoformat()
        # Build your realistic log message here
        raw = f"<134>{ts} host my-app: sample event data"
        structured = {
            "timestamp": ts,
            "message": "sample event",
            "vendor": "myvendor",
        }
        return LogEvent(
            raw=raw,
            structured=structured,
            format="syslog_rfc5424",
            source_id=self.id,
        )
```

### 2. Restart the engine

```bash
docker compose restart engine
```

The auto-discovery mechanism (`sources/__init__.py`) uses `pkgutil.iter_modules` to find all modules in the `sources/` package and registers any class that:
- Is a subclass of `LogSource`
- Has a non-empty `id` attribute
- Is not the base class itself

The GUI will immediately show the new source card on the Dashboard.

## Available Helpers

All in `utils/faker_helpers.py`:

| Helper | Purpose |
|--------|---------|
| `random_internal_ip()` | Realistic RFC-1918 IP |
| `random_external_ip()` | Random public IP |
| `random_windows_host()` | WIN-XXXXXX hostname |
| `random_linux_host()` | web01.corp.local etc |
| `random_network_device()` | Router/switch/firewall-style hostname |
| `random_user(include_service=False)` | Domain username; set `include_service=True` to include service accounts |
| `random_domain_user()` | Fully-qualified `user@domain` string |
| `random_process_windows()` | Realistic Windows process name |
| `random_process_linux()` | Realistic Linux process name |
| `random_port()` | Random ephemeral port (1024-65535) |
| `random_well_known_port()` | Random port from a common services list (80, 443, 22, …) |
| `random_sid(rid=None)` | Windows SID string, shared domain prefix per engine run |
| `weighted_choice(items, weights)` | Weighted random selection |

## Scenario Support (optional)

A source works standalone with no extra code. To make it usable as a step in an [attack scenario](../README.md#attack-scenarios) — so its events can share a `ScenarioEntities` identity/host with other sources in a correlated story — override `generate_with_entities`:

```python
from sources.base_source import LogEvent, LogSource, ScenarioEntities

class MyNewSource(LogSource):
    ...
    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        overrides = overrides or {}
        # build the event using entities.username / entities.host / entities.internal_ip / etc.,
        # and overrides.get("event_type", <your default>) for any per-step forced field
        ...
```

The base class's default implementation just calls `generate()`, so a source that skips this is still safe to reference in a scenario step — it produces normal, uncorrelated output instead of erroring.

## Transport Format Reference

| `format` value | Description |
|---------------|-------------|
| `syslog_rfc5424` | RFC 5424 `<pri>1 timestamp host app - - - msg` |
| `syslog_rfc3164` | RFC 3164 `<pri>Mon DD HH:MM:SS host prog: msg` |
| `syslog_kv` | Key=value pair syslog (FortiGate-style) |
| `windows_evtx` | Windows Event XML (rendered as JSON for WEC) |
| `json` | Plain JSON for HTTP transport |
| `w3c_elff` | W3C Extended Log File Format (space-delimited) |

## LogEvent Fields

| Field | Type | Required |
|-------|------|---------|
| `raw` | `str` | Yes — the exact bytes sent over the wire |
| `structured` | `dict` | Yes — parsed fields for the log viewer |
| `format` | `str` | Yes — determines how the transport frames it |
| `source_id` | `str` | Yes — must match `self.id` |
| `timestamp` | `datetime` | Auto-set to now if omitted |
