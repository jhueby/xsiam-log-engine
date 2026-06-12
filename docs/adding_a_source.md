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

| Helper | Location | Purpose |
|--------|----------|---------|
| `random_internal_ip()` | `utils/faker_helpers.py` | Realistic RFC-1918 IP |
| `random_external_ip()` | `utils/faker_helpers.py` | Random public IP |
| `random_windows_host()` | `utils/faker_helpers.py` | WIN-XXXXXX hostname |
| `random_linux_host()` | `utils/faker_helpers.py` | web01.corp.local etc |
| `random_user()` | `utils/faker_helpers.py` | Domain username |
| `weighted_choice(items, weights)` | `utils/faker_helpers.py` | Weighted random selection |

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
