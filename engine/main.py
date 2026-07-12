from __future__ import annotations

import asyncio
import json
import signal
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from config.settings import settings, load_defaults
from scenarios.runner import ScenarioRunner
from sources import get_registry
from sources.base_source import LogSource, LogEvent, ScenarioEntities
from transports.http_transport import HTTPTransport
from transports.syslog_transport import SyslogTransport
from transports.wec_transport import WECTransport
from transports.base import Transport, SourceMeta
from utils.logger import get_logger
from utils.rate_limiter import SlidingWindowCounter, TokenBucket

logger = get_logger(__name__, settings.engine_log_level)

LOG_RING_SIZE = 500


_MAX_CONSECUTIVE_ERRORS = 5


class SourceState:
    def __init__(self, source: LogSource, eps: float, transport_name: str) -> None:
        self.source = source
        self.eps = eps
        self.transport_name = transport_name
        self.enabled = False
        self.bucket = TokenBucket(eps)
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

        # Stats
        self.total_sent = 0
        self.total_errors = 0
        self.last_event_ts: str | None = None
        self.start_time: float | None = None
        self.eps_window = SlidingWindowCounter()

        # Per-source HTTP collector settings
        self.http_log_type: str = "raw"
        self.http_compression: str = "none"
        self.http_api_key: str = ""

        # Cribl Stream metadata emulation (opt-in, default off)
        self.cribl_emulation: bool = False
        self.cribl_pipe_name: str = ""
        self.cribl_host_name: str = ""

        # Circuit-breaker reason; set when auto-disabled, cleared on manual start
        self.auto_disabled_reason: str | None = None

    def set_eps(self, eps: float) -> None:
        self.eps = eps
        self.bucket.set_rate(eps)

    def set_transport(self, name: str) -> None:
        self.transport_name = name


class Engine:
    def __init__(self) -> None:
        self._http = HTTPTransport()
        self._syslog = SyslogTransport()
        self._wec = WECTransport()
        self._transports: dict[str, Transport] = {
            "http": self._http,
            "syslog": self._syslog,
            "wec": self._wec,
        }

        defaults = load_defaults().get("sources", {})
        registry = get_registry()
        self.sources: dict[str, SourceState] = {}

        for sid, source in registry.items():
            cfg = defaults.get(sid, {})
            eps = cfg.get("eps", source.default_eps)
            transport = cfg.get("transport", source.default_transport)
            state = SourceState(source, eps, transport)
            if cfg.get("enabled", False):
                state.enabled = True
            self.sources[sid] = state

        self._log_ring: deque[dict] = deque(maxlen=LOG_RING_SIZE)
        self._running = False
        self.scenarios = ScenarioRunner(self)

    def get_transport(self, name: str) -> Transport:
        return self._transports[name]

    async def start_source(self, source_id: str) -> None:
        state = self.sources.get(source_id)
        if not state:
            return
        async with state._lock:
            if state.enabled:
                return
            state.enabled = True
            state.auto_disabled_reason = None
            state._stop_event.clear()
            state._task = asyncio.create_task(self._run_source(state))
        logger.info({"event": "source_started", "source": source_id})

    async def stop_source(self, source_id: str) -> None:
        state = self.sources.get(source_id)
        if not state:
            return
        async with state._lock:
            if not state.enabled:
                return
            state.enabled = False
            state._stop_event.set()
            task = state._task
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.info({"event": "source_stopped", "source": source_id})

    async def _send_and_record(self, state: SourceState, event: LogEvent) -> bool:
        """Send one already-generated event through a source's configured
        transport and record it into stats/log ring. Shared by the normal
        per-EPS loop and scenario-triggered firing so both paths show up
        identically in the Dashboard, Log Viewer, and per-source stats."""
        transport = self.get_transport(state.transport_name)
        meta = SourceMeta(
            source_id=state.source.id,
            source_name=state.source.display_name,
            format=event.format,
            transport=state.transport_name,
            hostname=(
                event.structured.get("device")
                or event.structured.get("host")
                or ""
            ),
            facility=getattr(state.source, "syslog_facility", 1),
            severity=getattr(state.source, "syslog_severity", 6),
            dataset=getattr(state.source, "xsiam_dataset", "") or "",
            http_log_type=state.http_log_type,
            http_compression=state.http_compression,
            http_api_key=state.http_api_key,
            cribl_emulation=state.cribl_emulation,
            cribl_pipe_name=state.cribl_pipe_name,
            cribl_host_name=state.cribl_host_name,
        )
        result = await transport.send(event.raw, meta)

        now_ts = datetime.now(timezone.utc).isoformat()
        state.last_event_ts = now_ts

        log_entry = {
            "source_id": state.source.id,
            "timestamp": now_ts,
            "transport": state.transport_name,
            "format": event.format,
            "raw": event.raw[:500],
            "success": result.success,
        }

        if result.success:
            state.total_sent += 1
            state.eps_window.increment()
        else:
            state.total_errors += 1
            log_entry["error"] = result.error

        self._log_ring.append(log_entry)
        return result.success

    async def fire_scenario_event(
        self, source_id: str, entities: ScenarioEntities, overrides: dict | None = None
    ) -> bool:
        """Generate and send one correlated scenario event for a source,
        independent of whether that source is currently enabled/running its
        own EPS loop. Raises KeyError for an unknown source_id."""
        state = self.sources[source_id]
        event = await state.source.generate_with_entities(entities, overrides)
        return await self._send_and_record(state, event)

    async def _run_source(self, state: SourceState) -> None:
        state.start_time = time.monotonic()
        consecutive_errors = 0
        while not state._stop_event.is_set():
            await state.bucket.acquire()
            if state._stop_event.is_set():
                break
            try:
                event: LogEvent = await state.source.generate()
                await self._send_and_record(state, event)
                consecutive_errors = 0

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state.total_errors += 1
                consecutive_errors += 1
                logger.error({"event": "generate_error", "source": state.source.id, "error": str(exc)})
                if consecutive_errors >= _MAX_CONSECUTIVE_ERRORS:
                    reason = f"{_MAX_CONSECUTIVE_ERRORS} consecutive errors"
                    logger.error({
                        "event": "source_auto_disabled",
                        "source": state.source.id,
                        "reason": reason,
                    })
                    state.enabled = False
                    state.auto_disabled_reason = reason
                    state._task = None
                    break

    async def start_all(self) -> None:
        for sid in self.sources:
            await self.start_source(sid)

    async def stop_all(self) -> None:
        tasks = [self.stop_source(sid) for sid in self.sources]
        await asyncio.gather(*tasks)

    def get_stats(self) -> dict:
        total_sent = sum(s.total_sent for s in self.sources.values())
        total_errors = sum(s.total_errors for s in self.sources.values())
        # Unconditional, mirroring total_sent above: both are lifetime counters,
        # not "currently active" breakdowns. A source can accrue total_sent via
        # a scenario firing even while disabled, and per_transport must still
        # reconcile with total_sent when that happens.
        per_transport: dict[str, int] = {"http": 0, "syslog": 0, "wec": 0}
        for s in self.sources.values():
            per_transport[s.transport_name] = per_transport.get(s.transport_name, 0) + s.total_sent

        eps_actual = sum(s.eps_window.rate() for s in self.sources.values())

        return {
            "total_sent": total_sent,
            "total_errors": total_errors,
            "eps_actual": round(eps_actual, 2),
            "per_transport": per_transport,
            "active_sources": sum(1 for s in self.sources.values() if s.enabled),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_source_stats(self) -> list[dict]:
        result = []
        for sid, state in self.sources.items():
            result.append({
                "id": sid,
                "enabled": state.enabled,
                "eps_configured": state.eps,
                "eps_actual": round(state.eps_window.rate(), 2),
                "total_sent": state.total_sent,
                "total_errors": state.total_errors,
                "last_event_ts": state.last_event_ts,
                "transport": state.transport_name,
            })
        return result

    def get_recent_logs(self, limit: int = 100) -> list[dict]:
        logs = list(self._log_ring)
        return logs[-limit:]

    async def health(self) -> dict:
        results = {}
        for name, transport in self._transports.items():
            try:
                results[name] = await asyncio.wait_for(transport.health_check(), timeout=5.0)
            except Exception:
                results[name] = False
        return results

    async def close(self) -> None:
        await self.scenarios.cancel_all()
        await self.stop_all()
        for transport in self._transports.values():
            await transport.close()


_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = Engine()
    return _engine


async def main() -> None:
    engine = get_engine()
    logger.info({"event": "engine_start", "sources_loaded": len(engine.sources)})

    loop = asyncio.get_event_loop()

    def handle_sigterm() -> None:
        logger.info({"event": "sigterm_received"})
        asyncio.create_task(engine.close())

    loop.add_signal_handler(signal.SIGTERM, handle_sigterm)
    loop.add_signal_handler(signal.SIGHUP, lambda: logger.info({"event": "sighup_received"}))

    # Start sources that are enabled by default
    for sid, state in engine.sources.items():
        if state.enabled:
            await engine.start_source(sid)

    # Keep alive — the FastAPI app drives the event loop
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await engine.close()


if __name__ == "__main__":
    asyncio.run(main())
