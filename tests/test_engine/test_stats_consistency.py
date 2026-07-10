"""Regression test: scenario-fired events on a disabled source must still
reconcile in get_stats() -- total_sent and per_transport are both lifetime
counters and must always agree, regardless of a source's current enabled
state. (Previously per_transport was gated by `if s.enabled`, so a
scenario firing on a never-started source inflated total_sent without
per_transport following, breaking the Dashboard's own arithmetic.)
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from main import get_engine
from sources.base_source import ScenarioEntities
from transports.base import SendResult

ENTITIES = ScenarioEntities(
    username="jsmith",
    domain_user="jsmith@corp.local",
    host="WIN-TESTHOST",
    internal_ip="10.10.5.5",
    external_ip="203.0.113.9",
)


def _stats_reconcile(stats: dict) -> bool:
    return stats["total_sent"] == sum(stats["per_transport"].values())


@pytest.mark.asyncio
async def test_stats_reconcile_before_and_after_scenario_fire_on_disabled_source(monkeypatch):
    engine = get_engine()
    source_id = "okta"
    state = engine.sources[source_id]

    if state.enabled:
        await engine.stop_source(source_id)
    assert not state.enabled

    async def fake_send(payload, meta):
        return SendResult(success=True, bytes_sent=len(payload))

    monkeypatch.setattr(engine.get_transport(state.transport_name), "send", fake_send)

    before = engine.get_stats()
    assert _stats_reconcile(before)

    delivered = await engine.fire_scenario_event(source_id, ENTITIES, {"event_type": "user.session.start"})
    assert delivered is True

    after = engine.get_stats()
    assert _stats_reconcile(after), (
        f"total_sent ({after['total_sent']}) must equal sum(per_transport) "
        f"({sum(after['per_transport'].values())}) even though '{source_id}' is disabled"
    )
    assert after["total_sent"] == before["total_sent"] + 1
    assert not state.enabled  # firing a scenario event must not flip enabled state
