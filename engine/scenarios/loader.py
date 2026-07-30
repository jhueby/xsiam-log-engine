from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from utils.logger import get_logger

logger = get_logger(__name__)

_DEFINITIONS_DIR = Path(__file__).parent / "definitions"

# Both spellings are accepted -- globbing only "*.yaml" silently ignored a
# dropped-in "*.yml", which looks identical to the file simply not working.
_PATTERNS = ("*.yaml", "*.yml")


def _validate_steps(scenario_id: str, raw_steps: Any) -> list[dict] | None:
    """Return normalized steps, or None if the definition is unusable.

    Everything downstream (the API's _scenario_to_info, ScenarioRunner.start)
    indexes steps directly -- step["source"], float(step["delay"]) -- so a
    structurally-broken step that gets past this function doesn't fail
    locally, it 500s GET /api/scenarios and takes *every* scenario off the
    page with it. Validation therefore happens once, here, and callers can
    treat whatever comes back as well-formed.
    """
    if not isinstance(raw_steps, list) or not raw_steps:
        logger.error({"event": "scenario_invalid", "scenario": scenario_id,
                      "reason": "'steps' must be a non-empty list"})
        return None

    steps: list[dict] = []
    for i, step in enumerate(raw_steps):
        if not isinstance(step, dict):
            logger.error({"event": "scenario_invalid", "scenario": scenario_id,
                          "reason": f"step {i} is not a mapping"})
            return None

        source = step.get("source")
        if not isinstance(source, str) or not source:
            logger.error({"event": "scenario_invalid", "scenario": scenario_id,
                          "reason": f"step {i} is missing a non-empty 'source'"})
            return None

        try:
            delay = float(step.get("delay", 0))
            jitter = float(step.get("jitter", 0))
        except (TypeError, ValueError):
            logger.error({"event": "scenario_invalid", "scenario": scenario_id,
                          "reason": f"step {i} has a non-numeric delay/jitter"})
            return None

        # Negative values aren't fatal but are always a mistake: a negative
        # jitter makes random.uniform(0, jitter) return a negative offset, so
        # the step fires earlier than its declared delay rather than later.
        if delay < 0 or jitter < 0:
            logger.warning({"event": "scenario_negative_timing", "scenario": scenario_id,
                            "step": i, "delay": delay, "jitter": jitter,
                            "action": "clamped to 0"})
            delay = max(delay, 0.0)
            jitter = max(jitter, 0.0)

        overrides = step.get("overrides") or {}
        if not isinstance(overrides, dict):
            logger.error({"event": "scenario_invalid", "scenario": scenario_id,
                          "reason": f"step {i} has non-mapping 'overrides'"})
            return None

        steps.append({"source": source, "delay": delay, "jitter": jitter, "overrides": overrides})

    # Delays are absolute offsets from scenario start, so an out-of-order
    # list doesn't reorder itself -- the runner just finds the deadline
    # already passed and fires immediately. Legal, but almost always a typo.
    if any(b["delay"] < a["delay"] for a, b in zip(steps, steps[1:])):
        logger.warning({"event": "scenario_delays_out_of_order", "scenario": scenario_id,
                        "hint": "delays are absolute offsets from scenario start; "
                                "a step earlier than its predecessor fires immediately"})

    return steps


def load_scenarios() -> dict[str, dict]:
    """Load every *.yaml / *.yml scenario definition, keyed by its declared id.

    A file that is unreadable, isn't valid YAML, or doesn't describe a
    well-formed scenario is skipped with an explanatory log line rather than
    taking anything else down with it. That isolation matters more than it
    looks: this runs from ScenarioRunner.__init__ -> Engine.__init__, so an
    uncaught parse error here doesn't just break scenarios, it stops the
    whole engine from starting.
    """
    scenarios: dict[str, dict] = {}
    if not _DEFINITIONS_DIR.is_dir():
        return scenarios

    paths = sorted(p for pattern in _PATTERNS for p in _DEFINITIONS_DIR.glob(pattern))
    for path in paths:
        try:
            with open(path) as f:
                defn = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            logger.error({"event": "scenario_parse_failed", "file": path.name,
                          "error": str(exc).replace("\n", " ")[:200]})
            continue
        except OSError as exc:
            logger.error({"event": "scenario_read_failed", "file": path.name, "error": str(exc)})
            continue

        if not isinstance(defn, dict):
            logger.error({"event": "scenario_invalid", "file": path.name,
                          "reason": "top level is not a mapping"})
            continue

        scenario_id = defn.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            logger.error({"event": "scenario_invalid", "file": path.name,
                          "reason": "missing a non-empty 'id'"})
            continue

        steps = _validate_steps(scenario_id, defn.get("steps"))
        if steps is None:
            continue

        if scenario_id in scenarios:
            # Deterministic because paths are sorted; warn rather than let a
            # copy-pasted id silently shadow an existing scenario.
            logger.warning({"event": "scenario_duplicate_id", "scenario": scenario_id,
                            "file": path.name, "action": "keeping the first definition"})
            continue

        scenarios[scenario_id] = {**defn, "id": scenario_id, "steps": steps}

    return scenarios
