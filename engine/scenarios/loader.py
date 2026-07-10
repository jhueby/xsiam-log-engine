from __future__ import annotations

from pathlib import Path

import yaml

_DEFINITIONS_DIR = Path(__file__).parent / "definitions"


def load_scenarios() -> dict[str, dict]:
    """Load every *.yaml scenario definition, keyed by its declared id.
    A scenario missing required fields is skipped (logged by the caller via
    the returned dict simply not containing it) rather than crashing engine
    startup over one malformed file.
    """
    scenarios: dict[str, dict] = {}
    if not _DEFINITIONS_DIR.is_dir():
        return scenarios

    for path in sorted(_DEFINITIONS_DIR.glob("*.yaml")):
        with open(path) as f:
            defn = yaml.safe_load(f)
        if not isinstance(defn, dict):
            continue
        if not defn.get("id") or not defn.get("steps"):
            continue
        scenarios[defn["id"]] = defn

    return scenarios
