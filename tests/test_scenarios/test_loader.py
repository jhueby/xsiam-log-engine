import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from scenarios.loader import load_scenarios


def test_loads_shipped_scenario_definitions():
    scenarios = load_scenarios()
    assert "phishing_to_exfiltration" in scenarios
    assert "insider_privilege_escalation" in scenarios


def test_each_scenario_has_valid_steps():
    for scenario_id, defn in load_scenarios().items():
        assert defn["steps"], f"{scenario_id}: no steps"
        for step in defn["steps"]:
            assert "source" in step, f"{scenario_id}: step missing 'source'"
            assert isinstance(step.get("delay", 0), (int, float))


def test_malformed_file_is_skipped(tmp_path, monkeypatch):
    import scenarios.loader as loader_module

    bad_dir = tmp_path / "definitions"
    bad_dir.mkdir()
    (bad_dir / "no_id.yaml").write_text("name: Missing ID\nsteps:\n  - source: okta\n")
    (bad_dir / "no_steps.yaml").write_text("id: no_steps\nname: Missing steps\n")
    (bad_dir / "good.yaml").write_text("id: good\nname: Good\nsteps:\n  - source: okta\n    delay: 0\n")

    monkeypatch.setattr(loader_module, "_DEFINITIONS_DIR", bad_dir)
    result = loader_module.load_scenarios()

    assert list(result.keys()) == ["good"]


def _load_from(tmp_path, monkeypatch, files: dict[str, str]) -> dict:
    import scenarios.loader as loader_module

    d = tmp_path / "definitions"
    d.mkdir()
    for name, body in files.items():
        (d / name).write_text(body)
    monkeypatch.setattr(loader_module, "_DEFINITIONS_DIR", d)
    return loader_module.load_scenarios()


GOOD = "id: good\nname: Good\nsteps:\n  - source: okta\n    delay: 0\n"


def test_yaml_syntax_error_does_not_abort_the_whole_load(tmp_path, monkeypatch):
    """Regression: yaml.safe_load() was uncaught, so one file with a syntax
    error raised straight through ScenarioRunner.__init__ -> Engine.__init__
    and stopped the entire engine from starting -- not just scenarios. The
    valid files in the same directory never got a chance to load."""
    result = _load_from(tmp_path, monkeypatch, {
        "broken.yaml": "id: broken\nsteps:\n  - source: okta\n   bad_indent: [unclosed\n",
        "good.yaml": GOOD,
    })
    assert list(result.keys()) == ["good"]


def test_structurally_invalid_steps_are_skipped(tmp_path, monkeypatch):
    """Regression: the loader only checked that 'steps' was truthy, so a step
    missing 'source' (KeyError) or a non-list 'steps' (TypeError) reached the
    API's _scenario_to_info and 500'd GET /api/scenarios -- hiding every
    scenario, including the valid ones."""
    result = _load_from(tmp_path, monkeypatch, {
        "no_source.yaml": "id: no_source\nsteps:\n  - delay: 0\n",
        "steps_not_list.yaml": 'id: steps_not_list\nsteps: "nope"\n',
        "step_not_mapping.yaml": "id: step_not_mapping\nsteps:\n  - just-a-string\n",
        "bad_overrides.yaml": "id: bad_overrides\nsteps:\n  - source: okta\n    overrides: nope\n",
        "bad_delay.yaml": "id: bad_delay\nsteps:\n  - source: okta\n    delay: soon\n",
        "good.yaml": GOOD,
    })
    assert list(result.keys()) == ["good"]


def test_yml_extension_is_loaded(tmp_path, monkeypatch):
    """Regression: the glob was "*.yaml" only, so a dropped-in .yml file was
    silently ignored -- indistinguishable from it just not working."""
    result = _load_from(tmp_path, monkeypatch, {
        "scenario.yml": "id: from_yml\nname: From yml\nsteps:\n  - source: okta\n",
    })
    assert "from_yml" in result


def test_duplicate_id_keeps_first_deterministically(tmp_path, monkeypatch):
    result = _load_from(tmp_path, monkeypatch, {
        "a_first.yaml": "id: dupe\nname: First\nsteps:\n  - source: okta\n",
        "b_second.yaml": "id: dupe\nname: Second\nsteps:\n  - source: crowdstrike_falcon\n",
    })
    assert list(result.keys()) == ["dupe"]
    assert result["dupe"]["name"] == "First"  # sorted filenames -> first wins


def test_negative_timing_is_clamped(tmp_path, monkeypatch):
    """A negative jitter makes random.uniform(0, jitter) return a negative
    offset, firing the step earlier than its declared delay."""
    result = _load_from(tmp_path, monkeypatch, {
        "neg.yaml": "id: neg\nsteps:\n  - source: okta\n    delay: -5\n    jitter: -2\n",
    })
    step = result["neg"]["steps"][0]
    assert step["delay"] == 0
    assert step["jitter"] == 0


def test_normalized_steps_are_safe_for_downstream_indexing(tmp_path, monkeypatch):
    """Whatever survives the loader must satisfy the assumptions the API and
    runner make, since neither re-validates."""
    result = _load_from(tmp_path, monkeypatch, {"good.yaml": GOOD})
    for defn in result.values():
        assert isinstance(defn["steps"], list) and defn["steps"]
        for step in defn["steps"]:
            assert isinstance(step["source"], str) and step["source"]
            assert isinstance(step["delay"], float)
            assert isinstance(step["jitter"], float)
            assert isinstance(step["overrides"], dict)
