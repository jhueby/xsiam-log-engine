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
