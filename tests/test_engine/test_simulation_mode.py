"""Simulation mode: divert every source to a parallel *_sim_raw dataset so the
real vendor datasets are left untouched.

The toggle has to move the Cribl vendor/product headers too -- those are what
actually select the destination dataset, so changing only the engine's own
dataset name would relabel without redirecting anything.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))

from config.settings import settings
from sources import get_registry
from transports.base import SourceMeta
from transports.http_transport import HTTPTransport
from utils.vendor_map import base_vendor_product, effective_dataset, vendor_product


@pytest.fixture
def sim(monkeypatch):
    """Enable simulation mode for one test without leaking into others."""
    def _enable(suffix="sim"):
        monkeypatch.setattr(settings, "simulation_mode", True)
        monkeypatch.setattr(settings, "simulation_suffix", suffix)
    return _enable


def test_off_by_default_targets_canonical_datasets():
    reg = get_registry()
    assert effective_dataset(reg["okta"]) == "okta_sso_raw"
    assert effective_dataset(reg["windows_security"]) == "microsoft_windows_raw"


def test_on_diverts_every_source(sim):
    sim()
    reg = get_registry()
    assert effective_dataset(reg["okta"]) == "okta_sso_sim_raw"
    assert effective_dataset(reg["windows_security"]) == "microsoft_windows_sim_raw"
    assert effective_dataset(reg["aws_cloudtrail"]) == "amazon_aws_sim_raw"


def test_no_source_still_points_at_a_real_dataset(sim):
    """The whole point is leaving originals untouched, so nothing may resolve
    to a canonical name while the toggle is on."""
    sim()
    reg = get_registry()
    canonical = {f"{v}_{p}_raw" for v, p in
                 (base_vendor_product(sid) for sid in reg)}
    for sid, source in reg.items():
        assert effective_dataset(source) not in canonical, f"{sid} leaked into a real dataset"


def test_cribl_headers_follow_the_toggle(sim):
    """Relabelling the engine's dataset without moving vendor/product would
    leave Cribl still delivering into the real dataset."""
    meta = SourceMeta(source_id="okta", source_name="Okta", format="json",
                      transport="http", http_log_type="json", cribl_emulation=True)
    assert HTTPTransport()._build_headers(meta)["product"] == "sso"

    sim()
    assert HTTPTransport()._build_headers(meta)["product"] == "sso_sim"
    assert HTTPTransport()._build_headers(meta)["vendor"] == "okta"  # vendor unchanged


def test_custom_suffix_is_honoured(sim):
    sim(suffix="demo")
    assert effective_dataset(get_registry()["okta"]) == "okta_sso_demo_raw"
    assert vendor_product("okta") == ("okta", "sso_demo")


def test_suffix_is_not_applied_twice(sim):
    """Reading config back and re-applying must not compound the suffix."""
    sim()
    assert vendor_product("okta") == ("okta", "sso_sim")
    assert vendor_product("okta") == ("okta", "sso_sim")


def test_per_source_override_is_diverted_too(sim):
    """A source that pins its own dataset must still be redirected, or the
    toggle silently leaks that one source into a real dataset."""
    class Pinned:
        id = "custom_thing"
        xsiam_dataset = "vendor_product_raw"

    assert effective_dataset(Pinned()) == "vendor_product_raw"
    sim()
    assert effective_dataset(Pinned()) == "vendor_product_sim_raw"


def test_override_without_raw_suffix_still_diverted(sim):
    class Pinned:
        id = "custom_thing"
        xsiam_dataset = "legacy_dataset"

    sim()
    assert effective_dataset(Pinned()) == "legacy_dataset_sim"
