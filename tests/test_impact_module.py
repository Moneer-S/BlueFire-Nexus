"""Focused tests for the standard `impact` module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    ImpactModule,
    _IMPACT_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "impact-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_default_technique_is_data_encryption(tmp_path: Path) -> None:
    mod = ImpactModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1486"]
    assert result.artifacts["technique"] == "data_encryption"
    assert result.detection_hints["mitre_technique"] == "T1486"
    assert result.telemetry[0].event_type == "impact_data_encryption"


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("data_encryption", "T1486"),
        ("data_destruction", "T1485"),
        ("data_manipulation", "T1565"),
        ("service_stop", "T1489"),
        ("service_modify", "T1489"),
        ("service_delete", "T1489"),
        ("system_reboot", "T1529"),
        ("system_shutdown", "T1529"),
        ("endpoint_dos", "T1499"),
        ("resource_hijacking", "T1496"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = ImpactModule()
    result = mod.execute({"technique": technique, "target": "lab-host"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre]
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["impact_technique"] == technique


def test_unknown_technique_falls_back_with_marker(tmp_path: Path) -> None:
    mod = ImpactModule()
    result = mod.execute({"technique": "not_a_thing"}, _ctx(tmp_path))
    assert result.artifacts["technique"] == "data_encryption"
    assert result.techniques == ["T1486"]
    assert result.detection_hints.get("unrecognized_impact_technique") == "not_a_thing"


def test_target_is_recorded(tmp_path: Path) -> None:
    mod = ImpactModule()
    result = mod.execute(
        {"technique": "system_shutdown", "target": "fileserver-03"},
        _ctx(tmp_path),
    )
    assert result.artifacts["target"] == "fileserver-03"
    assert result.detection_hints["target_host"] == "fileserver-03"
    assert "fileserver-03" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    mod = ImpactModule()
    seen: set[str] = set()
    for technique in _IMPACT_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_IMPACT_PROFILES)


def test_logsource_categories_span_file_and_service_and_process(tmp_path: Path) -> None:
    mod = ImpactModule()
    categories: set[str] = set()
    for technique in _IMPACT_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        categories.add(result.detection_hints["logsource"]["category"])
    assert "file_event" in categories
    assert "service_modification" in categories
    assert "process_creation" in categories


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "impact" in modules
    assert isinstance(modules["impact"], ImpactModule)


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {profile["mitre"] for profile in _IMPACT_PROFILES.values()}
    advertised = set(ImpactModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )


def test_destructive_techniques_do_not_actually_destroy(tmp_path: Path) -> None:
    """Even with the most destructive-sounding techniques, no real side effects.

    This is a paranoia-level assertion: registry-wide safety test
    (`test_module_safety.py`) already proves no module touches subprocess /
    socket / requests / urllib in dry-run, but we want a per-technique
    confirmation for the impact module specifically because its names
    would otherwise alarm a casual reader.
    """
    mod = ImpactModule()
    sentinel = tmp_path / "should-not-exist.txt"
    sentinel.write_text("safe-baseline-canary")
    for technique in _IMPACT_PROFILES:
        mod.execute({"technique": technique, "target": "lab-host"}, _ctx(tmp_path))
    # Sentinel file untouched by every impact technique.
    assert sentinel.read_text() == "safe-baseline-canary"
