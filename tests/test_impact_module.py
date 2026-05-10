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
        ("inhibit_system_recovery", "T1490"),
        ("disk_structure_wipe", "T1561.002"),
        ("internal_defacement", "T1491.001"),
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


def test_inhibit_system_recovery_pins_vssadmin_shadow_delete(
    tmp_path: Path,
) -> None:
    """Inhibit System Recovery (T1490) is THE canonical ransomware
    preparation step on Windows. The catalog must pin a Windows
    process_creation logsource and the ``vssadmin delete shadows``
    substring so a defender writing the rule catches the textbook
    LockBit / BlackCat / Conti / Royal pre-encryption sequence.
    """

    mod = ImpactModule()
    result = mod.execute(
        {"technique": "inhibit_system_recovery", "target": "fileserver-03"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1490"]
    assert result.artifacts["technique"] == "inhibit_system_recovery"
    logsource = result.detection_hints["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "process_creation"
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    assert selection_value == "vssadmin delete shadows"
    event = result.telemetry[0]
    assert event.event_type == "impact_inhibit_system_recovery"


def test_disk_structure_wipe_pins_physical_drive_substring(
    tmp_path: Path,
) -> None:
    """Disk Structure Wipe (T1561.002) is the canonical wiper-malware
    end-state. The catalog must pin a Windows process_creation
    logsource and the ``PhysicalDrive`` substring so a defender
    writing the rule catches Shamoon / NotPetya / CaddyWiper /
    HermeticWiper / IsaacWiper raw-disk write patterns.

    Distinct from data_destruction (T1485, bulk file deletion) by
    MITRE id and by the targeted resource (boot disk vs file content).
    """

    mod = ImpactModule()
    result = mod.execute(
        {"technique": "disk_structure_wipe", "target": "domain-controller-01"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1561.002"]
    assert result.artifacts["technique"] == "disk_structure_wipe"
    logsource = result.detection_hints["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "process_creation"
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    assert selection_value == "PhysicalDrive"
    # MITRE-id distinct from the bulk-delete data_destruction profile.
    assert result.detection_hints["mitre_technique"] != "T1485"
    event = result.telemetry[0]
    assert event.event_type == "impact_disk_structure_wipe"


def test_internal_defacement_pins_ransom_note_filename_marker(
    tmp_path: Path,
) -> None:
    """Internal Defacement (T1491.001) is the canonical ransomware
    ransom-note display step. The catalog must pin a file_event
    logsource and the ``ransom`` filename substring so the rule
    catches ``readme.txt`` / ``HOW_TO_DECRYPT.html`` /
    ``RESTORE_FILES_INFO.hta`` style markers.
    """

    mod = ImpactModule()
    result = mod.execute(
        {"technique": "internal_defacement", "target": "fileserver-03"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1491.001"]
    assert result.artifacts["technique"] == "internal_defacement"
    logsource = result.detection_hints["logsource"]
    assert logsource["category"] == "file_event"
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    assert selection_value == "ransom"
    event = result.telemetry[0]
    assert event.event_type == "impact_internal_defacement"


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
