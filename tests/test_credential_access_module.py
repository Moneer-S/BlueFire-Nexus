"""Focused tests for the standard `credential_access` module.

Registry-wide contract / safety / artifact-path tests cover this module
structurally (it is parametrized into them via the entry in
`tests/test_module_contract._MINIMAL_PARAMS`). These tests cover the
per-technique fan-out behaviour: each technique value produces a distinct
MITRE technique, telemetry event_type, logsource, and detection selection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    CredentialAccessModule,
    _CREDENTIAL_ACCESS_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "credential-access-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_default_technique_is_lsass_dump(tmp_path: Path) -> None:
    """No `technique` -> falls back to lsass_dump (T1003.001)."""
    mod = CredentialAccessModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1003.001"]
    assert result.artifacts["technique"] == "lsass_dump"
    assert result.detection_hints["mitre_technique"] == "T1003.001"
    assert result.telemetry[0].event_type == "credential_access_lsass_dump"


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("lsass_dump", "T1003.001"),
        ("sam_dump", "T1003.002"),
        ("ntds_dump", "T1003.003"),
        ("browser_credentials", "T1555.003"),
        ("keychain", "T1555.001"),
        ("ssh_keys", "T1552.004"),
        ("keylogging", "T1056.001"),
        ("clipboard", "T1115"),
        ("screen_capture", "T1113"),
        ("dpapi_master_key", "T1555.004"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    """Each catalog entry maps to the correct MITRE sub-technique."""
    mod = CredentialAccessModule()
    result = mod.execute(
        {"technique": technique, "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.techniques == [expected_mitre], (
        f"{technique} should emit {expected_mitre}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["credential_technique"] == technique
    assert result.artifacts["mitre_technique"] == expected_mitre


def test_dpapi_master_key_pins_protect_directory_file_event(
    tmp_path: Path,
) -> None:
    """DPAPI master-key extraction (T1555.004) is the canonical
    Windows credential-store unwrap path. Defenders alert on file
    reads of ``%APPDATA%\\Microsoft\\Protect\\<SID>\\``; the catalog
    must pin that path fragment so the detection draft fires.

    Distinct from ``lsass_dump`` (in-memory MasterKeys via LSASS) -
    the file-based path persists across reboots and surfaces in
    file_event telemetry rather than process_access.
    """

    mod = CredentialAccessModule()
    result = mod.execute(
        {"technique": "dpapi_master_key", "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.status == "success"
    assert result.techniques == ["T1555.004"]
    assert result.artifacts["technique"] == "dpapi_master_key"
    # Detection hint targets file_event of the Protect directory.
    detection = result.detection_hints["detection"]
    assert "file_event" in str(result.detection_hints["logsource"]).lower() or (
        "file" in str(result.detection_hints["logsource"]).lower()
    )
    selection_value = next(iter(detection["selection"].values()))
    assert "Protect" in selection_value
    # Telemetry event type carries the technique-specific marker.
    event = result.telemetry[0]
    assert event.event_type == "credential_access_dpapi_master_key"


def test_unknown_technique_falls_back_with_marker(tmp_path: Path) -> None:
    """An unrecognized `technique` falls back to lsass_dump and is recorded."""
    mod = CredentialAccessModule()
    result = mod.execute(
        {"technique": "definitely_not_a_real_technique"}, _ctx(tmp_path)
    )
    assert result.artifacts["technique"] == "lsass_dump"
    assert result.techniques == ["T1003.001"]
    assert (
        result.detection_hints.get("unrecognized_credential_technique")
        == "definitely_not_a_real_technique"
    )


def test_target_is_recorded_everywhere(tmp_path: Path) -> None:
    """`target` lands in artifacts, telemetry details, and hint text."""
    mod = CredentialAccessModule()
    result = mod.execute(
        {"technique": "browser_credentials", "target": "finance-laptop-07"},
        _ctx(tmp_path),
    )
    assert result.artifacts["target"] == "finance-laptop-07"
    assert result.telemetry[0].details["target"] == "finance-laptop-07"
    assert result.detection_hints["target_host"] == "finance-laptop-07"
    assert "finance-laptop-07" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    """Detection-pipeline consumers can fan out on event_type."""
    mod = CredentialAccessModule()
    seen: set[str] = set()
    for technique in _CREDENTIAL_ACCESS_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_CREDENTIAL_ACCESS_PROFILES), (
        f"Expected {len(_CREDENTIAL_ACCESS_PROFILES)} distinct event types, got {len(seen)}"
    )


def test_logsource_varies_by_technique_category(tmp_path: Path) -> None:
    """Process / registry / file-event categories all appear across the catalog."""
    mod = CredentialAccessModule()
    categories: set[str] = set()
    for technique in _CREDENTIAL_ACCESS_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        categories.add(result.detection_hints["logsource"]["category"])
    # The catalog spans process_access, registry_event, file_event, and process_creation.
    assert "process_access" in categories
    assert "registry_event" in categories
    assert "file_event" in categories
    assert "process_creation" in categories


def test_detection_selection_uses_profile_field_and_value(tmp_path: Path) -> None:
    """Detection draft selection identifies the technique."""
    mod = CredentialAccessModule()
    result = mod.execute({"technique": "ntds_dump"}, _ctx(tmp_path))
    selection = result.detection_hints["detection"]["selection"]
    # NTDS profile uses file.path|contains -> NTDS.dit
    assert selection.get("file.path|contains") == "NTDS.dit"


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "credential_access" in modules
    assert isinstance(modules["credential_access"], CredentialAccessModule)


def test_module_advertises_all_catalog_techniques_in_attack_techniques() -> None:
    """Class attribute should mirror the catalog so registry consumers can introspect."""
    expected = {profile["mitre"] for profile in _CREDENTIAL_ACCESS_PROFILES.values()}
    advertised = set(CredentialAccessModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Class attack_techniques missing entries: {expected - advertised}"
    )
