"""Focused tests for the standard ``defense_evasion`` module.

Per-technique fan-out covers the catalog: each technique value
produces a distinct MITRE technique, telemetry event_type, logsource,
and detection selection. Pinned specifically on the recently added
profiles (``debugger_evasion`` T1622, ``encrypted_encoded_file``
T1027.013) so a regression that drops one of these techniques
surfaces immediately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    DefenseEvasionModule,
    _DEFENSE_EVASION_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "defense-evasion-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("argument_spoofing", "T1564.010"),
        ("masquerading", "T1036"),
        ("timestomping", "T1070.006"),
        ("log_clearing", "T1070.001"),
        ("hidden_files", "T1564.001"),
        ("system_binary_proxy", "T1218"),
        ("powershell_obfuscation", "T1027"),
        ("impair_defenses", "T1562.001"),
        ("debugger_evasion", "T1622"),
        ("encrypted_encoded_file", "T1027.013"),
        ("environmental_keying", "T1480.001"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = DefenseEvasionModule()
    result = mod.execute(
        {"technique": technique, "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.techniques == [expected_mitre], (
        f"{technique} should emit {expected_mitre}, got {result.techniques}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre


def test_debugger_evasion_pins_t1622_with_api_substring(tmp_path: Path) -> None:
    """Debugger Evasion (T1622) pins the canonical Win32 API
    substring ``IsDebuggerPresent`` so the rendered detection draft
    fires on processes probing for an attached debugger before
    executing sensitive code."""

    mod = DefenseEvasionModule()
    result = mod.execute(
        {"technique": "debugger_evasion", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1622"]
    assert result.detection_hints["logsource"] == {
        "category": "process_creation",
        "product": "windows",
    }
    selection = result.detection_hints["detection"]["selection"]
    assert "IsDebuggerPresent" in selection.get(
        "process.command_line|contains", ""
    )


def test_encrypted_encoded_file_pins_t1027_013_with_extension_selector(
    tmp_path: Path,
) -> None:
    """Encrypted/Encoded File (T1027.013) writes a high-entropy
    artefact to disk. Pin the MITRE id, file_event logsource, and
    the ``.enc`` extension substring selector. Distinct from
    ``powershell_obfuscation`` (T1027) which targets the PowerShell
    command-line FromBase64String form rather than a disk artefact."""

    mod = DefenseEvasionModule()
    result = mod.execute(
        {"technique": "encrypted_encoded_file", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1027.013"]
    assert result.detection_hints["logsource"] == {
        "category": "file_event",
        "product": "host",
    }
    selection = result.detection_hints["detection"]["selection"]
    assert ".enc" in selection.get("file.path|endswith", "")


def test_environmental_keying_pins_t1480_001_with_machineguid_selector(
    tmp_path: Path,
) -> None:
    """Environmental Keying (T1480.001) reads a per-machine identity
    value (typically ``HKLM\\Software\\Microsoft\\Cryptography\\
    MachineGuid``) and uses it as decryption key material so the
    payload only runs on the targeted host. Pin the MITRE id,
    registry_event logsource, and the ``MachineGuid`` substring
    selector so the rendered detection draft fires on the canonical
    machine-fingerprint read."""

    mod = DefenseEvasionModule()
    result = mod.execute(
        {"technique": "environmental_keying", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1480.001"]
    assert result.detection_hints["logsource"] == {
        "category": "registry_event",
        "product": "windows",
    }
    selection = result.detection_hints["detection"]["selection"]
    selector_value = next(iter(selection.values()))
    assert "MachineGuid" in selector_value
    assert "Cryptography" in selector_value


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    """Every profile must emit a unique telemetry event_type so a
    defender summing event_types can quantify technique distribution
    without joining tables."""

    mod = DefenseEvasionModule()
    seen: set[str] = set()
    for technique in _DEFENSE_EVASION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_DEFENSE_EVASION_PROFILES)


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {
        profile["mitre"] for profile in _DEFENSE_EVASION_PROFILES.values()
    }
    advertised = set(DefenseEvasionModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )
