"""Focused tests for the legacy_impact adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyImpactModule
from src.core.modules.registry import build_runtime_modules


def _enable_impact(cfg_path: Path, *, mode: str, ack: bool) -> None:
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    base = "modules.legacy.tactic_pack.capabilities.impact"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def test_registry_includes_legacy_impact() -> None:
    modules = build_runtime_modules()
    assert "legacy_impact" in modules
    instance = modules["legacy_impact"]
    assert isinstance(instance, LegacyImpactModule)
    assert instance.pack_name == "tactic_pack"
    assert instance.capability_name == "impact"
    expected_subset = {
        "T1485",      # Data destruction
        "T1486",      # Data encryption (ransomware)
        "T1489",      # Service stop
        "T1499",      # Endpoint DoS
        "T1529",      # System reboot/shutdown
        "T1543.003",  # Service modify/delete (Windows service)
        "T1565",      # Stored data manipulation
    }
    assert expected_subset.issubset(set(instance.attack_techniques))


def test_disabled_pack_raises_runtime_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "data_encryption", "target": "lab-host"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


def test_simulate_mode_emits_rich_tradecraft_notes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "data_encryption", "target": "lab-fileshare"},
    )
    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["pack"] == "tactic_pack"
    assert legacy["capability"] == "impact"
    assert legacy["mode"] == "simulate"

    payload = legacy["payload"]
    assert payload["technique"] == "data_encryption"
    assert payload["mitre_technique"] == "T1486"
    notes = payload["tradecraft_notes"]
    assert isinstance(notes, dict) and notes
    # Simulate-mode runtime_outcome must explicitly say "simulated".
    assert payload["runtime_outcome"]["status"] == "simulated"


def test_simulate_mode_unrecognized_technique_falls_back(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "definitely-not-a-real-technique"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["technique"] == "data_encryption"


def test_emulate_without_ack_raises(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="emulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "data_encryption"},
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="emulate", ack=True)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "service_stop", "target": "lab-host"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    assert runtime["status"] in {"success", "completed", "failure"}
    assert runtime.get("technique") == "service_stop"


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": "data_encryption"},
    )
    assert result["status"] == "success"
    output_dir = Path(result["output_dir"])
    for path_key in ("report_path", "risk_summary_path"):
        path_value = result.get(path_key)
        if path_value:
            assert Path(path_value).resolve().is_relative_to(output_dir.resolve())
    for output_type, output_paths in (result.get("detection_artifacts") or {}).items():
        if isinstance(output_paths, list):
            for path_str in output_paths:
                assert Path(path_str).resolve().is_relative_to(output_dir.resolve()), (
                    f"{output_type} path {path_str} escaped output_dir {output_dir}"
                )


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("data_encryption", "T1486"),
        ("data_destruction", "T1485"),
        ("data_manipulation", "T1565"),
        ("service_stop", "T1489"),
        ("service_modify", "T1543.003"),
        ("service_delete", "T1543.003"),
        ("system_reboot", "T1529"),
        ("system_shutdown", "T1529"),
        ("endpoint_dos", "T1499"),
    ],
)
def test_each_technique_emits_canonical_mitre_id(
    tmp_path: Path,
    technique: str,
    expected_mitre: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_impact(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_impact",
        {"technique": technique, "target": "lab-host"},
    )
    assert result["status"] == "success"
    techniques = result["techniques"]
    assert techniques == [expected_mitre]
    hints = result["detection_hints"]
    selection: Dict[str, Any] = hints["detection"]["selection"]
    assert selection["legacy.pack"] == "tactic_pack"
    assert selection["legacy.capability"] == "impact"
    assert selection["legacy.technique"] == technique
