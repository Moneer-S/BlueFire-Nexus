"""Focused tests for the legacy_lateral_movement adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyLateralMovementModule
from src.core.modules.registry import build_runtime_modules


def _enable_lateral_movement(cfg_path: Path, *, mode: str, ack: bool) -> None:
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    base = "modules.legacy.tactic_pack.capabilities.lateral_movement"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def test_registry_includes_legacy_lateral_movement() -> None:
    modules = build_runtime_modules()
    assert "legacy_lateral_movement" in modules
    instance = modules["legacy_lateral_movement"]
    assert isinstance(instance, LegacyLateralMovementModule)
    assert instance.pack_name == "tactic_pack"
    assert instance.capability_name == "lateral_movement"
    expected_subset = {
        "T1021.002",  # PsExec / SMB share
        "T1021.004",  # SSH lateral
        "T1021.006",  # WinRM
        "T1047",      # WMI
        "T1059.001",  # PowerShell remoting
        "T1105",      # FTP / SCP lateral tool transfer
        "T1543.003",  # Service create / modify
        "T1489",      # Service stop / disruption
        "T1570",      # Lateral tool transfer (parent)
    }
    assert expected_subset.issubset(set(instance.attack_techniques))


def test_disabled_pack_raises_runtime_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "psexec", "source": "a", "target": "b"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


def test_simulate_mode_emits_rich_tradecraft_notes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "psexec", "source": "lab-attacker", "target": "lab-host"},
    )
    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["pack"] == "tactic_pack"
    assert legacy["capability"] == "lateral_movement"
    assert legacy["mode"] == "simulate"

    payload = legacy["payload"]
    assert payload["technique"] == "psexec"
    assert payload["mitre_technique"] == "T1021.002"
    assert payload["source"] == "lab-attacker"
    assert payload["target"] == "lab-host"
    notes = payload["tradecraft_notes"]
    assert isinstance(notes, dict) and notes
    assert "canonical_tools" in notes
    # Simulate-mode runtime_outcome must explicitly say "simulated".
    assert payload["runtime_outcome"]["status"] == "simulated"


def test_simulate_mode_unrecognized_technique_falls_back(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "definitely-not-a-real-technique"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["technique"] == "psexec"


def test_emulate_without_ack_raises(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="emulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "psexec"},
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="emulate", ack=True)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "wmi", "source": "lab-attacker", "target": "lab-host"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    assert runtime["status"] in {"success", "completed", "failure"}
    assert runtime.get("technique") == "wmi"


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": "psexec"},
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
        ("psexec", "T1021.002"),
        ("wmi", "T1047"),
        ("powershell_remoting", "T1059.001"),
        ("winrm", "T1021.006"),
        ("smb_share", "T1021.002"),
        ("ftp_transfer", "T1105"),
        ("scp_transfer", "T1105"),
        ("service_create", "T1543.003"),
        ("service_modify", "T1543.003"),
        ("service_stop", "T1489"),
    ],
)
def test_each_technique_emits_canonical_mitre_id(
    tmp_path: Path,
    technique: str,
    expected_mitre: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_lateral_movement(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_lateral_movement",
        {"technique": technique, "source": "a", "target": "b"},
    )
    assert result["status"] == "success"
    techniques = result["techniques"]
    assert techniques == [expected_mitre]
    hints = result["detection_hints"]
    selection: Dict[str, Any] = hints["detection"]["selection"]
    assert selection["legacy.pack"] == "tactic_pack"
    assert selection["legacy.capability"] == "lateral_movement"
    assert selection["legacy.technique"] == technique
