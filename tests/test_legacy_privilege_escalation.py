"""Focused tests for the legacy_privilege_escalation adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyPrivilegeEscalationModule
from src.core.modules.registry import build_runtime_modules


def _enable_privilege_escalation(cfg_path: Path, *, mode: str, ack: bool) -> None:
    cfg = ConfigManager(str(cfg_path))
    base = "modules.legacy.tactic_pack.capabilities.privilege_escalation"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def test_registry_includes_legacy_privilege_escalation() -> None:
    modules = build_runtime_modules()
    assert "legacy_privilege_escalation" in modules
    instance = modules["legacy_privilege_escalation"]
    assert isinstance(instance, LegacyPrivilegeEscalationModule)
    assert instance.pack_name == "tactic_pack"
    assert instance.capability_name == "privilege_escalation"
    expected_subset = {
        "T1134.001",  # Token impersonation
        "T1134.002",  # Token duplication
        "T1134.003",  # Make-and-impersonate token
        "T1055",      # Process injection (parent)
        "T1055.012",  # Process hollowing
        "T1036.005",  # Process masquerading
        "T1543.003",  # Service create/modify
        "T1489",      # Service stop
    }
    assert expected_subset.issubset(set(instance.attack_techniques))


def test_disabled_pack_raises_runtime_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    ConfigManager(str(cfg_path)).save()
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "token_impersonation", "target": "lab-host"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


def test_simulate_mode_emits_rich_tradecraft_notes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "process_hollowing", "target": "lab-host"},
    )
    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["pack"] == "tactic_pack"
    assert legacy["capability"] == "privilege_escalation"
    assert legacy["mode"] == "simulate"

    payload = legacy["payload"]
    assert payload["technique"] == "process_hollowing"
    assert payload["mitre_technique"] == "T1055.012"
    notes = payload["tradecraft_notes"]
    assert isinstance(notes, dict) and notes
    assert "canonical_apis" in notes
    assert payload["runtime_outcome"]["status"] == "simulated"


def test_simulate_mode_unrecognized_technique_falls_back(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "definitely-not-a-real-technique"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["technique"] == "token_impersonation"


def test_emulate_without_ack_raises(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="emulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "token_impersonation"},
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="emulate", ack=True)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "process_injection", "target": "lab-host"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    assert runtime["status"] in {"success", "completed", "failure"}
    assert runtime.get("technique") == "process_injection"


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": "token_impersonation"},
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
        ("token_impersonation", "T1134.001"),
        ("token_duplication", "T1134.002"),
        ("token_creation", "T1134.003"),
        ("process_hollowing", "T1055.012"),
        ("process_injection", "T1055"),
        ("process_masquerading", "T1036.005"),
        ("service_creation", "T1543.003"),
        ("service_modification", "T1543.003"),
        ("service_stop", "T1489"),
    ],
)
def test_each_technique_emits_canonical_mitre_id(
    tmp_path: Path,
    technique: str,
    expected_mitre: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_privilege_escalation(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_privilege_escalation",
        {"technique": technique, "target": "lab-host"},
    )
    assert result["status"] == "success"
    techniques = result["techniques"]
    assert techniques == [expected_mitre]
    hints = result["detection_hints"]
    selection: Dict[str, Any] = hints["detection"]["selection"]
    assert selection["legacy.pack"] == "tactic_pack"
    assert selection["legacy.capability"] == "privilege_escalation"
    assert selection["legacy.technique"] == technique
