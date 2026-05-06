"""Focused tests for the legacy_collection adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyCollectionModule
from src.core.modules.registry import build_runtime_modules


def _enable_collection(cfg_path: Path, *, mode: str, ack: bool) -> None:
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    base = "modules.legacy.tactic_pack.capabilities.collection"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def test_registry_includes_legacy_collection() -> None:
    modules = build_runtime_modules()
    assert "legacy_collection" in modules
    instance = modules["legacy_collection"]
    assert isinstance(instance, LegacyCollectionModule)
    assert instance.pack_name == "tactic_pack"
    assert instance.capability_name == "collection"
    expected_subset = {
        "T1022",      # Encryption of collected data
        "T1056.001",  # Keyboard capture
        "T1074.001",  # Local data staging
        "T1113",      # Screen capture
        "T1115",      # Clipboard capture
        "T1132",      # Encoding
        "T1560",      # Archive collected data
        "T1560.001",  # Archive via custom method
    }
    assert expected_subset.issubset(set(instance.attack_techniques))


def test_disabled_pack_raises_runtime_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "file_staging", "target": "lab-host"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


def test_simulate_mode_emits_rich_tradecraft_notes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "archive_staging", "target": "lab-host"},
    )
    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["pack"] == "tactic_pack"
    assert legacy["capability"] == "collection"
    assert legacy["mode"] == "simulate"

    payload = legacy["payload"]
    assert payload["technique"] == "archive_staging"
    assert payload["mitre_technique"] == "T1560.001"
    notes = payload["tradecraft_notes"]
    assert isinstance(notes, dict) and notes
    assert payload["runtime_outcome"]["status"] == "simulated"


def test_simulate_mode_unrecognized_technique_falls_back(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "definitely-not-a-real-technique"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["technique"] == "file_staging"


def test_emulate_without_ack_raises(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="emulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "file_staging"},
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="emulate", ack=True)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "compression", "target": "lab-host"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    assert runtime["status"] in {"success", "completed", "failure"}
    assert runtime.get("technique") == "compression"


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": "file_staging"},
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
        ("file_staging", "T1074.001"),
        ("directory_staging", "T1074.001"),
        ("archive_staging", "T1560.001"),
        ("keyboard_capture", "T1056.001"),
        ("clipboard_capture", "T1115"),
        ("screen_capture", "T1113"),
        ("compression", "T1560"),
        ("encryption", "T1022"),
        ("encoding", "T1132"),
    ],
)
def test_each_technique_emits_canonical_mitre_id(
    tmp_path: Path,
    technique: str,
    expected_mitre: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_collection(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_collection",
        {"technique": technique, "target": "lab-host"},
    )
    assert result["status"] == "success"
    techniques = result["techniques"]
    assert techniques == [expected_mitre]
    hints = result["detection_hints"]
    selection: Dict[str, Any] = hints["detection"]["selection"]
    assert selection["legacy.pack"] == "tactic_pack"
    assert selection["legacy.capability"] == "collection"
    assert selection["legacy.technique"] == technique
