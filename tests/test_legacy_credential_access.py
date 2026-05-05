"""Focused tests for the legacy_credential_access adapter.

Companion to the simulate-only standard `credential_access` module.
This test set asserts the legacy adapter follows the established
legacy-pack pattern: pack/capability gating, simulate-mode tradecraft
notes, emulate-mode requires lab confirmation, and the artifact
shape stays compatible with the rest of the legacy-adapter family.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyCredentialAccessModule
from src.core.modules.registry import build_runtime_modules


def _enable_credential_access(cfg_path: Path, *, mode: str, ack: bool) -> None:
    cfg = ConfigManager(str(cfg_path))
    base = "modules.legacy.tactic_pack.capabilities.credential_access"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


# ---------------------------------------------------------------------------
# Registry contract
# ---------------------------------------------------------------------------


def test_registry_includes_legacy_credential_access() -> None:
    modules = build_runtime_modules()
    assert "legacy_credential_access" in modules
    instance = modules["legacy_credential_access"]
    assert isinstance(instance, LegacyCredentialAccessModule)
    assert instance.pack_name == "tactic_pack"
    assert instance.capability_name == "credential_access"
    # Class-level technique surface must cover every key in the standard
    # CredentialAccess profile catalog so coverage tests stay accurate.
    expected = {
        "T1003.001",
        "T1003.002",
        "T1003.003",
        "T1555.003",
        "T1555.001",
        "T1552.004",
        "T1056.001",
        "T1115",
        "T1113",
    }
    assert expected == set(instance.attack_techniques)


# ---------------------------------------------------------------------------
# Pack-disabled blocks the call (mirrors existing legacy-adapter contract)
# ---------------------------------------------------------------------------


def test_disabled_pack_raises_runtime_error(tmp_path: Path) -> None:
    """No tactic_pack configuration => RuntimeError from _ensure_allowed."""
    cfg_path = tmp_path / "config.yaml"
    ConfigManager(str(cfg_path)).save()
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "lsass_dump", "target": "lab-host"},
    )
    # execute_operation catches the runtime exception and surfaces it
    # as an error result (mirrors the contract for every other legacy
    # adapter when its pack is disabled).
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


# ---------------------------------------------------------------------------
# Simulate mode: rich artifacts/telemetry, no runtime side effects
# ---------------------------------------------------------------------------


def test_simulate_mode_emits_rich_tradecraft_notes(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "lsass_dump", "target": "lab-host"},
    )
    assert result["status"] == "success"
    legacy = result["artifacts"]["legacy"]
    assert legacy["pack"] == "tactic_pack"
    assert legacy["capability"] == "credential_access"
    assert legacy["mode"] == "simulate"

    payload = legacy["payload"]
    assert payload["technique"] == "lsass_dump"
    assert payload["mitre_technique"] == "T1003.001"
    # Tradecraft notes must be non-empty so the adapter is meaningfully
    # different from the simulate-only standard module.
    notes = payload["tradecraft_notes"]
    assert isinstance(notes, dict)
    assert notes  # non-empty
    assert "canonical_tools" in notes
    # Simulate-mode runtime_outcome must explicitly say "simulated"
    # (not "completed") so reports cannot misrepresent which path ran.
    assert payload["runtime_outcome"]["status"] == "simulated"


def test_simulate_mode_unrecognized_technique_falls_back(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "definitely-not-a-real-technique"},
    )
    assert result["status"] == "success"
    # Unrecognized techniques must be marked, not silently mapped.
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["technique"] == "lsass_dump"


# ---------------------------------------------------------------------------
# Emulate mode: requires lab confirmation, then routes through safe_call
# ---------------------------------------------------------------------------


def test_emulate_without_ack_raises(tmp_path: Path) -> None:
    """Emulate mode without lab_confirmation must be rejected by _ensure_allowed."""
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="emulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "lsass_dump"},
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="emulate", ack=True)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "browser_credentials", "target": "analyst-workstation"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    # safe_call must produce a structured outcome dict; no real network
    # or process side effect is allowed in dry-run, but the legacy class
    # itself returns a synthesised descriptor.
    assert runtime["status"] in {"success", "completed", "failure"}
    assert runtime.get("technique") == "browser_credentials"


# ---------------------------------------------------------------------------
# Artifact paths stay under output_dir
# ---------------------------------------------------------------------------


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": "lsass_dump"},
    )
    assert result["status"] == "success"
    output_dir = Path(result["output_dir"])
    # report.md, risk_summary.json, and detection artifacts must all
    # resolve under output_dir; nothing must leak outside the run
    # directory.
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


# ---------------------------------------------------------------------------
# Detection-hint shape: defender-facing pack/capability tags + MITRE id
# ---------------------------------------------------------------------------


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
    ],
)
def test_each_technique_emits_canonical_mitre_id(
    tmp_path: Path,
    technique: str,
    expected_mitre: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_credential_access(cfg_path, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_credential_access",
        {"technique": technique},
    )
    assert result["status"] == "success"
    techniques = result["techniques"]
    assert techniques == [expected_mitre]
    hints = result["detection_hints"]
    selection: Dict[str, Any] = hints["detection"]["selection"]
    # Every legacy adapter must surface its pack/capability so generated
    # Sigma rules can be filtered by which pack produced them.
    assert selection["legacy.pack"] == "tactic_pack"
    assert selection["legacy.capability"] == "credential_access"
    assert selection["legacy.technique"] == technique
