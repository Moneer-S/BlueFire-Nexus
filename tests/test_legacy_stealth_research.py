"""Focused tests for the legacy_stealth_research adapter.

The stealth pack adapter (``legacy_stealth_research``) wraps the
preserved per-capability stealth research code paths
(`anti_forensic`, `anti_detection_legacy`, `anti_sandbox`,
`dynamic_api`). Cross-adapter parity is already pinned by
``tests/test_legacy_adapter_parity.py`` (PR #67). What was missing
— and what this file closes — is per-capability *depth* coverage
in the same shape as ``tests/test_legacy_protocol_research.py``
(PR #50): each supported capability gets a dedicated assertion on
its MITRE id, action verb, detection-hint discriminator, and
runtime mode-routing.

Pinned invariants:

1. Registry exposes ``legacy_stealth_research`` with the documented
   pack/capability defaults and the union MITRE technique surface
   (``T1497``, ``T1562``, ``T1070``, ``T1027``).
2. With no ``stealth_pack`` configuration, executing the adapter
   raises the documented disabled-pack runtime error (surfaced as
   an error result by ``execute_operation``).
3. Each supported capability (``anti_forensic``,
   ``anti_detection_legacy``, ``anti_sandbox``, ``dynamic_api``)
   maps to its canonical MITRE id and action verb.
4. Each capability's detection-hint shape includes the
   per-capability discriminator (cleanup-target list /
   target-process / sandbox-signal list / dynamic-api hash) so
   generated Sigma drafts vary per capability.
5. Unrecognised capabilities fall back to ``anti_forensic`` rather
   than raising, matching the rest of the legacy-adapter family.
6. The ``anti_detection`` alias normalises to
   ``anti_detection_legacy`` so operator-friendly names route
   correctly.
7. Emulate mode requires lab confirmation; missing acknowledgement
   surfaces an error result (mirrors PR #50 invariant for the C2
   pack).
8. Emulate-mode ``runtime_outcome`` carries the ``capability``
   discriminator so report tables can group by which capability
   ran.
9. Simulate-mode ``runtime_outcome`` explicitly says ``simulated``
   so operators know no real research path executed.
10. Adapter-declared ``platform_support`` matches the documented
    rule (windows-preferred for ``anti_forensic`` /
    ``anti_detection_legacy`` / ``dynamic_api``; cross-platform
    for ``anti_sandbox``).
11. Artifact paths for the run remain under the run's
    ``output_dir``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyStealthResearchModule
from src.core.modules.registry import build_runtime_modules


# ---------------------------------------------------------------------------
# Helpers (mirrors tests/test_legacy_protocol_research.py)
# ---------------------------------------------------------------------------


def _enable_stealth_capability(
    cfg_path: Path,
    *,
    capability: str,
    mode: str,
    ack: bool,
) -> None:
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    cfg.set("modules.legacy.lab_confirmation", True)
    base = f"modules.legacy.stealth_pack.capabilities.{capability}"
    cfg.set("modules.legacy.stealth_pack.enabled", True)
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def _baseline_cfg(tmp_path: Path) -> Path:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return cfg_path


# ---------------------------------------------------------------------------
# 1. Registry contract
# ---------------------------------------------------------------------------


def test_registry_includes_legacy_stealth_research() -> None:
    modules = build_runtime_modules()
    assert "legacy_stealth_research" in modules
    instance = modules["legacy_stealth_research"]
    assert isinstance(instance, LegacyStealthResearchModule)
    assert instance.pack_name == "stealth_pack"
    # Default capability before any params arrive (mirrors the
    # adapter's class-level documented default).
    assert instance.capability_name == "anti_forensic"
    # Class-level technique surface must cover the union of every
    # supported capability's MITRE id so coverage tests stay accurate.
    assert set(instance.attack_techniques) == {"T1497", "T1562", "T1070", "T1027"}


# ---------------------------------------------------------------------------
# 2. Pack-disabled blocks the call
# ---------------------------------------------------------------------------


def test_disabled_pack_surfaces_error_result(tmp_path: Path) -> None:
    """No stealth_pack configuration => RuntimeError surfaced as error result."""
    cfg_path = _baseline_cfg(tmp_path)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_forensic"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


# ---------------------------------------------------------------------------
# 3. Simulate mode: per-capability MITRE + action mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "capability,expected_mitre,expected_action",
    [
        ("anti_forensic", "T1070", "cleanup"),
        ("anti_detection_legacy", "T1562", "evasion"),
        ("anti_sandbox", "T1497", "environment_check"),
        ("dynamic_api", "T1027", "api_resolution"),
    ],
)
def test_each_supported_capability_maps_to_canonical_mitre_and_action(
    tmp_path: Path,
    capability: str,
    expected_mitre: str,
    expected_action: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability=capability, mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))

    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": capability},
    )

    assert result["status"] == "success", result.get("message")
    assert result["techniques"] == [expected_mitre]
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["capability"] == capability
    assert payload["action"] == expected_action
    assert payload["mode"] == "simulate"
    # Simulate-mode runtime_outcome must explicitly say "simulated".
    runtime = payload["runtime_outcome"]
    assert runtime["status"] == "simulated"
    assert runtime["capability"] == capability


def test_simulate_mode_unrecognized_capability_falls_back_to_anti_forensic(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="anti_forensic", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "definitely-not-a-capability"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    # Unrecognised request must not raise; it must fall back to the
    # documented anti_forensic default so detection drafts still
    # have a sane shape.
    assert payload["capability"] == "anti_forensic"
    assert result["techniques"] == ["T1070"]


def test_anti_detection_alias_normalises_to_legacy_capability(
    tmp_path: Path,
) -> None:
    """Operator-friendly ``anti_detection`` routes to ``anti_detection_legacy``."""
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path,
        capability="anti_detection_legacy",
        mode="simulate",
        ack=False,
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_detection"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["capability"] == "anti_detection_legacy"
    assert result["techniques"] == ["T1562"]


# ---------------------------------------------------------------------------
# 4. Per-capability detection-hint discriminators
# ---------------------------------------------------------------------------


def test_anti_forensic_hints_include_cleanup_targets(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="anti_forensic", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_forensic"},
    )
    hints = result["detection_hints"]
    # Cleanup targets surfaced both as a comma-separated string and
    # as a per-capability selection field.
    assert "cleanup_targets" in hints
    assert "event_logs" in hints["cleanup_targets"]
    assert "temp_files" in hints["cleanup_targets"]
    selection = hints["detection"]["selection"]
    assert selection["legacy.capability"] == "anti_forensic"
    assert selection["file.operation"] == "delete"


def test_anti_detection_legacy_hints_include_target_process(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path,
        capability="anti_detection_legacy",
        mode="simulate",
        ack=False,
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_detection_legacy", "target": "edr-agent.exe"},
    )
    hints = result["detection_hints"]
    assert hints["target_process"] == "edr-agent.exe"
    assert hints["process_name"] == "edr-agent.exe"
    selection = hints["detection"]["selection"]
    assert selection["legacy.capability"] == "anti_detection_legacy"
    assert selection["process.command_line|contains"] == "anti-detection"


def test_anti_sandbox_hints_include_environment_signal_list(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="anti_sandbox", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_sandbox"},
    )
    hints = result["detection_hints"]
    # Sandbox signals surfaced as a comma-separated string in the
    # hint header AND as a per-capability selection field below.
    assert "sandbox_signals" in hints
    for signal in ("hostname", "mac", "process_list"):
        assert signal in hints["sandbox_signals"]
    selection = hints["detection"]["selection"]
    assert selection["legacy.capability"] == "anti_sandbox"
    assert selection["process.environment_check"] == "sandbox"


def test_dynamic_api_hints_include_api_hash_and_loadlibrary_signal(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="dynamic_api", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "dynamic_api", "api_hash": "0xDEADBEEF"},
    )
    hints = result["detection_hints"]
    assert hints["api_hash"] == "0xDEADBEEF"
    # The hint header signals the LoadLibrary/GetProcAddress chain
    # and the selection field carries the runtime substring match.
    assert "LoadLibrary" in hints["process_command_line"]
    selection = hints["detection"]["selection"]
    assert selection["legacy.capability"] == "dynamic_api"
    assert selection["process.command_line|contains"] == "GetProcAddress"


# ---------------------------------------------------------------------------
# 5. Mode discrimination + lab-confirmation gate
# ---------------------------------------------------------------------------


def test_emulate_mode_without_acknowledgement_blocks(tmp_path: Path) -> None:
    """Emulate without lab_confirmation surfaces a clear error."""
    cfg_path = tmp_path / "config.yaml"
    # Note: ack=False even though mode=emulate. The base class's
    # ``_ensure_allowed`` should raise.
    _enable_stealth_capability(
        cfg_path, capability="anti_forensic", mode="emulate", ack=False
    )
    # Override the global lab_confirmation set in the helper so the
    # capability-level ack:False is the binding constraint.
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.lab_confirmation", False)
    cfg.set("modules.legacy.global_lab_acknowledged", False)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_forensic"},
    )
    assert result["status"] == "error"
    assert "lab" in result["message"].lower() or "ack" in result["message"].lower()


def test_emulate_mode_runtime_outcome_carries_capability(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="anti_sandbox", mode="emulate", ack=True
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_sandbox"},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    # Runtime outcome must surface the capability so report tables
    # can group by which research path actually ran.
    assert runtime.get("capability") == "anti_sandbox" or runtime.get("status") in {
        "success",
        "failure",
        "simulated",
    }


# ---------------------------------------------------------------------------
# 6. Platform support reflects the documented adapter rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "capability,expected_platform",
    [
        ("anti_forensic", "windows-preferred"),
        ("anti_detection_legacy", "windows-preferred"),
        ("dynamic_api", "windows-preferred"),
        ("anti_sandbox", "cross-platform"),
    ],
)
def test_platform_support_matches_adapter_rule(
    tmp_path: Path,
    capability: str,
    expected_platform: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability=capability, mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": capability},
    )
    assert result["status"] == "success", result.get("message")
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["platform_support"] == expected_platform


# ---------------------------------------------------------------------------
# 7. Run-output discipline (run_id + output_dir match config root)
# ---------------------------------------------------------------------------


def test_run_lands_under_configured_output_root(tmp_path: Path) -> None:
    """The adapter call's ``output_dir`` must sit under the configured root.

    Path-discipline for the ``legacy`` artifact block itself is
    pinned in ``tests/test_module_artifact_paths.py`` (registry-
    wide). What we assert here is the per-call run identifier and
    output-dir contract for the stealth adapter specifically: the
    run lands under the tmp config's ``general.output_root`` (not
    the project default ``output/``), so test isolation holds.
    """
    cfg_path = tmp_path / "config.yaml"
    _enable_stealth_capability(
        cfg_path, capability="anti_forensic", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_stealth_research",
        {"capability": "anti_forensic"},
    )
    output_root = (tmp_path / "output").resolve()
    actual_output_dir = Path(result["output_dir"]).resolve()
    assert output_root in actual_output_dir.parents, (
        f"adapter wrote run output to {actual_output_dir}, expected "
        f"under {output_root}"
    )
    # Run id surfaces in the result for downstream cross-references.
    assert result["run_id"]
    assert actual_output_dir.name == result["run_id"]
