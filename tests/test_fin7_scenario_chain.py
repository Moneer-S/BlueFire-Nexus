"""Realism / chain-pair pins for the FIN7 initial-access-to-C2 scenario.

The scenario was deepened from a 3-step phish->execution->C2 stub into
a 7-step chain that mirrors FIN7's documented hospitality tradecraft:
attacker domain registration, macro-bearing invoice spearphish, encoded
PowerShell loader parented by WINWORD.EXE, masquerade as svchost.exe,
HTTPS C2 to the staged domain, POS-environment file enumeration, and
exfiltration over the established C2 channel.

These tests pin the structural shape of the scenario so a future edit
that drops a chain pair, an objective, or the FIN7-specific tradecraft
hooks (parent_command_line=WINWORD.EXE, c2_endpoint_from_step) is
caught explicitly rather than only at the run-shape layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATH = Path("scenarios") / "fin7_initial_access_to_c2.yaml"


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


def test_fin7_scenario_loads_and_has_seven_steps() -> None:
    """The deepened FIN7 chain has resource_development through
    exfiltration in seven steps; a regression that drops a step gets
    caught here before any runtime check."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert len(scenario.steps) == 7
    expected_modules = [
        "resource_development",
        "initial_access",
        "execution",
        "defense_evasion",
        "command_control",
        "discovery",
        "exfiltration",
    ]
    actual = [step.module for step in scenario.steps]
    assert actual == expected_modules, (
        f"FIN7 scenario step order changed; expected {expected_modules}, got {actual}"
    )


def test_fin7_every_step_has_a_per_step_objective() -> None:
    """Every backbone step must carry an ``objective:`` line; an empty
    or missing objective is a regression for the operator-readable
    scenario contract."""

    scenario = load_scenario(str(SCENARIO_PATH))
    missing = [s.step_id for s in scenario.steps if not s.objective.strip()]
    assert missing == [], (
        f"FIN7 scenario steps missing objective: {missing}"
    )


def test_fin7_loader_step_pins_winword_parent_command_line() -> None:
    """FIN7's documented tradecraft is the macro-bearing invoice
    spawning powershell from WINWORD.EXE. The loader-execution step
    must pin ``parent_command_line: WINWORD.EXE`` explicitly so the
    detection draft fires on the parent/child chain."""

    scenario = load_scenario(str(SCENARIO_PATH))
    loader = next(s for s in scenario.steps if s.module == "execution")
    assert loader.params.get("parent_command_line") == "WINWORD.EXE"


def test_fin7_c2_step_propagates_from_resource_development() -> None:
    """The c2-https step must consume the staged domain via
    ``c2_endpoint_from_step`` so defenders see the registration -> C2
    destination link."""

    scenario = load_scenario(str(SCENARIO_PATH))
    c2 = next(s for s in scenario.steps if s.module == "command_control")
    assert c2.params.get("c2_endpoint_from_step") == "stage-fin7-domain"
    assert c2.params.get("channel") == "https"


def test_fin7_exfil_step_propagates_target_from_discovery() -> None:
    """The exfil-over-c2 step must consume the recon host via
    ``target_from_step`` so the host -> egress correlation against the
    POS-environment recon step is visible in the propagation graph."""

    scenario = load_scenario(str(SCENARIO_PATH))
    exfil = next(s for s in scenario.steps if s.module == "exfiltration")
    assert exfil.params.get("target_from_step") == "pos-environment-recon"


def test_fin7_attack_coverage_lists_t1218_or_t1059_subtechnique() -> None:
    """The scenario should declare T1059.001 (PowerShell sub-technique)
    rather than the bare T1059 parent, since the loader step is
    PowerShell-specific."""

    scenario = load_scenario(str(SCENARIO_PATH))
    # attack_coverage drift is enforced by another invariant test;
    # here we only pin that the powershell sub-technique is present.
    assert "T1059.001" in scenario.attack_techniques


def test_fin7_runs_end_to_end_with_seven_successful_steps(tmp_path: Path) -> None:
    """End-to-end pin: every step succeeds when the scenario runs in
    the default simulate mode; a regression that breaks a chain
    consumer pair surfaces as a non-success step."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    assert result["status"] in {"success", "partial_success"}
    steps = result.get("steps") or []
    assert len(steps) == 7
    statuses = [step.get("status") for step in steps]
    assert all(s == "success" for s in statuses), (
        f"FIN7 chain has a non-success step: {statuses}"
    )


def test_fin7_loader_execution_emits_decoded_command_artifact(tmp_path: Path) -> None:
    """The encoded PowerShell loader's payload must decode under the
    Windows-first execution depth contract (PR #151), so a defender
    sees the actual script body in artifacts rather than the opaque
    base64 blob."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    loader = next(
        (s for s in steps if s.get("module") == "execution"),
        None,
    )
    assert loader is not None
    artifacts = loader.get("artifacts") or {}
    assert artifacts.get("decoded_command"), (
        "loader-execution did not surface decoded_command in artifacts"
    )
    assert artifacts.get("parent_command_line") == "WINWORD.EXE"


def test_fin7_c2_endpoint_pulls_from_stage_fin7_domain(tmp_path: Path) -> None:
    """End-to-end: the c2-https step's endpoint should reference the
    domain the resource_development step staged in step 1."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    c2 = next(
        (s for s in steps if s.get("module") == "command_control"),
        None,
    )
    assert c2 is not None
    artifacts = c2.get("artifacts") or {}
    # The propagation marker should be set whenever the upstream step
    # actually fed the value; we don't pin the exact endpoint string
    # because the orchestrator rebuilds it, but the propagation marker
    # must reference the upstream step id.
    assert artifacts.get("c2_endpoint_propagated_from_step") == "stage-fin7-domain", (
        f"c2-https step did not record propagation; artifacts: {artifacts}"
    )
