"""Realism / chain-pair pins for the APT29 credential-access scenario.

The scenario was deepened from a 5-step phish-execution-evasion-creds-
exfil sequence into an 8-step intrusion chain that mirrors APT29's
documented finance-sector tradecraft:

1. resource_development for an attacker-staged C2 domain
2. spearphishing email to a finance analyst
3. encoded PowerShell loader parented by OUTLOOK.EXE
4. in-memory evasion before credential harvest
5. browser credential extraction
6. host enumeration on adjacent finance subnet
7. PsExec lateral pivot using harvested creds (source + target
   propagated)
8. exfiltration over the staged C2 (source propagated from
   lateral-pivot)

These tests pin the structural shape so a future edit that drops a
chain pair, an objective, or the APT29-specific tradecraft hooks
(parent_command_line=OUTLOOK.EXE, source_from_step + target_from_step
on lateral-pivot) is caught explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATH = Path("scenarios") / "apt29_credential_access.yaml"


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


def test_apt29_scenario_loads_and_has_eight_steps() -> None:
    """Eight steps in the documented order; a regression that drops
    a step is caught here."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert len(scenario.steps) == 8
    expected_modules = [
        "resource_development",
        "initial_access",
        "execution",
        "anti_detection",
        "credential_access",
        "discovery",
        "lateral_movement",
        "exfiltration",
    ]
    actual = [step.module for step in scenario.steps]
    assert actual == expected_modules, (
        f"APT29 scenario step order changed; expected {expected_modules}, got {actual}"
    )


def test_apt29_every_step_has_objective() -> None:
    scenario = load_scenario(str(SCENARIO_PATH))
    missing = [s.step_id for s in scenario.steps if not s.objective.strip()]
    assert missing == [], (
        f"APT29 scenario steps missing objective: {missing}"
    )


def test_apt29_loader_step_pins_outlook_parent() -> None:
    """APT29's documented tradecraft is a phishing email loader
    spawning powershell from OUTLOOK.EXE. The loader-execution
    step must pin ``parent_command_line: OUTLOOK.EXE``."""

    scenario = load_scenario(str(SCENARIO_PATH))
    loader = next(s for s in scenario.steps if s.module == "execution")
    assert loader.params.get("parent_command_line") == "OUTLOOK.EXE"


def test_apt29_lateral_pivot_consumes_source_and_target_propagation() -> None:
    """The lateral-pivot step must consume both:
    - source from harvest-browser-creds (the host the credential
      came from)
    - target from discover-finance-hosts (the destination host)
    """

    scenario = load_scenario(str(SCENARIO_PATH))
    pivot = next(s for s in scenario.steps if s.module == "lateral_movement")
    assert pivot.params.get("source_from_step") == "harvest-browser-creds"
    assert pivot.params.get("target_from_step") == "discover-finance-hosts"
    assert pivot.params.get("technique") == "psexec"


def test_apt29_exfil_step_propagates_target_from_lateral() -> None:
    """The exfil step pulls source host from the lateral-pivot step
    so the host -> egress correlation is anchored on the pivoted
    destination, not the original phish target."""

    scenario = load_scenario(str(SCENARIO_PATH))
    exfil = next(s for s in scenario.steps if s.module == "exfiltration")
    assert exfil.params.get("target_from_step") == "lateral-pivot"


def test_apt29_attack_coverage_lists_t1059_001_and_t1555_003() -> None:
    """The scenario should declare the PowerShell sub-technique
    (T1059.001) and browser credentials (T1555.003) explicitly."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert "T1059.001" in scenario.attack_techniques
    assert "T1555.003" in scenario.attack_techniques


def test_apt29_runs_end_to_end_with_eight_successful_steps(tmp_path: Path) -> None:
    """End-to-end pin: every step succeeds when the scenario runs in
    the default simulate mode."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    assert result["status"] in {"success", "partial_success"}
    steps = result.get("steps") or []
    assert len(steps) == 8
    statuses = [step.get("status") for step in steps]
    assert all(s == "success" for s in statuses), (
        f"APT29 chain has a non-success step: {statuses}"
    )


def test_apt29_loader_execution_emits_decoded_command(tmp_path: Path) -> None:
    """The encoded PowerShell loader must decode under the
    Windows-first execution depth contract (PR #151)."""

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
    assert artifacts.get("parent_command_line") == "OUTLOOK.EXE"


def test_apt29_lateral_pivot_propagation_markers(tmp_path: Path) -> None:
    """End-to-end: the lateral-pivot step's artifacts should record
    both source + target propagation markers."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    pivot = next(
        (s for s in steps if s.get("module") == "lateral_movement"),
        None,
    )
    assert pivot is not None
    artifacts = pivot.get("artifacts") or {}
    assert artifacts.get("source_propagated_from_step") == "harvest-browser-creds"
    assert artifacts.get("target_propagated_from_step") == "discover-finance-hosts"


def test_apt29_lateral_pivot_target_is_concrete_host_not_cidr(
    tmp_path: Path,
) -> None:
    """Codex P2 (PR #159): the discovery step's targets must be
    concrete host names, not a CIDR block. Otherwise propagation
    via ``target_from_step`` lands the lateral-pivot step on a
    subnet string rather than a host - mismatching the module's
    host-level contract and the scenario objective ("pivot to one
    of the discovered hosts")."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    pivot = next(
        (s for s in steps if s.get("module") == "lateral_movement"),
        None,
    )
    assert pivot is not None
    target = (pivot.get("artifacts") or {}).get("target", "")
    # No CIDR notation should appear in the propagated target host.
    assert "/" not in target, (
        f"lateral-pivot target propagated as a CIDR: {target!r}"
    )
    # And the value must be one of the discovery step's concrete
    # hosts (the propagation picks the first entry).
    discovery = next(
        (s for s in steps if s.get("module") == "discovery"),
        None,
    )
    assert discovery is not None
    declared_targets = (discovery.get("artifacts") or {}).get("targets") or []
    assert target in declared_targets, (
        f"lateral-pivot target {target!r} not in discovery targets "
        f"{declared_targets!r}"
    )


def test_apt29_chain_summary_produces_required_types(tmp_path: Path) -> None:
    """The chain summary in manifest.chain should include the
    canonical APT29-relevant types: c2_endpoint (from
    resource_development), credential (from credential_access),
    host (from discovery + lateral_movement), exfil_package (from
    exfiltration)."""

    import json
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    run_id = result["run_id"]
    manifest = json.loads(
        (tmp_path / "output" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    chain = manifest.get("chain", {})
    produced = set(chain.get("produced_types") or [])
    expected_subset = {"c2_endpoint", "credential", "host", "exfil_package"}
    assert expected_subset.issubset(produced), (
        f"APT29 chain summary missing expected types: "
        f"{expected_subset - produced}; got {produced}"
    )
