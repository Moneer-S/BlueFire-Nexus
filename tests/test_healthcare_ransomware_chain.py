"""Realism / chain-pair pins for the healthcare double-extortion
ransomware scenario.

The scenario was deepened from a 5-step phish/exec/persistence/
exfil/impact stub into a 10-step double-extortion chain that
mirrors documented healthcare-sector tradecraft (BlackCat / Royal
/ LockBit / Clop): leak-site domain registration, spearphishing,
encoded loader, LSASS for domain creds, EHR/fileshare enumeration,
PsExec lateral pivot, data staging, defender impairment, leak-
site egress BEFORE encryption (so the leak threat survives a
backup restore), and finally fileshare encryption.

These tests pin the structural shape so a future edit that drops a
chain pair, an objective, or one of the healthcare-specific hooks
(staging-host propagation across collection -> exfil + impact,
defender impairment immediately before encryption, etc.) is
caught explicitly.

This file also pins the ``CollectionModule`` propagation fix that
landed alongside this scenario: collection now reads
``target_from_step`` so a lateral_movement -> collection chain
lands the staging step on the pivoted host instead of the
fallback ``lab-host``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATH = Path("scenarios") / "healthcare_ransomware.yaml"


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


def test_healthcare_scenario_loads_and_has_ten_steps() -> None:
    """Ten steps in the documented order; a regression that drops
    a step is caught here."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert len(scenario.steps) == 10
    expected_modules = [
        "resource_development",
        "initial_access",
        "execution",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "defense_evasion",
        "exfiltration",
        "impact",
    ]
    actual = [step.module for step in scenario.steps]
    assert actual == expected_modules, (
        f"healthcare scenario step order changed; expected "
        f"{expected_modules}, got {actual}"
    )


def test_healthcare_every_step_has_objective() -> None:
    scenario = load_scenario(str(SCENARIO_PATH))
    missing = [s.step_id for s in scenario.steps if not s.objective.strip()]
    assert missing == [], (
        f"healthcare scenario steps missing objective: {missing}"
    )


def test_healthcare_loader_step_pins_outlook_parent() -> None:
    """OUTLOOK.EXE -> powershell.exe is the documented phishing-to-
    loader signal; pin it explicitly."""

    scenario = load_scenario(str(SCENARIO_PATH))
    loader = next(s for s in scenario.steps if s.module == "execution")
    assert loader.params.get("parent_command_line") == "OUTLOOK.EXE"


def test_healthcare_lateral_pivot_consumes_source_and_target() -> None:
    """Both source (from credential harvest) AND target (from
    discovery) propagation slots are exercised by the lateral
    pivot step - a single step demonstrating two consumer pairs."""

    scenario = load_scenario(str(SCENARIO_PATH))
    pivot = next(s for s in scenario.steps if s.module == "lateral_movement")
    assert pivot.params.get("source_from_step") == "harvest-domain-creds"
    assert pivot.params.get("target_from_step") == "discover-clinical-hosts"
    assert pivot.params.get("technique") == "psexec"


def test_healthcare_collection_propagates_target_from_lateral() -> None:
    """Collection should stage on the host the lateral pivot landed
    on, NOT a fresh operator-supplied target. The propagation slot
    requires CollectionModule to read ``target_from_step`` (added
    alongside this scenario)."""

    scenario = load_scenario(str(SCENARIO_PATH))
    collect = next(s for s in scenario.steps if s.module == "collection")
    assert collect.params.get("target_from_step") == "lateral-pivot-to-fileshare"
    assert collect.params.get("technique") == "file_staging"


def test_healthcare_double_extortion_exfil_before_impact() -> None:
    """The defining characteristic of double-extortion ransomware is
    that exfiltration happens BEFORE encryption so the leak threat
    survives a backup restore. Pin the order: exfil index < impact
    index in the step list."""

    scenario = load_scenario(str(SCENARIO_PATH))
    modules = [step.module for step in scenario.steps]
    exfil_index = modules.index("exfiltration")
    impact_index = modules.index("impact")
    assert exfil_index < impact_index, (
        f"healthcare scenario exfil ({exfil_index}) must precede impact "
        f"({impact_index}) for the double-extortion sequence"
    )


def test_healthcare_defense_evasion_runs_before_impact() -> None:
    """Defender / AV impairment immediately precedes the bulk
    encryption rewrites - the canonical ransomware encryption
    runway."""

    scenario = load_scenario(str(SCENARIO_PATH))
    modules = [step.module for step in scenario.steps]
    evasion_index = modules.index("defense_evasion")
    impact_index = modules.index("impact")
    assert evasion_index < impact_index, (
        f"defense_evasion ({evasion_index}) must precede impact "
        f"({impact_index})"
    )


def test_healthcare_exfil_step_uses_https_to_cloud_storage() -> None:
    """Healthcare double-extortion crews push to attacker-staged
    cloud storage (S3 buckets, gsuite, custom Tor leak sites
    fronted by HTTPS). Pin the method to make the chain
    recognisable."""

    scenario = load_scenario(str(SCENARIO_PATH))
    exfil = next(s for s in scenario.steps if s.module == "exfiltration")
    assert exfil.params.get("method") == "https_to_cloud_storage"


def test_healthcare_attack_coverage_lists_t1003_001_and_t1486() -> None:
    """LSASS dump (T1003.001) and data encryption for impact (T1486)
    are the two most defender-relevant techniques in the chain."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert "T1003.001" in scenario.attack_techniques
    assert "T1486" in scenario.attack_techniques


def test_healthcare_runs_end_to_end_with_ten_successful_steps(
    tmp_path: Path,
) -> None:
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    assert result["status"] in {"success", "partial_success"}
    steps = result.get("steps") or []
    assert len(steps) == 10
    statuses = [step.get("status") for step in steps]
    assert all(s == "success" for s in statuses), (
        f"healthcare chain has a non-success step: {statuses}"
    )


def test_healthcare_collection_step_lands_on_pivoted_host(tmp_path: Path) -> None:
    """End-to-end: the collection step's target should be the
    pivoted host (``clinical-fileshare-01.example.lab``), not the
    fallback ``lab-host``. Pins the CollectionModule
    target_from_step propagation that landed alongside this
    scenario."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    collect = next(
        (s for s in steps if s.get("module") == "collection"),
        None,
    )
    assert collect is not None
    target = (collect.get("artifacts") or {}).get("target", "")
    assert target == "clinical-fileshare-01.example.lab", (
        f"collection step's target should be the pivoted host; got {target!r}"
    )
    # Propagation marker should also be set.
    propagated_from = (collect.get("artifacts") or {}).get(
        "target_propagated_from_step"
    )
    assert propagated_from == "lateral-pivot-to-fileshare"


def test_healthcare_exfil_and_impact_land_on_staging_host(tmp_path: Path) -> None:
    """End-to-end: exfil + impact should both land on the
    fileshare host (the staging target). This is what makes the
    double-extortion sequence coherent - same host emits the
    egress signal AND the bulk-rewrite signal."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    exfil = next(
        (s for s in steps if s.get("module") == "exfiltration"),
        None,
    )
    impact = next(
        (s for s in steps if s.get("module") == "impact"),
        None,
    )
    assert exfil is not None
    assert impact is not None
    exfil_target = (exfil.get("artifacts") or {}).get("target", "")
    impact_target = (impact.get("artifacts") or {}).get("target", "")
    assert exfil_target == "clinical-fileshare-01.example.lab", (
        f"exfil should source from the staging host; got {exfil_target!r}"
    )
    assert impact_target == "clinical-fileshare-01.example.lab", (
        f"impact should encrypt the staging host; got {impact_target!r}"
    )


def test_healthcare_chain_summary_produces_double_extortion_types(
    tmp_path: Path,
) -> None:
    """The chain summary in manifest.chain should include the
    canonical double-extortion-relevant types: c2_endpoint (leak
    site), credential (LSASS), host (recon + lateral),
    staged_file + collected_data (collection), exfil_package
    (egress)."""

    import json
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    run_id = result["run_id"]
    manifest = json.loads(
        (tmp_path / "output" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    chain = manifest.get("chain", {})
    produced = set(chain.get("produced_types") or [])
    expected_subset = {
        "c2_endpoint",
        "credential",
        "host",
        "exfil_package",
    }
    assert expected_subset.issubset(produced), (
        f"healthcare chain summary missing expected types: "
        f"{expected_subset - produced}; got {produced}"
    )


def test_healthcare_loader_execution_emits_decoded_command(tmp_path: Path) -> None:
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
