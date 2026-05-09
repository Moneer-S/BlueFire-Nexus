"""Realism / chain-pair pins for the insider DNS exfiltration scenario.

The scenario was deepened from a 4-step
discovery/exfiltration/c2/obfuscation stub into a 7-step insider
chain that mirrors documented insider-threat tradecraft: outside
accomplice stages a DNS-tunnel domain, the insider enumerates
sensitive HR / payroll files on their authorised workstation,
stages them into a local archive, timestomps the archive to slow
forensic triage, opens DNS-channel C2 to the staged domain,
applies DNS protocol obfuscation, and exfiltrates over the DNS
tunnel.

Key distinguishers from the FIN7 / APT29 / healthcare patterns:

- No phishing / no initial-access vector (insider has authorised
  access).
- No execution step (no loader; insider opens a console).
- No credential harvest (insider has legitimate creds).
- No lateral movement (insider's authorised workstation IS the
  staging host).
- ``defense_evasion`` uses ``timestomping`` rather than
  ``impair_defenses`` because the insider rarely has admin rights.

These tests pin the structural shape so a future edit that drops
a chain pair, an objective, or one of the insider-specific hooks
(no execution / no credential_access / timestomping precursor)
is caught explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATH = Path("scenarios") / "insider_exfil_dns.yaml"


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


def test_insider_scenario_loads_and_has_seven_steps() -> None:
    scenario = load_scenario(str(SCENARIO_PATH))
    assert len(scenario.steps) == 7
    expected_modules = [
        "resource_development",
        "discovery",
        "collection",
        "defense_evasion",
        "command_control",
        "network_obfuscator",
        "exfiltration",
    ]
    actual = [step.module for step in scenario.steps]
    assert actual == expected_modules, (
        f"insider scenario step order changed; expected "
        f"{expected_modules}, got {actual}"
    )


def test_insider_every_step_has_objective() -> None:
    scenario = load_scenario(str(SCENARIO_PATH))
    missing = [s.step_id for s in scenario.steps if not s.objective.strip()]
    assert missing == [], (
        f"insider scenario steps missing objective: {missing}"
    )


def test_insider_does_not_have_initial_access_or_execution() -> None:
    """Defining characteristic of insider scenarios: no phishing,
    no exploit, no loader. The chain skips initial_access AND
    execution because the insider has authorised access and runs
    against their own workstation."""

    scenario = load_scenario(str(SCENARIO_PATH))
    modules = {step.module for step in scenario.steps}
    assert "initial_access" not in modules, (
        "insider scenario must not include initial_access"
    )
    assert "execution" not in modules, (
        "insider scenario must not include a loader-execution step"
    )
    assert "credential_access" not in modules, (
        "insider has authorised access; no credential harvest needed"
    )


def test_insider_collection_propagates_target_from_discovery() -> None:
    """Collection should stage on the same workstation the
    discovery step ran on - validates the new
    target_from_step plumbing on CollectionModule (PR #162)."""

    scenario = load_scenario(str(SCENARIO_PATH))
    collect = next(s for s in scenario.steps if s.module == "collection")
    assert collect.params.get("target_from_step") == "enumerate-sensitive-files"
    assert collect.params.get("technique") == "archive_compressed"


def test_insider_c2_step_propagates_endpoint_from_resource_development() -> None:
    """The DNS C2 step pulls the staged tunnel domain from the
    resource_development step so registrar intelligence ties
    directly to the tunnel destination."""

    scenario = load_scenario(str(SCENARIO_PATH))
    c2 = next(s for s in scenario.steps if s.module == "command_control")
    assert c2.params.get("c2_endpoint_from_step") == "stage-tunnel-domain"
    assert c2.params.get("channel") == "dns"


def test_insider_exfil_step_uses_dns_tunneling() -> None:
    """DNS tunneling is the defining exfil method for this
    scenario; pin it so a future edit can't silently swap it."""

    scenario = load_scenario(str(SCENARIO_PATH))
    exfil = next(s for s in scenario.steps if s.module == "exfiltration")
    assert exfil.params.get("method") == "dns_tunneling"
    assert exfil.params.get("target_from_step") == "stage-archive"


def test_insider_defense_evasion_uses_timestomping() -> None:
    """Insider tradecraft favours timestomping (filesystem-only
    permissions) over impair_defenses (admin-required service
    stop). Pin that distinction."""

    scenario = load_scenario(str(SCENARIO_PATH))
    evasion = next(s for s in scenario.steps if s.module == "defense_evasion")
    assert evasion.params.get("technique") == "timestomping"


def test_insider_attack_coverage_lists_t1071_004_and_t1070_006() -> None:
    """T1071.004 (DNS C2) and T1070.006 (timestomping) are the
    two most defender-relevant techniques in the chain."""

    scenario = load_scenario(str(SCENARIO_PATH))
    assert "T1071.004" in scenario.attack_techniques
    assert "T1070.006" in scenario.attack_techniques


def test_insider_runs_end_to_end_with_seven_successful_steps(
    tmp_path: Path,
) -> None:
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    assert result["status"] in {"success", "partial_success"}
    steps = result.get("steps") or []
    assert len(steps) == 7
    statuses = [step.get("status") for step in steps]
    assert all(s == "success" for s in statuses), (
        f"insider chain has a non-success step: {statuses}"
    )


def test_insider_chain_anchors_on_single_workstation(tmp_path: Path) -> None:
    """The whole chain anchors on the insider's authorised
    workstation - discovery, collection, evasion, and exfil
    should all reference the same host. This is the structural
    distinction from FIN7 / APT29 / healthcare (which span
    multiple hosts via lateral movement)."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    target_hosts: set[str] = set()
    for step in steps:
        module = step.get("module")
        artifacts = step.get("artifacts") or {}
        if module in {"collection", "defense_evasion", "exfiltration"}:
            target = artifacts.get("target", "")
            if target:
                target_hosts.add(target)
    # Every targeted host should be the insider's workstation.
    assert target_hosts == {"insider-finance-laptop.example.lab"}, (
        f"insider chain spans multiple hosts: {target_hosts}"
    )


def test_insider_chain_summary_produces_dns_tunnel_types(tmp_path: Path) -> None:
    """The chain summary should produce the canonical
    insider-DNS-exfil types: c2_endpoint (the staged tunnel
    domain), exfil_package (the egress bundle), and
    collected_data + staged_file (the staged archive)."""

    import json
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    run_id = result["run_id"]
    manifest = json.loads(
        (tmp_path / "output" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    chain = manifest.get("chain", {})
    produced = set(chain.get("produced_types") or [])
    expected_subset = {"c2_endpoint", "exfil_package"}
    assert expected_subset.issubset(produced), (
        f"insider chain summary missing expected types: "
        f"{expected_subset - produced}; got {produced}"
    )


def test_insider_collection_records_propagation_marker(tmp_path: Path) -> None:
    """End-to-end: the collection step's artifacts should record
    the target_propagated_from_step marker pointing at the
    discovery step (validates PR #162's CollectionModule
    propagation gap fix end-to-end)."""

    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(SCENARIO_PATH))
    steps = result.get("steps") or []
    collect = next(
        (s for s in steps if s.get("module") == "collection"),
        None,
    )
    assert collect is not None
    artifacts = collect.get("artifacts") or {}
    assert artifacts.get("target_propagated_from_step") == "enumerate-sensitive-files"
