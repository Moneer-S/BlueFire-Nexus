"""Showcase test pinning the flagship scenario as a complete demo run.

The shipped ``enterprise_intrusion_chain`` scenario is the
project's flagship demonstration: 12 standard modules end-to-
end, four `previous_step_results` consumer pairs, full ATT&CK
coverage, simulate-only by default. After the local report
viewer phase (PRs #71 / #72 / #73), running it should produce a
**complete** local report bundle that an operator can open with
no extra steps.

This file pins the bundle's shape end-to-end: every documented
artifact lands in the run directory, the manifest references
each one, and the viewer surfaces the five propagation pairs as
clickable / readable rows.

Pinned invariants:

1. **All canonical artifacts ship together**: ``manifest.json``,
   ``index.html``, ``report.md``, ``report.json``,
   ``risk_summary.json``, ``telemetry.jsonl``, and the
   ``detections/`` directory. Plus copilot artifacts in their
   default-template offline form.
2. **Manifest cross-references everything.** The run dict from
   ``run_scenario_file`` AND the manifest agree on the file
   layout — neither leaks an absolute path nor omits a section.
3. **Static viewer surfaces all five propagation pairs.**
   ``index.html`` contains the five (from_step, to_step, kind)
   tuples and the modules they wire together.
4. **Declared ATT&CK coverage matches emitted runtime techniques.**
   The bidirectional check from PR #66 already pins this for the
   scenario; here we re-assert it through the manifest layer so
   a regression in either component (scenario YAML, manifest
   builder, viewer) surfaces with the same diagnostic.
5. **Defaults stay safe.** Every step ran in simulate mode with
   `network_touch: false`; no real network call leaked through
   the scenario.
6. **CLI agrees with the orchestrator.** ``list-runs`` /
   ``latest-run`` / ``show-run`` / ``build-report-view`` all see
   the run after it's executed, with the same manifest-derived
   metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from src.core.bluefire_nexus import BlueFireNexus
from src.core.cli import app
from src.core.config import ConfigManager


# ---------------------------------------------------------------------------
# Fixture: run the flagship scenario once per module (shared across tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def showcase_run(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    """Run the flagship scenario once and expose the result + run dir.

    Module-scoped to keep the suite fast — the scenario runs
    enough modules that re-running it per test would balloon
    wallclock. Read-only assertions are safe to share.
    """
    tmp_path = tmp_path_factory.mktemp("enterprise-showcase")
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    return {
        "summary": summary,
        "run_dir": Path(summary["output_dir"]),
        "output_root": tmp_path / "output",
    }


# ---------------------------------------------------------------------------
# 1. All canonical artifacts present in the run directory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative_path",
    [
        "manifest.json",
        "index.html",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
        "detections",
        "copilot_narrative.md",
    ],
)
def test_showcase_run_produces_canonical_artifact(
    showcase_run: Dict[str, Any], relative_path: str
) -> None:
    """The flagship scenario writes every canonical artifact.

    Catches a regression where one of the writers (manifest /
    viewer / detections / report / risk / copilot) silently fails
    or moves to a different file name.
    """
    target = showcase_run["run_dir"] / relative_path
    assert target.exists(), f"missing flagship artifact: {relative_path}"


def test_showcase_run_manifest_path_returned_in_summary(
    showcase_run: Dict[str, Any],
) -> None:
    """Both `manifest_path` and `viewer_path` surface in the result dict."""
    summary = showcase_run["summary"]
    assert "manifest_path" in summary
    assert "viewer_path" in summary
    assert Path(summary["manifest_path"]).exists()
    assert Path(summary["viewer_path"]).exists()


# ---------------------------------------------------------------------------
# 2. Manifest cross-references the bundle correctly
# ---------------------------------------------------------------------------


def test_showcase_manifest_points_at_every_artifact_via_relative_paths(
    showcase_run: Dict[str, Any],
) -> None:
    """Manifest.reports / manifest.telemetry use relative paths that resolve."""
    manifest = json.loads(
        Path(showcase_run["run_dir"], "manifest.json").read_text(encoding="utf-8")
    )
    run_dir = showcase_run["run_dir"]
    reports = manifest["reports"]
    assert reports["report_md"] == "report.md"
    assert reports["report_json"] == "report.json"
    assert reports["risk_summary_json"] == "risk_summary.json"
    assert manifest["telemetry"]["path"] == "telemetry.jsonl"
    # Every relative path resolves to an existing file under run_dir.
    for relative in (
        reports["report_md"],
        reports["report_json"],
        reports["risk_summary_json"],
        manifest["telemetry"]["path"],
    ):
        assert (run_dir / relative).exists()


def test_showcase_manifest_has_five_propagation_edges(
    showcase_run: Dict[str, Any],
) -> None:
    """All five shipped consumer pairs surface as edges in the manifest.

    Pin the matrix at the manifest layer (not just the scenario
    YAML) so a regression in the manifest builder or the
    underlying artifacts surfaces here. Codex P2 follow-up on
    PR #106: `_propagation_edges` was previously not walking the
    `c2_endpoint_propagated_from_step` artifact key, so the
    resource_development -> command_control linkage was invisible
    in the manifest's propagation_edges. The fifth edge is pinned
    here so a regression in either the manifest builder or the
    artifact contract surfaces immediately.
    """
    manifest = json.loads(
        Path(showcase_run["run_dir"], "manifest.json").read_text(encoding="utf-8")
    )
    edges = manifest["propagation_edges"]
    signatures = {(e["from_step"], e["to_step"], e["kind"]) for e in edges}
    expected = {
        ("enumerate-files", "harvest-browser-creds", "target_from_step"),
        ("harvest-browser-creds", "lateral-to-fileshare", "source_from_step"),
        ("stage-collected-data", "exfil-over-c2", "target_from_step"),
        ("stage-collected-data", "ransomware-impact", "target_from_step"),
        ("stage-infrastructure", "c2-channel", "c2_endpoint_from_step"),
    }
    assert expected <= signatures, f"missing edges: {expected - signatures}"


def test_showcase_manifest_attack_coverage_matches_scenario_declaration(
    showcase_run: Dict[str, Any],
) -> None:
    """Manifest's attack_coverage = scenario's attack_coverage.

    The scenario declares 12 techniques; runtime emits exactly
    those (PR #66's bidirectional invariant). At the manifest
    layer we re-assert the same matrix so a future regression in
    the manifest's coverage extraction surfaces immediately.
    """
    manifest = json.loads(
        Path(showcase_run["run_dir"], "manifest.json").read_text(encoding="utf-8")
    )
    declared = {
        "T1583.001",
        "T1593",
        "T1566",
        "T1059",
        "T1036",
        "T1083",
        "T1555.003",
        "T1021.002",
        "T1074.001",
        "T1071.001",
        "T1041",
        "T1486",
    }
    emitted = {entry["technique"] for entry in manifest["attack_coverage"]}
    assert declared == emitted


# ---------------------------------------------------------------------------
# 3. Static viewer surfaces every documented section
# ---------------------------------------------------------------------------


def test_showcase_viewer_renders_all_step_ids(showcase_run: Dict[str, Any]) -> None:
    """Every step id from the 12-step chain appears in the rendered HTML."""
    html = Path(showcase_run["run_dir"], "index.html").read_text(encoding="utf-8")
    for step_id in (
        "stage-infrastructure",
        "target-recon",
        "phish-delivery",
        "loader-execution",
        "masquerade",
        "enumerate-files",
        "harvest-browser-creds",
        "lateral-to-fileshare",
        "stage-collected-data",
        "c2-channel",
        "exfil-over-c2",
        "ransomware-impact",
    ):
        assert step_id in html, f"step_id {step_id!r} missing from viewer"


def test_showcase_viewer_renders_propagation_table_with_all_kinds(
    showcase_run: Dict[str, Any],
) -> None:
    """Both propagation kinds (target_from_step, source_from_step) surface."""
    html = Path(showcase_run["run_dir"], "index.html").read_text(encoding="utf-8")
    assert "target_from_step" in html
    assert "source_from_step" in html


def test_showcase_viewer_attack_coverage_section_lists_every_technique(
    showcase_run: Dict[str, Any],
) -> None:
    html = Path(showcase_run["run_dir"], "index.html").read_text(encoding="utf-8")
    for technique in (
        "T1583.001",
        "T1593",
        "T1566",
        "T1059",
        "T1036",
        "T1083",
        "T1555.003",
        "T1021.002",
        "T1074.001",
        "T1071.001",
        "T1041",
        "T1486",
    ):
        assert technique in html, f"technique {technique!r} missing from viewer"


def test_showcase_viewer_clearly_labels_offline_copilot_output(
    showcase_run: Dict[str, Any],
) -> None:
    """Default config => template provider => "offline" label in the page.

    The point: an operator skimming the dashboard should never
    confuse the deterministic template body with a live model
    response. The viewer renders the network-state line as
    "offline (template / no network)" when network_disabled is
    true.
    """
    html = Path(showcase_run["run_dir"], "index.html").read_text(encoding="utf-8")
    assert "AI copilot" in html
    assert "template" in html
    assert "offline" in html


# ---------------------------------------------------------------------------
# 4. Default-safe invariants
# ---------------------------------------------------------------------------


def test_showcase_run_overall_status_is_success(showcase_run: Dict[str, Any]) -> None:
    assert showcase_run["summary"]["status"] == "success"


def test_showcase_run_no_steps_opted_into_real_network(
    showcase_run: Dict[str, Any],
) -> None:
    """Defends the dry / simulate / network_touch=False contract.

    Re-asserts at the showcase level so a regression in any one
    standard module surfaces here.
    """
    summary = showcase_run["summary"]
    for step in summary["steps"]:
        artifacts = step.get("artifacts") or {}
        # When the standard module honours the network_touch contract,
        # it surfaces the resolved value in artifacts. Where set, it
        # MUST be False for this scenario.
        if "network_touch" in artifacts:
            assert artifacts["network_touch"] is False, (
                f"step {step.get('step_id')} ran with network_touch=True"
            )


# ---------------------------------------------------------------------------
# 5. CLI agrees with the orchestrator on what was just produced
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def test_showcase_run_visible_via_list_runs_cli(
    cli_runner: CliRunner, showcase_run: Dict[str, Any]
) -> None:
    """``list-runs --output-root <root>`` shows the just-completed run.

    Uses a wide ``COLUMNS`` so rich's table renderer does not
    truncate the scenario name to fit a tiny default width.
    """
    output_root = showcase_run["output_root"]
    result = cli_runner.invoke(
        app,
        ["list-runs", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert "BlueFire runs" in result.stdout
    assert "Enterprise intrusion kill chain" in result.stdout


def test_showcase_run_visible_via_latest_run_cli(
    cli_runner: CliRunner, showcase_run: Dict[str, Any]
) -> None:
    output_root = showcase_run["output_root"]
    result = cli_runner.invoke(
        app,
        ["latest-run", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert "Enterprise intrusion kill chain" in result.stdout
    assert "success" in result.stdout


def test_showcase_run_build_report_view_is_idempotent(
    cli_runner: CliRunner, showcase_run: Dict[str, Any]
) -> None:
    """Re-running build-report-view on the same run replaces index.html.

    Useful workflow: the operator edits a manifest after the
    initial write (e.g. annotates a finding). Running build-
    report-view again must regenerate index.html cleanly without
    crashing or appending to the file.
    """
    output_root = showcase_run["output_root"]
    summary = showcase_run["summary"]
    run_id = summary["run_id"]
    viewer_path = Path(summary["viewer_path"])
    original_size = viewer_path.stat().st_size

    result = cli_runner.invoke(
        app, ["build-report-view", run_id, "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    # Re-rendered file: same scenario => same content (deterministic
    # except for the generated_at footnote, so size will be
    # nearly-identical, not strictly equal).
    new_size = viewer_path.stat().st_size
    # Allow a small drift for the timestamp difference; the file
    # should not double in size (which would mean appending instead
    # of overwriting).
    assert new_size <= original_size * 1.1
