"""Per-step ``objective:`` field — schema-additive plumbing across surfaces.

The scenario YAML's top-level ``objective:`` block has surfaced in the
dashboard / report.md / copilot since the chain-narrative loop. PR #144
extends the same "why this is in the chain" treatment to individual
steps so a defender reading a timeline sees not just *what* each step
does (the existing ``name:``) but *why* the chain author put it there.

Pinned invariants (each layer):

1. ``ScenarioStep`` dataclass carries ``objective: str = ""`` (backwards
   compatible default).
2. ``load_scenario`` parses the per-step ``objective:`` field and
   strips leading/trailing whitespace.
3. The orchestrator threads ``step.objective`` into the per-step
   result dict so manifest / report.md / copilot can read it.
4. ``_normalise_steps`` includes ``objective`` in the manifest-friendly
   per-step dict.
5. The viewer timeline surfaces the objective inline beneath the step
   ``name`` cell (with a ``muted`` class for de-emphasis); the row
   stays in the same shape when objective is empty so older runs
   don't suddenly grow a stray ``<br>``.
6. ``write_markdown_report`` renders ``- Objective: <text>`` as the
   second bullet of each per-step section when the orchestrator passes
   a ``step_objectives`` map; the legacy report shape (no objective
   line) is preserved for callers that don't pass the map or for steps
   without an objective.
7. ``summarise_run_state`` accepts ``step_objectives`` and folds each
   per-step entry into the ``module_statuses`` block.
8. The prompt-formatter renders each per-step objective as a sub-bullet
   under its status line so the offline copilot template can ground
   per-step narrative in the operator's intent.
9. The flagship ``enterprise_intrusion_chain`` scenario carries
   per-step objectives for every step that has one declared, end-to-end.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.core.ai.copilot import (
    _format_run_summary_for_prompt,
    summarise_run_state,
)
from src.core.models import ModuleResult
from src.core.reporting.manifest import _normalise_steps
from src.core.reporting.run_reports import write_markdown_report
from src.core.reporting.viewer import _render_timeline
from src.core.scenario import Scenario, ScenarioStep, load_scenario


# ---------------------------------------------------------------------------
# 1. Parsing — ScenarioStep + load_scenario
# ---------------------------------------------------------------------------


def test_scenario_step_has_objective_field_with_empty_default() -> None:
    """``ScenarioStep.objective`` is schema-additive — empty by default."""
    step = ScenarioStep(
        step_id="x",
        name="x",
        module="m",
        params={},
    )
    assert step.objective == ""


def test_scenario_step_carries_objective_when_provided() -> None:
    step = ScenarioStep(
        step_id="x",
        name="x",
        module="m",
        params={},
        objective="Defender-facing why",
    )
    assert step.objective == "Defender-facing why"


def test_load_scenario_parses_per_step_objective(tmp_path: Path) -> None:
    """Scenario YAML's per-step ``objective:`` lands on ``ScenarioStep.objective``."""
    yaml_text = """
id: test
name: test
objective: |
  Top-level scenario objective.
attack_coverage: []
steps:
  - id: alpha
    name: First step
    module: discovery
    objective: |
      Walk the user profile to identify high-value documents.
  - id: beta
    name: Second step
    module: execution
    # No per-step objective declared — backwards-compat default.
"""
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(yaml_text, encoding="utf-8")
    scenario = load_scenario(scenario_file)
    assert scenario.steps[0].objective == (
        "Walk the user profile to identify high-value documents."
    )
    assert scenario.steps[1].objective == ""


def test_load_scenario_strips_objective_whitespace(tmp_path: Path) -> None:
    """Trailing newlines from YAML literal blocks must not survive."""
    yaml_text = """
id: test
name: test
attack_coverage: []
steps:
  - id: alpha
    name: First step
    module: discovery
    objective: '   surrounded by whitespace   '
"""
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(yaml_text, encoding="utf-8")
    scenario = load_scenario(scenario_file)
    assert scenario.steps[0].objective == "surrounded by whitespace"


# ---------------------------------------------------------------------------
# 2. Manifest — _normalise_steps carries objective
# ---------------------------------------------------------------------------


def test_normalise_steps_carries_objective(tmp_path: Path) -> None:
    """Per-step ``objective`` flows into the manifest's normalised step dict."""
    steps = [
        {
            "step_id": "alpha",
            "module": "discovery",
            "name": "First step",
            "objective": "Find sensitive files on the user host.",
            "status": "success",
            "message": "",
            "techniques": ["T1083"],
            "artifacts": {},
            "detections": {},
        },
        {
            "step_id": "beta",
            "module": "execution",
            "name": "Second step",
            "status": "success",
            "message": "",
            "techniques": ["T1059"],
            "artifacts": {},
            "detections": {},
        },
    ]
    normalised = _normalise_steps(steps, tmp_path)
    assert normalised[0]["objective"] == "Find sensitive files on the user host."
    # Second step omitted ``objective``: defaults to empty string for
    # schema stability, NOT None / missing key.
    assert normalised[1]["objective"] == ""


def test_normalise_steps_strips_objective_whitespace(tmp_path: Path) -> None:
    """Manifest stores stripped form, not raw YAML literal."""
    steps = [
        {
            "step_id": "alpha",
            "module": "discovery",
            "objective": "   leading and trailing   ",
        }
    ]
    normalised = _normalise_steps(steps, tmp_path)
    assert normalised[0]["objective"] == "leading and trailing"


# ---------------------------------------------------------------------------
# 3. Viewer timeline — objective inline beneath step name cell
# ---------------------------------------------------------------------------


def test_timeline_surfaces_step_objective_below_name() -> None:
    """Viewer timeline renders the objective as a muted line under name."""
    manifest = {
        "steps": [
            {
                "step_id": "alpha",
                "module": "discovery",
                "name": "First step",
                "objective": "Find sensitive files on the user host.",
                "status": "success",
                "techniques": ["T1083"],
            },
        ]
    }
    html = _render_timeline(manifest)
    assert "First step" in html
    # Objective lands as a separate inline element below the name,
    # styled as muted secondary content.
    assert '<br><span class="muted">Find sensitive files on the user host.</span>' in html


def test_timeline_omits_objective_block_when_step_has_none() -> None:
    """Without an objective, the name cell renders cleanly — no stray <br>."""
    manifest = {
        "steps": [
            {
                "step_id": "beta",
                "module": "execution",
                "name": "Second step",
                "status": "success",
                "techniques": [],
            },
        ]
    }
    html = _render_timeline(manifest)
    assert "Second step" in html
    # No <br> / muted block when the step doesn't declare an objective —
    # backwards-compat for older runs.
    assert "<br><span" not in html


def test_timeline_escapes_html_in_step_objective() -> None:
    """Operator-authored objective text must not break HTML escaping."""
    manifest = {
        "steps": [
            {
                "step_id": "alpha",
                "module": "discovery",
                "name": "Step",
                "objective": "Find <script>alert(1)</script> patterns.",
                "status": "success",
                "techniques": [],
            },
        ]
    }
    html = _render_timeline(manifest)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# 4. report.md — per-step Objective line surfaces
# ---------------------------------------------------------------------------


def _module_result(*, message: str = "ok") -> ModuleResult:
    return ModuleResult(
        status="success",
        module="discovery",
        message=message,
        techniques=["T1083"],
        artifacts={},
        detection_hints={
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection": {"Image|endswith": "x.exe"}, "condition": "selection"},
        },
        telemetry=[],
    )


def test_report_md_includes_per_step_objective_when_supplied(tmp_path: Path) -> None:
    """``write_markdown_report`` renders ``- Objective: ...`` per step."""
    results = {
        "discovery:enumerate-files": _module_result(),
    }
    detections: dict = {}
    report_path = write_markdown_report(
        tmp_path,
        "test scenario",
        results,
        detections,
        scenario_objective="top-level objective",
        step_objectives={
            "discovery:enumerate-files": "Walk the profile for high-value files.",
        },
    )
    text = report_path.read_text(encoding="utf-8")
    assert "### discovery:enumerate-files" in text
    assert "- Objective: Walk the profile for high-value files." in text


def test_report_md_omits_objective_line_when_no_text(tmp_path: Path) -> None:
    """Steps without an objective render the legacy shape — no stray bullet."""
    results = {
        "discovery:enumerate-files": _module_result(),
    }
    report_path = write_markdown_report(
        tmp_path,
        "test scenario",
        results,
        {},
    )
    text = report_path.read_text(encoding="utf-8")
    assert "- Objective:" not in text


def test_report_md_drops_empty_objective_text(tmp_path: Path) -> None:
    """Whitespace-only objective entry is treated as 'no objective'."""
    results = {
        "discovery:enumerate-files": _module_result(),
    }
    report_path = write_markdown_report(
        tmp_path,
        "test scenario",
        results,
        {},
        step_objectives={
            "discovery:enumerate-files": "   ",
        },
    )
    text = report_path.read_text(encoding="utf-8")
    assert "- Objective:" not in text


# ---------------------------------------------------------------------------
# 5. Copilot summariser — per-step objectives flow into module_statuses
# ---------------------------------------------------------------------------


def test_summarise_run_state_attaches_per_step_objective() -> None:
    """``module_statuses`` entry carries the objective when one exists."""
    summary = summarise_run_state(
        run_id="run-test-1",
        scenario_name="x",
        scenario_objective="top",
        module_results={
            "discovery:enumerate-files": _module_result(),
            "execution:loader": _module_result(),
        },
        step_objectives={
            "discovery:enumerate-files": "Find high-value files.",
        },
    )
    statuses = {entry["step"]: entry for entry in summary["module_statuses"]}
    assert statuses["discovery:enumerate-files"]["objective"] == "Find high-value files."
    # The other step has no objective — entry must NOT carry the key.
    assert "objective" not in statuses["execution:loader"]


def test_summarise_run_state_truncates_long_per_step_objective() -> None:
    """Long per-step objective values cap at 240 chars with ellipsis."""
    very_long = "x" * 500
    summary = summarise_run_state(
        run_id="run-test-2",
        module_results={
            "m:s": _module_result(),
        },
        step_objectives={"m:s": very_long},
    )
    rendered = summary["module_statuses"][0]["objective"]
    assert len(rendered) <= 240
    assert rendered.endswith("…")


def test_format_run_summary_for_prompt_surfaces_per_step_objective() -> None:
    """Prompt-formatter emits the ``objective:`` sub-bullet under step status."""
    summary = summarise_run_state(
        run_id="run-test-3",
        scenario_name="enterprise",
        scenario_objective="top objective",
        module_results={
            "discovery:enumerate-files": _module_result(),
        },
        step_objectives={
            "discovery:enumerate-files": "Find high-value files.",
        },
    )
    prompt_block = _format_run_summary_for_prompt(summary)
    assert "- discovery:enumerate-files: success" in prompt_block
    # Sub-bullet attaches under the status line.
    assert "      objective: Find high-value files." in prompt_block


def test_format_run_summary_for_prompt_omits_objective_line_when_missing() -> None:
    """No objective => no ``      objective:`` line, no stray indent."""
    summary = summarise_run_state(
        run_id="run-test-4",
        scenario_name="x",
        module_results={
            "discovery:enumerate-files": _module_result(),
        },
    )
    prompt_block = _format_run_summary_for_prompt(summary)
    assert "      objective:" not in prompt_block


# ---------------------------------------------------------------------------
# 6. End-to-end via the flagship enterprise_intrusion_chain scenario
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "step_id,expected_substring",
    [
        ("stage-infrastructure", "lookalike domain"),
        ("phish-delivery", "encoded loader"),
        ("loader-execution", "PowerShell loader"),
        ("masquerade", "svchost.exe"),
        ("enumerate-files", "high-value documents"),
        ("harvest-browser-creds", "stored browser credentials"),
        ("lateral-to-fileshare", "PsExec"),
        ("stage-collected-data", "high-value blob"),
        ("c2-channel", "freshly-registered attacker domain"),
        ("exfil-over-c2", "egress correlation"),
        ("ransomware-impact", "encrypt"),
    ],
)
def test_enterprise_chain_scenario_carries_per_step_objectives(
    step_id: str, expected_substring: str
) -> None:
    """Every meaningfully-shaped step in the showcase has a clear objective.

    The flagship ``enterprise_intrusion_chain`` is the canonical chain
    we ship — pinning per-step objectives end-to-end means external
    operators / contributors immediately see the schema in action when
    they read the file.
    """
    scenario_path = Path("scenarios") / "enterprise_intrusion_chain.yaml"
    scenario = load_scenario(scenario_path)
    step = next((s for s in scenario.steps if s.step_id == step_id), None)
    assert step is not None, f"step {step_id!r} not found in showcase scenario"
    assert step.objective, f"step {step_id!r} has no objective declared"
    assert expected_substring.lower() in step.objective.lower(), (
        step_id,
        step.objective,
    )


def test_enterprise_chain_scenario_objectives_round_trip_through_yaml(
    tmp_path: Path,
) -> None:
    """The YAML on disk parses cleanly and yields non-empty objectives."""
    scenario_path = Path("scenarios") / "enterprise_intrusion_chain.yaml"
    raw = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    declared = {
        step["id"]: str(step.get("objective") or "").strip()
        for step in raw.get("steps", [])
        if isinstance(step, dict)
    }
    populated = [step_id for step_id, objective in declared.items() if objective]
    # The flagship scenario carries per-step objectives on every step
    # in the backbone of the kill chain.
    assert len(populated) >= 11, populated
