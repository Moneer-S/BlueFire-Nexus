"""CLI surfaces for the scenario planner.

The :mod:`src.core.scenario_planner` module exposes
``offer_next_steps`` / ``explain_chain`` / ``suggest_scenario_variants``
in Python; this PR adds three CLI commands that wrap them so an
operator can interrogate the planner from the terminal without writing
Python.

These tests pin:

- the three commands run cleanly against shipped scenarios;
- the structured (``--json``) output shape stays stable;
- the rich-table / panel rendering surfaces the expected fields;
- the underlying planner functions are NOT being silently bypassed
  (a future regression that drops the scenario_planner dependency
  would surface here).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from src.core.cli import app


_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
_FIN7_SCENARIO = _SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml"
_APT29_SCENARIO = _SCENARIOS_DIR / "apt29_credential_access.yaml"
_INSIDER_SCENARIO = _SCENARIOS_DIR / "insider_exfil_dns.yaml"


# ---------------------------------------------------------------------------
# planner-suggest
# ---------------------------------------------------------------------------


def test_planner_suggest_runs_against_shipped_scenario() -> None:
    """The command exits cleanly and surfaces a Next-step suggestions
    table when run against a tier-1 scenario."""

    runner = CliRunner()
    result = runner.invoke(app, ["planner-suggest", str(_FIN7_SCENARIO)])
    assert result.exit_code == 0, result.stdout
    assert "Next-step suggestions" in result.stdout
    # FIN7's scenario name comes through the panel title.
    assert "FIN7" in result.stdout


def test_planner_suggest_json_mode_emits_structured_payload() -> None:
    """``--json`` returns a list of dicts with the suggestion shape so
    automation can pipe the output into another tool."""

    runner = CliRunner()
    result = runner.invoke(
        app, ["planner-suggest", str(_FIN7_SCENARIO), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    if parsed:
        first = parsed[0]
        # Pin the documented fields of NextStepSuggestion.
        assert {
            "module",
            "rank",
            "score",
            "required_satisfied",
            "optional_satisfied",
            "required_missing",
            "produces",
            "rationale",
        }.issubset(first.keys())


def test_planner_suggest_respects_limit() -> None:
    """``--limit`` caps the number of suggestions returned."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "planner-suggest",
            str(_FIN7_SCENARIO),
            "--limit",
            "3",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert len(parsed) <= 3


# ---------------------------------------------------------------------------
# planner-explain
# ---------------------------------------------------------------------------


def test_planner_explain_runs_against_shipped_scenario() -> None:
    """The explain command renders a chain explanation panel for a
    shipped scenario."""

    runner = CliRunner()
    result = runner.invoke(app, ["planner-explain", str(_APT29_SCENARIO)])
    assert result.exit_code == 0, result.stdout
    assert "Chain explanation" in result.stdout
    assert "APT29" in result.stdout


def test_planner_explain_filters_warnings_to_missing_required(
    tmp_path: Path,
) -> None:
    """``ChainState.warnings`` should carry only ``missing_required``
    rows when the planner CLI builds it from the static graph.

    The static graph also emits ``unused_emission`` /
    ``high_value_unused`` for dangling producer types; forwarding
    those into ``ChainState.warnings`` would mislead
    ``planner-explain`` consumers because the runtime warning
    surface that ``explain_chain`` semantically corresponds to is
    consumer-side only ("required input not produced upstream").
    Codex P2 on PR #168.
    """

    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    # Scenario produces a c2_endpoint with no consumer downstream
    # → triggers a high_value_unused warning in the static graph.
    # If the CLI forwards it into ChainState.warnings, the JSON
    # output's unsatisfied_warnings list will include it (incorrect).
    (scenarios_dir / "dangling.yaml").write_text(
        "id: dangling-c2\n"
        "name: Dangling c2_endpoint scenario\n"
        "objective: Stand up c2 with no consumer downstream.\n"
        "fail_fast: false\n"
        "steps:\n"
        "  - id: stage\n"
        "    name: Stage adversary domain\n"
        "    module: resource_development\n"
        "    params:\n"
        "      resource_type: domain\n"
        "      target: x.example.invalid\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "planner-explain",
            str(scenarios_dir / "dangling.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    # The dangling c2_endpoint is a producer-side warning. It must
    # NOT appear under unsatisfied_warnings (which is the consumer-
    # side surface).
    for warning in parsed["unsatisfied_warnings"]:
        assert warning.get("severity") == "missing_required", (
            f"non-missing_required warning leaked through: {warning}"
        )


def test_planner_explain_json_mode_emits_structured_payload() -> None:
    """``--json`` returns the explanation dict so automation can pipe
    it forward."""

    runner = CliRunner()
    result = runner.invoke(
        app, ["planner-explain", str(_APT29_SCENARIO), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert {
        "produced_types",
        "unused_emissions",
        "unsatisfied_warnings",
        "narrative",
    }.issubset(parsed.keys())
    # APT29 has rich chaining — produced_types should be non-empty.
    assert isinstance(parsed["produced_types"], list)
    assert parsed["narrative"]


# ---------------------------------------------------------------------------
# planner-variants
# ---------------------------------------------------------------------------


def test_planner_variants_runs_against_shipped_scenario() -> None:
    """The variants command renders one tree per generated variant."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "planner-variants",
            str(_INSIDER_SCENARIO),
            "--count",
            "2",
            "--seed",
            "42",
        ],
    )
    assert result.exit_code == 0, result.stdout
    # Count ``Variant N`` headers — should match --count.
    assert result.stdout.count("Variant 1") >= 1
    assert result.stdout.count("Variant 2") >= 1


def test_planner_variants_json_mode_emits_step_lists() -> None:
    """``--json`` returns a list-of-lists (one inner list per variant,
    each holding step dicts) so automation can pipe variants into
    other tooling."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "planner-variants",
            str(_INSIDER_SCENARIO),
            "--count",
            "3",
            "--seed",
            "42",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) == 3
    for variant in parsed:
        assert isinstance(variant, list)
        for step in variant:
            assert "module" in step
            assert "step_id" in step or "id" in step or "name" in step


def test_planner_variants_seed_is_reproducible() -> None:
    """Same ``--seed`` → byte-identical JSON across two invocations."""

    runner = CliRunner()
    result_a = runner.invoke(
        app,
        [
            "planner-variants",
            str(_INSIDER_SCENARIO),
            "--count",
            "3",
            "--seed",
            "1234",
            "--json",
        ],
    )
    result_b = runner.invoke(
        app,
        [
            "planner-variants",
            str(_INSIDER_SCENARIO),
            "--count",
            "3",
            "--seed",
            "1234",
            "--json",
        ],
    )
    assert result_a.exit_code == 0 and result_b.exit_code == 0
    assert result_a.stdout == result_b.stdout


def test_planner_variants_handles_scenario_without_mutable_steps(tmp_path: Path) -> None:
    """A scenario where no step matches a mutation catalog slot must
    not raise — the command surfaces an empty-state message instead."""

    scenario = tmp_path / "no_mutations.yaml"
    # ``resource_development`` has no mutation catalog slots.
    scenario.write_text(
        "id: no-mutations\n"
        "name: No mutable steps\n"
        "objective: scenario without any catalog-slotted modules\n"
        "fail_fast: false\n"
        "steps:\n"
        "  - id: stage\n"
        "    name: Stage\n"
        "    module: resource_development\n"
        "    params:\n"
        "      resource_type: domain\n"
        "      target: x.example.invalid\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["planner-variants", str(scenario), "--count", "2", "--seed", "1"],
    )
    # Either the no-mutations message OR an unmutated variants list
    # is acceptable — both are valid behaviour for a chain with no
    # catalog slots. Pin that the command at least exits cleanly.
    assert result.exit_code == 0, result.stdout
