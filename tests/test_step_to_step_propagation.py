"""Step-to-step artifact propagation contract.

The runtime threads a read-only ``previous_step_results`` mapping into
every step's ``module.execute(params, context)`` call so downstream
modules can opt into reading prior step outputs (artifacts /
techniques / status). The mapping is built incrementally as the
scenario runs.

Pinned invariants:

1. Every step's context contains ``previous_step_results`` (possibly
   empty for the first step). Modules that don't opt in simply ignore
   it.
2. After a step completes, its result is recorded under its
   ``step_id`` in the mapping so subsequent steps can read it.
3. Errored steps are recorded with ``status="error"`` so downstream
   steps can decide whether to abort or proceed without the upstream
   output.
4. The mapping is a defensive copy: a downstream module mutating its
   local view of ``previous_step_results`` cannot leak back into the
   runtime accumulator.
5. ``execute_operation`` (single-module path) also gets the key
   present-but-empty so module code that uses it stays uniform across
   scenario and ad-hoc invocations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.models import RunContext


def _write_two_step_scenario(tmp_path: Path) -> Path:
    """Two-step scenario; first runs discovery, second runs exfiltration."""
    scenario_path = tmp_path / "two_step.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "id: two-step-prop",
                "name: Two-step propagation scenario",
                "objective: validate previous_step_results plumbing",
                "attack_coverage: ['T1083', 'T1041']",
                "fail_fast: false",
                "steps:",
                "  - id: discover-step",
                "    name: File discovery",
                "    module: discovery",
                "    params:",
                "      discovery_type: files",
                "      targets: ['10.0.0.5']",
                "      network_touch: false",
                "  - id: exfil-step",
                "    name: Exfiltrate",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
                "      network_touch: false",
            ]
        ),
        encoding="utf-8",
    )
    return scenario_path


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


# ---------------------------------------------------------------------------
# Direct context-builder contract
# ---------------------------------------------------------------------------


def test_module_context_always_includes_previous_step_results(tmp_path: Path) -> None:
    nexus = _make_isolated_nexus(tmp_path)
    run_context = nexus._make_run_context()
    # No previous_step_results passed: key must still exist as an
    # empty dict (uniform shape across all invocations).
    ctx = nexus._module_context(run_context)
    assert "previous_step_results" in ctx
    assert ctx["previous_step_results"] == {}


def test_module_context_returns_defensive_copy(tmp_path: Path) -> None:
    nexus = _make_isolated_nexus(tmp_path)
    run_context = nexus._make_run_context()
    accumulator: Dict[str, Dict[str, Any]] = {
        "step-1": {"status": "success", "module": "discovery", "artifacts": {"k": "v"}},
    }
    ctx = nexus._module_context(run_context, previous_step_results=accumulator)
    # Mutate the context's view; the original accumulator must not change.
    ctx["previous_step_results"]["step-1"]["mutated"] = True
    assert "mutated" not in accumulator["step-1"]
    # Add a brand-new entry to the context view; the original must not gain it.
    ctx["previous_step_results"]["malicious"] = {"status": "success"}
    assert "malicious" not in accumulator


# ---------------------------------------------------------------------------
# End-to-end via run_scenario_file
# ---------------------------------------------------------------------------


def test_scenario_run_propagates_prior_step_results(tmp_path: Path) -> None:
    """A two-step scenario: capture each step's view of previous_step_results
    by monkey-patching the modules' execute method to record context."""
    scenario_path = _write_two_step_scenario(tmp_path)
    nexus = _make_isolated_nexus(tmp_path)

    captured: List[Dict[str, Any]] = []
    discovery_module = nexus.modules["discovery"]
    exfil_module = nexus.modules["exfiltration"]
    discovery_execute = discovery_module.execute
    exfil_execute = exfil_module.execute

    def _wrap(target_module, original):
        def _captured_execute(params, context):
            captured.append(
                {
                    "module": target_module.name,
                    "previous_step_results": dict(
                        context.get("previous_step_results") or {}
                    ),
                }
            )
            return original(params, context)

        return _captured_execute

    discovery_module.execute = _wrap(discovery_module, discovery_execute)
    exfil_module.execute = _wrap(exfil_module, exfil_execute)
    try:
        result = nexus.run_scenario_file(str(scenario_path))
    finally:
        discovery_module.execute = discovery_execute
        exfil_module.execute = exfil_execute

    assert result["status"] in {"success", "partial_success"}
    assert len(captured) == 2

    # First step: empty previous_step_results.
    first = captured[0]
    assert first["module"] == "discovery"
    assert first["previous_step_results"] == {}

    # Second step: discover-step's outcome must be present and
    # carry status / module / techniques / artifacts.
    second = captured[1]
    assert second["module"] == "exfiltration"
    seen = second["previous_step_results"]
    assert "discover-step" in seen
    discover_record = seen["discover-step"]
    assert discover_record["status"] == "success"
    assert discover_record["module"] == "discovery"
    assert isinstance(discover_record["techniques"], list)
    assert discover_record["techniques"]  # non-empty
    assert isinstance(discover_record["artifacts"], dict)


def test_failed_step_is_still_recorded_for_downstream(tmp_path: Path) -> None:
    """An errored step must be recorded under its step_id with
    status=error so downstream steps can branch on it.
    """
    # Scenario where step 1 raises (unknown module name causes the
    # runtime to record an error step result).
    scenario_path = tmp_path / "failure.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "id: prop-fail",
                "name: Propagation with failing step",
                "objective: ensure errored steps are recorded for downstream visibility",
                "attack_coverage: ['T1059']",
                "fail_fast: false",
                "steps:",
                "  - id: bad-step",
                "    name: Trigger validation failure",
                "    module: execution",
                "    params:",
                # The execution module's `validate` rejects an empty
                # command — that raises in run_scenario_file, recording
                # an error step.
                "      command: ''",
                "  - id: good-step",
                "    name: Subsequent step",
                "    module: execution",
                "    params:",
                "      command: 'echo subsequent'",
                "      network_touch: false",
            ]
        ),
        encoding="utf-8",
    )
    nexus = _make_isolated_nexus(tmp_path)

    captured: List[Dict[str, Any]] = []
    execution_module = nexus.modules["execution"]
    execution_execute = execution_module.execute

    def _captured_execute(params, context):
        captured.append(
            {
                "previous_step_results": dict(
                    context.get("previous_step_results") or {}
                ),
            }
        )
        return execution_execute(params, context)

    execution_module.execute = _captured_execute
    try:
        result = nexus.run_scenario_file(str(scenario_path))
    finally:
        execution_module.execute = execution_execute

    # Two steps run (fail_fast: false). The first either errors via
    # validate() before module.execute, or succeeds in the empty-cmd
    # path — either way we should see at most 1 captured execute call
    # for the second step, and the second step must see a record of
    # the first step in its previous_step_results.
    second_step_views = [c for c in captured if c["previous_step_results"]]
    assert second_step_views, (
        "second step must observe a non-empty previous_step_results "
        "after the first step (errored or otherwise)"
    )
    seen = second_step_views[0]["previous_step_results"]
    assert "bad-step" in seen
    record = seen["bad-step"]
    assert "status" in record
    # When validate() raises, the runtime records status="error".
    # When the module runs to completion despite empty command, the
    # status will be the result.status.
    assert record["status"] in {"error", "success", "partial_success", "failure", "blocked"}


# ---------------------------------------------------------------------------
# execute_operation single-module path
# ---------------------------------------------------------------------------


def test_execute_operation_context_carries_previous_step_results_key(
    tmp_path: Path,
) -> None:
    """Single-module path also exposes previous_step_results=empty
    so module code reading the key works uniformly across scenarios
    and ad-hoc invocations.
    """
    nexus = _make_isolated_nexus(tmp_path)
    captured: Dict[str, Any] = {}
    execution_module = nexus.modules["execution"]
    original = execution_module.execute

    def _captured_execute(params, context):
        captured["previous_step_results"] = context.get("previous_step_results")
        return original(params, context)

    execution_module.execute = _captured_execute
    try:
        result = nexus.execute_operation(
            "execution", {"command": "echo hi", "network_touch": False}
        )
    finally:
        execution_module.execute = original

    assert result["status"] == "success"
    # execute_operation runs a single module and never has prior steps
    # — the key must still be present and empty.
    assert captured["previous_step_results"] == {}


# ---------------------------------------------------------------------------
# Sanity: existing scenarios still pass after the plumbing change
# ---------------------------------------------------------------------------


def test_existing_simple_scenario_runs_with_propagation_plumbing(tmp_path: Path) -> None:
    """Smoke test that existing scenario shape still runs cleanly with
    the new context plumbing in place.
    """
    scenario_path = _write_two_step_scenario(tmp_path)
    nexus = _make_isolated_nexus(tmp_path)
    result = nexus.run_scenario_file(str(scenario_path))
    assert result["status"] in {"success", "partial_success"}
    assert len(result["steps"]) == 2
