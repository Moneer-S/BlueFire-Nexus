"""Cross-scenario quality invariants.

The flagship `enterprise_intrusion_chain` is pinned in detail by
``tests/test_enterprise_intrusion_chain_quality.py``. The other
nine shipped scenarios were previously covered only by:

* ``test_declared_attack_coverage_is_emittable`` (static — scenario's
  declared coverage is a subset of what its referenced modules can
  emit).
* ``test_runtime_emits_declared_attack_coverage`` (runtime — declared
  techniques must surface during a real run).

That left several drift modes uncovered: a scenario could reuse the
same step id twice (propagation refs would resolve to the wrong
step), forward-reference a step that hasn't run yet, lose its
explicit step ids during a refactor, leak artifact paths outside the
runtime output dir, or stop reaching ``status: success`` at runtime
under default config — and none of those would fail any existing
test until an operator hit the regression in production.

This file parametrizes the same shape of static + runtime
invariants over **every** shipped scenario (including the flagship,
for symmetry with the dedicated quality file). Each invariant is
tailored to the constraints actually shipped:

* Step IDs unique + every step has explicit id (always).
* `target_from_step` / `source_from_step` references resolve to a
  step that runs **before** them in the linear runtime (always).
* Runtime overall status is `success` (always).
* Every step finishes `success` (always; no `partial_success` in
  the shipped baseline).
* Every step's detection artifact paths sit under the runtime
  output dir (always).
* Declared `attack_coverage` is fully covered by runtime emissions
  (already pinned by `test_scenario_attack_coverage`; re-asserted
  here as a single contract surface).

Legacy-pack scenarios (`legacy_*.yaml`) need lab opt-in to run end
to end; the runtime fixture sets `modules.legacy.enable_all_lab_capabilities`
+ `modules.legacy.lab_confirmation` so those adapters dispatch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATHS = sorted(Path("scenarios").glob("*.yaml"))


# ---------------------------------------------------------------------------
# Static YAML invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_step_ids_are_unique(scenario_path: Path) -> None:
    """Duplicate step ids would make `target_from_step` ambiguous.

    The runtime resolves a `target_from_step: <id>` reference by
    looking up `<id>` in the live `previous_step_results` mapping,
    keyed by step id. Two steps with the same id would silently
    overwrite each other in that mapping, and downstream
    propagation would pick the later one regardless of which one
    the YAML author intended.
    """
    scenario = load_scenario(scenario_path)
    seen: List[str] = []
    duplicates: List[str] = []
    for step in scenario.steps:
        if step.step_id in seen:
            duplicates.append(step.step_id)
        seen.append(step.step_id)
    assert duplicates == [], (
        f"{scenario_path.name}: duplicate step ids: {duplicates}"
    )


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_every_step_has_explicit_id(scenario_path: Path) -> None:
    """A step without an explicit `id` falls back to a generated
    name that breaks `target_from_step` references and makes the
    timeline harder to read."""
    scenario = load_scenario(scenario_path)
    for step in scenario.steps:
        assert step.step_id and isinstance(step.step_id, str), (
            f"{scenario_path.name}: step {step!r} has no explicit id"
        )


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_propagation_references_resolve_to_earlier_steps(scenario_path: Path) -> None:
    """`target_from_step` / `source_from_step` must point at a prior step.

    The runtime walks steps in order; a forward reference would
    silently fall back to the module default (because the
    referenced step has not produced any artifacts yet), so the
    propagation goes nowhere with no error surfaced.
    """
    scenario = load_scenario(scenario_path)
    seen: List[str] = []
    for step in scenario.steps:
        params = step.params or {}
        for key in ("target_from_step", "source_from_step"):
            referenced = params.get(key)
            if referenced:
                assert referenced in seen, (
                    f"{scenario_path.name}: step {step.step_id!r} "
                    f"references {key}={referenced!r} but that step has "
                    f"not run yet (seen so far: {seen})"
                )
        seen.append(step.step_id)


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_every_step_specifies_a_module(scenario_path: Path) -> None:
    """A step missing `module` would fail at runtime with a
    confusing 'unknown module' error; reject at scenario-load time
    so the failure is YAML-shaped instead.
    """
    scenario = load_scenario(scenario_path)
    for step in scenario.steps:
        assert step.module and isinstance(step.module, str), (
            f"{scenario_path.name}: step {step.step_id!r} has no module"
        )


# ---------------------------------------------------------------------------
# Runtime invariants
# ---------------------------------------------------------------------------


def _needs_legacy_opt_in(scenario_path: Path) -> bool:
    return scenario_path.stem.startswith("legacy_")


@pytest.fixture
def _runtime_factory(tmp_path: Path):
    """Build a ConfigManager + BlueFireNexus and return a callable
    that runs a scenario file. Caching the factory at the test
    level lets each parametrized case get its own tmp_path while
    sharing the construction boilerplate."""
    def _run(scenario_path: Path) -> Dict[str, Any]:
        cfg_path = tmp_path / "config.yaml"
        cfg = ConfigManager(str(cfg_path))
        cfg.set("general.output_root", str(tmp_path / "output"))
        if _needs_legacy_opt_in(scenario_path):
            cfg.set("modules.legacy.enable_all_lab_capabilities", True)
            cfg.set("modules.legacy.lab_confirmation", True)
        cfg.save()
        nexus = BlueFireNexus(str(cfg_path))
        return nexus.run_scenario_file(str(scenario_path))
    return _run


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_runtime_overall_status_is_success(scenario_path: Path, _runtime_factory) -> None:
    """The shipped scenarios must each reach `status: success` end-to-end.

    A regression (e.g. a module's profile catalog change drops the
    branch a scenario step uses, or a lab gate accidentally tightens)
    surfaces here before any operator runs the scenario.
    """
    summary = _runtime_factory(scenario_path)
    assert summary["status"] == "success", (
        f"{scenario_path.name}: overall status was "
        f"{summary['status']!r}, not 'success'"
    )


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_every_step_reaches_success(scenario_path: Path, _runtime_factory) -> None:
    """No step in the shipped scenarios reaches `partial_success` /
    `error` / `blocked` in default config. Catches scenarios where a
    module's gate accidentally tightened (now blocking a step the
    YAML expects to succeed) without anyone updating the YAML.
    """
    summary = _runtime_factory(scenario_path)
    for step in summary.get("steps", []):
        status = step.get("status")
        assert status == "success", (
            f"{scenario_path.name}: step {step.get('step_id')!r} reached "
            f"status={status!r}; expected 'success'. Message: "
            f"{step.get('message')!r}"
        )


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_runtime_artifact_paths_stay_under_output_root(
    scenario_path: Path, _runtime_factory, tmp_path: Path
) -> None:
    """Pin the test-isolation guarantee: every detection artifact
    path emitted by a step sits under the runtime output_root. A
    path-handling regression in any module surfaces here before it
    can pollute shared filesystem state.
    """
    output_root = (tmp_path / "output").resolve()
    summary = _runtime_factory(scenario_path)
    for step in summary.get("steps", []):
        detections = step.get("detections") or {}
        for kind, paths in detections.items():
            if not paths:
                continue
            for path in paths if isinstance(paths, list) else [paths]:
                resolved = Path(path).resolve()
                assert str(resolved).startswith(str(output_root)), (
                    f"{scenario_path.name}: step {step.get('step_id')!r} "
                    f"{kind} path leaked outside output_root: {resolved}"
                )


def _collect_emitted_techniques(steps: List[Dict[str, Any]]) -> Set[str]:
    emitted: Set[str] = set()
    for step in steps:
        for tech in step.get("techniques") or []:
            emitted.add(str(tech))
    return emitted


def _is_satisfied(declared: str, emitted: Set[str]) -> bool:
    if declared in emitted:
        return True
    parent_prefix = f"{declared}."
    return any(tech.startswith(parent_prefix) for tech in emitted)


# Modules that are intentionally metadata-only — they report on
# control-plane state (legacy enablement summary, etc.) rather
# than emulating a specific ATT&CK technique. Steps using these
# modules must NOT count against the "every success step emits a
# technique" invariant; they advertise `attack_techniques = ()`.
_METADATA_ONLY_MODULES: Set[str] = {"legacy_capability_summary"}


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_runtime_emits_at_least_one_technique_per_success_step(
    scenario_path: Path, _runtime_factory
) -> None:
    """A successful step that emits no ATT&CK technique is dead
    weight in the report — the scenario claims to exercise the
    technique but the runtime emission is empty. Excludes the
    metadata-only modules listed in :data:`_METADATA_ONLY_MODULES`
    (e.g. `legacy_capability_summary`, which intentionally reports
    on legacy enablement state and advertises no MITRE techniques).
    """
    scenario = load_scenario(scenario_path)
    metadata_only_step_ids = {
        step.step_id
        for step in scenario.steps
        if step.module in _METADATA_ONLY_MODULES
    }
    summary = _runtime_factory(scenario_path)
    silent_steps: List[str] = []
    for step in summary.get("steps", []):
        if step.get("status") != "success":
            continue
        if step.get("step_id") in metadata_only_step_ids:
            continue
        if not (step.get("techniques") or []):
            silent_steps.append(str(step.get("step_id")))
    assert silent_steps == [], (
        f"{scenario_path.name}: success steps emitted no techniques: "
        f"{silent_steps}. (Metadata-only modules "
        f"{sorted(_METADATA_ONLY_MODULES)} are excluded.)"
    )


@pytest.mark.parametrize("scenario_path", SCENARIO_PATHS, ids=lambda p: p.stem)
def test_declared_coverage_is_satisfied_by_runtime_emissions(
    scenario_path: Path, _runtime_factory
) -> None:
    """Every declared `attack_coverage` technique must be exercised
    by some step's runtime emission (parent-of-subtechnique still
    satisfies parent). Mirrors `test_runtime_emits_declared_attack_coverage`
    but co-located here so the full quality contract for a
    scenario is in one place.
    """
    scenario = load_scenario(scenario_path)
    declared = list(scenario.attack_techniques or [])
    if not declared:
        pytest.skip(f"{scenario_path.name} declares no attack_coverage")
    summary = _runtime_factory(scenario_path)
    emitted = _collect_emitted_techniques(summary.get("steps", []))
    drift = [tech for tech in declared if not _is_satisfied(str(tech), emitted)]
    assert not drift, (
        f"{scenario_path.name}: declared coverage missing from runtime "
        f"emissions: {sorted(drift)}. Emitted: {sorted(emitted)}."
    )
