"""Quality invariants for the enterprise_intrusion_chain scenario.

This is the project's flagship multi-tactic showcase scenario.
The tests in this file assert the *quality* properties operators
rely on when using it for purple-team validation, in addition to
the propagation-pair tests scattered across
``test_credential_access_target_propagation``,
``test_exfiltration_target_propagation``,
``test_lateral_movement_source_propagation``, and
``test_impact_target_propagation``.

Pinned invariants:

1. **Declared `attack_coverage` matches runtime emissions** — the
   scenario YAML's `attack_coverage` field lists technique IDs the
   chain claims to exercise. After running the scenario through
   the orchestrator, every claimed ID must appear in some step's
   `techniques` output, and conversely no step may emit a
   technique not in the declared list. Catches drift in either
   direction (YAML lists a technique no module emits; module
   profile change drops a technique the YAML still claims).

2. **All steps run in safe / dry mode** — every step sets
   `network_touch: false`. The chain MUST stay safe by default;
   any future edit that introduces live behaviour to the shipped
   scenario fails this test.

3. **Tactic coverage** — at least one step per documented
   tactic phase (resource_development, reconnaissance,
   initial_access, execution, defense_evasion, discovery,
   credential_access, lateral_movement, collection,
   command_control, exfiltration, impact). The chain is the
   project's "all 12 tactics in one place" showcase.

4. **Step IDs are unique** — every step has an explicit `id`
   field and no two share the same value, so propagation
   references resolve unambiguously.

5. **Propagation references resolve** — every `target_from_step`
   / `source_from_step` value points at a step that appears
   *earlier* in the step list (forward references would never
   resolve in the linear runtime).

6. **All five propagation pairs are demonstrated end-to-end**:
   discovery -> credential_access, credential_access ->
   lateral_movement (source), collection -> exfiltration,
   collection -> impact, and resource_development ->
   command_control endpoint axis (the c2_endpoint_from_step
   slot wires the resource_development step's registered
   domain into the command_control step's c2_url).

7. **Output stays under the runtime output directory** — every
   step's artifacts/detections land under `output_dir`; nothing
   leaks into the project root or other shared paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.scenario import load_scenario


SCENARIO_PATH = "scenarios/enterprise_intrusion_chain.yaml"


# ---------------------------------------------------------------------------
# Static YAML invariants (no runtime needed)
# ---------------------------------------------------------------------------


def _scenario():
    return load_scenario(SCENARIO_PATH)


def test_step_ids_are_unique() -> None:
    scenario = _scenario()
    seen: List[str] = []
    duplicates: List[str] = []
    for step in scenario.steps:
        if step.step_id in seen:
            duplicates.append(step.step_id)
        seen.append(step.step_id)
    assert duplicates == [], f"duplicate step ids: {duplicates}"


def test_every_step_has_explicit_id() -> None:
    scenario = _scenario()
    for step in scenario.steps:
        assert step.step_id and isinstance(step.step_id, str), step


def test_every_step_runs_in_safe_dry_mode() -> None:
    """No step in the shipped chain may opt into live behaviour.

    The chain is designed for purple-team validation against
    detection content; it must stay safe by default. Any edit
    that flips `network_touch` to `true` (or drops the param so
    the module's default fires) fails this test.
    """
    scenario = _scenario()
    for step in scenario.steps:
        params = step.params or {}
        assert params.get("network_touch") is False, (
            f"step {step.step_id!r} missing or non-False network_touch: "
            f"{params.get('network_touch')!r}"
        )


_PROPAGATION_KEYS = (
    "target_from_step",
    "source_from_step",
    "c2_endpoint_from_step",
)


def test_propagation_references_resolve_to_earlier_steps() -> None:
    """`target_from_step` / `source_from_step` / `c2_endpoint_from_step`
    must point at a prior step.

    The runtime walks steps in order; a forward reference
    (`step-b` referring to `step-c` that runs after it) would
    silently fall back to the module default with no error.
    Catching this at scenario-load time keeps the YAML
    self-consistent.
    """
    scenario = _scenario()
    seen: List[str] = []
    for step in scenario.steps:
        params = step.params or {}
        for key in _PROPAGATION_KEYS:
            referenced = params.get(key)
            if referenced:
                assert referenced in seen, (
                    f"step {step.step_id!r} references {key}={referenced!r} "
                    f"but that step has not run yet (seen so far: {seen})"
                )
        seen.append(step.step_id)


def test_all_five_propagation_pairs_are_demonstrated() -> None:
    """The shipped chain demonstrates five `previous_step_results` pairs.

    Pinning the matrix here so a future "simplification" that
    drops one of the demos surfaces here rather than only being
    visible to readers of the YAML.
    """
    scenario = _scenario()
    expected_pairs = {
        # downstream step id -> (upstream step id, propagation key)
        "harvest-browser-creds": ("enumerate-files", "target_from_step"),
        "lateral-to-fileshare": ("harvest-browser-creds", "source_from_step"),
        "exfil-over-c2": ("stage-collected-data", "target_from_step"),
        "ransomware-impact": ("stage-collected-data", "target_from_step"),
        "c2-channel": ("stage-infrastructure", "c2_endpoint_from_step"),
    }
    found: Dict[str, tuple[str, str]] = {}
    for step in scenario.steps:
        params = step.params or {}
        for key in _PROPAGATION_KEYS:
            ref = params.get(key)
            if ref:
                found[step.step_id] = (str(ref), key)
    assert found == expected_pairs, found


def test_every_documented_tactic_phase_has_at_least_one_step() -> None:
    """The chain demonstrates every standard tactic at least once.

    Pin the matrix so the scenario stays a complete showcase; if
    a future refactor drops a tactic step (e.g. removes
    defense_evasion to "simplify"), the test fails and forces an
    explicit decision.
    """
    scenario = _scenario()
    modules_used = {step.module for step in scenario.steps}
    expected_tactics = {
        "resource_development",
        "reconnaissance",
        "initial_access",
        "execution",
        "defense_evasion",
        "discovery",
        "credential_access",
        "lateral_movement",
        "collection",
        "command_control",
        "exfiltration",
        "impact",
    }
    missing = expected_tactics - modules_used
    assert missing == set(), f"missing tactic modules: {missing}"


def test_every_step_has_a_narrative_name() -> None:
    """Step names must be defender-facing prose, not the step id repeated.

    The flagship scenario is the project's storytelling surface for
    SOC analysts and recruiters. A step whose ``name`` field
    is empty (or just echoes its ``id``) shows up in the dashboard
    timeline as a procedural label, not a chain narrative beat.
    Each name must be a short sentence-style description of what
    the step does — not just a slug.

    Concrete contract:

    - ``name`` is non-empty and stripped.
    - ``name`` is not equal to ``step_id`` (id is a slug; name is prose).
    - ``name`` is at least 12 characters (rules out terse one-word labels).
    - ``name`` contains a space (rules out a single token).

    This is a narrative-quality invariant, not just a length check.
    Catching a regression here means a future "simplification" PR
    that strips story polish from the showcase fails this test
    rather than landing silently.
    """
    scenario = _scenario()
    failures: List[str] = []
    for step in scenario.steps:
        name = (step.name or "").strip()
        if not name:
            failures.append(f"{step.step_id}: empty name")
            continue
        if name == step.step_id:
            failures.append(
                f"{step.step_id}: name equals step_id "
                f"(slugs are not narrative — use prose)"
            )
            continue
        if len(name) < 12:
            failures.append(
                f"{step.step_id}: name {name!r} is shorter than 12 chars"
            )
            continue
        if " " not in name:
            failures.append(
                f"{step.step_id}: name {name!r} is a single token (need prose)"
            )
    assert failures == [], "narrative step names regressed: " + "; ".join(failures)


def test_scenario_objective_reads_as_story_not_label() -> None:
    """The scenario-level ``objective`` must read as a chain narrative.

    The objective is the SOC analyst's single-paragraph summary of
    what this run is supposed to look like. We assert it is:

    - non-empty and stripped (a missing objective would surface as
      an empty card in the dashboard once the viewer renders it),
    - long enough to be a real description (at least 200 chars),
    - mentions ``simulate`` / ``network_touch`` so the operator
      sees the safe-by-default contract on the first read.
    """
    scenario = _scenario()
    objective = (scenario.objective or "").strip()
    assert objective, "scenario.objective is missing"
    assert len(objective) >= 200, (
        f"objective is too short to convey the chain narrative "
        f"(was {len(objective)} chars): {objective!r}"
    )
    lower = objective.lower()
    assert "simulate" in lower or "network_touch" in lower, (
        "objective should call out the safe-by-default contract "
        "(mention 'simulate' or 'network_touch' so a defender knows "
        "no live traffic leaves the host)"
    )


# ---------------------------------------------------------------------------
# Runtime invariants (executes the scenario)
# ---------------------------------------------------------------------------


@pytest.fixture
def _scenario_run(tmp_path: Path) -> Dict[str, Any]:
    """Run the chain end-to-end with output scoped to ``tmp_path``."""
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file(SCENARIO_PATH)
    return summary


def test_declared_attack_coverage_matches_runtime_emissions(
    _scenario_run: Dict[str, Any],
) -> None:
    """Every claimed ATT&CK ID is emitted; nothing extra leaks in.

    Drift in either direction is bad:
    - Claimed ID with no emission means the YAML over-promises
      (operator builds detection coverage for a technique the
      scenario doesn't actually exercise).
    - Emitted ID not in the declared list means the YAML
      under-promises (operator misses detections for a technique
      the scenario does exercise).

    The scenario YAML's ``attack_coverage`` is the single source
    of truth for the "what does this chain test" question; this
    test makes sure that promise stays accurate.
    """
    scenario = _scenario()
    # The YAML key is ``attack_coverage`` but the loader normalises
    # it (and historic ``mitre`` / ``attack_techniques`` aliases)
    # into a single ``attack_techniques`` field on the Scenario
    # dataclass.
    declared = set(scenario.attack_techniques or [])

    emitted: set[str] = set()
    for step in _scenario_run["steps"]:
        for technique in step.get("techniques") or []:
            emitted.add(str(technique))

    missing = declared - emitted
    extra = emitted - declared
    assert missing == set(), (
        f"declared coverage missing from runtime emissions: {sorted(missing)}"
    )
    assert extra == set(), (
        f"runtime emissions not in declared coverage: {sorted(extra)}"
    )


def test_runtime_emits_one_technique_per_step(_scenario_run: Dict[str, Any]) -> None:
    """Each shipped step exercises exactly one ATT&CK technique.

    Defends the chain's "single technique per step" structure so
    detection drafts are unambiguously attributable. A step that
    suddenly emits multiple techniques is usually a regression
    (e.g. a module's profile catalog was edited to include extra
    fall-through entries).
    """
    for step in _scenario_run["steps"]:
        techniques = step.get("techniques") or []
        # All shipped steps reach `success` and emit exactly one tech.
        if step.get("status") == "success":
            assert len(techniques) == 1, (
                f"step {step.get('step_id')!r} emitted {techniques}"
            )


def test_runtime_artifacts_stay_under_output_dir(
    _scenario_run: Dict[str, Any], tmp_path: Path
) -> None:
    """All step artifact / detection paths sit under the runtime output dir.

    Pins the test-isolation guarantee from PR #34: nothing leaks
    into the project root. Any path-handling regression in a
    module surfaces here before it can pollute shared filesystem
    state.
    """
    output_root = (tmp_path / "output").resolve()
    for step in _scenario_run["steps"]:
        detections = step.get("detections") or {}
        for kind, paths in detections.items():
            if not paths:
                continue
            for path in paths if isinstance(paths, list) else [paths]:
                resolved = Path(path).resolve()
                assert str(resolved).startswith(str(output_root)), (
                    f"step {step.get('step_id')} {kind} path leaked: {resolved}"
                )


def test_runtime_overall_status_is_success(_scenario_run: Dict[str, Any]) -> None:
    """The chain runs cleanly to ``success`` (not ``partial_success``).

    Every step in the shipped scenario reaches ``status: success``
    in default config. A regression (e.g. a module accidentally
    failing on the lab values used in the YAML) shows up here.
    """
    assert _scenario_run["status"] == "success", _scenario_run["status"]
    for step in _scenario_run["steps"]:
        assert step.get("status") == "success", step
