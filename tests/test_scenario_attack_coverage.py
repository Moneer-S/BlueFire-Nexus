"""Cross-check declared scenario attack_coverage against module-emittable techniques.

Each module class exposes a class-level `attack_techniques` tuple naming the
ATT&CK technique IDs that module can emit. A scenario's declared coverage
should be a subset of the union of those tuples across the modules it
actually invokes — otherwise the run report claims coverage the run never
produces.

Parent-of-subtechnique matching is intentional: declaring `T1053` is
satisfied by any emitted `T1053.xxx`, since the parent technique is the
broader ATT&CK ID.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Set

import pytest

from src.core.modules.impl.legacy_packs import discover_legacy_modules
from src.core.modules.registry import discover_modules
from src.core.scenario import load_scenario


def _all_module_classes() -> dict:
    classes = dict(discover_modules())
    classes.update(discover_legacy_modules())
    return classes


def _emittable_techniques(modules: Iterable[str]) -> Set[str]:
    classes = _all_module_classes()
    emitted: Set[str] = set()
    for module_name in modules:
        cls = classes.get(module_name)
        if cls is None:
            continue
        emitted.update(getattr(cls, "attack_techniques", ()) or ())
    return emitted


def _is_satisfied(declared: str, emitted: Set[str]) -> bool:
    if declared in emitted:
        return True
    parent_prefix = f"{declared}."
    return any(tech.startswith(parent_prefix) for tech in emitted)


@pytest.mark.parametrize(
    "scenario_path",
    sorted(Path("scenarios").glob("*.yaml")),
    ids=lambda p: p.stem,
)
def test_declared_attack_coverage_is_emittable(scenario_path: Path) -> None:
    scenario = load_scenario(scenario_path)
    declared = list(scenario.attack_techniques)
    if not declared:
        pytest.skip(f"{scenario_path.name} declares no attack_coverage")
    referenced_modules = {step.module for step in scenario.steps if step.module}
    emitted = _emittable_techniques(referenced_modules)

    drift = [tech for tech in declared if not _is_satisfied(str(tech), emitted)]
    assert not drift, (
        f"{scenario_path.name} declares attack_coverage techniques that no "
        f"referenced module can emit: {drift}. Referenced modules: "
        f"{sorted(referenced_modules)}. Emittable: {sorted(emitted)}."
    )


def test_unknown_modules_are_flagged() -> None:
    """Every module referenced by a scenario must exist in the registry."""
    classes = _all_module_classes()
    unknown: list[tuple[str, str]] = []
    for scenario_path in sorted(Path("scenarios").glob("*.yaml")):
        scenario = load_scenario(scenario_path)
        for step in scenario.steps:
            if step.module and step.module not in classes:
                unknown.append((scenario_path.name, step.module))
    assert not unknown, f"Scenarios reference unknown modules: {unknown}"


def _collect_emitted_techniques(steps: list[dict]) -> set[str]:
    emitted: set[str] = set()
    for step in steps:
        for tech in step.get("techniques", []) or []:
            emitted.add(str(tech))
    return emitted


def _is_satisfied_by_run(declared: str, emitted: set[str]) -> bool:
    if declared in emitted:
        return True
    parent_prefix = f"{declared}."
    return any(tech.startswith(parent_prefix) for tech in emitted)


@pytest.mark.parametrize(
    "scenario_path",
    sorted(Path("scenarios").glob("*.yaml")),
    ids=lambda p: p.stem,
)
def test_runtime_emits_declared_attack_coverage(scenario_path: Path, tmp_path) -> None:
    """Stronger drift gate: each declared technique must be exercised by an
    actual scenario step (parent-of-subtechnique still satisfies parent).
    Catches the case where the scenario's specific param choices never
    trigger emission of a technique listed in `attack_coverage`.
    """
    from src.core.bluefire_nexus import BlueFireNexus
    from src.core.config import ConfigManager

    scenario = load_scenario(scenario_path)
    declared = list(scenario.attack_techniques)
    if not declared:
        pytest.skip(f"{scenario_path.name} declares no attack_coverage")

    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    # Legacy scenarios need lab opt-in so their adapters can run.
    cfg.set("modules.legacy.enable_all_lab_capabilities", True)
    cfg.set("modules.legacy.lab_confirmation", True)
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))

    result = nexus.run_scenario_file(str(scenario_path))
    emitted = _collect_emitted_techniques(result.get("steps", []))

    drift = [tech for tech in declared if not _is_satisfied_by_run(str(tech), emitted)]
    assert not drift, (
        f"{scenario_path.name} declares attack_coverage techniques that no "
        f"step actually emitted at runtime: {drift}. Emitted: {sorted(emitted)}."
    )
