"""Scenario loader semantics: explicit `attack_coverage` always wins.

Earlier versions used Python's truthy-falsy `or` chain to fall back from
`attack_coverage` through `mitre` to `attack_techniques`. That silently
swallowed an explicit empty list — `attack_coverage: []` was treated as
absent, so coverage drifted to the first populated alternative key.
"""

from __future__ import annotations

from pathlib import Path

from src.core.scenario import load_scenario


def _write_scenario(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_explicit_empty_attack_coverage_is_preserved(tmp_path: Path) -> None:
    """`attack_coverage: []` must stay [] — not fall through to mitre/legacy keys."""
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: empty-cov",
                "name: Empty Coverage",
                "objective: explicit no-coverage scenario",
                "attack_coverage: []",
                # These would have been picked up by the old or-chain:
                "mitre: ['T1059']",
                "attack_techniques: ['T1071']",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: execution",
                "    params: {command: echo hi}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == []


def test_attack_coverage_present_takes_precedence(tmp_path: Path) -> None:
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: cov-set",
                "name: Coverage Set",
                "objective: declared coverage wins over fallback keys",
                "attack_coverage: ['T1566']",
                "mitre: ['T1059']",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: initial_access",
                "    params: {vector: phishing_email, target: lab}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == ["T1566"]


def test_missing_attack_coverage_falls_back_to_mitre(tmp_path: Path) -> None:
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: legacy-mitre",
                "name: Legacy Mitre Key",
                "objective: scenarios authored before attack_coverage existed",
                "mitre: ['T1041', 'T1572']",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: exfiltration",
                "    params: {method: via_c2}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == ["T1041", "T1572"]


def test_missing_attack_coverage_and_mitre_falls_back_to_attack_techniques(
    tmp_path: Path,
) -> None:
    """Third fallback for scenarios that named the field `attack_techniques`."""
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: legacy-techniques",
                "name: Legacy Techniques Key",
                "objective: alternate spelling support",
                "attack_techniques: ['T1059', 'T1071.001']",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: execution",
                "    params: {command: echo hi}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == ["T1059", "T1071.001"]


def test_explicit_empty_mitre_is_preserved_when_attack_coverage_absent(
    tmp_path: Path,
) -> None:
    """An explicit empty `mitre: []` should not silently fall through to
    `attack_techniques` either — the loader honours the first key it finds.
    """
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: empty-mitre",
                "name: Empty Mitre",
                "objective: explicit no-coverage via legacy key",
                "mitre: []",
                "attack_techniques: ['T1071']",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: execution",
                "    params: {command: echo hi}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == []


def test_missing_all_coverage_keys_yields_empty(tmp_path: Path) -> None:
    scenario_path = _write_scenario(
        tmp_path / "scenario.yaml",
        "\n".join(
            [
                "id: no-cov",
                "name: No Coverage",
                "objective: scenario that doesn't declare coverage at all",
                "steps:",
                "  - id: s1",
                "    name: Run",
                "    module: execution",
                "    params: {command: echo hi}",
            ]
        ),
    )
    scenario = load_scenario(scenario_path)
    assert scenario.attack_techniques == []
