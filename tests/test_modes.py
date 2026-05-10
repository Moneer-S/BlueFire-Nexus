"""Operator-facing execution mode definitions and per-scenario plans.

The :mod:`src.core.modes` module is the single source of truth for
what each execution mode (``simulate`` / ``emulate`` / ``live-lab``)
implies in terms of config overrides, required gates, side effects,
and warnings. The CLI surfaces (``explain-mode`` / ``mode-plan``)
read off this metadata; the operator console will too in a follow-up
PR.

These tests pin:

- the canonical mode catalog (one ``ModeDefinition`` per documented
  mode);
- the safe-by-default invariant (``simulate`` requires no gates,
  ``live-lab`` requires the most);
- alias resolution (``sim`` / ``em`` / ``live`` / ``lab``);
- ``build_mode_plan`` composes mode metadata with scenario-specific
  detail (modules, legacy packs, per-pack gates);
- the plan serialises cleanly to JSON for downstream tooling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.modes import (
    MODE_METADATA,
    MODE_NAMES,
    ModeDefinition,
    ModePlan,
    build_mode_plan,
    resolve_mode,
)
from src.core.scenario import load_scenario


_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


# ---------------------------------------------------------------------------
# MODE_METADATA / MODE_NAMES
# ---------------------------------------------------------------------------


def test_mode_names_match_metadata_keys() -> None:
    """``MODE_NAMES`` is the canonical render order; the metadata
    dict carries one entry per name."""

    assert set(MODE_NAMES) == set(MODE_METADATA.keys())
    assert len(MODE_NAMES) == len(MODE_METADATA)


def test_mode_metadata_documents_three_modes() -> None:
    """The conceptual catalog is exactly simulate / emulate /
    live-lab. Adding a fourth mode is a deliberate choice — pin
    the current set so a slip surfaces immediately."""

    assert sorted(MODE_METADATA.keys()) == ["emulate", "live-lab", "simulate"]


def test_simulate_requires_no_gates_and_is_safe_for_unattended() -> None:
    """The default mode must stay zero-gate. A future change that
    starts requiring gates for simulate would silently break
    automation. Warnings are allowed (informational about prior
    runtime state) but must not promote to a required gate."""

    sim = MODE_METADATA["simulate"]
    assert sim.required_gates == ()
    assert sim.safe_for_unattended is True


def test_simulate_overrides_clear_prior_legacy_lab_state() -> None:
    """Simulate's "no real side effect" contract is global. The
    config patch must FULLY clear any prior emulate / live-lab
    execution state -- not just flip ``dry_run`` -- otherwise an
    operator transitioning from a previous emulate / live-lab run
    could leave ``modules.legacy.global_mode`` at ``emulate`` (and
    legacy modules would still resolve to emulate semantics).
    (Codex P1 on PR #169.)
    """

    sim_overrides = dict(MODE_METADATA["simulate"].config_overrides)
    # Core dry_run + enable-all toggle are already covered by the
    # pre-existing pin; explicitly check the global legacy state
    # resets land too.
    assert sim_overrides["modules.legacy.global_mode"] == "simulate"
    assert sim_overrides["modules.legacy.global_lab_acknowledged"] is False
    assert sim_overrides["modules.legacy.lab_confirmation"] is False


def test_emulate_requires_per_pack_lab_confirmation() -> None:
    """Emulate mode requires per-pack lab_confirmation when a
    scenario uses a legacy pack — the pin makes regressions visible."""

    emulate = MODE_METADATA["emulate"]
    assert emulate.safe_for_unattended is False
    gates_text = " ".join(emulate.required_gates).lower()
    assert "lab_confirmation" in gates_text


def test_live_lab_requires_loud_warnings_and_blast_radius_gate() -> None:
    """Live-lab is the most dangerous mode and must carry explicit
    warnings + an allowed_subnets gate."""

    live = MODE_METADATA["live-lab"]
    assert live.safe_for_unattended is False
    assert len(live.warnings) >= 2
    gates_text = " ".join(live.required_gates).lower()
    assert "allowed_subnets" in gates_text
    assert "lab_acknowledged" in gates_text


def test_simulate_config_overrides_keep_dry_run_true() -> None:
    """The simulate-mode config patch must keep ``general.dry_run``
    True. A regression that flips it to False would silently make
    every "safe default" run produce real side effects."""

    overrides = dict(MODE_METADATA["simulate"].config_overrides)
    assert overrides["general.dry_run"] is True
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is False


def test_live_lab_config_overrides_set_dry_run_false() -> None:
    """Live-lab disables dry_run AND enables every legacy capability
    toggle. The pin prevents a partial mode patch slipping through."""

    overrides = dict(MODE_METADATA["live-lab"].config_overrides)
    assert overrides["general.dry_run"] is False
    assert overrides["modules.legacy.enable_all_lab_capabilities"] is True
    assert overrides["modules.legacy.global_lab_acknowledged"] is True
    assert overrides["modules.legacy.lab_confirmation"] is True


# ---------------------------------------------------------------------------
# resolve_mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("simulate", "simulate"),
        ("Simulate", "simulate"),
        ("SIM", "simulate"),
        ("sim", "simulate"),
        ("emulate", "emulate"),
        ("em", "emulate"),
        ("EMULATE", "emulate"),
        ("live-lab", "live-lab"),
        ("live_lab", "live-lab"),
        ("live", "live-lab"),
        ("lab", "live-lab"),
    ],
)
def test_resolve_mode_accepts_aliases(alias: str, expected: str) -> None:
    """Common aliases / case variations resolve to canonical modes."""

    assert resolve_mode(alias).name == expected


@pytest.mark.parametrize("invalid", ["", "  ", "production", "lab-mode", "x"])
def test_resolve_mode_rejects_unknown(invalid: str) -> None:
    """Unknown / empty mode names raise ``ValueError`` so callers can
    surface a clear error rather than silently picking a default."""

    with pytest.raises(ValueError, match="Unknown mode"):
        resolve_mode(invalid)


# ---------------------------------------------------------------------------
# build_mode_plan
# ---------------------------------------------------------------------------


def test_build_mode_plan_for_simulate_against_fin7_has_no_gates() -> None:
    """FIN7 doesn't reference any legacy pack, and simulate has no
    mode-level gates, so the plan's required_gates list is empty."""

    scenario = load_scenario(_SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml")
    plan = build_mode_plan(scenario, "simulate")
    assert plan.mode == "simulate"
    assert plan.required_gates == ()
    # Simulate carries one informational warning about per-pack
    # cleanup (added in Codex P1 fix on PR #169) — the pin allows
    # any non-empty warnings tuple but verifies safe-for-unattended
    # stays True.
    assert plan.legacy_packs == ()
    assert plan.safe_for_unattended is True
    # Step count matches the loaded scenario.
    assert plan.step_count == len(scenario.steps)
    # Modules deduplicated.
    assert len(set(plan.modules)) == len(plan.modules)


def test_build_mode_plan_for_live_lab_carries_loud_warnings() -> None:
    """Live-lab on any scenario surfaces loud warnings that the
    operator must read before proceeding."""

    scenario = load_scenario(_SCENARIOS_DIR / "apt29_credential_access.yaml")
    plan = build_mode_plan(scenario, "live-lab")
    assert plan.mode == "live-lab"
    assert plan.safe_for_unattended is False
    assert len(plan.warnings) >= 2
    # Live-lab adds the global gates regardless of legacy-pack usage.
    gate_text = " ".join(plan.required_gates).lower()
    assert "allowed_subnets" in gate_text
    assert "lab_acknowledged" in gate_text


def test_build_mode_plan_emulate_with_legacy_pack_appends_pack_gate() -> None:
    """When a scenario references a legacy pack, the emulate-mode
    plan appends a per-pack lab_confirmation gate row so the
    operator sees one consolidated gate list."""

    # Synthesise a tiny scenario object that references a legacy
    # pack module — emulate-mode plan should call out the pack
    # explicitly.
    from src.core.scenario import Scenario, ScenarioStep

    scenario = Scenario(
        id="legacy-test",
        name="Legacy pack test scenario",
        objective="exercise emulate-mode pack-gate plumbing",
        attack_techniques=[],
        steps=[
            ScenarioStep(
                step_id="actor-1",
                name="APT29 research",
                module="legacy_apt29_research",
                params={},
            ),
            ScenarioStep(
                step_id="c2-1",
                name="Protocol research",
                module="legacy_protocol_research",
                params={},
            ),
        ],
        expected_detections=[],
        blue_team_guidance=[],
    )
    plan = build_mode_plan(scenario, "emulate")
    # Both packs appear in legacy_packs (deduplicated).
    assert "actor_pack" in plan.legacy_packs
    assert "c2_pack" in plan.legacy_packs
    # Per-pack gate rows appended for both packs.
    gates_text = "\n".join(plan.required_gates)
    assert "actor_pack.lab_confirmation" in gates_text
    assert "c2_pack.lab_confirmation" in gates_text


def test_build_mode_plan_simulate_with_legacy_pack_omits_pack_gate() -> None:
    """In simulate mode, the per-pack gate appendix is skipped
    because simulate has no mode-level gates by definition."""

    from src.core.scenario import Scenario, ScenarioStep

    scenario = Scenario(
        id="legacy-test",
        name="Legacy pack simulate test",
        objective="exercise simulate-mode no-gate plumbing",
        attack_techniques=[],
        steps=[
            ScenarioStep(
                step_id="actor-1",
                name="APT29 research",
                module="legacy_apt29_research",
                params={},
            ),
        ],
        expected_detections=[],
        blue_team_guidance=[],
    )
    plan = build_mode_plan(scenario, "simulate")
    assert plan.legacy_packs == ("actor_pack",)
    # Legacy pack is surfaced for visibility, but simulate's
    # required_gates list stays empty.
    assert plan.required_gates == ()


def test_build_mode_plan_to_dict_is_json_serialisable() -> None:
    """The plan dict serialises through ``json.dumps`` without a
    custom encoder so automation can pipe it into other tooling."""

    scenario = load_scenario(_SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml")
    plan = build_mode_plan(scenario, "live-lab")
    rendered = json.dumps(plan.to_dict(), indent=2)
    parsed = json.loads(rendered)
    assert parsed["mode"] == "live-lab"
    assert parsed["scenario_name"] == "FIN7 initial access to C2"
    assert isinstance(parsed["modules"], list)
    assert isinstance(parsed["config_overrides"], list)
    assert all(
        {"key", "value"}.issubset(entry.keys())
        for entry in parsed["config_overrides"]
    )


def test_build_mode_plan_step_count_matches_loaded_scenario() -> None:
    """A plan's step_count must equal the scenario's loaded step
    list length."""

    for filename in (
        "fin7_initial_access_to_c2.yaml",
        "apt29_credential_access.yaml",
        "healthcare_ransomware.yaml",
        "insider_exfil_dns.yaml",
        "enterprise_intrusion_chain.yaml",
    ):
        scenario = load_scenario(_SCENARIOS_DIR / filename)
        plan = build_mode_plan(scenario, "simulate")
        assert plan.step_count == len(scenario.steps), filename


def test_build_mode_plan_rejects_unknown_mode() -> None:
    """An unknown mode name raises ValueError so the CLI can surface
    the typer.BadParameter error verbatim."""

    scenario = load_scenario(_SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml")
    with pytest.raises(ValueError, match="Unknown mode"):
        build_mode_plan(scenario, "nonexistent")
