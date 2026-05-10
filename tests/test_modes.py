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
    ApplyPlan,
    ConfigChange,
    ModeDefinition,
    ModePlan,
    apply_mode_to_config_manager,
    build_mode_plan,
    check_apply_gates,
    compute_apply_plan,
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


# ---------------------------------------------------------------------------
# compute_apply_plan / check_apply_gates / apply_mode_to_config_manager
# ---------------------------------------------------------------------------


class _FakeConfigManager:
    """Minimal duck-typed stand-in for :class:`ConfigManager`.

    Only implements the surface :func:`apply_mode_to_config_manager`
    consumes (``set`` and ``save``) plus a ``to_dict`` shim so the
    tests can hand it to :func:`compute_apply_plan` without loading
    a real YAML file.
    """

    def __init__(self, initial: dict) -> None:
        self._data = json.loads(json.dumps(initial))  # deep copy via json
        self.set_calls: list[tuple[str, object]] = []
        self.save_calls: int = 0

    def to_dict(self) -> dict:
        return json.loads(json.dumps(self._data))

    def set(self, dot_path: str, value: object) -> None:
        self.set_calls.append((dot_path, value))
        cursor = self._data
        parts = dot_path.split(".")
        for part in parts[:-1]:
            if not isinstance(cursor.get(part), dict):
                cursor[part] = {}
            cursor = cursor[part]
        cursor[parts[-1]] = value

    def save(self) -> None:
        self.save_calls += 1


def _baseline_simulate_config() -> dict:
    """Return a config dict already at the simulate-mode target.

    Used by tests that need to assert simulate is a no-op against a
    canonical baseline.
    """
    return {
        "general": {"dry_run": True},
        "modules": {
            "legacy": {
                "enable_all_lab_capabilities": False,
                "global_mode": "simulate",
                "global_lab_acknowledged": False,
                "lab_confirmation": False,
            }
        },
    }


def _baseline_emulate_config() -> dict:
    """Return a config dict that's been into emulate mode previously.

    Used to assert simulate apply correctly clears prior emulate
    state, mirroring the Codex P1 fix on PR #169.
    """
    return {
        "general": {"dry_run": False},
        "modules": {
            "legacy": {
                "enable_all_lab_capabilities": False,
                "global_mode": "emulate",
                "global_lab_acknowledged": False,
                "lab_confirmation": False,
            }
        },
    }


def test_compute_apply_plan_simulate_against_simulate_baseline_is_full_noop() -> None:
    """Simulate against an already-simulate config produces a plan
    where every change row is no_op=True and ``effective_no_op`` is
    True. ``--write`` against this state would safely do nothing."""

    plan = compute_apply_plan("simulate", _baseline_simulate_config())
    assert plan.mode == "simulate"
    assert plan.effective_no_op is True
    assert plan.changes_to_write == ()
    # Every override key is still represented for visibility.
    keys = {change.key for change in plan.changes}
    assert "general.dry_run" in keys
    assert "modules.legacy.global_mode" in keys


def test_compute_apply_plan_simulate_against_emulate_baseline_marks_writes() -> None:
    """Simulate against a config that was previously moved into
    emulate mode marks the affected keys as writes (Codex P1 on PR
    #169 -- simulate's overrides MUST clear prior emulate state)."""

    plan = compute_apply_plan("simulate", _baseline_emulate_config())
    pending = {change.key: change for change in plan.changes_to_write}
    # dry_run flips False -> True.
    assert "general.dry_run" in pending
    assert pending["general.dry_run"].current is False
    assert pending["general.dry_run"].target is True
    # global_mode flips emulate -> simulate.
    assert "modules.legacy.global_mode" in pending
    assert pending["modules.legacy.global_mode"].current == "emulate"
    assert pending["modules.legacy.global_mode"].target == "simulate"
    assert plan.effective_no_op is False


def test_compute_apply_plan_against_empty_config_marks_every_override_pending() -> None:
    """An empty config has no current values -- every override is
    pending. ``current`` is None, ``no_op`` is False for every row."""

    plan = compute_apply_plan("emulate", {})
    assert all(not change.no_op for change in plan.changes)
    for change in plan.changes:
        assert change.current is None


def test_compute_apply_plan_rejects_unknown_mode() -> None:
    """Unknown mode names raise ValueError, mirroring resolve_mode."""

    with pytest.raises(ValueError, match="Unknown mode"):
        compute_apply_plan("not-a-mode", {})


def test_check_apply_gates_simulate_always_passes() -> None:
    """Simulate has no gates. ``check_apply_gates`` returns ``()`` no
    matter what the operator passed, so a CI script applying simulate
    never has to thread a confirmation flag."""

    assert check_apply_gates(
        "simulate", i_understand_this_is_a_lab=False, allowed_subnets=None
    ) == ()
    assert check_apply_gates(
        "simulate", i_understand_this_is_a_lab=True, allowed_subnets=["10.0.0.0/8"]
    ) == ()


def test_check_apply_gates_emulate_requires_lab_confirmation() -> None:
    """Emulate without ``i_understand_this_is_a_lab=True`` is
    blocked. The unmet-gate message names the missing flag so the
    CLI surface can paste it into the operator-facing error."""

    unmet = check_apply_gates(
        "emulate", i_understand_this_is_a_lab=False, allowed_subnets=None
    )
    assert len(unmet) == 1
    assert "--i-understand-this-is-a-lab" in unmet[0]


def test_check_apply_gates_emulate_with_confirmation_passes() -> None:
    """Emulate with the confirmation passes. Allowed_subnets is
    irrelevant for emulate (it's a live-lab gate)."""

    assert check_apply_gates(
        "emulate", i_understand_this_is_a_lab=True, allowed_subnets=None
    ) == ()


def test_check_apply_gates_live_lab_requires_both_gates() -> None:
    """Live-lab needs BOTH lab confirmation AND a non-empty
    allowed_subnets. Missing either is an unmet gate. The unmet
    list grows to 2 entries when both are missing."""

    unmet = check_apply_gates(
        "live-lab", i_understand_this_is_a_lab=False, allowed_subnets=None
    )
    assert len(unmet) == 2
    flat = " | ".join(unmet)
    assert "--i-understand-this-is-a-lab" in flat
    assert "--allowed-subnets" in flat


def test_check_apply_gates_live_lab_with_only_confirmation_blocks_on_subnets() -> None:
    """The lab-network bound is the destructive-blast-radius gate.
    Confirming the lab without setting allowed_subnets MUST still
    block -- otherwise the safety gate accepts arbitrary destinations
    on live-lab, which is the exact configuration we never want
    landing on disk."""

    unmet = check_apply_gates(
        "live-lab", i_understand_this_is_a_lab=True, allowed_subnets=[]
    )
    assert len(unmet) == 1
    assert "--allowed-subnets" in unmet[0]


def test_check_apply_gates_live_lab_with_both_passes() -> None:
    """Live-lab with both gates satisfied returns ``()``."""

    assert check_apply_gates(
        "live-lab",
        i_understand_this_is_a_lab=True,
        allowed_subnets=["10.10.0.0/24", "192.168.50.0/24"],
    ) == ()


def test_apply_mode_writes_only_pending_changes_and_calls_save() -> None:
    """The mutate path writes ONLY the non-no-op rows so an
    already-mostly-aligned config doesn't touch every key. ``save()``
    fires exactly once when at least one change was written."""

    cm = _FakeConfigManager(_baseline_emulate_config())
    plan = compute_apply_plan("simulate", cm.to_dict())
    written = apply_mode_to_config_manager(cm, plan, save=True)
    assert all(not change.no_op for change in written)
    # Every written change must show up in ``cm.set_calls`` exactly once.
    set_keys = [call[0] for call in cm.set_calls]
    assert sorted(set_keys) == sorted(change.key for change in written)
    assert cm.save_calls == 1


def test_apply_mode_with_full_noop_plan_does_not_call_save() -> None:
    """When every change is a no-op the apply path must NOT call
    ``save()`` -- otherwise an idempotent simulate apply would
    re-touch the on-disk file's mtime and confuse change-detection
    tooling."""

    cm = _FakeConfigManager(_baseline_simulate_config())
    plan = compute_apply_plan("simulate", cm.to_dict())
    written = apply_mode_to_config_manager(cm, plan, save=True)
    assert written == ()
    assert cm.set_calls == []
    assert cm.save_calls == 0


def test_apply_mode_save_false_never_persists_even_if_changes_pending() -> None:
    """``save=False`` is the in-memory-only path the operator console
    will use to populate a preview. Per-key ``set(...)`` calls fire
    so the in-memory ConfigManager carries the projected state, but
    ``save()`` is never called."""

    cm = _FakeConfigManager(_baseline_emulate_config())
    plan = compute_apply_plan("simulate", cm.to_dict())
    written = apply_mode_to_config_manager(cm, plan, save=False)
    assert len(written) > 0
    assert len(cm.set_calls) > 0
    assert cm.save_calls == 0


def test_apply_mode_rejects_object_without_set_method() -> None:
    """Defensive check: a wrongly-typed first argument raises
    TypeError loudly, instead of silently doing nothing."""

    plan = compute_apply_plan("simulate", {})

    class _NoSet:
        pass

    with pytest.raises(TypeError, match="set"):
        apply_mode_to_config_manager(_NoSet(), plan, save=False)


def test_apply_plan_to_dict_is_json_serialisable() -> None:
    """The ``--json`` CLI path serialises the plan; pin
    JSON-compatibility so a future field addition that uses a non-
    serialisable type (e.g. Path / set) surfaces immediately."""

    plan = compute_apply_plan("emulate", _baseline_simulate_config())
    payload = json.dumps(plan.to_dict(), default=str)
    decoded = json.loads(payload)
    assert decoded["mode"] == "emulate"
    assert "changes" in decoded
    assert "required_gates" in decoded
    assert "warnings" in decoded
    assert decoded["changes_to_write_count"] == len(plan.changes_to_write)


def test_apply_mode_default_is_preview_only_simulate_writes_nothing() -> None:
    """Sanity guard for the headline contract of the new command:
    apply is **preview by default**. Without ``--write`` the on-disk
    config is never touched. This is exercised at the CLI level in
    a separate test so a refactor that moves the writing into
    compute_apply_plan or check_apply_gates surfaces here too."""

    cm = _FakeConfigManager(_baseline_emulate_config())
    plan = compute_apply_plan("simulate", cm.to_dict())
    # Caller "decides not to write" -- never call apply_mode_to_config_manager.
    # Pin: cm.set / cm.save remained untouched.
    assert cm.set_calls == []
    assert cm.save_calls == 0
    # Plan still surfaces the would-be writes for the preview render.
    assert len(plan.changes_to_write) > 0


def test_apply_plan_for_live_lab_has_loud_warnings() -> None:
    """Live-lab carries multiple warnings the apply preview must
    render (NOT a default / lab-network-isolation / snapshot host /
    per-pack confirmations). Pin the count so a future refactor that
    drops a warning surfaces."""

    plan = compute_apply_plan("live-lab", {})
    assert len(plan.warnings) >= 4
    assert plan.safe_for_unattended is False
