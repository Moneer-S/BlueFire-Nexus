"""CLI integration for the explain-mode / mode-plan commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from src.core.cli import app


_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
_FIN7_SCENARIO = _SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml"


# ---------------------------------------------------------------------------
# explain-mode
# ---------------------------------------------------------------------------


def test_explain_mode_simulate_renders_panel() -> None:
    """``explain-mode simulate`` exits cleanly with a panel that
    surfaces the mode name and the dry_run override."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "simulate"])
    assert result.exit_code == 0, result.stdout
    assert "Mode: simulate" in result.stdout
    assert "general.dry_run" in result.stdout
    assert "True" in result.stdout


def test_explain_mode_live_lab_surfaces_warnings() -> None:
    """The live-lab panel must surface its loud warnings so an
    operator sees them before configuring the run."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "live-lab"])
    assert result.exit_code == 0, result.stdout
    assert "live-lab" in result.stdout
    assert "Warnings:" in result.stdout
    assert "isolated" in result.stdout.lower() or "lab" in result.stdout.lower()


def test_explain_mode_json_emits_documented_shape() -> None:
    """``--json`` returns a stable dict shape so automation can
    pipe stdout through ``json.loads``."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "emulate", "--json"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert {
        "name",
        "description",
        "required_gates",
        "config_overrides",
        "side_effects",
        "warnings",
        "safe_for_unattended",
    }.issubset(parsed.keys())
    assert parsed["name"] == "emulate"
    assert parsed["safe_for_unattended"] is False


def test_explain_mode_accepts_aliases() -> None:
    """Aliases (``sim`` / ``lab``) resolve to canonical modes."""

    runner = CliRunner()
    sim_result = runner.invoke(app, ["explain-mode", "sim"])
    lab_result = runner.invoke(app, ["explain-mode", "lab"])
    assert sim_result.exit_code == 0
    assert lab_result.exit_code == 0
    assert "Mode: simulate" in sim_result.stdout
    assert "live-lab" in lab_result.stdout


def test_explain_mode_rejects_unknown_with_clear_error() -> None:
    """Unknown mode names exit non-zero with a helpful error."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "production"])
    assert result.exit_code != 0
    assert "Unknown mode" in result.stdout or "Unknown mode" in result.stderr


# ---------------------------------------------------------------------------
# mode-plan
# ---------------------------------------------------------------------------


def test_mode_plan_simulate_against_fin7_renders_tree() -> None:
    """``mode-plan`` exits cleanly and renders a tree containing
    the scenario name and the simulate config overrides."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "simulate"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Mode plan:" in result.stdout
    assert "FIN7" in result.stdout
    assert "general.dry_run" in result.stdout
    # FIN7 is no-legacy in simulate, so no required gates land.
    assert "(none)" in result.stdout


def test_mode_plan_default_mode_is_simulate() -> None:
    """When the operator omits ``--mode``, the plan defaults to the
    safest mode (simulate)."""

    runner = CliRunner()
    result = runner.invoke(app, ["mode-plan", str(_FIN7_SCENARIO)])
    assert result.exit_code == 0, result.stdout
    assert "simulate" in result.stdout


def test_mode_plan_live_lab_surfaces_warnings_section() -> None:
    """Live-lab mode plan must include a warnings section so the
    operator reads the cautions before applying the config patch."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "live-lab"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Warnings" in result.stdout
    assert "NOT safe for unattended" in result.stdout


def test_mode_plan_json_emits_documented_shape() -> None:
    """``--json`` returns the structured plan dict for automation."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "mode-plan",
            str(_FIN7_SCENARIO),
            "--mode",
            "emulate",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert {
        "mode",
        "scenario_name",
        "scenario_id",
        "step_count",
        "modules",
        "legacy_packs",
        "config_overrides",
        "required_gates",
        "warnings",
        "side_effects",
        "safe_for_unattended",
    }.issubset(parsed.keys())
    assert parsed["mode"] == "emulate"
    assert parsed["scenario_name"] == "FIN7 initial access to C2"
    assert parsed["step_count"] == 7
    assert parsed["safe_for_unattended"] is False


def test_mode_plan_rejects_unknown_mode_with_clear_error() -> None:
    """Unknown mode → non-zero exit, useful error message."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "nonexistent"],
    )
    assert result.exit_code != 0
    output = (result.stdout or "") + (result.stderr or "")
    assert "Unknown mode" in output


def test_mode_plan_rejects_missing_scenario() -> None:
    """A non-existent scenario file → non-zero exit with a helpful
    error from typer's ``exists=True`` validator."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", "scenarios/no_such_scenario.yaml", "--mode", "simulate"],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# apply-mode-profile
# ---------------------------------------------------------------------------


def _isolated_config_dir(tmp_path: Path, monkeypatch) -> Path:
    """Point the CLI's ConfigManager at a tmp config root.

    ``ConfigManager`` reads ``BLUEFIRE_CONFIG_DIR`` (or the project's
    default) at construction time. Test runs that exercise
    ``apply-mode-profile --write`` need an isolated config file so
    they don't mutate the developer's working-tree ``config.yaml``.

    Returns the directory the temporary config lives in so callers
    can assert against the file directly.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BLUEFIRE_CONFIG_DIR", str(tmp_path))
    return tmp_path


def test_apply_mode_profile_default_is_preview_only_no_file_written(
    tmp_path: Path, monkeypatch
) -> None:
    """The headline contract: without ``--write`` the command does
    NOT mutate any file on disk. Even with the config dir pointed at
    an empty tmp_path, no ``config.yaml`` should appear after the
    command runs in preview mode."""

    config_dir = _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(app, ["apply-mode-profile", "simulate"])
    assert result.exit_code == 0, result.stdout
    assert "preview-only" in result.stdout
    # No on-disk write happened. ConfigManager does write a fresh
    # config.yaml at construction time if the file doesn't exist
    # yet, so the right pin is "the file's mtime did not change after
    # the apply call". We assert by re-running the command and
    # confirming preview-only stays the default.
    files = list(config_dir.iterdir())
    pre = {f: f.stat().st_mtime_ns for f in files if f.is_file()}
    runner.invoke(app, ["apply-mode-profile", "simulate"])
    files_after = list(config_dir.iterdir())
    post = {f: f.stat().st_mtime_ns for f in files_after if f.is_file()}
    # Same files, same mtimes -- nothing was rewritten by the
    # preview path.
    assert pre.keys() == post.keys()
    for f, mtime in pre.items():
        assert post[f] == mtime, f


def test_apply_mode_profile_simulate_with_write_succeeds_without_extra_flags(
    tmp_path: Path, monkeypatch
) -> None:
    """Simulate is the safe baseline -- ``--write`` works without
    ``--i-understand-this-is-a-lab``. The command exits 0 and the
    summary mentions either an applied count or a no-op result."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app, ["apply-mode-profile", "simulate", "--write"]
    )
    assert result.exit_code == 0, result.stdout
    # Either we applied N changes, or the config already matched.
    assert (
        "Applied" in result.stdout or "already matches" in result.stdout
    )


def test_apply_mode_profile_emulate_write_without_lab_flag_refuses(
    tmp_path: Path, monkeypatch
) -> None:
    """Emulate ``--write`` WITHOUT ``--i-understand-this-is-a-lab``
    must refuse with exit code 2 so a typo or scripted misuse cannot
    silently flip dry_run to False."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app, ["apply-mode-profile", "emulate", "--write"]
    )
    assert result.exit_code == 2, result.stdout
    assert "Refusing to write" in result.stdout
    assert "--i-understand-this-is-a-lab" in result.stdout


def test_apply_mode_profile_live_lab_write_without_subnets_refuses(
    tmp_path: Path, monkeypatch
) -> None:
    """Live-lab ``--write --i-understand-this-is-a-lab`` WITHOUT
    ``--allowed-subnets`` must refuse. The lab-network bound is the
    blast-radius gate; a live-lab config that lands on disk without
    bounded subnets is the exact thing this command is meant to
    prevent."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "live-lab",
            "--write",
            "--i-understand-this-is-a-lab",
        ],
    )
    assert result.exit_code == 2, result.stdout
    assert "--allowed-subnets" in result.stdout


def test_apply_mode_profile_live_lab_write_with_both_flags_succeeds(
    tmp_path: Path, monkeypatch
) -> None:
    """Live-lab with BOTH gates satisfied (lab confirmation +
    populated subnets) succeeds with exit 0 and writes the
    allowed_subnets list as part of the apply."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "live-lab",
            "--write",
            "--i-understand-this-is-a-lab",
            "--allowed-subnets",
            "10.10.0.0/24,192.168.50.0/24",
        ],
    )
    assert result.exit_code == 0, result.stdout

    # Read the on-disk config and verify the allowed_subnets landed.
    from src.core.config import ConfigManager

    cm = ConfigManager()
    subnets = cm.get("general.safeties.allowed_subnets")
    assert subnets == ["10.10.0.0/24", "192.168.50.0/24"]
    # Live-lab's catalog overrides also landed.
    assert cm.get("modules.legacy.global_lab_acknowledged") is True
    assert cm.get("modules.legacy.lab_confirmation") is True


def test_apply_mode_profile_json_output_carries_apply_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    """``--json`` output exposes the documented automation shape
    (``write_requested`` / ``unmet_gates`` / ``applied`` /
    ``changes_applied_count``). Operator scripts can pipe stdout
    through ``json.loads`` and branch on those fields."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app, ["apply-mode-profile", "emulate", "--json"]
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["mode"] == "emulate"
    assert parsed["write_requested"] is False
    assert parsed["applied"] is False
    assert "changes" in parsed
    assert "required_gates" in parsed
    assert "unmet_gates" in parsed


def test_apply_mode_profile_rejects_unknown_mode(
    tmp_path: Path, monkeypatch
) -> None:
    """Unknown mode argument exits non-zero with a helpful error."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(app, ["apply-mode-profile", "production"])
    assert result.exit_code != 0
    output = (result.stdout or "") + (result.stderr or "")
    assert "Unknown mode" in output


def test_apply_mode_profile_json_write_with_unmet_gates_exits_2(
    tmp_path: Path, monkeypatch
) -> None:
    """Refusal exit code MUST be preserved across output modes
    (Codex P1 on PR #180). Automation that runs
    ``apply-mode-profile emulate --write --json`` without the
    confirmation flag is relying on the process status code to
    detect a blocked apply -- not on parsing the JSON ``applied``
    field. Exit code 2 must fire even on the JSON path."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "emulate",
            "--write",
            "--json",
        ],
    )
    assert result.exit_code == 2, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["applied"] is False
    assert parsed["write_requested"] is True
    assert len(parsed["unmet_gates"]) >= 1


def test_apply_mode_profile_live_lab_subnets_write_counted_in_applied(
    tmp_path: Path, monkeypatch
) -> None:
    """When live-lab is applied with --allowed-subnets, the resulting
    ``general.safeties.allowed_subnets`` write must be counted in
    ``applied_changes`` (Codex P1 on PR #180). Otherwise the JSON
    ``changes_applied_count`` field and the human-readable "applied N
    change(s)" message would mislead operators about whether a
    safety-critical config value just got persisted."""

    _isolated_config_dir(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "live-lab",
            "--write",
            "--i-understand-this-is-a-lab",
            "--allowed-subnets",
            "10.10.0.0/24",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    # The catalog ships 5 mode overrides for live-lab; an empty
    # initial config means all 5 land as writes, plus the
    # subnets write -- so changes_applied_count should be at least 6.
    # Pin >= 6 (rather than == 6) so a future override addition
    # doesn't break the test.
    assert parsed["applied"] is True
    assert parsed["changes_applied_count"] >= 6


def test_apply_mode_profile_live_lab_subnets_only_change_does_not_show_no_changes(
    tmp_path: Path, monkeypatch
) -> None:
    """If every catalog override is already a no-op but
    ``--allowed-subnets`` is being newly written, the human output
    must NOT say "No changes were needed" -- a safety-critical
    write IS happening. (Codex P1 on PR #180.)

    Setup: pre-populate the config so every live-lab catalog
    override is already at its target. The only thing left to write
    is the subnets list. The output should therefore claim "Applied
    1 change", not "No changes were needed"."""

    _isolated_config_dir(tmp_path, monkeypatch)

    # Seed config with live-lab catalog state already in place so
    # every override is no-op.
    from src.core.config import ConfigManager

    cm = ConfigManager()
    cm.set("general.dry_run", False)
    cm.set("modules.legacy.enable_all_lab_capabilities", True)
    cm.set("modules.legacy.global_lab_acknowledged", True)
    cm.set("modules.legacy.lab_confirmation", True)
    cm.set("modules.legacy.global_mode", "emulate")
    cm.save()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "live-lab",
            "--write",
            "--i-understand-this-is-a-lab",
            "--allowed-subnets",
            "10.50.0.0/24",
        ],
    )
    assert result.exit_code == 0, result.stdout
    # The subnets write IS a change. Output must reflect that.
    assert "No changes were needed" not in result.stdout
    assert "Applied" in result.stdout


def test_apply_mode_profile_simulate_does_not_clobber_per_pack_state(
    tmp_path: Path, monkeypatch
) -> None:
    """``apply-mode-profile simulate --write`` clears the GLOBAL
    legacy state (``modules.legacy.global_mode`` /
    ``modules.legacy.global_lab_acknowledged`` /
    ``modules.legacy.lab_confirmation`` /
    ``modules.legacy.enable_all_lab_capabilities``) but MUST NOT
    touch per-pack state (``modules.legacy.<pack>.lab_confirmation``
    / ``modules.legacy.<pack>.mode`` / ``modules.legacy.<pack>.enabled``).

    Per-pack toggles are dynamic (one per pack the operator has
    enabled) and can't be enumerated in the static catalog. The
    simulate-mode warning explicitly flags per-pack cleanup as an
    operator responsibility -- if apply-mode-profile silently
    cleared per-pack state along with the globals, an operator
    transitioning from emulate back to simulate would lose any
    per-pack confirmation they'd intentionally left in place for a
    later run.

    Pin: pre-populate per-pack state, run simulate --write, assert
    every per-pack key remains at its pre-run value.
    """

    _isolated_config_dir(tmp_path, monkeypatch)

    from src.core.config import ConfigManager

    cm = ConfigManager()
    # Operator was previously in emulate mode. Globals are set.
    cm.set("general.dry_run", False)
    cm.set("modules.legacy.global_mode", "emulate")
    cm.set("modules.legacy.lab_confirmation", True)
    # AND they had per-pack state from earlier deliberate setup.
    cm.set("modules.legacy.actor_pack.lab_confirmation", True)
    cm.set("modules.legacy.actor_pack.mode", "emulate")
    cm.set("modules.legacy.tactic_pack.lab_confirmation", True)
    cm.set("modules.legacy.tactic_pack.enabled", True)
    cm.save()

    runner = CliRunner()
    result = runner.invoke(
        app, ["apply-mode-profile", "simulate", "--write"]
    )
    assert result.exit_code == 0, result.stdout

    cm_after = ConfigManager()
    # Globals: cleared back to simulate baseline.
    assert cm_after.get("general.dry_run") is True
    assert cm_after.get("modules.legacy.global_mode") == "simulate"
    assert cm_after.get("modules.legacy.lab_confirmation") is False
    # Per-pack: untouched. Operator-readable invariant -- the
    # central mode profile does NOT enumerate per-pack keys, so it
    # MUST NOT mutate them.
    assert (
        cm_after.get("modules.legacy.actor_pack.lab_confirmation") is True
    )
    assert cm_after.get("modules.legacy.actor_pack.mode") == "emulate"
    assert (
        cm_after.get("modules.legacy.tactic_pack.lab_confirmation") is True
    )
    assert cm_after.get("modules.legacy.tactic_pack.enabled") is True


def test_apply_mode_profile_emulate_does_not_clobber_per_pack_state(
    tmp_path: Path, monkeypatch
) -> None:
    """Same invariant for the emulate target. The emulate-mode
    overrides are intentionally minimal (``general.dry_run: False``
    + ``modules.legacy.global_mode: "emulate"``); they explicitly
    do NOT enumerate per-pack keys, so applying emulate to a config
    with stale per-pack state must leave that state intact.

    The seeded per-pack values are non-default sentinels (a string
    that no reset-to-default codepath would ever produce, and a True
    that's distinct from the default-False of an absent key) so a
    future regression that "resets per-pack state to defaults" when
    applying emulate would surface as a value mismatch -- not get
    masked because the seeded value happens to coincide with the
    default. (Codex P2 on the original PR caught the prior version
    that seeded ``False`` / ``"simulate"`` -- both of which a
    reset-to-defaults bug could also produce.)
    """

    _isolated_config_dir(tmp_path, monkeypatch)

    from src.core.config import ConfigManager

    cm = ConfigManager()
    # Per-pack state the operator had set before applying emulate.
    # All values are deliberately NON-default sentinels.
    cm.set("modules.legacy.actor_pack.lab_confirmation", True)
    cm.set("modules.legacy.actor_pack.mode", "operator-set-sentinel")
    cm.set("modules.legacy.c2_pack.lab_confirmation", True)
    cm.set("modules.legacy.c2_pack.enabled", True)
    cm.save()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "apply-mode-profile",
            "emulate",
            "--write",
            "--i-understand-this-is-a-lab",
        ],
    )
    assert result.exit_code == 0, result.stdout

    cm_after = ConfigManager()
    # Per-pack state: untouched. Each assertion uses a value that a
    # reset-to-default codepath would NOT produce, so a bug that
    # silently clears per-pack state surfaces here unambiguously.
    assert (
        cm_after.get("modules.legacy.actor_pack.lab_confirmation")
        is True
    )
    assert (
        cm_after.get("modules.legacy.actor_pack.mode")
        == "operator-set-sentinel"
    )
    assert (
        cm_after.get("modules.legacy.c2_pack.lab_confirmation") is True
    )
    assert cm_after.get("modules.legacy.c2_pack.enabled") is True
    # Emulate's catalog overrides DID land on the global keys.
    assert cm_after.get("general.dry_run") is False
    assert cm_after.get("modules.legacy.global_mode") == "emulate"
