"""CLI integration for the ``operator-console`` command.

The console is a read-only generator. The CLI plumbing must respect
that contract: invoking ``operator-console`` MUST NOT mutate any
on-disk state outside the ``output_root/operator-console/`` directory.
This test file pins the most-likely-to-regress aspects of that
invariant -- specifically the config-loading path that renders the
real per-mode current -> target diff.

Codex P1 on PR #183: ``ConfigManager()`` writes a default
``config.yaml`` when the file is missing, so a stray
``operator-console`` invocation in a clean directory would silently
create the config file just by previewing the page. The CLI now uses
a direct ``yaml.safe_load`` against ``config.yaml`` and skips loading
when the file is absent.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.core.cli import app


@pytest.fixture
def isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run each test in a fresh ``cwd`` so the relative ``config.yaml``
    path used by ``_load_config_for_console_preview`` resolves into the
    tmp dir rather than the developer's home / repo checkout. Returns
    the temp path so tests can assert on file presence/absence."""

    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_operator_console_cli_does_not_create_config_yaml_when_missing(
    isolated_cwd: Path,
) -> None:
    """The headline Codex P1 fix: ``operator-console`` invoked in a
    directory without ``config.yaml`` MUST NOT create one. The
    historical ``ConfigManager()`` path silently wrote a default
    ``config.yaml`` -- now the CLI uses ``yaml.safe_load`` directly
    and skips loading when the file is absent. Pin: no file at the
    config path after the command runs."""

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    # Headline contract: no config.yaml was created.
    assert not (isolated_cwd / "config.yaml").exists(), (
        "operator-console must not create config.yaml when the file is "
        "absent (Codex P1 on PR #183)"
    )
    # The console page itself was still built.
    page = output_root / "operator-console" / "index.html"
    assert page.exists()
    # And the missing-config notice surfaced to the operator.
    assert "config.yaml not found" in result.stdout


def test_operator_console_cli_renders_static_overrides_when_no_config(
    isolated_cwd: Path,
) -> None:
    """When ``config.yaml`` is absent, the console must fall back to
    the static target-only render path -- the legacy "Config
    overrides" header rather than the diff form. This pins that the
    fall-back path is wired correctly so the page still builds with
    a useful representation of every mode."""

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )
    # Static fallback: legacy header is rendered.
    assert "<h4>Config overrides</h4>" in body
    # And the diff form is NOT rendered (because no current_config).
    assert "Apply diff (current -&gt; target)" not in body


def test_operator_console_cli_renders_diff_when_config_exists(
    isolated_cwd: Path,
) -> None:
    """When ``config.yaml`` exists, the console must use the loaded
    config to render the real per-mode diff. Writes a minimal config
    matching simulate's safe defaults and pins that the simulate card
    advertises a complete-no-op summary."""

    config_yaml = isolated_cwd / "config.yaml"
    # Minimal config matching every simulate target value -> simulate
    # card renders as a complete no-op.
    config_yaml.write_text(
        "\n".join(
            [
                "general:",
                "  dry_run: true",
                "modules:",
                "  legacy:",
                "    enable_all_lab_capabilities: false",
                "    global_mode: simulate",
                "    global_lab_acknowledged: false",
                "    lab_confirmation: false",
                "",
            ]
        ),
        encoding="utf-8",
    )

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )
    # Diff form is rendered now that we have a current_config.
    assert "Apply diff (current -&gt; target)" in body
    # Simulate card renders the complete-no-op summary.
    assert "complete no-op" in body


def test_operator_console_cli_does_not_mutate_existing_config_yaml(
    isolated_cwd: Path,
) -> None:
    """Even when ``config.yaml`` already exists, the
    ``operator-console`` command must NOT mutate its contents. Pin
    the byte-for-byte contents before / after the command runs."""

    config_yaml = isolated_cwd / "config.yaml"
    original_text = "\n".join(
        [
            "general:",
            "  dry_run: true",
            "modules:",
            "  legacy:",
            "    global_mode: simulate",
            "",
        ]
    )
    config_yaml.write_text(original_text, encoding="utf-8")
    original_mtime = config_yaml.stat().st_mtime

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    # Content unchanged, byte for byte.
    assert config_yaml.read_text(encoding="utf-8") == original_text
    # mtime is also unchanged (a write that produced identical bytes
    # would still bump mtime; assert the stricter no-write contract
    # by pinning mtime equality where the OS supports it).
    assert config_yaml.stat().st_mtime == original_mtime


def test_operator_console_cli_tolerates_unreadable_config_yaml(
    isolated_cwd: Path,
) -> None:
    """A malformed ``config.yaml`` (non-mapping top-level value) must
    not crash the command -- the console still builds, falls back to
    the static-only render, and surfaces a warning. Pins the partial-
    failure tolerance so a developer with a junk ``config.yaml`` can
    still get the catalog view."""

    config_yaml = isolated_cwd / "config.yaml"
    # YAML scalar -> not a mapping. ``yaml.safe_load`` returns a string
    # rather than a dict.
    config_yaml.write_text("just a string\n", encoding="utf-8")

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    # Warning surfaced. ``rich.console.Console`` line-wraps prose at
    # the terminal width, which differs between local dev and CI;
    # normalise whitespace before asserting on the substrings.
    normalised = " ".join(result.stdout.split())
    assert "Warning" in normalised
    assert "non-mapping value" in normalised
    # Page still rendered via static fallback path.
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )
    assert "Apply diff (current -&gt; target)" not in body
    assert "<h4>Config overrides</h4>" in body


def test_operator_console_cli_diff_uses_default_merge_for_partial_config(
    isolated_cwd: Path,
) -> None:
    """Codex P2 fix: the diff must be computed against the same
    default-merged + alias-normalised config that
    ``apply-mode-profile`` operates on. With a sparse ``config.yaml``
    that only sets ``general.dry_run: true`` and leaves all
    ``modules.legacy.*`` keys absent, the simulate card MUST treat
    every simulate target value as a no-op (because the
    ``ConfigManager.load_readonly`` path merges the safe defaults in,
    and those defaults already match every simulate override).
    Without the default-merge fix, the legacy keys would render as
    ``(write)`` rows even though ``apply-mode-profile`` would treat
    them as no-ops -- the diff and the actual on-disk action would
    disagree.

    The simulate card therefore renders as ``complete no-op`` against
    a config that ONLY sets ``general.dry_run`` -- the rest of the
    simulate target values match the default-merged baseline.
    """

    config_yaml = isolated_cwd / "config.yaml"
    config_yaml.write_text(
        "general:\n  dry_run: true\n", encoding="utf-8"
    )

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    result = runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )
    # Must use the diff form (we have a config) ...
    assert "Apply diff (current -&gt; target)" in body
    # ... and the simulate card must render as a complete no-op,
    # because the default-merge pulled in
    # ``modules.legacy.global_mode: simulate``,
    # ``modules.legacy.global_lab_acknowledged: false``, etc.
    # (Codex P2 invariant: agreement with apply-mode-profile.)
    assert "complete no-op" in body


def test_operator_console_diff_agrees_with_apply_mode_profile_against_partial_config(
    isolated_cwd: Path,
) -> None:
    """Stronger Codex P2 invariant: the diff the operator console
    renders must use the SAME merged config dict that
    ``apply-mode-profile`` would compute its plan against.

    Construct a partial config, then verify both the operator-console
    diff (``--write`` rows) and the ``apply-mode-profile <mode>
    --json`` output (``changes_to_write_count``) report the same set
    of pending writes per mode."""

    import json

    config_yaml = isolated_cwd / "config.yaml"
    config_yaml.write_text(
        "general:\n  dry_run: true\n", encoding="utf-8"
    )

    output_root = isolated_cwd / "lab-output"
    runner = CliRunner()
    runner.invoke(
        app, ["operator-console", "--output-root", str(output_root)]
    )
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )

    # Per mode, the console's "N pending write of M total" count must
    # equal apply-mode-profile's changes_to_write_count.
    for mode_name in ("simulate", "emulate", "live-lab"):
        plan_result = runner.invoke(
            app, ["apply-mode-profile", mode_name, "--json"]
        )
        assert plan_result.exit_code == 0, plan_result.stdout
        plan = json.loads(plan_result.stdout)
        # The console renders either "complete no-op" (zero pending)
        # or "N change(s) pending write of M total". Locate the
        # mode's card and check the count agrees.
        css_safe = mode_name.replace("_", "-")
        card_marker = f"<div class='card mode-card mode-{css_safe}'>"
        card_start = body.find(card_marker)
        assert card_start != -1, f"mode card for {mode_name!r} missing"
        # End the card slice at the next mode card (or the page footer).
        end = body.find(
            "<div class='card mode-card mode-",
            card_start + len(card_marker),
        )
        if end == -1:
            end = body.find("class='footer'", card_start)
        card = body[card_start:end]
        # Compute the actual pending-write count we expect from
        # apply-mode-profile's plan.
        pending = sum(
            1 for change in plan["changes"] if not change["no_op"]
        )
        if pending == 0:
            assert "complete no-op" in card, (
                f"mode {mode_name!r}: apply-mode-profile says 0 "
                "pending writes but console card does not advertise "
                "complete no-op"
            )
        else:
            assert (
                f"{pending} change(s) pending write" in card
            ), (
                f"mode {mode_name!r}: apply-mode-profile says "
                f"{pending} pending writes; console card pending-"
                "count text does not match"
            )
