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
    # Warning surfaced.
    assert "not a mapping" in result.stdout
    # Page still rendered via static fallback path.
    body = (output_root / "operator-console" / "index.html").read_text(
        encoding="utf-8"
    )
    assert "Apply diff (current -&gt; target)" not in body
    assert "<h4>Config overrides</h4>" in body
