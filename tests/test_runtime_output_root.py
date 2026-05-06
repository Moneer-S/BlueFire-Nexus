"""Resolution order for `BlueFireNexus._output_root` and the runtime
output_dir contract that depends on it.

Three layers of precedence are exercised:

1. ``general.output_root`` in the loaded config — wins everything.
2. ``BLUEFIRE_OUTPUT_ROOT`` env var — fallback when config does not set
   the key. The test-suite conftest sets this to a per-session tmp
   directory so unrelated tests cannot pollute or observe each other
   via the project-root ``output/``.
3. Default ``output`` — preserves existing CLI behaviour.

The artifact-path invariant is also re-asserted: every run-context
``output_dir`` must resolve under the active output root.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager


def _make_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    ConfigManager(str(cfg_path)).save()
    return BlueFireNexus(str(cfg_path))


def test_output_root_defaults_to_output_when_unset(monkeypatch, tmp_path: Path) -> None:
    """With no config setting and no env var, default is ``output``."""
    monkeypatch.delenv("BLUEFIRE_OUTPUT_ROOT", raising=False)
    nexus = _make_nexus(tmp_path)
    # general.output_root must NOT be in default config
    assert "output_root" not in (nexus.config.get("general") or {})
    assert nexus._output_root() == Path("output")


def test_output_root_honors_env_var(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "env-output"
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(custom))
    nexus = _make_nexus(tmp_path)
    assert nexus._output_root() == custom


def test_output_root_config_wins_over_env_var(monkeypatch, tmp_path: Path) -> None:
    """Config takes precedence; env var is only a fallback."""
    config_root = tmp_path / "config-output"
    env_root = tmp_path / "env-output"
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(env_root))

    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(config_root))
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    assert nexus._output_root() == config_root


def test_output_root_empty_config_value_falls_back_to_env(
    monkeypatch, tmp_path: Path
) -> None:
    """Empty/whitespace config value must not shadow the env var fallback."""
    env_root = tmp_path / "env-output"
    monkeypatch.setenv("BLUEFIRE_OUTPUT_ROOT", str(env_root))

    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", "   ")  # whitespace-only
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    assert nexus._output_root() == env_root


def test_run_context_lands_under_configured_output_root(tmp_path: Path) -> None:
    """`_make_run_context` must place output_dir under the resolved root."""
    custom = tmp_path / "configured-output"
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(custom))
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    context = nexus._make_run_context()
    assert custom in context.output_dir.parents or context.output_dir.parent == custom
    assert context.output_dir.exists()


def test_execute_operation_writes_only_under_configured_root(tmp_path: Path) -> None:
    """End-to-end: every artifact path produced by a real run must
    resolve under the configured output root.
    """
    custom = tmp_path / "scoped-run-output"
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(custom))
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "execution",
        {"command": "echo hello", "network_touch": False},
    )
    assert result["status"] == "success"

    output_dir = Path(result["output_dir"]).resolve()
    custom_resolved = custom.resolve()
    assert custom_resolved in output_dir.parents or output_dir == custom_resolved

    # Every concrete on-disk artifact path the result reports must live
    # under the configured root (preserves the artifact-path invariant
    # under the new output_root abstraction).
    for path_key in ("report_path", "risk_summary_path"):
        path_value = result.get(path_key)
        if path_value:
            assert custom_resolved in Path(path_value).resolve().parents
    for output_paths in (result.get("detection_artifacts") or {}).values():
        if isinstance(output_paths, list):
            for path_str in output_paths:
                assert custom_resolved in Path(path_str).resolve().parents


def test_session_tmp_isolation_is_not_project_output(tmp_path: Path) -> None:
    """The conftest autouse fixture must point _output_root() somewhere
    OTHER than the project-root ``output/`` directory when no test-
    specific config is configured.
    """
    # Construct a nexus with empty config (no general.output_root).
    cfg_path = tmp_path / "config.yaml"
    ConfigManager(str(cfg_path)).save()
    nexus = BlueFireNexus(str(cfg_path))
    project_output = (Path(__file__).resolve().parent.parent / "output").resolve()
    resolved_root = nexus._output_root().resolve()
    # Either the env var pointed somewhere else (preferred) or the
    # default kicked in. Either way, this test must not silently
    # depend on project-root output/ for isolation.
    if os.environ.get("BLUEFIRE_OUTPUT_ROOT"):
        assert resolved_root != project_output, (
            f"conftest set BLUEFIRE_OUTPUT_ROOT but _output_root() still resolves to "
            f"the project-root output/ directory: {resolved_root}"
        )
    else:
        # Without conftest active (unlikely outside this test file in
        # practice), the default of "output" is acceptable.
        pytest.skip("conftest output-root fixture inactive; default behaviour OK")
