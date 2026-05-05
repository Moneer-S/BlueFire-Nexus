"""Tests for the `--mutate` flag on `python -m src.run_scenario`."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.run_scenario import (
    _MUTATE_STRATEGIES,
    _build_mutation_overrides,
    _build_parser,
)


def test_mutate_flag_default_is_off() -> None:
    parser = _build_parser()
    args = parser.parse_args([])
    assert args.mutate == ""


def test_mutate_flag_accepts_documented_strategies() -> None:
    parser = _build_parser()
    for strategy in _MUTATE_STRATEGIES:
        args = parser.parse_args(["--mutate", strategy])
        assert args.mutate == strategy


def test_mutate_flag_rejects_unknown_strategy(capsys: pytest.CaptureFixture) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--mutate", "definitely_not_a_real_strategy"])
    err = capsys.readouterr().err
    assert "definitely_not_a_real_strategy" in err or "invalid choice" in err


def test_build_mutation_overrides_returns_per_step_dict(tmp_path: Path) -> None:
    """`--mutate <strategy>` produces a step_id -> mutated-params dict."""
    scenario = tmp_path / "tiny.yaml"
    scenario.write_text(
        """\
id: tiny_chain
name: Tiny chain for mutation test
objective: Verify mutation overrides round-trip per step.
fail_fast: false
steps:
  - id: step_one
    name: First step
    module: execution
    params:
      command: "echo before"
  - id: step_two
    name: Second step
    module: command_control
    params:
      channel: http
""",
        encoding="utf-8",
    )

    overrides = _build_mutation_overrides(str(scenario), "low_noise")

    assert set(overrides.keys()) == {"step_one", "step_two"}
    # low_noise replaces "echo " with "printf " and bumps sleep_jitter_seconds.
    assert overrides["step_one"]["command"].startswith("printf ")
    assert overrides["step_one"]["mutation_applied"] is True
    assert overrides["step_one"]["sleep_jitter_seconds"] >= 1
    # The non-command step is still mutated (mutation_applied=True) but its
    # original `channel` value is preserved (no `command` key to rewrite).
    assert overrides["step_two"]["channel"] == "http"
    assert overrides["step_two"]["mutation_applied"] is True


def test_build_mutation_overrides_protocol_shift_rotates_protocol(tmp_path: Path) -> None:
    """`--mutate protocol_shift` rotates http -> dns -> https -> http."""
    scenario = tmp_path / "tiny.yaml"
    scenario.write_text(
        """\
id: tiny_chain
name: Tiny chain
objective: Test protocol_shift.
fail_fast: false
steps:
  - id: c2
    name: C2 step
    module: command_control
    params:
      protocol: http
""",
        encoding="utf-8",
    )

    overrides = _build_mutation_overrides(str(scenario), "protocol_shift")

    assert overrides["c2"]["protocol"] == "dns"
    assert overrides["c2"]["mutation_applied"] is True


def test_build_mutation_overrides_handles_steps_without_params(tmp_path: Path) -> None:
    scenario = tmp_path / "tiny.yaml"
    scenario.write_text(
        """\
id: tiny_chain
name: Tiny chain
objective: No-params step.
fail_fast: false
steps:
  - id: only
    name: Only step
    module: legacy_capability_summary
    params: {}
""",
        encoding="utf-8",
    )

    overrides = _build_mutation_overrides(str(scenario), "low_noise")

    assert "only" in overrides
    assert overrides["only"]["mutation_applied"] is True
