"""CLI ``risk-summary`` command — rationale column.

Mirrors PR #114's static-viewer rationale enhancement: the
``risk-summary`` CLI command now surfaces the per-module
``rationale`` list (``pack=tactic_pack`` / ``tactic_base=impact``
/ ``mode=emulate`` / ...) in a ``Why`` column so operators
triaging from a terminal don't need to open risk_summary.json to
see why a score landed where it did.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from src.core.cli import app


def _write_risk_summary(path: Path, modules: list[Dict[str, Any]]) -> None:
    payload = {
        "risk_summary": {
            "critical": sum(1 for m in modules if m.get("severity") == "critical"),
            "high": sum(1 for m in modules if m.get("severity") == "high"),
            "medium": sum(1 for m in modules if m.get("severity") == "medium"),
            "low": sum(1 for m in modules if m.get("severity") == "low"),
        },
        "average_score": (
            sum(m.get("score", 0) for m in modules) / len(modules) if modules else 0
        ),
        "max_score": max((m.get("score", 0) for m in modules), default=0),
        "min_score": min((m.get("score", 0) for m in modules), default=0),
        "module_count": len(modules),
        "modules": modules,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    """CLI runner that prints rich tables wide enough to read.

    Pinned width avoids rich truncating the new ``Why`` column on
    narrow Windows terminals during the test.
    """
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("NO_COLOR", "1")
    return CliRunner()


def test_risk_summary_cli_renders_rationale_column(
    tmp_path: Path, cli_env: CliRunner
) -> None:
    """The CLI risk-summary command lists rationale entries in a
    ``Why`` column for each top-risky module.
    """
    risk_path = tmp_path / "risk_summary.json"
    _write_risk_summary(
        risk_path,
        [
            {
                "module": "impact:ransomware",
                "severity": "critical",
                "score": 100,
                "pack": "tactic_pack",
                "capability": "impact",
                "mode": "emulate",
                "rationale": [
                    "pack=tactic_pack",
                    "tactic_base=impact",
                    "mode=emulate",
                ],
            },
            {
                "module": "discovery:files",
                "severity": "low",
                "score": 30,
                "pack": "",
                "capability": "",
                "mode": "simulate",
                "rationale": ["tactic_base=discovery"],
            },
        ],
    )
    result = cli_env.invoke(app, ["risk-summary", str(risk_path), "--top", "2"])
    assert result.exit_code == 0, result.stdout
    # Header and rationale tokens surface.
    assert "Why" in result.stdout
    assert "tactic_base=impact" in result.stdout
    assert "tactic_base=discovery" in result.stdout
    assert "pack=tactic_pack" in result.stdout
    assert "mode=emulate" in result.stdout


def test_risk_summary_cli_renders_matters_because_entry(
    tmp_path: Path, cli_env: CliRunner
) -> None:
    """The CLI Why column surfaces the ``matters_because=<text>`` entry.

    PR #129 added the chain-position rationale line; this test
    pins that the CLI renders it through verbatim so an operator
    triaging from a terminal sees why a step matters in the
    chain (e.g. ``destructive endgame``,
    ``data leaves perimeter``) without opening the dashboard.
    """
    risk_path = tmp_path / "risk_summary.json"
    _write_risk_summary(
        risk_path,
        [
            {
                "module": "impact:ransomware",
                "severity": "critical",
                "score": 95,
                "pack": "",
                "capability": "",
                "mode": "simulate",
                "rationale": [
                    "tactic_base=impact",
                    "matters_because=destructive endgame",
                ],
            }
        ],
    )
    result = cli_env.invoke(app, ["risk-summary", str(risk_path), "--top", "1"])
    assert result.exit_code == 0, result.stdout
    assert "matters_because=destructive endgame" in result.stdout


def test_risk_summary_cli_handles_missing_rationale(
    tmp_path: Path, cli_env: CliRunner
) -> None:
    """Pre-v3 risk_summary.json (without rationale) still renders
    cleanly — the ``Why`` cell is just empty.
    """
    risk_path = tmp_path / "risk_summary.json"
    _write_risk_summary(
        risk_path,
        [
            {
                "module": "execution:cmd",
                "severity": "medium",
                "score": 60,
                "pack": "",
                "capability": "",
                "mode": "simulate",
                # no rationale key
            }
        ],
    )
    result = cli_env.invoke(app, ["risk-summary", str(risk_path), "--top", "1"])
    assert result.exit_code == 0
    assert "Why" in result.stdout
    assert "execution:cmd" in result.stdout


def test_risk_summary_cli_handles_non_list_rationale(
    tmp_path: Path, cli_env: CliRunner
) -> None:
    """Defensive: a future caller writes rationale as a string
    instead of a list. The cell renders empty rather than crashing.
    """
    risk_path = tmp_path / "risk_summary.json"
    _write_risk_summary(
        risk_path,
        [
            {
                "module": "weird",
                "severity": "low",
                "score": 25,
                "pack": "",
                "capability": "",
                "mode": "simulate",
                "rationale": "not-a-list",
            }
        ],
    )
    result = cli_env.invoke(app, ["risk-summary", str(risk_path), "--top", "1"])
    assert result.exit_code == 0
    # The garbage string must NOT propagate to the CLI output (the
    # row renders the module / severity / etc. but the Why cell is
    # empty).
    assert "weird" in result.stdout
    assert "not-a-list" not in result.stdout
