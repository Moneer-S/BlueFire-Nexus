"""Public-facing prose pins.

Tests that user-facing strings in the README, CLI help, module
docstrings, and case-study docs describe authorized-emulation behaviour
rather than deployment-tool functionality. Runtime identifiers (method
names, dict keys, JSON field names, scenario contracts) are out of
scope for these checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_text(*relative_parts: str) -> str:
    return (REPO_ROOT.joinpath(*relative_parts)).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# README / docs
# ---------------------------------------------------------------------------


def test_readme_avoids_unsupported_deployment_terminology() -> None:
    """Public docs avoid unsupported deployment terminology."""

    body = _read_text("README.md").lower()
    for forbidden in ("implant", "callback", "beacon", "shellcode"):
        assert forbidden not in body, f"README contains {forbidden!r}"


# ---------------------------------------------------------------------------
# CLI help / docstrings
# ---------------------------------------------------------------------------


def test_cli_run_operation_describes_request_body() -> None:
    """CLI help describes request bodies accurately."""

    cli_text = _read_text("src", "core", "cli.py")
    assert "Run one module operation from inline JSON payload" not in cli_text
    assert "Run one module operation from an inline JSON request body" in cli_text


def test_cli_mutate_technique_describes_parameters() -> None:
    """CLI help describes the ``mutate-technique`` input as parameters."""

    cli_text = _read_text("src", "core", "cli.py")
    assert "Mutate a technique payload for lab-only research experiments" not in cli_text
    assert "Mutate a module's technique parameters for lab-only research experiments" in cli_text


def test_cli_payload_option_help_describes_request_body() -> None:
    """The ``--payload`` flag help text describes a request body."""

    cli_text = _read_text("src", "core", "cli.py")
    assert "Module operation request body" in cli_text


# ---------------------------------------------------------------------------
# Module top-of-file docstrings
# ---------------------------------------------------------------------------


def test_command_control_docstring_describes_emulation() -> None:
    """Module docstrings describe emulation behavior."""

    text = _read_text("src", "core", "command_control", "command_control.py")
    assert "Handles Command and Control operations, including C2 beaconing." not in text
    assert "scenario command-channel emulation profiles" in text


def test_initial_access_docstring_describes_emulation() -> None:
    """Module docstrings describe emulation behavior."""

    text = _read_text("src", "core", "access", "initial_access.py")
    assert (
        "Handles initial access for all APT implementations"
        not in text
    )
    assert "scenario initial-access emulation profiles" in text


def test_exfiltration_docstring_describes_emulation() -> None:
    """Module docstrings describe emulation behavior."""

    text = _read_text("src", "core", "exfiltration", "exfiltration.py")
    assert "Handles data collection and exfiltration techniques." not in text
    assert (
        "scenario data-collection-and-exfiltration emulation"
        in text
    )


# ---------------------------------------------------------------------------
# Docs touch-ups
# ---------------------------------------------------------------------------


def test_apt29_case_study_uses_event_data_phrasing() -> None:
    """Case-study docs describe normalised event-data shape."""

    body = _read_text("docs", "case-studies", "apt29_credential_access.md")
    assert "normalized payload used by the detection engine" not in body
    assert "normalised event-data shape" in body
