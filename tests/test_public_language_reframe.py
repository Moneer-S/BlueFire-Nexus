"""Pin the public-language-reframe contract.

The maintainer's stated direction for the public-facing copy is to
avoid "payload / implant / beacon / callback / shellcode" lexicon
when pitching BlueFire-Nexus as a tool, while preserving identifier-
level uses (method names, dict keys, JSON field names) and legitimate
ATT&CK technique terminology where it describes the adversary
behaviour being emulated.

These tests pin the high-traffic user-facing prose surfaces so a
future drift -- e.g. a new docstring that pitches "fast payload
deployment" or a CLI ``--help`` that talks about "implant tasking" --
fails locally rather than landing on the public clone. The pins are
kept narrow on purpose: they target only the surfaces explicitly
called out in the audit (CLI help text, top-of-file module docstrings
for the three audit-flagged modules, README, USAGE_GUIDELINES).
Method bodies / runtime identifiers / typed-dict JSON keys are not
targeted -- renaming those would change the runtime contract.
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


def test_readme_does_not_pitch_implant_or_beacon_lexicon() -> None:
    """The public README must not pitch BlueFire-Nexus as deploying
    implants / callbacks / beacons / shellcode. The maintainer's
    public-facing direction is to keep the language focused on
    authorised emulation and detection engineering, not malware-
    toolkit framing."""

    body = _read_text("README.md").lower()
    for forbidden in ("implant", "callback", "beacon", "shellcode"):
        assert forbidden not in body, (
            f"README must not contain {forbidden!r} (public-language "
            "reframe pin)"
        )


# ---------------------------------------------------------------------------
# CLI help / docstrings
# ---------------------------------------------------------------------------


def test_cli_run_operation_docstring_is_reframed() -> None:
    """The ``run-operation`` command's docstring used to read
    ``Run one module operation from inline JSON payload.`` -- "JSON
    payload" reads as malware-tradecraft to a casual reader. The
    reframe spells out that the value is a typed module request body
    so the public ``--help`` output frames the surface as a
    detection-engineering harness rather than a deployment tool."""

    cli_text = _read_text("src", "core", "cli.py")
    assert "Run one module operation from inline JSON payload" not in cli_text
    assert "Run one module operation from an inline JSON request body" in cli_text


def test_cli_mutate_technique_docstring_is_reframed() -> None:
    """``mutate-technique`` previously read ``Mutate a technique
    payload for lab-only research experiments.`` -- "technique
    payload" carries malware-tradecraft framing. The reframe is
    "technique parameters" so the ``--help`` output is consistent
    with the tool's actual surface (the value is a JSON request
    body, not a deployable artefact)."""

    cli_text = _read_text("src", "core", "cli.py")
    assert "Mutate a technique payload for lab-only research experiments" not in cli_text
    assert "Mutate a module's technique parameters for lab-only research experiments" in cli_text


def test_cli_payload_option_help_is_reframed() -> None:
    """The ``--payload`` flag's help text is the highest-traffic
    user-facing string in the CLI. The historical short string
    (``JSON payload``) reads as malware-tradecraft. The reframe
    spells out the typed request-body framing so an operator
    inspecting ``--help`` sees the abstraction explicitly. The
    flag NAME stays ``--payload`` so the existing CLI surface
    doesn't break."""

    cli_text = _read_text("src", "core", "cli.py")
    # The reframe content -- spelled out request-body framing.
    assert "Module operation request body" in cli_text


# ---------------------------------------------------------------------------
# Module top-of-file docstrings (the three audit-flagged modules)
# ---------------------------------------------------------------------------


def test_command_control_module_docstring_is_reframed() -> None:
    """``CommandControl`` previously read
    ``Handles Command and Control operations, including C2
    beaconing.`` That single line carried both the attacker-toolkit
    "C2" framing AND the "beaconing" verb. The reframe describes the
    class as coordinating scenario command-channel emulation profiles
    -- the runtime-level identifiers (``start_http_beacon``,
    ``beacon_threads``) stay because they're part of the runtime
    contract scenarios reference, but the user-facing prose drops
    the malware-toolkit framing."""

    text = _read_text("src", "core", "command_control", "command_control.py")
    assert "Handles Command and Control operations, including C2 beaconing." not in text
    # The reframe explicitly describes the class as a scenario
    # coordinator, not a deployer.
    assert "scenario command-channel emulation profiles" in text


def test_initial_access_module_docstring_is_reframed() -> None:
    """``InitialAccessManager`` previously read
    ``Handles initial access for all APT implementations``. The
    reframe spells out that the class catalogs technique fingerprints
    for emulation, not deployment-tool framing."""

    text = _read_text("src", "core", "access", "initial_access.py")
    assert (
        "Handles initial access for all APT implementations"
        not in text
    )
    assert "scenario initial-access emulation profiles" in text


def test_exfiltration_module_docstring_is_reframed() -> None:
    """``Exfiltration`` previously read ``Handles data collection and
    exfiltration techniques.`` The reframe spells out that the class
    coordinates scenario emulation of the tradecraft fingerprint, not
    real data movement off a target."""

    text = _read_text("src", "core", "exfiltration", "exfiltration.py")
    assert "Handles data collection and exfiltration techniques." not in text
    assert (
        "scenario data-collection-and-exfiltration emulation"
        in text
    )


# ---------------------------------------------------------------------------
# Light docs touch-ups
# ---------------------------------------------------------------------------


def test_apt29_case_study_uses_event_data_not_payload() -> None:
    """The APT29 credential-access case study (defender-facing
    detection-engineering doc) previously read ``the same normalized
    payload used by the detection engine``. "payload" in this
    detection-engine context is HTTP/JSON terminology rather than
    malware tradecraft, but the reframe to ``normalised event-data
    shape`` reads more clearly to a defender skimming the doc, and
    keeps the public docs free of the ambiguity even when a casual
    reader doesn't know which sense is meant."""

    body = _read_text("docs", "case-studies", "apt29_credential_access.md")
    assert "normalized payload used by the detection engine" not in body
    assert "normalised event-data shape" in body
