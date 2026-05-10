"""Focused tests for the standard `lateral_movement` module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    LateralMovementModule,
    _LATERAL_MOVEMENT_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "lateral-movement-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_default_technique_is_psexec(tmp_path: Path) -> None:
    mod = LateralMovementModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1021.002"]
    assert result.artifacts["technique"] == "psexec"
    assert result.detection_hints["mitre_technique"] == "T1021.002"
    assert result.telemetry[0].event_type == "lateral_movement_psexec"


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("psexec", "T1021.002"),
        ("wmi", "T1047"),
        ("winrm", "T1021.006"),
        ("smb_share", "T1021.002"),
        ("ssh", "T1021.004"),
        ("ftp_transfer", "T1570"),
        ("scp_transfer", "T1570"),
        ("service_create", "T1543.003"),
        ("rdp", "T1021.001"),
        ("pass_the_hash", "T1550.002"),
        ("pass_the_ticket", "T1550.003"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = LateralMovementModule()
    result = mod.execute(
        {"technique": technique, "source": "attacker-1", "target": "victim-1"},
        _ctx(tmp_path),
    )
    assert result.techniques == [expected_mitre]
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["lateral_technique"] == technique


def test_rdp_pins_port_3389_and_windows_logsource(tmp_path: Path) -> None:
    """RDP lateral movement (T1021.001) is the canonical Windows GUI-
    session pivot. Defenders alert on TCP connections to port 3389
    plus EventID 4624 logon-type 10. The catalog must pin port 3389
    and the windows logsource so the detection draft fires.

    Distinct from psexec/wmi/winrm: RDP delivers a full interactive
    session rather than a remote command runner, so the defender
    narrative differs.
    """

    mod = LateralMovementModule()
    result = mod.execute(
        {"technique": "rdp", "source": "jumpbox-01", "target": "victim-01"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1021.001"]
    assert result.artifacts["technique"] == "rdp"
    # Detection hint pins port 3389 + windows logsource.
    detection = result.detection_hints["detection"]
    assert detection["selection"]["network.dst_port"] == 3389
    logsource = result.detection_hints["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "network_connection"
    # Telemetry event type carries the technique-specific marker.
    event = result.telemetry[0]
    assert event.event_type == "lateral_movement_rdp"


def test_pass_the_hash_pins_ntlm_replay_tooling_marker(tmp_path: Path) -> None:
    """Pass-the-Hash (T1550.002) is the canonical Windows alternate-
    authentication-material pivot. Defenders alert on
    ``mimikatz sekurlsa::pth`` in process_creation telemetry; the
    catalog must pin a Windows process_creation logsource and the
    ``sekurlsa::pth`` substring so the detection draft fires.
    """

    mod = LateralMovementModule()
    result = mod.execute(
        {
            "technique": "pass_the_hash",
            "source": "compromised-host-01",
            "target": "fileserver-03",
        },
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1550.002"]
    assert result.artifacts["technique"] == "pass_the_hash"
    logsource = result.detection_hints["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "process_creation"
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    assert "pth" in selection_value.lower()
    # The selection must NOT collide with pass_the_ticket's marker --
    # both techniques live under T1550.* but a defender splitting the
    # two sub-techniques needs distinct selectors.
    assert "ptt" not in selection_value.lower()
    event = result.telemetry[0]
    assert event.event_type == "lateral_movement_pass_the_hash"


def test_pass_the_ticket_pins_kerberos_replay_tooling_marker(
    tmp_path: Path,
) -> None:
    """Pass-the-Ticket (T1550.003) reuses captured Kerberos tickets
    instead of NTLM hashes. Distinct from pass_the_hash by MITRE id,
    by the credential material reused (Kerberos ticket vs NTLM hash),
    and by the tooling-marker substring. The catalog must pin a
    Windows process_creation logsource and a selector that catches
    BOTH families: Rubeus's ``ptt`` subcommand AND mimikatz's
    ``kerberos::ptt`` module string.

    Pins the EXACT runtime selector (``ptt``) so a regression that
    narrows the substring back to a single tool family (``rubeus
    ptt`` was Codex P2 on PR #175 -- only matched Rubeus, silently
    missed every mimikatz invocation despite the comment claiming
    both) surfaces immediately.
    """

    mod = LateralMovementModule()
    result = mod.execute(
        {
            "technique": "pass_the_ticket",
            "source": "compromised-host-01",
            "target": "domain-controller-01",
        },
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1550.003"]
    assert result.artifacts["technique"] == "pass_the_ticket"
    logsource = result.detection_hints["logsource"]
    assert logsource["product"] == "windows"
    assert logsource["category"] == "process_creation"
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    # The selector must remain the bare ``ptt`` substring so it
    # matches BOTH ``Rubeus.exe ptt`` AND ``mimikatz "kerberos::ptt
    # ..."``. A regression that narrows the substring to a tool-
    # specific marker (e.g. ``rubeus ptt`` -- Codex P2 on PR #175)
    # silently misses one of the two tool families.
    assert selection_value == "ptt", (
        f"selector value must remain ``ptt`` to cover both Rubeus and "
        f"mimikatz invocations; got {selection_value!r}"
    )
    # Distinct from pass_the_hash's selector (no ``pth`` substring).
    assert "pth" not in selection_value.lower()
    event = result.telemetry[0]
    assert event.event_type == "lateral_movement_pass_the_ticket"


def test_pass_the_ticket_selector_matches_both_rubeus_and_mimikatz(
    tmp_path: Path,
) -> None:
    """Sanity check that the chosen ``ptt`` selector substring
    actually matches the canonical command lines for the two PtT
    tooling families. Pins the regression Codex P2 on PR #175
    surfaced (the prior ``rubeus ptt`` selector failed this check
    on the mimikatz invocation)."""

    mod = LateralMovementModule()
    result = mod.execute(
        {"technique": "pass_the_ticket"}, _ctx(tmp_path)
    )
    detection = result.detection_hints["detection"]
    selection_value = next(iter(detection["selection"].values()))
    rubeus_cmdline = (
        "C:\\Tools\\Rubeus.exe ptt /ticket:doIFTjCCBUqgAwIBBaED..."
    )
    mimikatz_cmdline = (
        'mimikatz.exe "kerberos::ptt admin.ccache" exit'
    )
    assert selection_value in rubeus_cmdline.lower(), (
        "selector must match Rubeus PtT command lines"
    )
    assert selection_value in mimikatz_cmdline.lower(), (
        "selector must match mimikatz PtT command lines"
    )


def test_unknown_technique_falls_back_with_marker(tmp_path: Path) -> None:
    mod = LateralMovementModule()
    result = mod.execute({"technique": "not_a_thing"}, _ctx(tmp_path))
    assert result.artifacts["technique"] == "psexec"
    assert result.techniques == ["T1021.002"]
    assert result.detection_hints.get("unrecognized_lateral_technique") == "not_a_thing"


def test_source_and_target_are_recorded(tmp_path: Path) -> None:
    mod = LateralMovementModule()
    result = mod.execute(
        {"technique": "winrm", "source": "jumpbox-01", "target": "fileserver-03"},
        _ctx(tmp_path),
    )
    assert result.artifacts["source"] == "jumpbox-01"
    assert result.artifacts["target"] == "fileserver-03"
    assert result.detection_hints["source_host"] == "jumpbox-01"
    assert result.detection_hints["target_host"] == "fileserver-03"
    assert "fileserver-03" in result.detection_hints["title"]
    assert "jumpbox-01" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    mod = LateralMovementModule()
    seen: set[str] = set()
    for technique in _LATERAL_MOVEMENT_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_LATERAL_MOVEMENT_PROFILES)


def test_logsource_categories_span_network_and_host(tmp_path: Path) -> None:
    """Mix of network_connection / process_creation / file_event / service_creation."""
    mod = LateralMovementModule()
    categories: set[str] = set()
    for technique in _LATERAL_MOVEMENT_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        categories.add(result.detection_hints["logsource"]["category"])
    assert "network_connection" in categories
    assert "process_creation" in categories
    assert "file_event" in categories
    assert "service_creation" in categories


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "lateral_movement" in modules
    assert isinstance(modules["lateral_movement"], LateralMovementModule)


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {profile["mitre"] for profile in _LATERAL_MOVEMENT_PROFILES.values()}
    advertised = set(LateralMovementModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )
