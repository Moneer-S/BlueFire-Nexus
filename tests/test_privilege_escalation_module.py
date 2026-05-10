"""Focused tests for the standard `privilege_escalation` module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    PrivilegeEscalationModule,
    _PRIVILEGE_ESCALATION_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "privilege-escalation-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_default_technique_is_token_impersonation(tmp_path: Path) -> None:
    mod = PrivilegeEscalationModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1134.001"]
    assert result.artifacts["technique"] == "token_impersonation"
    assert result.detection_hints["mitre_technique"] == "T1134.001"
    assert result.telemetry[0].event_type == "privilege_escalation_token_impersonation"


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("token_impersonation", "T1134.001"),
        ("token_duplication", "T1134.001"),
        ("token_creation", "T1134.003"),
        ("process_hollowing", "T1055.012"),
        ("process_injection", "T1055"),
        ("process_masquerading", "T1036.005"),
        ("service_creation", "T1543.003"),
        ("service_modification", "T1543.003"),
        ("uac_bypass", "T1548.002"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = PrivilegeEscalationModule()
    result = mod.execute({"technique": technique, "target": "lab-host"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre]
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["privesc_technique"] == technique


def test_unknown_technique_falls_back_with_marker(tmp_path: Path) -> None:
    mod = PrivilegeEscalationModule()
    result = mod.execute({"technique": "not_a_thing"}, _ctx(tmp_path))
    assert result.artifacts["technique"] == "token_impersonation"
    assert result.techniques == ["T1134.001"]
    assert (
        result.detection_hints.get("unrecognized_privesc_technique") == "not_a_thing"
    )


def test_target_is_recorded(tmp_path: Path) -> None:
    mod = PrivilegeEscalationModule()
    result = mod.execute(
        {"technique": "uac_bypass", "target": "workstation-22"},
        _ctx(tmp_path),
    )
    assert result.artifacts["target"] == "workstation-22"
    assert result.detection_hints["target_host"] == "workstation-22"
    assert "workstation-22" in result.detection_hints["title"]


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    mod = PrivilegeEscalationModule()
    seen: set[str] = set()
    for technique in _PRIVILEGE_ESCALATION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_PRIVILEGE_ESCALATION_PROFILES)


def test_logsource_categories_span_process_and_service(tmp_path: Path) -> None:
    mod = PrivilegeEscalationModule()
    categories: set[str] = set()
    for technique in _PRIVILEGE_ESCALATION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        categories.add(result.detection_hints["logsource"]["category"])
    assert "process_creation" in categories
    assert "service_creation" in categories
    assert "service_modification" in categories


def test_module_registers_at_canonical_name() -> None:
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    assert "privilege_escalation" in modules
    assert isinstance(modules["privilege_escalation"], PrivilegeEscalationModule)


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {profile["mitre"] for profile in _PRIVILEGE_ESCALATION_PROFILES.values()}
    advertised = set(PrivilegeEscalationModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )


# ---------------------------------------------------------------------------
# Parent PID Spoofing / SID-History Injection (T1134.004 / T1134.005)
# ---------------------------------------------------------------------------


def test_parent_pid_spoof_pins_t1134_004_with_api_substring(tmp_path: Path) -> None:
    """Parent PID Spoofing (T1134.004) pins the canonical Win32 API
    substring ``UpdateProcThreadAttribute``. Pin the MITRE id, the
    process_creation logsource, and the API substring so the rendered
    detection draft fires on tooling that constructs PPID-spoofed
    processes."""

    mod = PrivilegeEscalationModule()
    result = mod.execute(
        {"technique": "parent_pid_spoof", "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1134.004"]
    assert result.detection_hints["logsource"] == {
        "category": "process_creation",
        "product": "windows",
    }
    selection = result.detection_hints["detection"]["selection"]
    assert "UpdateProcThreadAttribute" in selection.get(
        "process.command_line|contains", ""
    )


def test_sid_history_injection_pins_t1134_005_with_sids_substring(
    tmp_path: Path,
) -> None:
    """SID-History Injection (T1134.005) pins the mimikatz CLI
    substring ``/sids:`` which appears in
    ``kerberos::golden /sids:<...>`` invocations. Pin the MITRE id,
    process_creation logsource, and the substring so the detection
    draft fires on the canonical SID-History forging tool."""

    mod = PrivilegeEscalationModule()
    result = mod.execute(
        {"technique": "sid_history_injection", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1134.005"]
    assert result.detection_hints["logsource"] == {
        "category": "process_creation",
        "product": "windows",
    }
    selection = result.detection_hints["detection"]["selection"]
    assert "/sids:" in selection.get("process.command_line|contains", "")


def test_t1134_subtechnique_family_includes_token_and_ppid_branches(
    tmp_path: Path,
) -> None:
    """The T1134 family (Access Token Manipulation) now spans
    ``T1134.001`` (Token Impersonation/Theft), ``T1134.002`` (Create
    Process with Token), ``T1134.003`` (Make and Impersonate Token),
    ``T1134.004`` (Parent PID Spoofing), and ``T1134.005`` (SID-
    History Injection). Pin presence so a future drop fails here."""

    mod = PrivilegeEscalationModule()
    expected = {
        "T1134.001",
        "T1134.002",
        "T1134.003",
        "T1134.004",
        "T1134.005",
    }
    seen: set[str] = set()
    for technique in _PRIVILEGE_ESCALATION_PROFILES:
        result = mod.execute({"technique": technique}, _ctx(tmp_path))
        seen.update(result.techniques)
    assert expected <= seen, f"missing T1134 sub-techniques: {expected - seen}"


def test_create_process_with_token_pins_t1134_002_with_api_substring(
    tmp_path: Path,
) -> None:
    """Create Process with Token (T1134.002) pins the canonical Win32
    API substring ``CreateProcessWithToken``. Pin the MITRE id, the
    process_creation logsource, and the API substring so the rendered
    detection draft fires on tooling that uses
    ``CreateProcessWithTokenW`` to spawn a child as a different
    principal. Distinct from ``token_impersonation`` (T1134.001)
    which hijacks the calling thread instead."""

    mod = PrivilegeEscalationModule()
    result = mod.execute(
        {"technique": "create_process_with_token", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1134.002"]
    assert result.detection_hints["logsource"] == {
        "category": "process_creation",
        "product": "windows",
    }
    selection = result.detection_hints["detection"]["selection"]
    assert "CreateProcessWithToken" in selection.get(
        "process.command_line|contains", ""
    )
