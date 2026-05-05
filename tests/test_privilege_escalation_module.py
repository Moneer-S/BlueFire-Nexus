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
