"""Focused tests for the standard `discovery` module.

The registry-wide tests in `test_module_contract.py`, `test_module_safety.py`,
and `test_module_artifact_paths.py` cover this module structurally. These
tests cover the per-input-fan-out behaviour added when DiscoveryModule
started honouring `discovery_type` and `network_touch`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import DiscoveryModule, _DISCOVERY_PROFILES


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "discovery-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": ["10.0.0.0/24"],
    }


def test_default_discovery_type_is_network_scan(tmp_path: Path) -> None:
    """No `discovery_type` -> falls back to network_scan profile (T1046)."""
    mod = DiscoveryModule()
    result = mod.execute({"targets": ["10.0.0.5"]}, _ctx(tmp_path))
    assert result.status == "success"
    assert result.techniques == ["T1046"]
    assert result.artifacts["discovery_type"] == "network_scan"
    assert result.detection_hints["mitre_technique"] == "T1046"
    assert result.telemetry[0].event_type == "discovery_network_scan"
    assert result.telemetry[0].details["discovery_type"] == "network_scan"


@pytest.mark.parametrize("disc_type,expected_mitre", [
    ("network_scan", "T1046"),
    ("host_discovery", "T1018"),
    ("port_scan", "T1046"),
    ("service_scan", "T1046"),
    ("system_info", "T1082"),
    ("process_info", "T1057"),
    ("service_info", "T1007"),
    ("user_info", "T1087"),
    ("group_info", "T1069"),
    ("files", "T1083"),
])
def test_discovery_type_fans_out_to_correct_mitre(
    disc_type: str, expected_mitre: str, tmp_path: Path
) -> None:
    """Each catalog entry maps to a distinct MITRE technique on the result."""
    mod = DiscoveryModule()
    result = mod.execute(
        {"targets": ["host-1"], "discovery_type": disc_type},
        _ctx(tmp_path),
    )
    assert result.techniques == [expected_mitre], (
        f"{disc_type} should emit {expected_mitre}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre
    assert result.detection_hints["discovery_type"] == disc_type


def test_unknown_discovery_type_falls_back_with_marker(tmp_path: Path) -> None:
    """An unrecognized `discovery_type` falls back to network_scan and is recorded."""
    mod = DiscoveryModule()
    result = mod.execute(
        {"targets": ["host-1"], "discovery_type": "definitely_not_a_real_type"},
        _ctx(tmp_path),
    )
    # Falls back to network_scan
    assert result.artifacts["discovery_type"] == "network_scan"
    assert result.techniques == ["T1046"]
    # But surfaces the unrecognized value for operator visibility
    assert (
        result.detection_hints.get("unrecognized_discovery_type")
        == "definitely_not_a_real_type"
    )


def test_network_touch_false_skips_discovered_listing(tmp_path: Path) -> None:
    """`network_touch=False` is planning-only: telemetry shape but no discovered hosts."""
    mod = DiscoveryModule()
    result = mod.execute(
        {"targets": ["10.0.0.5", "10.0.0.6"], "network_touch": False},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.artifacts["discovered"] == []
    assert result.artifacts["network_touch"] is False
    # Targets are still recorded; only the simulated "up" listing is suppressed.
    assert result.artifacts["targets"] == ["10.0.0.5", "10.0.0.6"]
    assert "Planned" in result.message
    assert result.telemetry[0].details["network_touch"] is False


def test_network_touch_true_default_lists_targets(tmp_path: Path) -> None:
    """Without `network_touch`, default behaviour matches the pre-fan-out shape."""
    mod = DiscoveryModule()
    result = mod.execute({"targets": ["10.0.0.5"]}, _ctx(tmp_path))
    assert result.artifacts["discovered"] == [
        {"target": "10.0.0.5", "status": "simulated_up"}
    ]
    assert result.artifacts["network_touch"] is True


def test_targets_string_is_normalized_to_list(tmp_path: Path) -> None:
    """Scenarios sometimes pass `targets: 10.0.0.5` as a bare string."""
    mod = DiscoveryModule()
    result = mod.execute({"targets": "10.0.0.5"}, _ctx(tmp_path))
    assert result.artifacts["targets"] == ["10.0.0.5"]
    assert result.detection_hints["network_targets"] == ["10.0.0.5"]


def test_falls_back_to_allowed_subnets_when_no_targets(tmp_path: Path) -> None:
    mod = DiscoveryModule()
    ctx = _ctx(tmp_path)
    ctx["allowed_subnets"] = ["192.168.1.0/24"]
    result = mod.execute({}, ctx)
    assert result.artifacts["targets"] == ["192.168.1.0/24"]


def test_telemetry_event_per_profile_uses_distinct_event_types(tmp_path: Path) -> None:
    """Each catalog entry emits a distinct event_type so telemetry consumers can fan out."""
    mod = DiscoveryModule()
    seen: set[str] = set()
    for disc_type in _DISCOVERY_PROFILES:
        result = mod.execute(
            {"targets": ["t"], "discovery_type": disc_type},
            _ctx(tmp_path),
        )
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_DISCOVERY_PROFILES), (
        f"Expected {len(_DISCOVERY_PROFILES)} distinct event types, got {len(seen)}: {sorted(seen)}"
    )


def test_logsource_varies_by_profile_category(tmp_path: Path) -> None:
    """Network-oriented profiles use network_connection logsource;
    host-oriented profiles use process_creation/file_event."""
    mod = DiscoveryModule()
    network_oriented = ["network_scan", "host_discovery", "port_scan", "service_scan"]
    host_oriented = ["system_info", "process_info", "service_info", "user_info", "group_info"]
    file_oriented = ["files"]

    for disc_type in network_oriented:
        result = mod.execute(
            {"targets": ["t"], "discovery_type": disc_type},
            _ctx(tmp_path),
        )
        assert result.detection_hints["logsource"]["category"] == "network_connection"

    for disc_type in host_oriented:
        result = mod.execute(
            {"targets": ["t"], "discovery_type": disc_type},
            _ctx(tmp_path),
        )
        assert result.detection_hints["logsource"]["category"] == "process_creation"

    for disc_type in file_oriented:
        result = mod.execute(
            {"targets": ["t"], "discovery_type": disc_type},
            _ctx(tmp_path),
        )
        assert result.detection_hints["logsource"]["category"] == "file_event"
