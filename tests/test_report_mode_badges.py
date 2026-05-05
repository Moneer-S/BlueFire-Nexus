"""Tests for the per-step mode-badge enhancement to run reports."""

from __future__ import annotations

import json
from pathlib import Path

from src.core.models import ModuleResult, TelemetryEvent
from src.core.reporting.run_reports import (
    _mode_badge,
    build_risk_summary,
    write_markdown_report,
    write_risk_summary,
)


def _result(
    module: str,
    *,
    status: str = "success",
    artifacts: dict | None = None,
    hints: dict | None = None,
) -> ModuleResult:
    return ModuleResult(
        status=status,
        module=module,
        message="ok",
        techniques=["T0000"],
        artifacts=artifacts or {},
        detection_hints=hints or {},
        telemetry=[TelemetryEvent(event_type="x", module=module)],
    )


def test_mode_badge_dry_run_for_execution_with_dry_run_marker() -> None:
    """ExecutionModule dry-run path leaves a `[dry-run]` marker in stdout."""
    result = _result(
        "execution",
        artifacts={"command": "echo x", "stdout": "[dry-run] would execute: echo x", "return_code": 0},
    )
    badge = _mode_badge(result)
    assert badge["mode"] == "dry-run"


def test_mode_badge_real_execution_when_subprocess_actually_ran() -> None:
    result = _result(
        "execution",
        artifacts={"command": "echo x", "stdout": "x\n", "return_code": 0},
    )
    badge = _mode_badge(result)
    assert badge["mode"] == "real-execution"


def test_mode_badge_simulate_for_simple_modules() -> None:
    """Modules without execution-specific shape default to simulate."""
    result = _result("discovery", artifacts={"discovered": []})
    badge = _mode_badge(result)
    assert badge["mode"] == "simulate"


def test_mode_badge_legacy_mode_extracted_from_artifacts() -> None:
    """Legacy adapters store mode under artifacts['legacy']."""
    result = _result(
        "legacy_actor_profile",
        artifacts={
            "legacy": {
                "pack": "actor_pack",
                "capability": "apt29",
                "mode": "emulate",
                "decision": {"acknowledged": True},
            }
        },
    )
    badge = _mode_badge(result)
    assert badge["mode"] == "emulate"
    assert badge["pack"] == "actor_pack"
    assert badge["lab_acknowledged"] is True


def test_mode_badge_network_touch_extracted_from_artifacts(tmp_path: Path) -> None:
    """Discovery records network_touch in artifacts; badge surfaces it."""
    result = _result("discovery", artifacts={"network_touch": True, "discovered": []})
    badge = _mode_badge(result)
    assert badge["network_touch"] is True


def test_mode_badge_target_os_extracted(tmp_path: Path) -> None:
    """Execution records target_os in artifacts (post-platform-aware logsource)."""
    result = _result(
        "execution",
        artifacts={"command": "echo x", "stdout": "[dry-run]", "return_code": 0, "target_os": "linux"},
    )
    badge = _mode_badge(result)
    assert badge["target_os"] == "linux"


def test_mode_badge_destructive_acknowledged_flag() -> None:
    """Destructive ops with explicit lab ack surface the destructive badge."""
    result = _result(
        "exfiltration",
        artifacts={"destructive": True, "i_understand_this_is_a_lab": True},
    )
    badge = _mode_badge(result)
    assert badge["destructive"] is True


def test_risk_summary_includes_mode_badges_per_module(tmp_path: Path) -> None:
    """build_risk_summary embeds mode/network_touch/target_os/lab_ack/destructive."""
    results = {
        "execution:s1": _result(
            "execution",
            artifacts={"command": "echo", "stdout": "[dry-run]", "return_code": 0, "target_os": "linux"},
        ),
        "discovery:s2": _result(
            "discovery", artifacts={"network_touch": False, "discovered": []}
        ),
        "legacy_actor_profile:s3": _result(
            "legacy_actor_profile",
            artifacts={
                "legacy": {
                    "pack": "actor_pack",
                    "capability": "apt29",
                    "mode": "simulate",
                    "decision": {"acknowledged": True},
                }
            },
        ),
    }
    summary = build_risk_summary(results)
    by_name = {m["module"]: m for m in summary["modules"]}

    assert by_name["execution:s1"]["mode"] == "dry-run"
    assert by_name["execution:s1"]["target_os"] == "linux"

    assert by_name["discovery:s2"]["mode"] == "simulate"
    assert by_name["discovery:s2"]["network_touch"] is False

    assert by_name["legacy_actor_profile:s3"]["mode"] == "simulate"
    assert by_name["legacy_actor_profile:s3"]["pack"] == "actor_pack"
    assert by_name["legacy_actor_profile:s3"]["lab_acknowledged"] is True

    # blocked_steps key always present, empty when no step is blocked
    assert summary["blocked_steps"] == []


def test_risk_summary_records_blocked_steps(tmp_path: Path) -> None:
    results = {
        "ok:s1": _result("execution", status="success", artifacts={"command": "echo", "stdout": "[dry-run]", "return_code": 0}),
        "blocked:s2": _result("legacy_apt29_research", status="blocked"),
    }
    summary = build_risk_summary(results)
    assert summary["blocked_steps"] == ["blocked:s2"]


def test_markdown_report_renders_mode_line_per_module(tmp_path: Path) -> None:
    results = {
        "execution:step": _result(
            "execution",
            artifacts={"command": "echo x", "stdout": "[dry-run]", "return_code": 0, "target_os": "linux"},
        ),
        "blocked:step": _result("anti_detection", status="blocked"),
    }
    detections: dict = {"execution:step": {"sigma": "sigma/x.yml"}, "blocked:step": {}}
    report_path = write_markdown_report(tmp_path, "test_scenario", results, detections)
    text = report_path.read_text(encoding="utf-8")

    assert "Mode:" in text
    assert "dry-run" in text
    assert "target_os=`linux`" in text
    assert "## Blocked Steps" in text
    assert "`blocked:step`" in text


def test_write_risk_summary_round_trip(tmp_path: Path) -> None:
    results = {
        "execution:step": _result(
            "execution",
            artifacts={"command": "echo", "stdout": "[dry-run]", "return_code": 0, "target_os": "windows"},
        ),
    }
    target = write_risk_summary(tmp_path, results)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert "blocked_steps" in payload
    assert payload["modules"][0]["mode"] == "dry-run"
    assert payload["modules"][0]["target_os"] == "windows"
