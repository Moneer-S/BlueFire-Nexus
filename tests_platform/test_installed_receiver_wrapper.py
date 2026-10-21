"""Pure contracts for the optional installed receiver baseline wrapper."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from tools.verify_installed_browser import (
    _RUNTIME_PROCESS_CLEANUP_KEYS,
    _receiver_baseline_accepted,
    _receiver_driver_passed,
    _resolve_receiver_driver,
    _runtime_cleanup_confirmed,
    _runtime_process_cleanup_confirmed,
)


def receiver_report() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-receiver-baseline.v1",
        "status": "passed",
        "installed_wheel_service": True,
        "native_execution_required": True,
        "workflow": "retained_redaction_baseline_only",
        "external_credentials": False,
        "live_model_inference": False,
        "generated_record_count": 8,
        "runner_profile": "sandbox-endpoint-deep-lab.v1",
        "target_scope": ["sandbox.workspace", "network.loopback"],
        "checks": [
            "packaged_starter_duplicated_and_saved_through_ui",
            "native_execute_baseline_and_authenticated_receiver_terminal",
        ],
        "blocked_requests": [],
        "errors": [],
        "cleanup": {"receiver_control_stopped": True, "runner_stopped": True},
        "owner_status": "stopped",
        "request_counts": {
            name: 1
            for name in ("save_scenario", "owner", "prepare", "review", "approval", "cancel")
        },
        "source_starter_scenario_id": "scenario.receiver-defense.redaction-validation.v1",
        "saved_scenario_copy": {
            "scenario_id": "scenario.receiver-defense.redaction-validation.copy.12345678-1234-4234-8234-123456789abc.v1",
            "version": 1,
            "digest": "sha256:" + "a" * 64,
        },
        "baseline": {
            "status": "completed",
            "execution_state": "completed",
            "mode": "execute",
            "scenario_id": "scenario.receiver-defense.redaction-validation.copy.12345678-1234-4234-8234-123456789abc.v1",
            "run_profile": "sandbox-endpoint-deep-lab.v1",
            "receiver_decision": "accepted",
            "observation_state": "verified",
            "receiver_terminal": {
                "decision": "accepted",
                "authenticated": True,
                "record_count": 8,
                "redacted_record_count": 0,
                "retained_record_count": 8,
            },
        },
    }


def clean_wrapper_report() -> dict[str, object]:
    return {
        **{key: True for key in _RUNTIME_PROCESS_CLEANUP_KEYS},
        "temporary_state_removed": True,
        "receiver_baseline_driver_passed": True,
    }


def test_receiver_baseline_requires_the_exact_retained_unredacted_semantics() -> None:
    report = receiver_report()
    assert _receiver_driver_passed(report)

    for path, value in (
        ("baseline.receiver_terminal.redacted_record_count", 1),
        ("baseline.receiver_terminal.retained_record_count", 0),
        ("baseline.receiver_terminal.retained_record_count", True),
        ("baseline.receiver_terminal.redacted_record_count", False),
        ("baseline.receiver_terminal.record_count", True),
        ("generated_record_count", True),
        ("baseline.receiver_terminal.record_count", 7),
        ("baseline.scenario_id", "scenario.receiver-defense.redaction-validation.v1"),
        ("request_counts.save_scenario", True),
        ("source_starter_scenario_id", "scenario.other.v1"),
    ):
        changed = deepcopy(report)
        if path.startswith("baseline.receiver_terminal."):
            field = path.split("receiver_terminal.", 1)[1]
            changed["baseline"]["receiver_terminal"][field] = value
        elif path.startswith("baseline."):
            changed["baseline"][path.split(".", 1)[1]] = value
        elif path.startswith("request_counts."):
            changed["request_counts"][path.split(".", 1)[1]] = value
        else:
            changed[path] = value
        assert not _receiver_driver_passed(changed), path

    for field, value in (
        ("version", 2),
        ("digest", "not-a-digest"),
        ("scenario_id", "scenario.other.v1"),
    ):
        changed = deepcopy(report)
        changed["saved_scenario_copy"][field] = value
        assert not _receiver_driver_passed(changed), f"saved_scenario_copy.{field}"


@pytest.mark.parametrize("driver_requested", [False, True])
def test_receiver_driver_paths_require_a_copied_driver_and_adjacent_guard(
    tmp_path: Path, driver_requested: bool
) -> None:
    checkout = tmp_path / "checkout"
    copied = tmp_path / "copied"
    checkout.mkdir()
    copied.mkdir()
    if not driver_requested:
        assert _resolve_receiver_driver(None, checkout) == (None, None)
        return

    driver = copied / "installed-receiver.mjs"
    guard = copied / "receiver-guards.mjs"
    driver.write_text("// pinned browser driver\n", encoding="utf-8")
    guard.write_text("// pinned request contract\n", encoding="utf-8")
    assert _resolve_receiver_driver(driver, checkout) == (driver.resolve(), guard.resolve())

    in_checkout_driver = checkout / driver.name
    in_checkout_driver.write_text("// not an external copy\n", encoding="utf-8")
    (checkout / guard.name).write_text("// guard\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _resolve_receiver_driver(in_checkout_driver, checkout)


def test_missing_receiver_guard_fails_before_launch(tmp_path: Path) -> None:
    driver = tmp_path / "installed-receiver.mjs"
    driver.write_text("// driver\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        _resolve_receiver_driver(driver, tmp_path / "checkout")


def test_each_unconfirmed_cleanup_state_blocks_runtime_removal_and_acceptance() -> None:
    report = clean_wrapper_report()
    assert _runtime_process_cleanup_confirmed(report)
    assert _runtime_cleanup_confirmed(report)
    assert _receiver_baseline_accepted(report)

    for key in (*_RUNTIME_PROCESS_CLEANUP_KEYS, "temporary_state_removed"):
        changed = clean_wrapper_report()
        changed[key] = False
        assert not _runtime_cleanup_confirmed(changed), key
        assert not _receiver_baseline_accepted(changed), key


def test_cleanup_confirmation_requires_boolean_true() -> None:
    report = clean_wrapper_report()
    report["receiver_driver_cleanup_confirmed"] = 1
    assert not _runtime_process_cleanup_confirmed(report)
    assert not _receiver_baseline_accepted(report)
