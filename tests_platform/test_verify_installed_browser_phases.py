"""Lifecycle gates for serial independent phases in the installed browser verifier."""

from __future__ import annotations

import pytest

from tools.verify_installed_browser import (
    _PRIMARY_PHASE_CLEANUP_KEYS,
    _phase_timeout,
    _receiver_phase_block_reason,
    _receiver_retained_redaction_accepted,
    _required_phases_passed,
    _runtime_process_cleanup_confirmed,
)


def clean_primary_report() -> dict[str, object]:
    return {key: True for key in _PRIMARY_PHASE_CLEANUP_KEYS}


def test_receiver_can_follow_an_assistant_failure_only_after_primary_cleanup() -> None:
    report = clean_primary_report()
    report.update(
        {
            "browser_phase_status": "passed",
            "assistant_fixture_phase_status": "failed",
            "receiver_phase_status": "passed",
        }
    )

    assert _receiver_phase_block_reason(report, runtime_admitted=True, work_remaining=30) is None
    assert not _required_phases_passed(report)


@pytest.mark.parametrize(
    ("runtime_admitted", "work_remaining", "changed_key", "expected"),
    [
        (False, 30, None, "installed_runtime_not_admitted"),
        (True, 30, "service_closed", "primary_phase_cleanup_unconfirmed"),
        (True, 0, None, "outer_work_deadline_reached"),
        (True, None, None, "outer_work_deadline_reached"),
    ],
)
def test_receiver_is_not_attempted_without_admission_cleanup_or_budget(
    runtime_admitted: bool,
    work_remaining: float | None,
    changed_key: str | None,
    expected: str,
) -> None:
    report = clean_primary_report()
    if changed_key is not None:
        report[changed_key] = False

    assert (
        _receiver_phase_block_reason(
            report, runtime_admitted=runtime_admitted, work_remaining=work_remaining
        )
        == expected
    )


def test_phase_timeout_never_exceeds_child_cap_or_outer_deadline() -> None:
    assert _phase_timeout(350.0, 240.0, now=100.0) == 240.0
    assert _phase_timeout(120.0, 360.0, now=100.0) == 20.0
    assert _phase_timeout(100.0, 360.0, now=100.0) is None


def test_unstarted_receiver_is_not_treated_as_unclean_or_as_receiver_proof() -> None:
    report = clean_primary_report()
    report.update(
        {
            "receiver_phase_status": "not_attempted",
            "receiver_driver_started": False,
            "receiver_driver_cleanup_confirmed": False,
            "receiver_process_group_stopped": True,
            "receiver_service_thread_stopped": True,
            "receiver_http_server_closed": True,
            "receiver_service_closed": True,
            "temporary_state_removed": True,
            "cleanup_errors": [],
            "receiver_retained_redaction_driver_passed": False,
        }
    )

    assert _runtime_process_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)


def test_started_receiver_requires_its_driver_cleanup_confirmation() -> None:
    report = clean_primary_report()
    report.update(
        {
            "receiver_phase_status": "failed",
            "receiver_driver_started": True,
            "receiver_driver_cleanup_confirmed": False,
            "receiver_process_group_stopped": True,
            "receiver_service_thread_stopped": True,
            "receiver_http_server_closed": True,
            "receiver_service_closed": True,
        }
    )

    assert not _runtime_process_cleanup_confirmed(report)
    report["receiver_driver_cleanup_confirmed"] = True
    assert _runtime_process_cleanup_confirmed(report)

    report["receiver_phase_status"] = "passed"
    report["receiver_driver_started"] = False
    assert not _runtime_process_cleanup_confirmed(report)


@pytest.mark.parametrize(
    ("browser", "assistant", "receiver", "expected"),
    [
        ("passed", "passed", "passed", True),
        ("passed", "failed", "passed", False),
        ("passed", "not_attempted", "passed", False),
        ("passed", "not_requested", "passed", True),
        ("passed", "not_requested", "not_attempted", False),
        ("failed", "not_attempted", "passed", False),
    ],
)
def test_overall_phase_result_is_a_conjunction(
    browser: str, assistant: str, receiver: str, expected: bool
) -> None:
    report = {
        "browser_phase_status": browser,
        "assistant_fixture_phase_status": assistant,
        "receiver_phase_status": receiver,
    }

    assert _required_phases_passed(report) is expected
