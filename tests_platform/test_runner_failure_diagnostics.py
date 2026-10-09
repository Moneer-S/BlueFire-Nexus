"""Authored diagnostic values and caches only; no child processes or live registry access."""

import json
import subprocess

import pytest

from tests_platform.runner_failure_diagnostics import (
    darwin_governor_snapshot,
    transport_error_labels,
)

SENSITIVE = "secret-token:/private/authored/path/task-identity"


@pytest.mark.parametrize(
    "message,category",
    [
        ("Darwin process containment capacity is exhausted", "capacity_exhausted"),
        ("Darwin child status ownership is unavailable", "child_status_unavailable"),
        ("Runner watchdog exited before readiness", "watchdog_readiness_early_exit"),
        ("Runner watchdog did not become ready", "watchdog_readiness_deadline"),
        ("Runner watchdog readiness is unavailable", "watchdog_readiness_unavailable"),
        ("Runner watchdog readiness is invalid", "watchdog_readiness_invalid"),
        (
            "Runner watchdog containment is indeterminate and requires reconciliation.",
            "watchdog_indeterminate",
        ),
        ("Runner watchdog remains active and requires reconciliation.", "watchdog_active"),
        ("Runner watchdog containment could not be released", "watchdog_containment_unreleased"),
        ("Runner watchdog exceeded its terminal deadline", "watchdog_terminal_deadline"),
        ("Runner watchdog failed before publishing a valid result", "watchdog_no_valid_result"),
        ("Runner process tree could not be stopped safely", "process_stop_unverified"),
        ("Runner process tree state could not be released", "process_cleanup_unreleased"),
        ("Runner watchdog process tree could not be stopped safely", "watchdog_stop_unverified"),
        ("Rust runner exceeded the transport output limit", "output_limit"),
        ("Runner pending result requires recovery before the task can start.", "pending_result"),
        ("runner result is not valid UTF-8 JSON", "invalid_json"),
        ("runner returned a result that did not match its request", "invalid_result"),
        ("runner returned an unsupported result schema", "unsupported_result_schema"),
        ("Rust runner transport timed out", "transport_deadline"),
        ("Rust runner transport failed", "transport_failure"),
        ("Rust runner could not be started", "launch_failed"),
    ],
)
def test_stored_transport_errors_have_exact_finite_labels(message, category):
    row = {"code": "runner_transport_failed", "message": message, "private": SENSITIVE}
    evidence = {"error": message, "private": SENSITIVE}
    assert transport_error_labels(row) == {
        "code": "runner_transport_failed",
        "category": category,
    }
    assert transport_error_labels(evidence, evidence=True) == {
        "code": "not_recorded",
        "category": category,
    }
    assert row["message"] == evidence["error"] == message


@pytest.mark.parametrize(
    "value",
    [
        SENSITIVE,
        "Rust runner transport failed " + SENSITIVE,
        SENSITIVE + "Rust runner transport failed",
        "Rust runner transport failed\n",
        "x" * 1025,
        None,
        True,
        {"secret": SENSITIVE},
        [SENSITIVE],
    ],
)
def test_unknown_values_are_redacted_and_not_mistaken_for_missing(value):
    labels = transport_error_labels({"code": value, "message": value})
    assert labels == {"code": "unknown", "category": "unknown"}
    assert transport_error_labels({"error": value}, evidence=True) == {
        "code": "not_recorded",
        "category": "unknown",
    }
    assert SENSITIVE not in json.dumps(labels)


def test_absent_fields_are_distinct_from_present_null_or_invalid_containers():
    assert transport_error_labels({}) == {"code": "missing", "category": "missing"}
    assert transport_error_labels({}, evidence=True) == {
        "code": "not_recorded",
        "category": "missing",
    }
    assert transport_error_labels({"code": None}) == {"code": "unknown", "category": "missing"}
    assert transport_error_labels(None) == {"code": "unknown", "category": "unknown"}


def test_diagnostics_do_not_format_or_hash_unknown_error_objects():
    class Opaque:
        def __str__(self):
            pytest.fail("must not format private values")

        def __repr__(self):
            pytest.fail("must not represent private values")

        def __hash__(self):
            pytest.fail("must reject non-string values before lookup")

    assert transport_error_labels({"code": Opaque(), "message": Opaque()}) == {
        "code": "unknown",
        "category": "unknown",
    }


def _cached_process(value, *, include_returncode=True):
    process = subprocess.Popen.__new__(subprocess.Popen)
    process._child_created = False
    if include_returncode:
        process.returncode = value

    def forbidden(*_args, **_kwargs):
        pytest.fail("cached diagnostics must not inspect, signal or reap a process")

    process.poll = forbidden
    process.wait = forbidden
    process.kill = forbidden
    process.terminate = forbidden
    process.pid = SENSITIVE
    process.args = [SENSITIVE]
    return process


@pytest.mark.parametrize(
    "include,value,category",
    [
        (False, None, "missing"),
        (True, None, "none"),
        (True, 0, "int"),
        (True, -9, "int"),
        (True, True, "unknown"),
        (True, SENSITIVE, "unknown"),
    ],
)
def test_only_exact_popen_cached_returncode_category_is_read(include, value, category):
    owner = object()
    process = _cached_process(value, include_returncode=include)
    active = {process: owner}
    report = darwin_governor_snapshot(active, {}, set(), owner=owner)
    assert report["available"] is True
    assert report["popen_returncode_" + category] == 1
    assert (
        sum(report["popen_returncode_" + key] for key in ("missing", "none", "int", "unknown")) == 1
    )
    assert report["non_popen_objects"] == 0 and report["occupied"] == 1
    assert report["owned_by_current_runner"] == 1
    assert SENSITIVE not in json.dumps(report)
    assert active == {process: owner}


def test_empty_registry_and_overlap_counts_are_honest_and_leave_inputs_unchanged():
    owner, other = object(), object()
    assert darwin_governor_snapshot({}, {}, set(), owner=owner)["occupied"] == 0
    process, retired = _cached_process(None), _cached_process(0)
    active = {process: owner}
    indeterminate = {process: (owner, True, True, False), retired: (other, False, False, True)}
    pending = {object(), object()}
    before = active.copy(), indeterminate.copy(), pending.copy()
    report = darwin_governor_snapshot(active, indeterminate, pending, owner=owner)
    assert report["counts"] == {"active": 1, "indeterminate": 2, "pending": 2}
    assert report["inspected_entries"] == 3 and report["inspected_unique_processes"] == 2
    assert report["occupied"] == 4
    assert report["owned_by_current_runner"] == report["owned_by_other_runner"] == 1
    assert report["identity_lost"] == report["observe_only"] == 1
    assert report["popen_returncode_none"] == report["popen_returncode_int"] == 1
    assert not report["count_overflow"] and not report["inspection_overflow"]
    assert before == (active, indeterminate, pending)


def test_fake_objects_and_malformed_retention_are_not_reported_as_native_processes():
    class Fake:
        armed = False

        def __hash__(self):
            assert not self.armed, "diagnostics must not hash unknown registry keys"
            return 731

        def __eq__(self, _other):
            pytest.fail("diagnostics must not compare unknown registry keys")

        @property
        def returncode(self):
            pytest.fail("unknown objects must not be introspected")

    fake = Fake()
    indeterminate = {fake: (SENSITIVE,)}
    fake.armed = True
    report = darwin_governor_snapshot({}, indeterminate, set(), owner=object())
    assert report["non_popen_objects"] == report["indeterminate_state_unknown"] == 1
    assert report["owner_unknown"] == 1
    assert SENSITIVE not in json.dumps(report)


def test_enumeration_stops_at_32_entries_and_flags_unknown_total():
    class BeyondLimit:
        armed = False

        def __hash__(self):
            assert not self.armed, "entry beyond the bound was inspected"
            return 731

    owner = object()
    active = {object(): owner for _ in range(32)}
    beyond = BeyondLimit()
    active[beyond] = owner
    beyond.armed = True
    report = darwin_governor_snapshot(active, {}, set(), owner=owner)
    assert report["available"] is True
    assert report["counts"] == {"active": 32, "indeterminate": 0, "pending": 0}
    assert report["inspected_entries"] == report["inspected_unique_processes"] == 32
    assert report["count_overflow"] is True and report["inspection_overflow"] is True
    assert report["occupied"] == "unknown"


def test_combined_registry_bound_and_pending_overflow_are_explicit():
    owner = object()
    active = {object(): owner for _ in range(20)}
    indeterminate = {object(): (owner, False, False, False) for _ in range(20)}
    pending = {object() for _ in range(33)}
    report = darwin_governor_snapshot(active, indeterminate, pending, owner=owner)
    assert report["counts"] == {"active": 20, "indeterminate": 20, "pending": 32}
    assert report["inspected_entries"] == 32 and report["inspection_overflow"] is True
    assert report["count_overflow"] is True and report["occupied"] == "unknown"


@pytest.mark.parametrize(
    "active,indeterminate,pending", [(None, {}, set()), ({}, [], set()), ({}, {}, [])]
)
def test_unknown_registry_shape_is_not_an_empty_snapshot(active, indeterminate, pending):
    assert darwin_governor_snapshot(active, indeterminate, pending, owner=object()) == {
        "available": False,
        "reason": "registry_shape_unknown",
    }
