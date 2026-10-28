"""Finite macOS startup exits from retained fakes; no native process is launched."""

from __future__ import annotations

import io
import json
import os
import threading
from contextlib import redirect_stdout
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import macos_file_access_creator as creator
from bluefire import macos_file_access_local as local
from bluefire import macos_file_access_worker as worker
from bluefire import macos_setup_failure_diagnostics as diagnostics
from tools import verify_macos_file_access_lifecycle as verifier


class RetainedPopen:
    def __init__(self, returncode):
        self.returncode = returncode


def _worker(monkeypatch, code):
    monkeypatch.setattr(worker, "subprocess", SimpleNamespace(Popen=RetainedPopen))
    value = object.__new__(worker.MacOSFileAccessWorker)
    process = RetainedPopen(code)
    value._lock = threading.Lock()
    value._settled = True
    value._local_cleanup_unknown = False
    value._creation_started = True
    value._factory_entered = True
    value._processes = [process]
    value._proven = [process]
    value._process = process
    value._native_diagnostic_thread = None
    return value


def _creator(workers):
    value = object.__new__(creator.MacOSFileAccessCreator)
    value._creator_pid = os.getpid()
    value._lock = threading.Lock()
    value._state = "retired"
    value._retired_workers_closed = True
    value._workers = workers
    return value


def test_settled_original_code_96_retains_only_one_finite_native_frame(monkeypatch):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity}
        for fd in (0, 1, 2, 3, 4, 9)
    ]
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    retained._native_diagnostic_complete = True
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_bytes = bytearray(
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}).encode()
        + b"\n"
    )
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {"role": "primitive_channel", "fd": 13, "identity": identity},
    ]
    status = retained.retained_native_startup_status()
    assert status["returncode"] == 96
    assert status["descriptor_observation"]["native_rows"] == rows
    assert status["descriptor_observation"]["scope"] == "diagnostic_only_no_descriptor_admission"
    assert retained._native_diagnostic_bytes == b""
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}

    retained._native_diagnostic_bytes = bytearray(b"arbitrary stderr\n")
    assert "descriptor_observation" not in retained.retained_native_startup_status()
    retained._native_diagnostic_bytes = bytearray(
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}).encode()
        + b"\n"
    )
    retained._process.returncode = 95
    assert "descriptor_observation" not in retained.retained_native_startup_status()


@pytest.mark.parametrize("code,label", sorted(diagnostics.NATIVE_STARTUP_EXIT_LABELS.items()))
def test_only_exact_reserved_reaped_native_code_maps_to_fixed_label(monkeypatch, code, label):
    retained = _worker(monkeypatch, code)
    original = _creator({"owner": retained})

    assert retained.retained_native_startup_exit_code() == code
    assert original.retained_native_startup_exits() == {"owner": label}


@pytest.mark.parametrize("code", [None, False, True, 0, 2, 3, 4, -15, 79, 107, "80"])
def test_unavailable_generic_signal_unknown_and_bool_codes_have_no_cause(monkeypatch, code):
    retained = _worker(monkeypatch, code)
    original = _creator({"reader": retained})

    assert original.retained_native_startup_exits() is None


@pytest.mark.parametrize(
    "code,expected",
    [
        (0, {"status": "clean_exit", "returncode": 0}),
        (2, {"status": "other_exit", "returncode": 2}),
        (107, {"status": "other_exit", "returncode": 107}),
        (
            84,
            {
                "status": "reserved_stage_exit",
                "returncode": 84,
                "label": "credential_selection",
            },
        ),
        (
            -15,
            {"status": "signal_termination", "returncode": -15},
        ),
        (-99, {"status": "signal_termination", "returncode": -99}),
        (None, {"status": "unavailable", "reason": "returncode_unavailable"}),
        (True, {"status": "unavailable", "reason": "returncode_invalid"}),
        (256, {"status": "unavailable", "reason": "returncode_out_of_bounds"}),
    ],
)
def test_cached_returncode_projects_only_bounded_status(code, expected):
    assert diagnostics.native_startup_status_from_returncode(code) == expected
    assert diagnostics.valid_native_startup_status(expected)


def test_native_status_validator_rejects_mismatched_label_and_unbounded_code():
    assert not diagnostics.valid_native_startup_status(
        {"status": "reserved_stage_exit", "returncode": 84, "label": "initial_clock_or_deadline"}
    )
    assert not diagnostics.valid_native_startup_status({"status": "other_exit", "returncode": 256})
    assert not diagnostics.valid_native_startup_status({"status": "other_exit", "returncode": True})


@pytest.mark.parametrize(
    "fault",
    [
        "unsettled",
        "cleanup_unknown",
        "unproven",
        "unretained",
        "forged_process",
        "ambiguous",
        "different_original",
    ],
)
def test_unreaped_or_unowned_worker_status_cannot_cross_retirement(monkeypatch, fault):
    retained = _worker(monkeypatch, 80)
    if fault == "unsettled":
        retained._settled = False
    elif fault == "cleanup_unknown":
        retained._local_cleanup_unknown = True
    elif fault == "unproven":
        retained._proven = []
    elif fault == "unretained":
        retained._processes = []
    elif fault == "forged_process":
        retained._processes = [SimpleNamespace(returncode=80)]
    elif fault == "ambiguous":
        retained._processes.append(RetainedPopen(80))
    else:
        retained._process = RetainedPopen(80)
    assert _creator({"reader": retained}).retained_native_startup_exits() is None


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("unsettled", "not_settled"),
        ("cleanup_unknown", "cleanup_unknown"),
        ("unproven", "proof_count_mismatch"),
        ("unretained", "process_count_mismatch"),
        ("forged_process", "process_identity_mismatch"),
        ("not_started", "not_started"),
        ("factory_not_entered", "factory_not_entered"),
    ],
)
def test_worker_status_reports_exact_fixed_capture_gate(monkeypatch, fault, reason):
    retained = _worker(monkeypatch, 86)
    if fault == "unsettled":
        retained._settled = False
    elif fault == "cleanup_unknown":
        retained._local_cleanup_unknown = True
    elif fault == "unproven":
        retained._proven = []
    elif fault == "unretained":
        retained._processes = []
    elif fault == "forged_process":
        retained._processes = [SimpleNamespace(returncode=86)]
    elif fault == "not_started":
        retained._creation_started = False
    else:
        retained._factory_entered = False
    assert retained.retained_native_startup_status() == {
        "status": "unavailable",
        "reason": reason,
    }


def test_busy_worker_lock_returns_without_waiting_or_reading_status(monkeypatch):
    retained = _worker(monkeypatch, 80)
    retained._lock.acquire()
    try:
        assert retained.retained_native_startup_exit_code() is None
        assert _creator({"reader": retained}).retained_native_startup_exits() is None
        assert retained.retained_native_startup_status() == {
            "status": "unavailable",
            "reason": "worker_lock_busy",
        }
    finally:
        retained._lock.release()


def test_unsettled_worker_never_reads_cached_popen_status(monkeypatch):
    class UnreadablePopen:
        @property
        def __dict__(self):
            raise AssertionError("cached status must not be read before settlement")

    retained = _worker(monkeypatch, 80)
    monkeypatch.setattr(worker, "subprocess", SimpleNamespace(Popen=UnreadablePopen))
    process = UnreadablePopen()
    retained._processes = [process]
    retained._proven = [process]
    retained._process = process
    retained._settled = False
    assert retained.retained_native_startup_exit_code() is None
    assert retained.retained_native_startup_status() == {
        "status": "unavailable",
        "reason": "not_settled",
    }


def test_creator_and_local_attach_require_completed_retirement(monkeypatch):
    retained = _worker(monkeypatch, 86)
    original = _creator({"reader": retained, "owner": _worker(monkeypatch, -15)})
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )

    original._retired_workers_closed = False
    assert original.retained_native_startup_exits() is None
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": True})
    assert not hasattr(failure, "safe_native_startup_exits")
    assert failure.safe_native_startup_statuses == {
        "reader": {"status": "unavailable", "reason": "workers_not_closed"},
        "owner": {"status": "unavailable", "reason": "workers_not_closed"},
    }

    original._retired_workers_closed = True
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": False})
    assert not hasattr(failure, "safe_native_startup_exits")
    assert failure.safe_native_startup_statuses == {
        "reader": {"status": "unavailable", "reason": "workers_not_closed"},
        "owner": {"status": "unavailable", "reason": "workers_not_closed"},
    }
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": True})
    assert failure.safe_native_startup_exits == {"reader": "initial_resource_validation"}
    assert failure.safe_native_startup_statuses["reader"]["status"] == "reserved_stage_exit"

    other_stage = local.MacOSSetupFailure("service_startup", "safe")
    local._attach_retired_native_startup_exits(other_stage, original, {"workers_closed": True})
    assert not hasattr(other_stage, "safe_native_startup_exits")
    assert not hasattr(other_stage, "safe_native_startup_statuses")


@pytest.mark.parametrize(
    "field,value",
    [
        ("_state", "unknown"),
        ("_retired_workers_closed", 1),
        ("_creator_pid", -1),
    ],
)
def test_forged_creator_retirement_does_not_grant_diagnostic(monkeypatch, field, value):
    original = _creator({"reader": _worker(monkeypatch, 80)})
    setattr(original, field, value)
    assert original.retained_native_startup_exits() is None


def test_unknown_creator_role_cannot_be_reported(monkeypatch):
    original = _creator({"outside_role": _worker(monkeypatch, 80)})
    assert original.retained_native_startup_exits() is None


def _cli_error(monkeypatch, failure):
    monkeypatch.setattr(cli, "_execute", lambda _args: (_ for _ in ()).throw(failure))
    output = io.StringIO()
    with redirect_stdout(output):
        assert cli.main(["runner", "macos-file-setup", "--confirm-create-generated-workspace"]) == 2
    return json.loads(output.getvalue())["error"]


@pytest.mark.parametrize(
    "code,label",
    [(code, label) for code, label in diagnostics.NATIVE_STARTUP_EXIT_LABELS.items() if code >= 88],
)
def test_inventory_substage_labels_cross_cli_and_verifier(monkeypatch, code, label):
    retained = _worker(monkeypatch, code)
    original = _creator({"reader": retained})
    original._retired_workers_closed = True
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": True})

    error = _cli_error(monkeypatch, failure)
    expected_exit = {"reader": label}
    assert error["native_startup_exits"] == expected_exit
    parsed = verifier._parse_child_cli_error(json.dumps({"error": error}))
    assert parsed["native_startup_exits"] == expected_exit
    readiness = verifier._safe_readiness_diagnostics("child_exited_before_readiness", {}, parsed)
    assert readiness["native_startup_exits"] == expected_exit
    assert code != 0


def test_cli_and_verifier_independently_revalidate_only_fixed_labels(monkeypatch):
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    failure.safe_native_startup_exits = {"reader": "initial_descriptor_inventory_rows"}
    failure.safe_native_startup_statuses = {
        "reader": {
            "status": "reserved_stage_exit",
            "returncode": 89,
            "label": "initial_descriptor_inventory_rows",
        },
        "owner": {"status": "other_exit", "returncode": 2},
    }
    error = _cli_error(monkeypatch, failure)
    assert error["native_startup_exits"] == {"reader": "initial_descriptor_inventory_rows"}
    assert error["native_startup_statuses"] == failure.safe_native_startup_statuses
    parsed = verifier._parse_child_cli_error(json.dumps({"error": error}))
    assert parsed["native_startup_exits"] == {"reader": "initial_descriptor_inventory_rows"}
    assert parsed["native_startup_statuses"] == failure.safe_native_startup_statuses
    readiness = verifier._safe_readiness_diagnostics("child_exited_before_readiness", {}, parsed)
    assert readiness["native_startup_exits"] == {"reader": "initial_descriptor_inventory_rows"}
    assert readiness["native_startup_statuses"] == failure.safe_native_startup_statuses

    no_reserved_exit = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    no_reserved_exit.safe_native_startup_statuses = {
        "reader": {"status": "other_exit", "returncode": 2},
        "owner": {"status": "unavailable", "reason": "workers_not_closed"},
    }
    error_without_stage_label = _cli_error(monkeypatch, no_reserved_exit)
    assert "native_startup_exits" not in error_without_stage_label
    parsed_without_stage_label = verifier._parse_child_cli_error(
        json.dumps({"error": error_without_stage_label})
    )
    assert parsed_without_stage_label["native_startup_statuses"] == (
        no_reserved_exit.safe_native_startup_statuses
    )
    readiness_without_stage_label = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness", {}, parsed_without_stage_label
    )
    assert readiness_without_stage_label["native_startup_statuses"] == (
        no_reserved_exit.safe_native_startup_statuses
    )
    forged_readiness = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {},
        {**parsed, "native_startup_exits": {"reader": "private-path"}},
    )
    assert "native_startup_exits" not in forged_readiness
    forged_statuses = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {},
        {
            **parsed,
            "native_startup_statuses": {"reader": {"status": "other_exit", "returncode": True}},
        },
    )
    assert "native_startup_statuses" not in forged_statuses

    for forged in (
        {"reader": "private-path"},
        {"reader": True},
        {"other": "initial_resource_validation"},
        {
            "reader": "initial_resource_validation",
            "owner": "unknown",
            "control": "readonly_descriptor",
            "extra": "credential_selection",
        },
    ):
        failure.safe_native_startup_exits = forged
        error = _cli_error(monkeypatch, failure)
        assert "native_startup_exits" not in error
        parsed = verifier._parse_child_cli_error(
            json.dumps({"error": {**error, "native_startup_exits": forged}})
        )
        assert parsed is not None and "native_startup_exits" not in parsed

    for forged_statuses in (
        {"reader": {"status": "other_exit", "returncode": True}},
        {"reader": {"status": "other_exit", "returncode": 256}},
        {"reader": {"status": "reserved_stage_exit", "returncode": 86, "label": "private-path"}},
        {"outside_role": {"status": "clean_exit", "returncode": 0}},
    ):
        failure.safe_native_startup_statuses = forged_statuses
        error = _cli_error(monkeypatch, failure)
        assert "native_startup_statuses" not in error
        parsed = verifier._parse_child_cli_error(
            json.dumps({"error": {**error, "native_startup_statuses": forged_statuses}})
        )
        assert parsed is not None and "native_startup_statuses" not in parsed

    parsed = verifier._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    **error,
                    "setup_stage": "service_startup",
                    "native_startup_exits": {"reader": "initial_resource_validation"},
                }
            }
        )
    )
    assert parsed is not None and "native_startup_exits" not in parsed
