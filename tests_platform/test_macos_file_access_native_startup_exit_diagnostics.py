"""Finite macOS startup exits from retained fakes; no native process is launched."""

from __future__ import annotations

import io
import json
import os
import queue
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
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
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
    assert status["preexec_descriptor_observation_withheld"] == "no_frame"
    assert retained._native_diagnostic_bytes == b""
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}

    retained._native_diagnostic_bytes = bytearray(b"arbitrary stderr\n")
    assert retained.retained_native_startup_status()["descriptor_observation_withheld"] == (
        "invalid_frame"
    )
    retained._native_diagnostic_bytes = bytearray(
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}).encode()
        + b"\n"
    )
    retained._process.returncode = 95
    status = retained.retained_native_startup_status()
    assert "descriptor_observation" not in status
    assert "descriptor_observation_withheld" not in status
    assert "preexec_descriptor_observation" not in status
    assert "preexec_descriptor_observation_withheld" not in status


def test_preexec_and_native_frames_remain_separate_code_96_diagnostics(monkeypatch):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
    ]
    preexec_frame = diagnostics.PREEXEC_FD_FRAME_PREFIX + (
        b"rows|0,8192,1,2,0,0;2,4096,1,4,0,0;3,49152,4294967295,33,0,0\n"
    )
    native_frame = (
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}) + "\n"
    ).encode()
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    retained._native_diagnostic_complete = True
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_bytes = bytearray(preexec_frame + native_frame)
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {"role": "primitive_channel", "fd": 13, "identity": identity},
    ]
    status = retained.retained_native_startup_status()
    assert status["descriptor_observation"]["native_rows"] == rows
    assert [row["fd"] for row in status["preexec_descriptor_observation"]["rows"]] == [0, 2, 3]
    assert status["preexec_descriptor_observation"]["scope"] == (
        diagnostics.PREEXEC_FD_OBSERVATION_SCOPE
    )
    assert retained._native_diagnostic_bytes == b""
    assert diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}

    retained._native_diagnostic_bytes = bytearray(preexec_frame + native_frame)
    retained._process.returncode = 0
    status = retained.retained_native_startup_status()
    assert status == {"status": "clean_exit", "returncode": 0}


def test_invalid_preexec_frame_is_withheld_without_erasing_native_rows(monkeypatch):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
    ]
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    retained._native_diagnostic_complete = True
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_bytes = bytearray(
        diagnostics.PREEXEC_FD_FRAME_PREFIX
        + b"rows|3,49152,1,2,0,0,/private/secret\n"
        + (
            json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}) + "\n"
        ).encode()
    )
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {"role": "primitive_channel", "fd": 13, "identity": identity},
    ]
    status = retained.retained_native_startup_status()
    assert status["descriptor_observation"]["native_rows"] == rows
    assert status["preexec_descriptor_observation_withheld"] == "invalid_frame"
    assert "secret" not in repr(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}


@pytest.mark.parametrize(
    "reason,complete,overflow,frame,launch_rows_valid",
    [
        ("eof_incomplete", False, False, b"partial", True),
        ("overflow", True, True, b"x" * 4096, True),
        ("no_frame", True, False, b"", True),
        ("invalid_frame", True, False, b"arbitrary stderr\n", True),
        ("invalid_launch_rows", True, False, None, False),
    ],
)
def test_only_settled_code_96_reports_finite_withheld_reason(
    monkeypatch, reason, complete, overflow, frame, launch_rows_valid
):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
    ]
    if frame is None:
        frame = (
            json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}) + "\n"
        ).encode()
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    retained._native_diagnostic_complete = complete
    retained._native_diagnostic_overflow = overflow
    retained._native_diagnostic_bytes = bytearray(frame)
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {
            "role": "primitive_channel" if launch_rows_valid else "unknown",
            "fd": 13,
            "identity": identity,
        },
    ]
    status = retained.retained_native_startup_status()
    preexec_reason = reason if reason in {"eof_incomplete", "overflow", "no_frame"} else "no_frame"
    assert status == {
        **diagnostics.native_startup_status_from_returncode(96),
        "descriptor_observation_withheld": reason,
        "preexec_descriptor_observation_withheld": preexec_reason,
    }
    assert diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}


def test_owned_pipe_drain_requires_eof_before_code_96_observation(monkeypatch):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [
        {"fd": fd, "kind": 2 if fd == 4 else 1, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
    ]
    frame = (
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}) + "\n"
    ).encode()
    retained._native_diagnostic_bytes = bytearray()
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_complete = False
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {"role": "primitive_channel", "fd": 13, "identity": identity},
    ]
    read_fd, write_fd = os.pipe()
    thread = threading.Thread(
        target=retained._drain_native_diagnostic, args=(read_fd,), daemon=True
    )
    retained._native_diagnostic_thread = thread
    try:
        thread.start()
        os.write(write_fd, frame)
        assert retained.retained_native_startup_status()["descriptor_observation_withheld"] == (
            "eof_incomplete"
        )
    finally:
        os.close(write_fd)
        thread.join(timeout=1)
    assert not thread.is_alive()
    assert retained._native_diagnostic_complete is True

    read_fd, write_fd = os.pipe()
    retained._native_diagnostic_bytes = bytearray()
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_complete = False
    thread = threading.Thread(
        target=retained._drain_native_diagnostic, args=(read_fd,), daemon=True
    )
    retained._native_diagnostic_thread = thread
    try:
        thread.start()
        os.write(write_fd, frame)
        os.close(write_fd)
        write_fd = -1
        thread.join(timeout=1)
        assert not thread.is_alive()
        status = retained.retained_native_startup_status()
        assert status["descriptor_observation"]["native_rows"] == rows
        assert "descriptor_observation_withheld" not in status
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        thread.join(timeout=1)


def test_drain_io_error_is_not_reported_as_an_overflow(monkeypatch):
    retained = _worker(monkeypatch, 96)
    retained._native_diagnostic_bytes = bytearray()
    retained._native_diagnostic_overflow = False
    retained._native_diagnostic_complete = False
    retained._drain_native_diagnostic(-1)
    assert retained._native_diagnostic_overflow is False
    assert retained._native_diagnostic_complete is False
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    assert retained.retained_native_startup_status()["descriptor_observation_withheld"] == (
        "eof_incomplete"
    )


def test_valid_combined_frames_above_old_capture_cap_survive_until_eof(monkeypatch):
    retained = _worker(monkeypatch, 96)
    identity = {"dev": 1, "ino": 2, "mode_type": 0o100000, "rdev": 0}
    rows = [{"fd": fd, "kind": 1, "identity": identity} for fd in range(6)]
    native_body = json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows})
    native_frame = native_body.encode().ljust(diagnostics.MAX_NATIVE_FD_FRAME_BYTES - 1) + b"\n"
    preexec_frame = diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|2,4096,1,4,0,0\n"
    raw = preexec_frame + native_frame
    assert 4096 < len(raw) <= diagnostics.MAX_COMBINED_FD_FRAME_BYTES == 5120
    assert diagnostics.native_fd_rows_from_frame(native_frame) == rows
    chunks = iter([raw[index : index + 1024] for index in range(0, len(raw), 1024)] + [b""])
    closed = []
    monkeypatch.setattr(
        worker, "os", SimpleNamespace(read=lambda *_args: next(chunks), close=closed.append)
    )
    retained._native_diagnostic_thread = SimpleNamespace(join=lambda timeout: None)
    retained._native_diagnostic_bytes = bytearray()
    retained._native_diagnostic_complete = False
    retained._native_diagnostic_overflow = False
    retained._launch_copy_rows = [
        {"role": "resource", "fd": 12, "identity": identity},
        {"role": "primitive_channel", "fd": 13, "identity": identity},
    ]
    retained._drain_native_diagnostic(71)
    assert closed == [71] and retained._native_diagnostic_complete
    assert not retained._native_diagnostic_overflow
    status = retained.retained_native_startup_status()
    assert status["descriptor_observation"]["native_rows"] == rows
    assert status["preexec_descriptor_observation"]["rows"][0]["fd"] == 2
    assert retained._native_diagnostic_bytes == b""


@pytest.mark.parametrize("extra", [0, 1])
def test_combined_capture_has_exact_bound_and_still_drains(monkeypatch, extra):
    retained = _worker(monkeypatch, 96)
    raw = b"x" * (diagnostics.MAX_COMBINED_FD_FRAME_BYTES + extra)
    chunks = iter([raw[index : index + 1024] for index in range(0, len(raw), 1024)] + [b""])
    closed = []
    monkeypatch.setattr(
        worker, "os", SimpleNamespace(read=lambda *_args: next(chunks), close=closed.append)
    )
    retained._native_diagnostic_bytes = bytearray()
    retained._native_diagnostic_complete = False
    retained._native_diagnostic_overflow = False
    retained._drain_native_diagnostic(71)
    assert len(retained._native_diagnostic_bytes) == diagnostics.MAX_COMBINED_FD_FRAME_BYTES
    assert retained._native_diagnostic_overflow is bool(extra)
    assert retained._native_diagnostic_complete and closed == [71]


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


def test_actual_pretty_cli_combined_failure_survives_eof_and_readiness_projection(monkeypatch):
    identity = {"dev": 2**64 - 1, "ino": 2**64 - 1, "mode_type": 0o170000, "rdev": 2**64 - 1}
    preexec_identity = {**identity, "dev": 2**32 - 1, "rdev": 2**32 - 1}
    status = {
        **diagnostics.native_startup_status_from_returncode(96),
        "descriptor_observation": {
            "schema_version": diagnostics.NATIVE_FD_OBSERVATION_SCHEMA,
            "scope": "diagnostic_only_no_descriptor_admission",
            "launch_copy_rows": [
                {
                    "role": (
                        "resource"
                        if index == 0
                        else "primitive_channel" if index == 1 else "launch_auxiliary"
                    ),
                    "fd": 2**31 - 1 - index,
                    "identity": identity,
                }
                for index in range(diagnostics.MAX_NATIVE_FD_ROWS)
            ],
            "native_rows": [
                {"fd": 2**31 - 1 - index, "kind": 2**32 - 1, "identity": identity}
                for index in range(diagnostics.MAX_NATIVE_FD_ROWS)
            ],
        },
        "preexec_descriptor_observation": {
            "schema_version": diagnostics.PREEXEC_FD_OBSERVATION_SCHEMA,
            "scope": diagnostics.PREEXEC_FD_OBSERVATION_SCOPE,
            "scan_slots": diagnostics.PREEXEC_FD_SLOTS,
            "rows": [
                {"fd": index, "cloexec": True, "identity": preexec_identity}
                for index in range(diagnostics.MAX_PREEXEC_FD_ROWS)
            ],
        },
    }
    assert diagnostics.valid_native_startup_status(status)
    statuses = {role: status for role in ("reader", "owner", "control")}
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    failure.safe_native_startup_statuses = statuses
    monkeypatch.setattr(cli, "_execute", lambda _args: (_ for _ in ()).throw(failure))
    output = io.StringIO()
    with redirect_stdout(output):
        assert cli.main(["runner", "macos-file-setup", "--confirm-create-generated-workspace"]) == 2
    raw = output.getvalue()
    assert 4096 < len(raw.encode()) < diagnostics.MAX_STARTUP_CLI_ERROR_BYTES
    stdout_lines, child_errors = queue.Queue(maxsize=1), queue.Queue(maxsize=1)
    verifier._read_supervisor_stdout(io.StringIO(raw), stdout_lines, child_errors)
    assert stdout_lines.empty()
    readiness = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness", {"streams_drained": True}, child_errors.get_nowait()
    )
    assert readiness["native_startup_statuses"] == statuses
    assert readiness["error_code"] == "command_failed"
    assert "message" not in readiness and "child_cli_error_withheld" not in readiness
    forged = json.loads(raw)
    forged["error"]["native_startup_statuses"]["reader"]["private_path"] = "/private/secret"
    parsed = verifier._parse_child_cli_error(json.dumps(forged, indent=2))
    assert parsed is not None and "native_startup_statuses" not in parsed
    assert "secret" not in repr(parsed)


@pytest.mark.parametrize(
    "raw,reason",
    [
        ("", "no_document"),
        ("/private/secret", "invalid_json"),
        ("[" * 2000, "invalid_json"),
        ('{"private_path":"/private/secret"}', "unrecognized_document"),
        ('{"error":{"message":"/private/secret"}}', "invalid_error"),
        (
            json.dumps(
                {
                    "error": {
                        "code": "command_failed",
                        "message": "/private/secret" * diagnostics.MAX_STARTUP_CLI_ERROR_BYTES,
                    }
                }
            ),
            "envelope_overflow",
        ),
        (
            json.dumps(
                {
                    "error": {
                        "code": "command_failed",
                        "message": "x" * diagnostics.MAX_STARTUP_CLI_ERROR_BYTES,
                    }
                }
            ),
            "envelope_overflow",
        ),
    ],
    ids=[
        "empty",
        "not-json",
        "deep-json",
        "unknown-document",
        "invalid-error",
        "stream-overflow",
        "error-envelope-overflow",
    ],
)
def test_child_parse_rejection_is_finite_and_never_retains_output(raw, reason):
    stdout_lines, child_errors = queue.Queue(maxsize=1), queue.Queue(maxsize=1)
    verifier._read_supervisor_stdout(io.StringIO(raw), stdout_lines, child_errors)
    assert stdout_lines.empty()
    projected = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness", {}, child_errors.get_nowait()
    )
    assert projected == {
        "failure_stage": "child_exited_before_readiness",
        "child_cli_error_withheld": reason,
    }
    for unknown in ("/private/secret", [], {}, True, None):
        assert "child_cli_error_withheld" not in verifier._safe_readiness_diagnostics(
            "child_exited_before_readiness", {}, {"child_cli_error_withheld": unknown}
        )


def test_success_stdout_protocol_keeps_existing_independent_budget():
    raw = json.dumps(
        {
            "schema_version": "bluefire.macos-file-access-local-supervisor-result.v1",
            "padding": "x" * diagnostics.MAX_STARTUP_CLI_ERROR_BYTES,
        }
    )
    stdout_lines, child_errors = queue.Queue(maxsize=1), queue.Queue(maxsize=1)
    verifier._read_supervisor_stdout(io.StringIO(raw), stdout_lines, child_errors)
    assert stdout_lines.get_nowait() == raw and child_errors.empty()


def test_cli_error_envelope_limit_is_exact_and_keeps_only_projection():
    document = {"error": {"code": "command_failed", "message": ""}}
    overhead = len(json.dumps(document).encode())
    document["error"]["message"] = "x" * (diagnostics.MAX_STARTUP_CLI_ERROR_BYTES - overhead)
    raw = json.dumps(document)
    assert len(raw.encode()) == diagnostics.MAX_STARTUP_CLI_ERROR_BYTES
    expected = {"error_code": "command_failed", "error_class": "unclassified_command_failure"}
    assert verifier._parse_child_cli_error(raw) == expected
    assert verifier._parse_child_cli_error(raw + " ") is None
    stdout_lines, child_errors = queue.Queue(maxsize=1), queue.Queue(maxsize=1)
    verifier._read_supervisor_stdout(io.StringIO(raw + " "), stdout_lines, child_errors)
    assert stdout_lines.empty()
    assert child_errors.get_nowait() == {"child_cli_error_withheld": "envelope_overflow"}


def test_decoder_numeric_domain_refusal_is_finite_without_decoder_message(monkeypatch):
    def refuse(_raw):
        raise ValueError("private decoder detail /private/secret")

    monkeypatch.setattr(verifier, "json", SimpleNamespace(**{**vars(json), "loads": refuse}))
    assert verifier._parse_child_cli_error("{}") is None
    stdout_lines, child_errors = queue.Queue(maxsize=1), queue.Queue(maxsize=1)
    verifier._read_supervisor_stdout(io.StringIO("{}"), stdout_lines, child_errors)
    assert stdout_lines.empty()
    assert child_errors.get_nowait() == {"child_cli_error_withheld": "invalid_json"}


def test_withheld_reason_crosses_only_failure_status_projections(monkeypatch):
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    status = {
        **diagnostics.native_startup_status_from_returncode(96),
        "descriptor_observation_withheld": "no_frame",
    }
    failure.safe_native_startup_statuses = {"reader": status}
    error = _cli_error(monkeypatch, failure)
    assert error["native_startup_statuses"] == {"reader": status}
    parsed = verifier._parse_child_cli_error(json.dumps({"error": error}))
    assert parsed["native_startup_statuses"] == {"reader": status}
    readiness = verifier._safe_readiness_diagnostics("child_exited_before_readiness", {}, parsed)
    assert readiness["native_startup_statuses"] == {"reader": status}

    failure.safe_native_startup_statuses = {
        "reader": {**status, "descriptor_observation_withheld": "private-path"}
    }
    assert "native_startup_statuses" not in _cli_error(monkeypatch, failure)


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
