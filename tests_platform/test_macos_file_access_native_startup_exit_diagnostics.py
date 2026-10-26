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
    return value


def _creator(workers):
    value = object.__new__(creator.MacOSFileAccessCreator)
    value._creator_pid = os.getpid()
    value._lock = threading.Lock()
    value._state = "retired"
    value._retired_workers_closed = True
    value._workers = workers
    return value


@pytest.mark.parametrize("code,label", sorted(diagnostics.NATIVE_STARTUP_EXIT_LABELS.items()))
def test_only_exact_reserved_reaped_native_code_maps_to_fixed_label(monkeypatch, code, label):
    retained = _worker(monkeypatch, code)
    original = _creator({"owner": retained})

    assert retained.retained_native_startup_exit_code() == code
    assert original.retained_native_startup_exits() == {"owner": label}


@pytest.mark.parametrize("code", [None, False, True, 0, 2, 3, 4, -15, 79, 88, "80"])
def test_unavailable_generic_signal_unknown_and_bool_codes_have_no_cause(monkeypatch, code):
    retained = _worker(monkeypatch, code)
    original = _creator({"reader": retained})

    assert original.retained_native_startup_exits() is None


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


def test_busy_worker_lock_returns_without_waiting_or_reading_status(monkeypatch):
    retained = _worker(monkeypatch, 80)
    retained._lock.acquire()
    try:
        assert retained.retained_native_startup_exit_code() is None
        assert _creator({"reader": retained}).retained_native_startup_exits() is None
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

    original._retired_workers_closed = True
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": False})
    assert not hasattr(failure, "safe_native_startup_exits")
    local._attach_retired_native_startup_exits(failure, original, {"workers_closed": True})
    assert failure.safe_native_startup_exits == {"reader": "initial_resource_validation"}

    other_stage = local.MacOSSetupFailure("service_startup", "safe")
    local._attach_retired_native_startup_exits(other_stage, original, {"workers_closed": True})
    assert not hasattr(other_stage, "safe_native_startup_exits")


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


def test_cli_and_verifier_independently_revalidate_only_fixed_labels(monkeypatch):
    failure = local.MacOSSetupFailure(
        "namespace_creation", "The original sealed Darwin namespace is unavailable."
    )
    failure.safe_native_startup_exits = {"reader": "initial_resource_validation"}
    error = _cli_error(monkeypatch, failure)
    assert error["native_startup_exits"] == {"reader": "initial_resource_validation"}
    parsed = verifier._parse_child_cli_error(json.dumps({"error": error}))
    assert parsed["native_startup_exits"] == {"reader": "initial_resource_validation"}
    readiness = verifier._safe_readiness_diagnostics("child_exited_before_readiness", {}, parsed)
    assert readiness["native_startup_exits"] == {"reader": "initial_resource_validation"}
    forged_readiness = verifier._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {},
        {**parsed, "native_startup_exits": {"reader": "private-path"}},
    )
    assert "native_startup_exits" not in forged_readiness

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
