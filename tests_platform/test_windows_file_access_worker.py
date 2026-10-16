from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_worker as worker
from bluefire.util import canonical_json_bytes
from bluefire.windows_file_access_policy import WindowsFileAccessPolicy
from bluefire.windows_file_access_read import (
    WindowsFileReadError,
    WindowsReadExpectation,
    WindowsReadObservation,
    WindowsResourceExpectation,
)
from bluefire.windows_session_facts import WindowsPrincipalFacts

PRINCIPAL = WindowsPrincipalFacts(41, 123456, "S-1-5-21-101-202-303-1002", 10, 20, 30, 2, False)
RESOURCE = WindowsResourceExpectation(
    "a" * 32,
    WindowsFileAccessPolicy("S-1-5-21-101-202-303-1001", PRINCIPAL.user_sid),
    ((1, 1), (1, 2), (1, 3), (1, 4)),
    (1, 5),
    13,
    "sha256:" + "a" * 64,
    1,
    "readable",
)
EXPECTED = WindowsReadExpectation(RESOURCE, PRINCIPAL)
OPERATION = worker.WindowsReadOperation(EXPECTED, "b" * 32, "c" * 64, 1, 1000, 6000)
OBSERVED = WindowsReadObservation(
    "allowed",
    PRINCIPAL,
    RESOURCE.file_identity,
    RESOURCE.size,
    RESOURCE.sha256,
    1,
    "sha256:" + "d" * 64,
)


@pytest.fixture
def native(monkeypatch):
    state = SimpleNamespace(clock=2000, monotonic=10.0, calls=0, observation=OBSERVED)
    monkeypatch.setattr(worker, "_milliseconds", lambda: state.clock)
    monkeypatch.setattr(worker.time, "monotonic", lambda: state.monotonic)

    def read(expected):
        assert expected is EXPECTED or expected == EXPECTED
        state.calls += 1
        return state.observation

    monkeypatch.setattr(worker, "fresh_windows_read", read)
    return state


def test_one_original_read_produces_private_bounded_report(native):
    instance = worker.OneReadWorker(OPERATION)
    result = instance.execute(OPERATION.request())
    accepted = worker.accept_read_result(OPERATION, result)
    assert native.calls == 1 and accepted["outcome"] == "allowed"
    assert accepted["read_handles_closed"] is True
    assert PRINCIPAL.user_sid.encode() not in result + OPERATION.request()
    assert b"C:" not in result + OPERATION.request()
    assert len(result) < worker.MAX_MESSAGE_BYTES
    with pytest.raises(worker.WindowsReadWorkerError, match="consumed"):
        instance.execute(OPERATION.request())
    assert native.calls == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("operation_id", "e" * 32),
        ("challenge", "f" * 64),
        ("control_revision", 2),
        ("deadline_ms", 5999),
        ("enrollment_digest", "sha256:" + "0" * 64),
        ("path", "C:\\not-enrolled"),
        ("command", "not-accepted"),
        ("credential", "not-accepted"),
    ],
)
def test_changed_or_expanded_request_never_opens_resource(native, key, value):
    row = worker._document(OPERATION.request())
    row[key] = value
    instance = worker.OneReadWorker(OPERATION)
    with pytest.raises(worker.WindowsReadWorkerError):
        instance.execute(canonical_json_bytes(row))
    with pytest.raises(worker.WindowsReadWorkerError, match="consumed"):
        instance.execute(OPERATION.request())
    assert native.calls == 0


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x" * 4097,
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b' {"a":1}',
        b'{"a":1}\n',
        b"\xff",
        b'{"a":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}",
    ],
)
def test_noncanonical_duplicate_nonfinite_and_oversized_messages_refuse(native, payload):
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.OneReadWorker(OPERATION).execute(payload)
    assert native.calls == 0


@pytest.mark.parametrize("clock", [999, 6000, 6001])
def test_noncurrent_operation_never_opens_resource(native, clock):
    native.clock = clock
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.OneReadWorker(OPERATION)
    assert native.calls == 0


def test_clock_rollback_does_not_restore_elapsed_allowance(native):
    native.clock = 5500
    instance = worker.OneReadWorker(OPERATION)
    native.clock = 2000
    native.monotonic = 10.6
    with pytest.raises(worker.WindowsReadWorkerError, match="deadline"):
        instance.execute(OPERATION.request())
    assert native.calls == 0


@pytest.mark.parametrize("kind", ["wall", "monotonic"])
def test_expiry_during_read_does_not_return_a_usable_result(native, monkeypatch, kind):
    def read(_expected):
        native.calls += 1
        if kind == "wall":
            native.clock = 6000
        else:
            native.monotonic = 15.1
        return OBSERVED

    monkeypatch.setattr(worker, "fresh_windows_read", read)
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.OneReadWorker(OPERATION).execute(OPERATION.request())
    assert native.calls == 1


def test_failed_native_read_is_unknown_and_never_replayed(native, monkeypatch):
    def read(_expected):
        native.calls += 1
        raise WindowsFileReadError("private native details")

    monkeypatch.setattr(worker, "fresh_windows_read", read)
    instance = worker.OneReadWorker(OPERATION)
    with pytest.raises(worker.WindowsReadWorkerError, match="observation is unavailable") as caught:
        instance.execute(OPERATION.request())
    assert "private native" not in str(caught.value)
    with pytest.raises(worker.WindowsReadWorkerError, match="consumed"):
        instance.execute(OPERATION.request())
    assert native.calls == 1


def test_explicit_denial_does_not_invent_contents(native):
    native.observation = replace(
        OBSERVED, outcome="permission_denied", sha256=None, record_count=None
    )
    raw = worker.OneReadWorker(OPERATION).execute(OPERATION.request())
    result = worker.accept_read_result(OPERATION, raw)
    assert result["outcome"] == "permission_denied"
    assert result["sha256"] is result["record_count"] is None


@pytest.mark.parametrize(
    "key,value",
    [
        ("principal", replace(PRINCIPAL, process_id=42)),
        ("file_identity", (1, 99)),
        ("observed_size", True),
        ("read_handles_closed", False),
        ("selected_descriptor_sha256", "unknown"),
        ("outcome", "unknown"),
        ("sha256", None),
        ("record_count", True),
    ],
)
def test_unbound_or_inconsistent_native_report_refuses(native, key, value):
    native.observation = replace(OBSERVED, **{key: value})
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.OneReadWorker(OPERATION).execute(OPERATION.request())


@pytest.mark.parametrize(
    "key,value",
    [
        ("request_digest", "sha256:" + "0" * 64),
        ("observed_at_ms", 2001),
        ("observed_at_ms", True),
        ("observed_at_ms", 999),
        ("size", True),
        ("size", 14),
        ("read_handles_closed", False),
        ("record_count", True),
        ("outcome", "prevented"),
        ("selected_descriptor_sha256", None),
        ("sha256", "sha256:" + "e" * 64),
        ("extra", 1),
    ],
)
def test_modified_wire_result_refuses(native, key, value):
    row = worker._document(worker.OneReadWorker(OPERATION).execute(OPERATION.request()))
    row[key] = value
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.accept_read_result(OPERATION, canonical_json_bytes(row))


@pytest.mark.parametrize(
    "key,value",
    [
        ("operation_id", "../invalid"),
        ("challenge", "x" * 64),
        ("control_revision", True),
        ("created_at_ms", 6000),
        ("deadline_ms", 6001),
        ("deadline_ms", True),
    ],
)
def test_original_task_limits_refuse(key, value):
    with pytest.raises(worker.WindowsReadWorkerError):
        replace(OPERATION, **{key: value})


def test_result_cannot_be_accepted_after_original_expiry(native):
    raw = worker.OneReadWorker(OPERATION).execute(OPERATION.request())
    native.clock = 6000
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.accept_read_result(OPERATION, raw)


def test_same_resource_does_not_make_other_primary_process_requests_interchangeable(native):
    other = replace(
        OPERATION,
        expectation=replace(EXPECTED, principal=replace(PRINCIPAL, process_id=42)),
    )
    assert other.expectation.resource is RESOURCE
    assert other.request() != OPERATION.request()
    with pytest.raises(worker.WindowsReadWorkerError):
        worker.OneReadWorker(OPERATION).execute(other.request())
    assert native.calls == 0
