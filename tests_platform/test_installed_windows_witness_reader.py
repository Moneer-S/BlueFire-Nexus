from __future__ import annotations

import ctypes
import json
import os
import threading
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import runner_descriptor_io, runner_private_files, windows_owner_acl
from bluefire.runner_private_files import _PinnedPrivateDirectory
from tools import verify_installed_windows_cancellation as verifier


def _ready() -> dict[str, object]:
    return {
        "schema_version": "bluefire.process-tree-cancellation-ready.v1",
        "task_id": "execute-" + "a" * 64,
        "request_hash": "sha256:" + "a" * 64,
        "parent_process_id": 101,
        "descendant_process_id": 202,
    }


def _private_task(tmp_path: Path) -> tuple[Path, Path]:
    sandbox = tmp_path / "sandbox"
    task = (
        sandbox
        / ".bluefire-executions"
        / "owner"
        / ".bluefire-cancellation-witness-v1"
        / ("a" * 64)
    )
    task.mkdir(parents=True)
    with _PinnedPrivateDirectory(task):
        pass
    return sandbox, task


def _write_native_child(task: Path, payload: bytes) -> None:
    # Unlike PinnedPrivateDirectory.create, the native producer inherits its
    # parent's ACL and never applies a protected-file DACL to the child.
    descriptor = os.open(task / "ready.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        assert os.write(descriptor, payload) == len(payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def test_ready_reader_uses_read_only_pinned_parent_without_permission_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox, task = _private_task(tmp_path)
    ready = _ready()
    _write_native_child(task, json.dumps(ready).encode())
    before = (task.stat(), (task / "ready.json").stat())
    original_enter = _PinnedPrivateDirectory.__enter__
    original_open = _PinnedPrivateDirectory._open_existing
    modes: list[tuple[bool, bool]] = []
    opens: list[tuple[str, bool]] = []

    def enter(control):
        modes.append((control.share_delete, control._verify_permissions_only))
        return original_enter(control)

    def open_existing(control, name, *, delete=False, write_dac=True):
        assert delete is False
        opens.append((name, write_dac))
        return original_open(control, name, delete=delete, write_dac=write_dac)

    def refuse_mutation(*args, **kwargs):
        pytest.fail("the observer must not apply permissions")

    monkeypatch.setattr(_PinnedPrivateDirectory, "__enter__", enter)
    monkeypatch.setattr(_PinnedPrivateDirectory, "_open_existing", open_existing)
    monkeypatch.setattr(runner_private_files, "_owner_private_handle", refuse_mutation)
    monkeypatch.setattr(os, "fchmod", refuse_mutation, raising=False)
    pins: list[dict[str, object]] = []
    monkeypatch.setattr(verifier, "_pin_windows_processes", lambda record: pins.append(record))

    result = verifier._private_ready_record(sandbox, threading.Event())

    assert result == {**ready, "control_path": task}
    assert pins == [ready]
    assert modes == [(True, True)] and opens == [("ready.json", False)]
    after = (task.stat(), (task / "ready.json").stat())
    for original, current in zip(before, after, strict=True):
        assert (original.st_mode, original.st_ino, original.st_mtime_ns, original.st_ctime_ns) == (
            current.st_mode,
            current.st_ino,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )


def _windows_security_snapshot(descriptor: int) -> str:
    import msvcrt

    advapi32, kernel32 = windows_owner_acl._configure_apis()
    security = ctypes.c_void_p()
    text = wintypes.LPWSTR()
    convert = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    )
    convert.restype = wintypes.BOOL
    try:
        assert (
            advapi32.GetSecurityInfo(
                wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
                1,
                0x1 | 0x4,
                None,
                None,
                None,
                None,
                ctypes.byref(security),
            )
            == 0
        )
        assert convert(security, 1, 0x1 | 0x4, ctypes.byref(text), None)
        assert text.value
        return text.value
    finally:
        if text:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        if security.value:
            kernel32.LocalFree(security)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows retained file sharing")
def test_native_inherited_ready_is_readable_while_write_delete_pin_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import msvcrt

    sandbox, task = _private_task(tmp_path)
    ready = _ready()
    create = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create.restype = wintypes.HANDLE
    path = task / "ready.json"
    # Exact Rust producer access/sharing, CREATE_NEW and OPEN_REPARSE_POINT.
    handle = create(str(path), 0x40000000 | 0x10000, 0x1, None, 1, 0x00200000, None)
    assert handle != wintypes.HANDLE(-1).value
    writer = msvcrt.open_osfhandle(int(handle), os.O_WRONLY | os.O_BINARY)
    reader: int | None = None
    try:
        payload = json.dumps(ready).encode()
        assert os.write(writer, payload) == len(payload)
        os.fsync(writer)
        reader = windows_owner_acl._windows_open_descriptor(
            path, directory=False, share_delete=True
        )
        before_acl = _windows_security_snapshot(reader)
        before = path.stat()
        assert "ID" in before_acl and "D:P" not in before_acl
        with pytest.raises(windows_owner_acl.WindowsOwnerAclError):
            windows_owner_acl.verify_owner_private_acl(reader, directory=False)
        with pytest.raises(OSError):
            path.open("rb")
        pins: list[dict[str, object]] = []
        monkeypatch.setattr(verifier, "_pin_windows_processes", lambda record: pins.append(record))

        assert verifier._private_ready_record(sandbox, threading.Event()) == {
            **ready,
            "control_path": task,
        }

        assert pins == [ready]
        assert _windows_security_snapshot(reader) == before_acl
        after = path.stat()
        assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
    finally:
        if reader is not None:
            os.close(reader)
        os.close(writer)


@pytest.mark.parametrize(
    "payload",
    [b"{", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'"secret"', b"\xff"],
)
def test_ready_reader_rejects_malformed_json_without_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    sandbox, task = _private_task(tmp_path)
    _write_native_child(task, payload)
    monkeypatch.setattr(verifier, "_pin_windows_processes", lambda _record: pytest.fail("pinned"))
    with pytest.raises(RuntimeError) as caught:
        verifier._private_ready_record(sandbox, threading.Event())
    assert verifier._witness_observation_error_code(caught.value) == "ready_json_invalid"


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", "execute-" + "b" * 64),
        ("parent_process_id", True),
        ("descendant_process_id", 101),
    ],
)
def test_ready_reader_preserves_exact_contract_before_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    sandbox, task = _private_task(tmp_path)
    _write_native_child(task, json.dumps({**_ready(), field: value}).encode())
    monkeypatch.setattr(verifier, "_pin_windows_processes", lambda _record: pytest.fail("pinned"))
    with pytest.raises(ValueError) as caught:
        verifier._private_ready_record(sandbox, threading.Event())
    assert verifier._witness_observation_error_code(caught.value) == "ready_contract_invalid"


@pytest.mark.parametrize("invalid", ["oversize", "hardlink", "changed", "replaced"])
def test_ready_reader_refuses_unsafe_or_changing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    _sandbox, task = _private_task(tmp_path)
    payload = json.dumps(_ready()).encode()
    _write_native_child(
        task, b"x" * (verifier._MAX_READY_BYTES + 1) if invalid == "oversize" else payload
    )
    path = task / "ready.json"
    if invalid == "hardlink":
        os.link(path, task / "second-link")
    elif invalid in {"changed", "replaced"}:
        real_read = runner_descriptor_io._read_descriptor_bounded

        def read_then_change(descriptor, maximum):
            value = real_read(descriptor, maximum)
            if invalid == "changed":
                with path.open("ab") as stream:
                    stream.write(b" ")
            else:
                replacement = task / "replacement"
                replacement.write_bytes(payload)
                os.replace(replacement, path)
            return value

        monkeypatch.setattr(runner_descriptor_io, "_read_descriptor_bounded", read_then_change)
    with pytest.raises(RuntimeError) as caught:
        verifier._read_witness_ready(task)
    assert verifier._witness_observation_error_code(caught.value) == "ready_read_failed"


def test_ready_reader_refuses_unverified_parent_without_applying_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sandbox, task = _private_task(tmp_path)
    _write_native_child(task, json.dumps(_ready()).encode())

    def refuse_parent(*args, **kwargs):
        raise OSError("secret path or ACL diagnostic")

    monkeypatch.setattr(runner_private_files, "_verify_private_permissions", refuse_parent)
    with pytest.raises(RuntimeError) as caught:
        verifier._read_witness_ready(task)
    assert verifier._witness_observation_error_code(caught.value) == "ready_directory_unavailable"


@pytest.mark.parametrize("value", ["secret/path", "parent_process_id=123", None, [], {}])
def test_observer_diagnostics_never_project_unchecked_values(value: object) -> None:
    error = verifier._WitnessObservationError(value)  # type: ignore[arg-type]
    assert verifier._witness_observation_error_code(error) == "witness_observation_failed"
    assert verifier._witness_observation_error_code(RuntimeError(str(value))) == (
        "witness_observation_failed"
    )


class _Function:
    def __init__(self, operation):
        self.operation = operation

    def __call__(self, *args):
        return self.operation(*args)


@pytest.mark.parametrize("role", ["parent", "descendant"])
@pytest.mark.parametrize("failure", ["open_failed", "not_live", "wait_failed"])
def test_process_pin_failure_is_finite_and_releases_all_acquired_handles(
    monkeypatch: pytest.MonkeyPatch, role: str, failure: str
) -> None:
    target = 101 if role == "parent" else 202
    acquired: list[int] = []
    closed: list[int] = []

    def open_process(access, inherit, process_id):
        assert access == 0x00100000 | 0x1000 and inherit is False
        if process_id == target and failure == "open_failed":
            return 0
        acquired.append(process_id)
        return process_id

    def wait(handle, milliseconds):
        assert milliseconds == 0
        if handle == target:
            return 0 if failure == "not_live" else 0xFFFFFFFF
        return 0x102

    kernel = SimpleNamespace(
        OpenProcess=_Function(open_process),
        WaitForSingleObject=_Function(wait),
        CloseHandle=lambda handle: closed.append(handle.value),
    )
    held: list[int] = []
    monkeypatch.setattr(verifier, "_windows_kernel32", lambda _ctypes: kernel)
    monkeypatch.setattr(verifier, "_HELD_WITNESS_HANDLES", held)
    with pytest.raises(RuntimeError) as caught:
        verifier._pin_windows_processes(_ready())
    assert verifier._witness_observation_error_code(caught.value) == f"{role}_process_{failure}"
    assert closed == acquired and held == []
