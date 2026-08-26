"""Installed-module entry point for the managed authenticated runner host.

The lifecycle starts this module in a separate Python process.  The host owns
the loopback listener and transport ledger and publishes only a bounded,
authenticated address hint.  A caller must still complete mutual-TLS health
verification before treating that hint as a live runner.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .runner_client import RunnerTransport, SubprocessRustRunner
from .runner_transport import AuthenticatedRunnerServer
from .runner_trust import (
    RunnerEnrollment,
    RunnerTrustError,
    _is_link_or_reparse,
    _owner_private,
    load_local_enrollment,
)
from .secret_store import SecretProvider
from .util import canonical_json_bytes, file_hash

PROCESS_RECORD_SCHEMA_VERSION = "bluefire.runner-process.v1"
PROCESS_RECORD_MAX_BYTES = 16 * 1024
LOOPBACK_HOST = "127.0.0.1"

_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_HEX_16 = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_PROCESS_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "launch_id",
        "pid",
        "host",
        "port",
        "runner_id",
        "client_id",
        "server_fingerprint",
        "server_instance_id",
        "runner_binary_digest",
        "started_at_ns",
        "authentication",
    }
)


class RunnerHostError(RuntimeError):
    """A deliberately path- and secret-free managed-host refusal."""


def _receiver_task_key(enrollment: RunnerEnrollment, task_id: str) -> bytes:
    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerHostError("Runner receiver task identity is invalid.")
    return hmac.new(
        enrollment.hmac_key(),
        b"bluefire.loopback-receiver.task.v1\0" + task_id.encode("ascii"),
        hashlib.sha256,
    ).digest()


def process_record_authentication(enrollment: RunnerEnrollment, payload: Mapping[str, Any]) -> str:
    """Authenticate the exact process-record payload with enrollment material."""

    return (
        "sha256:"
        + hmac.new(
            enrollment.hmac_key(), canonical_json_bytes(dict(payload)), hashlib.sha256
        ).hexdigest()
    )


def validate_process_record(
    value: Any,
    *,
    enrollment: RunnerEnrollment,
    expected_binary_digest: str,
) -> dict[str, Any]:
    """Validate a process record as an address hint, never as health proof."""

    if not isinstance(value, dict) or set(value) != _PROCESS_RECORD_FIELDS:
        raise RunnerHostError("Runner process record is invalid.")
    unsigned = {key: value[key] for key in value if key != "authentication"}
    authentication = value.get("authentication")
    expected_authentication = process_record_authentication(enrollment, unsigned)
    if (
        value.get("schema_version") != PROCESS_RECORD_SCHEMA_VERSION
        or not isinstance(value.get("launch_id"), str)
        or _HEX_32.fullmatch(str(value["launch_id"])) is None
        or isinstance(value.get("pid"), bool)
        or not isinstance(value.get("pid"), int)
        or not 1 <= int(value["pid"]) <= 2**63 - 1
        or value.get("host") != LOOPBACK_HOST
        or isinstance(value.get("port"), bool)
        or not isinstance(value.get("port"), int)
        or not 1 <= int(value["port"]) <= 65535
        or value.get("runner_id") != enrollment.runner_id
        or value.get("client_id") != enrollment.client_id
        or value.get("server_fingerprint") != enrollment.metadata["server_fingerprint"]
        or not isinstance(value.get("server_instance_id"), str)
        or _HEX_16.fullmatch(str(value["server_instance_id"])) is None
        or value.get("runner_binary_digest") != expected_binary_digest
        or _DIGEST.fullmatch(str(value.get("runner_binary_digest"))) is None
        or isinstance(value.get("started_at_ns"), bool)
        or not isinstance(value.get("started_at_ns"), int)
        or not 1 <= int(value["started_at_ns"]) <= 2**63 - 1
        or not isinstance(authentication, str)
        or _DIGEST.fullmatch(authentication) is None
        or not hmac.compare_digest(authentication, expected_authentication)
    ):
        raise RunnerHostError("Runner process record is invalid.")
    return dict(value)


def read_process_record(
    path: str | Path,
    *,
    enrollment: RunnerEnrollment,
    expected_binary_digest: str,
) -> dict[str, Any]:
    """Read one owner-private, bounded process record without following links."""

    record_path = Path(path)
    try:
        if _is_link_or_reparse(record_path):
            raise OSError("linked process record")
        before = record_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("unsafe process record")
        descriptor = os.open(
            record_path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise OSError("process record changed")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read(PROCESS_RECORD_MAX_BYTES + 1)
            _owner_private_open_regular(record_path, descriptor)
        finally:
            os.close(descriptor)
        after = record_path.stat(follow_symlinks=False)
        if (
            len(payload) > PROCESS_RECORD_MAX_BYTES
            or _is_link_or_reparse(record_path)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OSError("process record changed")
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if canonical_json_bytes(value) != payload:
            raise ValueError("non-canonical process record")
    except (OSError, UnicodeDecodeError, ValueError, RunnerTrustError):
        raise RunnerHostError("Runner process record is unavailable or invalid.") from None
    return validate_process_record(
        value,
        enrollment=enrollment,
        expected_binary_digest=expected_binary_digest,
    )


def serve_managed_runner(
    *,
    enrollment_root: str | Path,
    runner_binary: str | Path,
    work_root: str | Path,
    state_path: str | Path,
    process_record_path: str | Path,
    start_gate_path: str | Path | None = None,
    launch_id: str,
    runner_timeout_seconds: float = 35.0,
    secret_provider: SecretProvider | None = None,
    runner: RunnerTransport | None = None,
) -> None:
    """Run the authenticated loopback service until an authenticated shutdown."""

    if _HEX_32.fullmatch(launch_id) is None:
        raise RunnerHostError("Runner launch identity is invalid.")
    if not 0.1 <= runner_timeout_seconds <= 24 * 60 * 60:
        raise RunnerHostError("Runner timeout is invalid.")
    server: AuthenticatedRunnerServer | None = None
    record_path = Path(process_record_path)
    try:
        if start_gate_path is not None:
            _await_start_gate(Path(start_gate_path), record_path.parent)
        binary = Path(runner_binary).expanduser().resolve(strict=True)
        if _is_link_or_reparse(binary) or not binary.is_file():
            raise OSError("unsafe runner binary")
        enrollment = load_local_enrollment(
            enrollment_root,
            secret_provider=secret_provider,
        )
        transport = runner or SubprocessRustRunner(
            binary,
            work_root,
            timeout_seconds=runner_timeout_seconds,
            receiver_task_key_factory=lambda task_id: _receiver_task_key(
                enrollment,
                task_id,
            ),
        )
        server = AuthenticatedRunnerServer(
            enrollment.root,
            transport,
            state_path,
            host=LOOPBACK_HOST,
            port=0,
            socket_timeout_seconds=max(runner_timeout_seconds + 5.0, 10.0),
            secret_provider=secret_provider,
        )
        host, port = server.server_address
        if host != LOOPBACK_HOST:
            raise RunnerHostError("Runner host refused a non-loopback listener.")
        unsigned: dict[str, Any] = {
            "schema_version": PROCESS_RECORD_SCHEMA_VERSION,
            "launch_id": launch_id,
            "pid": os.getpid(),
            "host": LOOPBACK_HOST,
            "port": port,
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "server_fingerprint": enrollment.metadata["server_fingerprint"],
            "server_instance_id": server.instance_id,
            "runner_binary_digest": file_hash(binary),
            "started_at_ns": time.time_ns(),
        }
        record = {
            **unsigned,
            "authentication": process_record_authentication(enrollment, unsigned),
        }
        _write_process_record(record_path, record)
        server.serve_forever()
    except RunnerHostError:
        raise
    except Exception:
        raise RunnerHostError("Runner host could not be initialized or served.") from None
    finally:
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
        _remove_owned_process_record(record_path, launch_id)


def default_host_command(
    *,
    enrollment_root: Path,
    runner_binary: Path,
    work_root: Path,
    state_path: Path,
    process_record_path: Path,
    start_gate_path: Path,
    launch_id: str,
    runner_timeout_seconds: float,
) -> tuple[str, ...]:
    """Return the installed-Python command used by the production lifecycle."""

    import sys

    return (
        str(Path(sys.executable).resolve()),
        "-I",
        "-m",
        "bluefire.runner_host",
        "--enrollment-root",
        str(enrollment_root),
        "--runner-binary",
        str(runner_binary),
        "--work-root",
        str(work_root),
        "--state-path",
        str(state_path),
        "--process-record-path",
        str(process_record_path),
        "--start-gate-path",
        str(start_gate_path),
        "--launch-id",
        launch_id,
        "--runner-timeout-seconds",
        str(runner_timeout_seconds),
    )


def _owner_private_open_regular(path: Path, descriptor: int) -> None:
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RunnerTrustError("Runner host state is unavailable or unsafe.")
    if os.name == "nt":
        expected = _windows_descriptor_details(descriptor)
        handle: int | None = None
        try:
            handle, pinned = _windows_open_pinned_path(
                path,
                directory=False,
                delete_access=False,
                share_delete=False,
            )
            if pinned != expected or pinned[0] & 0x00000410 or pinned[1] != 1:
                raise RunnerTrustError("Runner host state changed while it was opened.")
            # The native handle explicitly omits FILE_SHARE_DELETE.  This, not
            # an undocumented CRT sharing default, pins the pathname while the
            # path-based ACL utility addresses it.
            _owner_private(path, directory=False)
            if _windows_handle_details(handle) != expected:
                raise RunnerTrustError("Runner host state changed while it was hardened.")
        except OSError:
            raise RunnerTrustError("Runner host state changed while it was opened.") from None
        finally:
            if handle is not None:
                _windows_close_handle(handle)
        return
    fchmod = getattr(os, "fchmod", None)
    if not callable(fchmod):
        raise RunnerTrustError("Runner host state permissions could not be restricted.")
    fchmod(descriptor, 0o600)
    checked = os.fstat(descriptor)
    getuid = getattr(os, "getuid", None)
    if stat.S_IMODE(checked.st_mode) != 0o600 or (callable(getuid) and checked.st_uid != getuid()):
        raise RunnerTrustError("Runner host state permissions could not be restricted.")


def _windows_open_pinned_path(
    path: Path,
    *,
    directory: bool,
    delete_access: bool,
    share_delete: bool,
    read_data: bool = False,
    share_write: bool = True,
) -> tuple[int, tuple[int, int, int, int, int, int]]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    desired_access = 0x00020000 | 0x00000080
    if delete_access:
        desired_access |= 0x00010000
    if read_data:
        desired_access |= 0x80000000
    share_mode = 0x00000001
    if share_write:
        share_mode |= 0x00000002
    if share_delete:
        share_mode |= 0x00000004
    flags = 0x00200000 | (0x02000000 if directory else 0)
    raw_handle = create(str(path), desired_access, share_mode, None, 3, flags, None)
    invalid = ctypes.c_void_p(-1).value
    if not raw_handle or int(raw_handle) == invalid:
        error = ctypes.get_last_error()
        if error in {2, 3}:
            raise FileNotFoundError(error, "path is absent")
        raise OSError(error, "path handle is unavailable")
    handle = int(raw_handle)
    try:
        details = _windows_handle_details(handle)
    except OSError:
        _windows_close_handle(handle)
        raise
    is_directory = bool(details[0] & 0x00000010)
    if is_directory is not directory:
        _windows_close_handle(handle)
        raise OSError("path kind changed")
    return handle, details


def _windows_handle_details(handle: int) -> tuple[int, int, int, int, int, int]:
    import ctypes
    from ctypes import wintypes

    class _Information(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.GetFileInformationByHandle
    operation.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Information)]
    operation.restype = wintypes.BOOL
    information = _Information()
    if not operation(ctypes.c_void_p(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "path identity is unavailable")
    return (
        int(information.dwFileAttributes),
        int(information.nNumberOfLinks),
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
        (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow),
    )


def _windows_descriptor_details(descriptor: int) -> tuple[int, int, int, int, int, int]:
    import msvcrt

    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise OSError("file identity is unavailable")
    return _windows_handle_details(handle)


def _windows_close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.CloseHandle
    operation.argtypes = [wintypes.HANDLE]
    operation.restype = wintypes.BOOL
    operation(ctypes.c_void_p(handle))


def _windows_mark_delete(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    value = wintypes.BOOL(True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.c_void_p(handle), 4, ctypes.byref(value), ctypes.sizeof(value)):
        raise OSError(ctypes.get_last_error(), "path could not be deleted safely")


def _await_start_gate(path: Path, expected_parent: Path) -> None:
    """Wait until the lifecycle has placed this process in its containment."""

    deadline = time.monotonic() + 30.0
    try:
        parent = expected_parent.resolve(strict=True)
        if (
            path.parent.resolve(strict=True) != parent
            or _is_link_or_reparse(parent)
            or _is_link_or_reparse(path)
        ):
            raise OSError("unsafe start gate")
        while path.exists() or _is_link_or_reparse(path):
            if _is_link_or_reparse(path) or not path.is_file() or path.stat().st_nlink != 1:
                raise OSError("unsafe start gate")
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                _owner_private_open_regular(path, descriptor)
            finally:
                os.close(descriptor)
            if time.monotonic() >= deadline:
                raise OSError("start gate timed out")
            time.sleep(0.01)
    except (OSError, RunnerTrustError):
        raise RunnerHostError("Runner host containment gate is unavailable.") from None


def _write_process_record(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(dict(value))
    if not payload or len(payload) > PROCESS_RECORD_MAX_BYTES:
        raise RunnerHostError("Runner process record exceeds its size limit.")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    try:
        parent = path.parent.resolve(strict=True)
        if path.parent != parent or _is_link_or_reparse(parent) or not parent.is_dir():
            raise OSError("unsafe process record parent")
        if path.exists() or _is_link_or_reparse(path) or _is_link_or_reparse(temporary):
            raise OSError("process record already exists")
        if os.name == "nt":
            _windows_publish_process_record(path, temporary, payload)
        else:
            _posix_publish_process_record(path, temporary, parent, payload)
    except (OSError, RunnerTrustError):
        raise RunnerHostError("Runner process record could not be published.") from None


def _posix_publish_process_record(
    path: Path,
    temporary: Path,
    parent: Path,
    payload: bytes,
) -> None:
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor: int | None = None
    opened: os.stat_result | None = None
    promoted = False
    try:
        descriptor = os.open(
            temporary.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _owner_private_open_regular(temporary, descriptor)
        opened = os.fstat(descriptor)
        current = os.stat(
            temporary.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise OSError("process record temporary changed")
        # Publish without replacement: a process racing a foreign file into
        # the well-known record name must never have that file unlinked.
        os.link(
            temporary.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("process record promotion changed identity")
        current = os.stat(
            temporary.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("process record temporary changed after promotion")
        os.unlink(temporary.name, dir_fd=parent_descriptor)
        final = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened_final = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or opened_final.st_nlink != 1
            or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (opened_final.st_dev, opened_final.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise OSError("process record changed after promotion")
        os.fsync(parent_descriptor)
        promoted = True
    finally:
        if not promoted and descriptor is not None and opened is not None:
            # Cleanup is relative to the pinned parent and only attempted while
            # the temporary name still identifies the object kept open here.
            try:
                current = os.stat(
                    temporary.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                    os.unlink(temporary.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _windows_publish_process_record(path: Path, temporary: Path, payload: bytes) -> None:
    descriptor: int | None = None
    tracking_handle: int | None = None
    tracking_exact = False
    promoted = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _owner_private_open_regular(temporary, descriptor)
        expected = _windows_descriptor_details(descriptor)
        os.close(descriptor)
        descriptor = None

        # Reopen with DELETE access after the CRT descriptor closes.  A swap in
        # this boundary is detected before any ACL or delete operation touches
        # the object now at the random temporary name.
        tracking_handle, tracked = _windows_open_pinned_path(
            temporary,
            directory=False,
            delete_access=True,
            share_delete=False,
        )
        if tracked != expected or tracked[0] & 0x00000410 or tracked[1] != 1:
            raise OSError("process record temporary changed")
        tracking_exact = True
        _windows_rename_handle(tracking_handle, path)
        final_handle, published = _windows_open_pinned_path(
            path,
            directory=False,
            delete_access=False,
            share_delete=True,
        )
        try:
            if published != expected:
                raise OSError("process record promotion changed identity")
        finally:
            _windows_close_handle(final_handle)
        promoted = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if tracking_handle is not None:
            if tracking_exact and not promoted:
                try:
                    _windows_mark_delete(tracking_handle)
                except OSError:
                    pass
            _windows_close_handle(tracking_handle)


def _windows_rename_handle(handle: int, destination: Path) -> None:
    import ctypes
    from ctypes import wintypes

    destination_text = str(destination)

    class _RenameInformation(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", ctypes.c_wchar * (len(destination_text) + 1)),
        ]

    value = _RenameInformation()
    value.Flags = 0
    value.RootDirectory = None
    value.FileNameLength = len(destination_text.encode("utf-16-le"))
    value.FileName = destination_text
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.c_void_p(handle), 3, ctypes.byref(value), ctypes.sizeof(value)):
        raise OSError(ctypes.get_last_error(), "process record could not be promoted safely")


def _remove_owned_process_record(path: Path, launch_id: str) -> None:
    """Best-effort cleanup of only this host's exact regular record."""

    try:
        if os.name == "nt":
            _windows_remove_owned_process_record(path, launch_id)
            return
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                return
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    return
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read(PROCESS_RECORD_MAX_BYTES + 1)
                if not payload or len(payload) > PROCESS_RECORD_MAX_BYTES:
                    return
                value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
                if (
                    canonical_json_bytes(value) != payload
                    or not isinstance(value, dict)
                    or value.get("launch_id") != launch_id
                ):
                    return
                fchmod = getattr(os, "fchmod", None)
                if not callable(fchmod):
                    return
                fchmod(descriptor, 0o600)
                current = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    return
                os.unlink(path.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)
    except (OSError, UnicodeDecodeError, ValueError):
        return


def _windows_remove_owned_process_record(path: Path, launch_id: str) -> None:
    import ctypes
    from ctypes import wintypes

    class _Information(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    pinned = create(
        str(path),
        0x80000000 | 0x00010000 | 0x00020000 | 0x00000080,
        0x00000001,
        None,
        3,
        0x00200000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not pinned or int(pinned) == invalid:
        return
    try:
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Information)]
        get_information.restype = wintypes.BOOL
        information = _Information()
        if not get_information(pinned, ctypes.byref(information)):
            return
        if information.dwFileAttributes & 0x00000410 or information.nNumberOfLinks != 1:
            return
        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if not 0 < size <= PROCESS_RECORD_MAX_BYTES:
            return
        identity = (
            int(information.dwFileAttributes),
            int(information.nNumberOfLinks),
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
            size,
        )
        buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        if not read_file(pinned, buffer, size, ctypes.byref(read), None) or read.value != size:
            return
        payload = bytes(buffer.raw[:size])
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if (
            canonical_json_bytes(value) != payload
            or not isinstance(value, dict)
            or value.get("launch_id") != launch_id
        ):
            return
        _owner_private(path, directory=False)
        checked = _Information()
        if not get_information(pinned, ctypes.byref(checked)):
            return
        if identity != (
            int(checked.dwFileAttributes),
            int(checked.nNumberOfLinks),
            int(checked.dwVolumeSerialNumber),
            int(checked.nFileIndexHigh),
            int(checked.nFileIndexLow),
            (int(checked.nFileSizeHigh) << 32) | int(checked.nFileSizeLow),
        ):
            return
        disposition = wintypes.BOOL(True)
        set_information = kernel32.SetFileInformationByHandle
        set_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        set_information.restype = wintypes.BOOL
        if not set_information(
            pinned,
            4,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            return
    finally:
        kernel32.CloseHandle(pinned)


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BlueFire managed runner host")
    parser.add_argument("--enrollment-root", required=True)
    parser.add_argument("--runner-binary", required=True)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--state-path", required=True)
    parser.add_argument("--process-record-path", required=True)
    parser.add_argument("--start-gate-path", required=True)
    parser.add_argument("--launch-id", required=True)
    parser.add_argument("--runner-timeout-seconds", type=float, default=35.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        serve_managed_runner(
            enrollment_root=arguments.enrollment_root,
            runner_binary=arguments.runner_binary,
            work_root=arguments.work_root,
            state_path=arguments.state_path,
            process_record_path=arguments.process_record_path,
            start_gate_path=arguments.start_gate_path,
            launch_id=arguments.launch_id,
            runner_timeout_seconds=arguments.runner_timeout_seconds,
        )
    except (RunnerHostError, RuntimeError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LOOPBACK_HOST",
    "PROCESS_RECORD_MAX_BYTES",
    "PROCESS_RECORD_SCHEMA_VERSION",
    "RunnerHostError",
    "default_host_command",
    "main",
    "process_record_authentication",
    "read_process_record",
    "serve_managed_runner",
    "validate_process_record",
]
