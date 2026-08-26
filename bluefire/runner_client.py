"""The only maintained Python transport allowed to launch the Rust runner."""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import signal
import stat

# Only the fixed, absolute Rust runner boundary uses subprocess.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Callable, Mapping, Protocol, cast, runtime_checkable

from .util import canonical_json_bytes, content_hash, file_hash

_INVENTORY_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_INVENTORY_MAX_ACTIONS = 512
_INVENTORY_MAX_BYTES = 2 * 1024 * 1024
_INVENTORY_PLATFORMS = frozenset({"linux", "macos", "windows"})
_ACTION_READINESS = frozenset({"ready", "structural", "unavailable"})
_TASK_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RECEIVER_TASK_KEY = re.compile(r"^[0-9a-f]{64}$")
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_WATCHDOG_START_GRACE_SECONDS = 10.0
_WATCHDOG_EXIT_GRACE_SECONDS = 12.0
_WATCHDOG_CONFIG_LIMIT_BYTES = 8 * 1024 * 1024
_WATCHDOG_CONTROL_NAMES = frozenset({"config.json", "start", "cancel", "ready.json", "status.json"})
_KILL_PROCESS_GROUP = getattr(os, "killpg", None)
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_CREATE_NEW = 1
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_DISPOSITION_INFO = 4
_RECEIVER_TASK_ID_ENV = "BLUEFIRE_RECEIVER_TASK_ID"
_RECEIVER_TASK_KEY_ENV = "BLUEFIRE_RECEIVER_TASK_KEY"
_RECEIVER_TASK_ENV_NAMES = frozenset({_RECEIVER_TASK_ID_ENV, _RECEIVER_TASK_KEY_ENV})

FORBIDDEN_EXECUTION_KEYS = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "script",
        "script_body",
        "payload",
        "binary",
        "shellcode",
        "interpreter",
        "executable",
    }
)


class RunnerTransportError(RuntimeError):
    pass


class RunnerReadinessError(RunnerTransportError):
    """A sanitized refusal raised before an Execute effect can be dispatched."""


class RunnerTaskCancelled(RunnerTransportError):
    """The complete runner process tree was confirmed stopped after cancellation."""


class RunnerTaskTimedOut(RunnerTransportError):
    """The complete runner process tree was confirmed stopped after a timeout."""


class RunnerPendingResultExists(RunnerTransportError):
    """A prior task attempt left crash-recovery output that must be reconciled."""


class RunnerDurableResultExists(RunnerTransportError):
    """A final task result already exists and was not overwritten."""


def _validated_receiver_task_environment(
    value: Mapping[str, str] | None,
    *,
    expected_task_id: str | None = None,
) -> dict[str, str]:
    if value is None or not value:
        return {}
    candidate = dict(value)
    task_id = candidate.get(_RECEIVER_TASK_ID_ENV)
    task_key = candidate.get(_RECEIVER_TASK_KEY_ENV)
    if (
        set(candidate) != _RECEIVER_TASK_ENV_NAMES
        or not isinstance(task_id, str)
        or _TASK_IDENTIFIER.fullmatch(task_id) is None
        or (expected_task_id is not None and task_id != expected_task_id)
        or not isinstance(task_key, str)
        or _RECEIVER_TASK_KEY.fullmatch(task_key) is None
    ):
        raise RunnerTransportError("runner receiver authentication is invalid")
    return {
        _RECEIVER_TASK_ID_ENV: task_id,
        _RECEIVER_TASK_KEY_ENV: task_key,
    }


def _consume_receiver_task_environment(*, expected_task_id: str) -> dict[str, str]:
    present = frozenset(name for name in _RECEIVER_TASK_ENV_NAMES if name in os.environ)
    candidate = {name: os.environ.pop(name) for name in present}
    if not present:
        return {}
    if present != _RECEIVER_TASK_ENV_NAMES:
        raise RunnerTransportError("runner receiver authentication is incomplete")
    return _validated_receiver_task_environment(
        candidate,
        expected_task_id=expected_task_id,
    )


def _read_descriptor_bounded(descriptor: int, maximum: int) -> bytes:
    if isinstance(maximum, bool) or maximum < 0:
        raise OSError("invalid bounded read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= maximum:
        block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(payload)))
        if not block:
            break
        payload.extend(block)
    if len(payload) > maximum:
        raise OSError("private file exceeds its size limit")
    return bytes(payload)


def _windows_open_descriptor(
    path: Path,
    *,
    directory: bool,
    write: bool = False,
    delete: bool = False,
    create: bool = False,
) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    raw_path = os.path.abspath(os.fspath(path))
    if raw_path.startswith("\\\\?\\"):
        api_path = raw_path
    elif raw_path.startswith("\\\\"):
        api_path = "\\\\?\\UNC\\" + raw_path[2:]
    else:
        api_path = "\\\\?\\" + raw_path

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    access = _WINDOWS_GENERIC_READ
    if write:
        access |= _WINDOWS_GENERIC_WRITE
    if delete:
        access |= _WINDOWS_DELETE
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    share = _WINDOWS_FILE_SHARE_READ | (_WINDOWS_FILE_SHARE_WRITE if directory else 0)
    handle = create_file(
        api_path,
        access,
        share,
        None,
        _WINDOWS_CREATE_NEW if create else _WINDOWS_OPEN_EXISTING,
        flags,
        None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        if create and error in {80, 183}:
            raise FileExistsError(error, "CreateFileW target exists", str(path))
        if not create and error in {2, 3}:
            raise FileNotFoundError(error, "CreateFileW target is absent", str(path))
        raise OSError(error, "CreateFileW failed", str(path))
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            (os.O_RDWR if write else os.O_RDONLY) | getattr(os, "O_BINARY", 0),
        )
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise


def _windows_mark_delete_descriptor(descriptor: int) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Disposition(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    set_information = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    disposition = _Disposition(True)
    if not set_information(
        wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
        _WINDOWS_FILE_DISPOSITION_INFO,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise OSError(ctypes.get_last_error(), "handle deletion failed")


def _windows_rename_descriptor(descriptor: int, root_descriptor: int, target_name: str) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    if not target_name or Path(target_name).name != target_name:
        raise OSError("invalid rename target")

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    class _FileRename(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_ubyte),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", ctypes.c_wchar * len(target_name)),
        ]

    rename = _FileRename()
    rename.ReplaceIfExists = 0
    rename.RootDirectory = wintypes.HANDLE(msvcrt.get_osfhandle(root_descriptor))
    rename.FileNameLength = len(target_name.encode("utf-16-le"))
    rename.FileName = target_name
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    rename_file = ntdll.NtSetInformationFile
    rename_file.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    )
    rename_file.restype = ctypes.c_long
    status = _IoStatusBlock()
    result = rename_file(
        wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
        ctypes.byref(status),
        ctypes.byref(rename),
        ctypes.sizeof(rename),
        10,  # FileRenameInformation
    )
    if result != 0:
        if ctypes.c_ulong(result).value == 0xC0000035:  # STATUS_OBJECT_NAME_COLLISION
            raise FileExistsError("handle rename target exists")
        raise OSError(int(result), "handle rename failed")


class _PinnedPrivateDirectory:
    """Pin one exact private directory for bounded child-file operations."""

    def __init__(
        self,
        path: Path,
        *,
        delete: bool = False,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        self.path = path
        self.delete = delete
        self.expected_identity = expected_identity
        self._descriptor: int | None = None
        self._parent_descriptor: int | None = None
        self._identity: tuple[int, int] | None = None

    def __enter__(self) -> _PinnedPrivateDirectory:
        from .runner_trust import RunnerTrustError, _is_link_or_reparse, _owner_private

        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise RunnerTransportError("private directory identity is invalid")
        try:
            if os.name == "nt":
                self._descriptor = _windows_open_descriptor(
                    self.path, directory=True, delete=self.delete
                )
            else:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                self._parent_descriptor = os.open(self.path.parent, flags)
                self._descriptor = os.open(self.path.name, flags, dir_fd=self._parent_descriptor)
            details = os.fstat(self._require_descriptor())
            if (
                not stat.S_ISDIR(details.st_mode)
                or _is_link_or_reparse(self.path)
                or (
                    self.expected_identity is not None
                    and (details.st_dev, details.st_ino) != self.expected_identity
                )
            ):
                raise OSError("unsafe private directory")
            self._identity = details.st_dev, details.st_ino
            if os.name == "nt":
                _owner_private(self.path, directory=True)
            else:
                getattr(os, "fchmod")(  # noqa: B009 - absent on Windows
                    self._require_descriptor(), 0o700
                )
            self._validate_directory()
            return self
        except FileNotFoundError:
            self.close()
            raise
        except (OSError, RunnerTrustError):
            self.close()
            raise RunnerTransportError("private directory is unavailable or unsafe") from None

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _require_descriptor(self) -> int:
        if self._descriptor is None:
            raise OSError("private directory is closed")
        return self._descriptor

    def _validate_directory(self) -> None:
        from .runner_trust import _is_link_or_reparse

        descriptor = self._require_descriptor()
        details = os.fstat(descriptor)
        current = self.path.stat(follow_symlinks=False)
        if (
            self._identity is None
            or _is_link_or_reparse(self.path)
            or not stat.S_ISDIR(details.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (details.st_dev, details.st_ino) != self._identity
            or (current.st_dev, current.st_ino) != self._identity
        ):
            raise OSError("private directory identity changed")

    def directory_identity(self) -> tuple[int, int]:
        self._validate_directory()
        if self._identity is None:
            raise OSError("private directory identity is unavailable")
        return self._identity

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._parent_descriptor is not None:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None

    @staticmethod
    def _name(name: str) -> str:
        if not name or Path(name).name != name:
            raise OSError("invalid private child name")
        return name

    def names(self, *, maximum: int | None = None) -> tuple[str, ...]:
        if maximum is not None and (isinstance(maximum, bool) or maximum < 0):
            raise OSError("invalid private directory entry bound")
        self._validate_directory()
        iterator = (
            os.scandir(self.path) if os.name == "nt" else os.scandir(self._require_descriptor())
        )
        names: list[str] = []
        try:
            with iterator:
                for entry in iterator:
                    if maximum is not None and len(names) >= maximum:
                        raise OSError("private directory entry bound exceeded")
                    names.append(entry.name)
        finally:
            self._validate_directory()
        return tuple(names)

    def has_name(self, name: str) -> bool:
        name = self._name(name)
        self._validate_directory()
        try:
            if os.name == "nt":
                (self.path / name).stat(follow_symlinks=False)
            else:
                os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
        except FileNotFoundError:
            self._validate_directory()
            return False
        self._validate_directory()
        return True

    def _open_existing(self, name: str, *, delete: bool = False) -> int:
        name = self._name(name)
        self._validate_directory()
        if os.name == "nt":
            return _windows_open_descriptor(self.path / name, directory=False, delete=delete)
        return os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self._require_descriptor(),
        )

    def _open_new(self, name: str) -> int:
        name = self._name(name)
        self._validate_directory()
        if os.name == "nt":
            return _windows_open_descriptor(
                self.path / name,
                directory=False,
                write=True,
                delete=True,
                create=True,
            )
        return os.open(
            name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=self._require_descriptor(),
        )

    def _validate_file(
        self,
        name: str,
        descriptor: int,
        *,
        maximum: int,
        apply_permissions: bool = True,
        expected_identity: tuple[int, int] | None = None,
    ) -> os.stat_result:
        from .runner_trust import _is_link_or_reparse, _owner_private

        name = self._name(name)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size < 0
            or details.st_size > maximum
            or (
                expected_identity is not None
                and (details.st_dev, details.st_ino) != expected_identity
            )
        ):
            raise OSError("unsafe private file")
        if apply_permissions:
            if os.name == "nt":
                _owner_private(self.path / name, directory=False)
            else:
                getattr(os, "fchmod")(descriptor, 0o600)  # noqa: B009 - absent on Windows
        current = (
            (self.path / name).stat(follow_symlinks=False)
            if os.name == "nt"
            else os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
        )
        final = os.fstat(descriptor)
        if (
            _is_link_or_reparse(self.path / name)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or final.st_nlink != 1
            or (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino)
            or (final.st_dev, final.st_ino) != (details.st_dev, details.st_ino)
            or final.st_size > maximum
        ):
            raise OSError("private file identity changed")
        return final

    def read(self, name: str, *, maximum: int) -> bytes:
        payload, _identity = self.read_with_identity(name, maximum=maximum)
        return payload

    def read_with_identity(
        self,
        name: str,
        *,
        maximum: int,
        expected_identity: tuple[int, int] | None = None,
    ) -> tuple[bytes, tuple[int, int]]:
        descriptor = self._open_existing(name)
        try:
            before = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                expected_identity=expected_identity,
            )
            payload = _read_descriptor_bounded(descriptor, maximum)
            after = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=False,
                expected_identity=(before.st_dev, before.st_ino),
            )
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise OSError("private file changed while read")
            return payload, (before.st_dev, before.st_ino)
        finally:
            os.close(descriptor)

    def file_identity(
        self,
        name: str,
        *,
        maximum: int,
        apply_permissions: bool = True,
    ) -> tuple[int, int]:
        descriptor = self._open_existing(name)
        try:
            details = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=apply_permissions,
            )
            return details.st_dev, details.st_ino
        finally:
            os.close(descriptor)

    def create(self, name: str, payload: bytes, *, maximum: int) -> None:
        if not 0 <= len(payload) <= maximum:
            raise OSError("private payload exceeds its size limit")
        name = self._name(name)
        # Keep the Win32-facing ACL path short even when the pinned directory
        # itself is near the legacy path limit. CREATE_NEW still makes the
        # random 48-bit temporary name collision-safe and fail closed.
        temporary = f".t-{secrets.token_hex(6)}"
        descriptor = self._open_new(temporary)
        written_ok = False
        temporary_identity: tuple[int, int] | None = None
        try:
            self._validate_file(temporary, descriptor, maximum=maximum)
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short private file write")
                written += count
            os.fsync(descriptor)
            details = self._validate_file(
                temporary,
                descriptor,
                maximum=maximum,
                apply_permissions=False,
            )
            temporary_identity = details.st_dev, details.st_ino
            written_ok = True
        finally:
            if not written_ok:
                try:
                    if os.name == "nt":
                        _windows_mark_delete_descriptor(descriptor)
                    else:
                        os.unlink(temporary, dir_fd=self._require_descriptor())
                except OSError:
                    pass
            os.close(descriptor)
        try:
            if temporary_identity is None:
                raise OSError("private temporary identity is unavailable")
            self.promote(
                temporary,
                name,
                maximum=maximum,
                expected=payload,
                permissions_already_private=True,
                expected_identity=temporary_identity,
            )
        except BaseException:
            try:
                self.unlink(
                    temporary,
                    maximum=maximum,
                    expected=payload,
                    expected_identity=temporary_identity,
                )
            except OSError:
                pass
            raise

    def open_new(self, name: str, *, maximum: int) -> _GuardedBinaryFile:
        descriptor = self._open_new(name)
        try:
            self._validate_file(name, descriptor, maximum=maximum)
            handle = os.fdopen(descriptor, "w+b", buffering=0)
            return _GuardedBinaryFile(handle, self, name, maximum)
        except BaseException:
            try:
                if os.name == "nt":
                    _windows_mark_delete_descriptor(descriptor)
                else:
                    os.unlink(name, dir_fd=self._require_descriptor())
            except OSError:
                pass
            os.close(descriptor)
            self.close()
            raise

    def unlink(
        self,
        name: str,
        *,
        maximum: int,
        expected: bytes | None = None,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        descriptor = self._open_existing(name, delete=True)
        try:
            opened = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                expected_identity=expected_identity,
            )
            if expected is not None and _read_descriptor_bounded(descriptor, maximum) != expected:
                raise OSError("private file content changed")
            self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=False,
                expected_identity=(opened.st_dev, opened.st_ino),
            )
            if os.name == "nt":
                _windows_mark_delete_descriptor(descriptor)
            else:
                current = os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
                opened = os.fstat(descriptor)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise OSError("private file identity changed")
                os.unlink(name, dir_fd=self._require_descriptor())
            self.sync()
        finally:
            os.close(descriptor)

    def promote(
        self,
        source: str,
        destination: str,
        *,
        maximum: int,
        expected: bytes,
        permissions_already_private: bool = False,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        source = self._name(source)
        destination = self._name(destination)
        descriptor = self._open_existing(source, delete=True)
        try:
            source_details = self._validate_file(
                source,
                descriptor,
                maximum=maximum,
                apply_permissions=not permissions_already_private,
                expected_identity=expected_identity,
            )
            if _read_descriptor_bounded(descriptor, maximum) != expected:
                raise OSError("private promotion source changed")
            if os.name == "nt":
                _windows_rename_descriptor(descriptor, self._require_descriptor(), destination)
                # A handle with DELETE access can transiently deny ordinary
                # readers even after rename. Close it immediately after the
                # handle-relative publication, then re-open and bind the final
                # validation to the same file identity.
                os.close(descriptor)
                descriptor = -1
                final_descriptor = self._open_existing(destination)
                try:
                    final_details = os.fstat(final_descriptor)
                    if (final_details.st_dev, final_details.st_ino) != (
                        source_details.st_dev,
                        source_details.st_ino,
                    ):
                        raise OSError("private promotion target changed")
                    self._validate_file(
                        destination,
                        final_descriptor,
                        maximum=maximum,
                        apply_permissions=False,
                    )
                finally:
                    os.close(final_descriptor)
            else:
                os.link(
                    source,
                    destination,
                    src_dir_fd=self._require_descriptor(),
                    dst_dir_fd=self._require_descriptor(),
                    follow_symlinks=False,
                )
                os.unlink(source, dir_fd=self._require_descriptor())
                self._validate_file(
                    destination,
                    descriptor,
                    maximum=maximum,
                    apply_permissions=False,
                )
            self.sync()
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def sync(self) -> None:
        if os.name != "nt":
            os.fsync(self._require_descriptor())

    def remove(self) -> None:
        if self.names():
            raise OSError("private directory is not empty")
        descriptor = self._require_descriptor()
        if os.name == "nt":
            if not self.delete:
                raise OSError("private directory delete was not authorized")
            _windows_mark_delete_descriptor(descriptor)
        else:
            if self._parent_descriptor is None:
                raise OSError("private parent directory is unavailable")
            current = os.stat(
                self.path.name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
            if self._identity is None or (current.st_dev, current.st_ino) != self._identity:
                raise OSError("private directory identity changed")
            os.rmdir(self.path.name, dir_fd=self._parent_descriptor)
            os.fsync(self._parent_descriptor)


class _GuardedBinaryFile:
    def __init__(
        self,
        handle: BinaryIO,
        directory: _PinnedPrivateDirectory,
        name: str,
        maximum: int,
    ) -> None:
        self._handle = handle
        self._directory = directory
        self._name = name
        self._maximum = maximum

    def fileno(self) -> int:
        return self._handle.fileno()

    def write(self, payload: bytes) -> int:
        return self._handle.write(payload)

    def flush(self) -> None:
        self._handle.flush()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._handle.seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        return self._handle.read(size)

    def validate_identity(self) -> None:
        self._directory._validate_file(
            self._name,
            self.fileno(),
            maximum=self._maximum,
            apply_permissions=False,
        )

    def identity(self) -> tuple[int, int]:
        details = self._directory._validate_file(
            self._name,
            self.fileno(),
            maximum=self._maximum,
            apply_permissions=False,
        )
        return details.st_dev, details.st_ino

    def close(self) -> None:
        try:
            self._handle.close()
        finally:
            self._directory.close()


@runtime_checkable
class RunnerTransport(Protocol):
    def inventory(self) -> Mapping[str, Any]: ...

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


@runtime_checkable
class TaskAwareRunnerTransport(RunnerTransport, Protocol):
    """Runner transport that durably identifies and cancels one exact task."""

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]: ...


def canonical_runner_inventory(inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and normalize the stable identity-bearing runner inventory.

    The returned document deliberately contains only bounded, non-secret fields.
    Its digest is therefore safe to surface and stable across JSON key ordering.
    """

    if not isinstance(inventory, Mapping):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    runner_id = _inventory_token(inventory.get("runner_id"), maximum=128)
    runner_version = _inventory_token(inventory.get("runner_version"), maximum=128)
    action_sdk_version = _inventory_token(inventory.get("action_sdk_version"), maximum=128)
    receipt_protocol = _inventory_token(inventory.get("receipt_protocol"), maximum=128)
    platform = inventory.get("platform")
    raw_actions = inventory.get("actions")
    if (
        runner_id is None
        or runner_version is None
        or action_sdk_version is None
        or receipt_protocol is None
        or not isinstance(platform, str)
        or platform not in _INVENTORY_PLATFORMS
        or not isinstance(raw_actions, list)
        or len(raw_actions) > _INVENTORY_MAX_ACTIONS
    ):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")

    try:
        source_bytes = canonical_json_bytes(dict(inventory))
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(source_bytes) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")

    actions: list[dict[str, str]] = []
    action_ids: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_id = _inventory_token(raw_action.get("action_id"), maximum=200)
        action_version = _inventory_token(raw_action.get("action_version"), maximum=64)
        readiness = raw_action.get("readiness")
        if (
            action_id is None
            or not _INVENTORY_IDENTIFIER.fullmatch(action_id)
            or action_version is None
            or not isinstance(readiness, str)
            or readiness not in _ACTION_READINESS
            or action_id in action_ids
        ):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_ids.add(action_id)
        actions.append(
            {
                "action_id": action_id,
                "action_version": action_version,
                "readiness": readiness,
                "contract_digest": content_hash(dict(raw_action)),
            }
        )
    actions.sort(key=lambda item: item["action_id"])
    canonical = {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": runner_id,
        "runner_version": runner_version,
        "action_sdk_version": action_sdk_version,
        "receipt_protocol": receipt_protocol,
        "platform": platform,
        "source_digest": content_hash(dict(inventory)),
        "actions": actions,
    }
    try:
        encoded = canonical_json_bytes(canonical)
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(encoded) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")
    return canonical


def runner_inventory_digest(inventory: Mapping[str, Any]) -> str:
    """Return the canonical digest used by the approval and dispatch gates."""

    return content_hash(canonical_runner_inventory(inventory))


def runner_transport_identity(
    runner: RunnerTransport,
    inventory: Mapping[str, Any],
) -> Mapping[str, str]:
    """Build a secret-safe identity for the exact transport and runner binary."""

    canonical = canonical_runner_inventory(inventory)
    identity = {
        "transport": f"{type(runner).__module__}.{type(runner).__qualname__}",
        "runner_id": str(canonical["runner_id"]),
        "runner_version": str(canonical["runner_version"]),
        "platform": str(canonical["platform"]),
    }
    raw_binary = getattr(runner, "runner_binary", None)
    if isinstance(raw_binary, Path):
        try:
            binary = raw_binary.resolve(strict=True)
            if not binary.is_file():
                raise OSError("runner binary is not a file")
            identity["runner_binary_digest"] = file_hash(binary)
        except OSError as exc:
            raise RunnerReadinessError("Runner identity could not be verified.") from exc
    return identity


class InventoryBoundRunner:
    """Fail closed if the approved runner identity or inventory changes.

    Inventory is checked when orchestration claims the approval and again
    immediately before every action dispatch. The underlying transport error is
    never exposed because it may contain local paths or process diagnostics.
    """

    def __init__(
        self,
        runner: RunnerTransport,
        *,
        expected_inventory_digest: str,
        expected_identity_digest: str,
        recovery_identity: Mapping[str, Any],
    ) -> None:
        self.runner = runner
        self.expected_inventory_digest = expected_inventory_digest
        self.expected_identity_digest = expected_identity_digest
        self.recovery_identity = dict(recovery_identity)

    @property
    def runner_binary(self) -> Any:
        return getattr(self.runner, "runner_binary", None)

    @property
    def runner_binary_digest(self) -> Any:
        return getattr(self.runner, "runner_binary_digest", None)

    def inventory(self) -> Mapping[str, Any]:
        try:
            inventory = self.runner.inventory()
            canonical = canonical_runner_inventory(inventory)
            identity = runner_transport_identity(self.runner, inventory)
        except (AttributeError, OSError, RunnerTransportError, TypeError, ValueError) as exc:
            raise RunnerReadinessError(
                "Runner became unavailable after approval; no action was dispatched."
            ) from exc
        if content_hash(canonical) != self.expected_inventory_digest:
            raise RunnerReadinessError(
                "Runner inventory changed after approval; submit a new Execute request."
            )
        if content_hash(identity) != self.expected_identity_digest:
            raise RunnerReadinessError(
                "Runner identity changed after approval; submit a new Execute request."
            )
        return inventory

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.inventory()
        return self.runner.execute(manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Preserve the approval-time inventory gate for task-aware dispatch."""

        self.inventory()
        operation = getattr(self.runner, "execute_task", None)
        if not callable(operation):
            raise RunnerTransportError("Runner transport does not support task-aware execution.")
        result = operation(
            manifest,
            profile,
            task_id=task_id,
            cancel_event=cancel_event,
            durable_result_path=durable_result_path,
        )
        if not isinstance(result, Mapping):
            raise RunnerTransportError("runner result must be a JSON object")
        return result


def _inventory_token(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not 1 <= len(token) <= maximum or any(ord(character) < 32 for character in token):
        return None
    return token


def reject_forbidden_execution_keys(value: Any, *, path: str = "$") -> None:
    """Recursively reject free-form executable content at the transport edge."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in FORBIDDEN_EXECUTION_KEYS:
                raise RunnerTransportError(f"forbidden execution field at {path}.{key}")
            reject_forbidden_execution_keys(child, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            reject_forbidden_execution_keys(child, path=f"{path}[{index}]")


def runner_pending_result_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic crash-recovery path for a task's runner stdout.

    The task identifier is hashed into a fixed filename, so it can never select
    a path.  A server that restarts after its parent process was interrupted can
    use this helper to find and reconcile a complete, parseable runner result.
    """

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    return destination.with_name(f".bluefire-result-{identity}.pending")


def runner_watchdog_control_root(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic private control directory for one runner task."""

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    return destination.parent / f".bluefire-watchdog-{identity}"


def runner_watchdog_cancel_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's deterministic cancellation marker path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "cancel"


def runner_watchdog_ready_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's private watchdog-readiness record path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "ready.json"


def runner_watchdog_status_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's durable terminal watchdog-status path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "status.json"


def request_runner_task_cancel(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Durably request cancellation for an already-started watchdog task."""

    root = runner_watchdog_control_root(durable_result_path, task_id)
    try:
        with _PinnedPrivateDirectory(root) as pinned:
            try:
                pinned.create("cancel", b"cancel\n", maximum=32)
            except FileExistsError:
                if pinned.read("cancel", maximum=32) != b"cancel\n":
                    raise OSError("invalid cancellation marker") from None
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("runner cancellation signal is unavailable") from None


def cleanup_runner_watchdog_terminal_state(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Remove only a terminal watchdog record after durable task reconciliation."""

    root = runner_watchdog_control_root(durable_result_path, task_id)
    deadline = time.monotonic() + 0.5
    expected_status_identity: tuple[int, int] | None = None
    expected_status_payload: bytes | None = None
    while True:
        try:
            with _PinnedPrivateDirectory(root, delete=True) as pinned:
                if pinned.names() != ("status.json",):
                    raise OSError("watchdog task is not terminal")
                payload, status_identity = pinned.read_with_identity(
                    "status.json",
                    maximum=4096,
                    expected_identity=expected_status_identity,
                )
                if expected_status_identity is None:
                    expected_status_identity = status_identity
                    expected_status_payload = payload
                elif (
                    status_identity != expected_status_identity
                    or payload != expected_status_payload
                ):
                    raise OSError("watchdog terminal status identity changed")
                status = SubprocessRustRunner._decode_json(
                    payload,
                    "runner watchdog status",
                )
                if (
                    status.get("schema_version") != "bluefire.runner-watchdog-status.v1"
                    or status.get("task_id") != task_id
                    or status.get("state") not in {"succeeded", "failed", "cancelled"}
                ):
                    raise OSError("invalid watchdog status")
                pinned.unlink(
                    "status.json",
                    maximum=4096,
                    expected=payload,
                    expected_identity=status_identity,
                )
                pinned.remove()
                return
        except (OSError, RunnerTransportError):
            if time.monotonic() >= deadline:
                raise RunnerTransportError(
                    "runner watchdog state is not ready for reconciliation"
                ) from None
            time.sleep(0.01)


class SubprocessRustRunner:
    """Invoke one preconfigured runner binary with a fixed argument grammar."""

    def __init__(
        self,
        runner_binary: str | Path,
        work_root: str | Path,
        *,
        timeout_seconds: float = 35.0,
        output_limit_bytes: int = 2 * 1024 * 1024,
        receiver_task_key_factory: Callable[[str], bytes] | None = None,
        _kill_child_on_job_close: bool = False,
    ) -> None:
        binary = Path(runner_binary).expanduser()
        if not binary.is_absolute() or not binary.is_file():
            raise RunnerTransportError("runner binary must be an existing absolute file")
        root = Path(work_root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        self.runner_binary = binary.resolve(strict=True)
        try:
            self.runner_binary_digest = file_hash(self.runner_binary)
        except OSError:
            raise RunnerTransportError("Runner identity could not be verified.") from None
        self.work_root = root.resolve(strict=True)
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self._receiver_task_key_factory = receiver_task_key_factory
        self._kill_child_on_job_close = bool(_kill_child_on_job_close)
        self._windows_jobs: dict[int, int] = {}
        self._windows_jobs_lock = threading.Lock()
        if (
            timeout_seconds <= 0
            or not 4096 <= output_limit_bytes <= _WATCHDOG_CONFIG_LIMIT_BYTES
            or (receiver_task_key_factory is not None and not callable(receiver_task_key_factory))
        ):
            raise RunnerTransportError("runner transport bounds are invalid")

    def inventory(self) -> Mapping[str, Any]:
        output = self._invoke([str(self.runner_binary), "inventory", "--json"])
        return self._decode_json(output, "runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
            request_root = Path(directory)
            manifest_path = request_root / "manifest.json"
            profile_path = request_root / "profile.json"
            manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
            output = self._invoke(
                [
                    str(self.runner_binary),
                    "execute",
                    "--manifest",
                    str(manifest_path),
                    "--profile",
                    str(profile_path),
                    "--json",
                ]
            )
        return self._validate_result(output, manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Run one task through an independent crash-surviving watchdog process."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if not callable(getattr(cancel_event, "is_set", None)):
            raise RunnerTransportError("runner cancellation signal is invalid")
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )

        destination, pending = self._durable_paths(durable_result_path, task_id)
        receiver_environment = self._receiver_environment(task_id)
        control_root = runner_watchdog_control_root(destination, task_id)
        config_path = control_root / "config.json"
        start_path = control_root / "start"
        watchdog: subprocess.Popen[bytes] | None = None
        try:
            self._prepare_watchdog_control(control_root)
            try:
                current_binary_digest = file_hash(self.runner_binary)
            except OSError:
                raise RunnerTransportError("Runner identity could not be verified.") from None
            if current_binary_digest != self.runner_binary_digest:
                raise RunnerTransportError("Runner identity changed after construction.")
            config = {
                "schema_version": "bluefire.runner-watchdog-config.v1",
                "task_id": task_id,
                "runner_binary": str(self.runner_binary),
                "runner_binary_digest": self.runner_binary_digest,
                "work_root": str(self.work_root),
                "timeout_seconds": self.timeout_seconds,
                "output_limit_bytes": self.output_limit_bytes,
                "durable_result_path": str(destination),
                "manifest": dict(manifest),
                "profile": dict(profile),
            }
            self._write_private_control_file(
                config_path,
                canonical_json_bytes(config) + b"\n",
                maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
            )
            try:
                current_binary_digest = file_hash(self.runner_binary)
            except OSError:
                raise RunnerTransportError("Runner identity could not be verified.") from None
            if current_binary_digest != self.runner_binary_digest:
                raise RunnerTransportError("Runner identity changed before watchdog launch.")
            watchdog = self._spawn_watchdog(
                config_path,
                receiver_environment=receiver_environment,
            )
            # `_spawn_watchdog` returns only after Windows job assignment. The
            # watchdog refuses to launch Rust until this exclusive gate exists.
            self._write_private_control_file(start_path, b"start\n", maximum=32)
            return self._await_watchdog(
                watchdog,
                manifest=manifest,
                profile=profile,
                task_id=task_id,
                destination=destination,
                pending=pending,
                cancel_event=cancel_event,
            )
        except BaseException:
            if watchdog is not None and watchdog.poll() is None:
                try:
                    request_runner_task_cancel(destination, task_id)
                except RunnerTransportError:
                    pass
                stop_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while watchdog.poll() is None and time.monotonic() < stop_deadline:
                    time.sleep(_PROCESS_POLL_SECONDS)
                if watchdog.poll() is None:
                    if os.name != "nt":
                        # Rust owns a separate POSIX process group. Killing only
                        # the watchdog here would orphan the exact effect whose
                        # status must remain recoverable. Leave the private state
                        # intact and let the watchdog enforce its own deadline.
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        ) from None
                    if not self._terminate_process_tree(watchdog):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        ) from None
                elif os.name == "nt" and not self._finish_windows_job(watchdog.pid):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
                elif os.name != "nt" and not self._finish_posix_process_group(watchdog):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
            raise
        finally:
            if watchdog is None or watchdog.poll() is not None:
                self._cleanup_watchdog_control(control_root)

    def _execute_task_locally(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
        receiver_environment: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        """Watchdog-only fixed-runner execution and durable-result commit."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )
        destination, pending = self._durable_paths(durable_result_path, task_id)
        pending_identities: list[tuple[int, int]] = []
        try:
            with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
                request_root = Path(directory)
                manifest_path = request_root / "manifest.json"
                profile_path = request_root / "profile.json"
                manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
                profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
                output, pending_identity = self._invoke_task(
                    [
                        str(self.runner_binary),
                        "execute",
                        "--manifest",
                        str(manifest_path),
                        "--profile",
                        str(profile_path),
                        "--json",
                    ],
                    cancel_event=cancel_event,
                    pending_result_path=pending,
                    identity_sink=pending_identities,
                    receiver_environment=receiver_environment,
                )
            result = self._validate_result(output, manifest, profile)
            self._promote_pending_result(
                pending,
                destination,
                pending_expected=output,
                pending_identity=pending_identity,
                final_payload=canonical_json_bytes(dict(result)) + b"\n",
            )
            return result
        except (RunnerDurableResultExists, RunnerPendingResultExists):
            raise
        except BaseException:
            self._remove_pending_result(
                pending,
                expected_identity=(pending_identities[-1] if pending_identities else None),
            )
            raise

    @staticmethod
    def _prepare_watchdog_control(root: Path) -> None:
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            created = root.stat(follow_symlinks=False)
            with _PinnedPrivateDirectory(root, expected_identity=(created.st_dev, created.st_ino)):
                pass
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner watchdog state is unavailable") from None

    @staticmethod
    def _write_private_control_file(path: Path, payload: bytes, *, maximum: int) -> None:
        if not 0 < len(payload) <= maximum:
            raise RunnerTransportError("runner watchdog state exceeds its size limit")
        try:
            with _PinnedPrivateDirectory(path.parent) as pinned:
                pinned.create(path.name, payload, maximum=maximum)
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner watchdog state is unavailable") from None

    def _receiver_environment(self, task_id: str) -> dict[str, str]:
        if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
            raise RunnerTransportError("runner task identity is invalid")
        factory = self._receiver_task_key_factory
        if factory is None:
            return {}
        try:
            task_key = factory(task_id)
        except BaseException:
            raise RunnerTransportError("runner receiver authentication is unavailable") from None
        if type(task_key) is not bytes or len(task_key) != 32:
            raise RunnerTransportError("runner receiver authentication is invalid")
        return _validated_receiver_task_environment(
            {
                _RECEIVER_TASK_ID_ENV: task_id,
                _RECEIVER_TASK_KEY_ENV: task_key.hex(),
            },
            expected_task_id=task_id,
        )

    def _spawn_watchdog(
        self,
        config_path: Path,
        *,
        receiver_environment: Mapping[str, str],
    ) -> subprocess.Popen[bytes]:
        try:
            interpreter = Path(sys.executable).resolve(strict=True)
            if not interpreter.is_file():
                raise OSError("Python runtime is unavailable")
        except OSError:
            raise RunnerTransportError("Runner watchdog runtime is unavailable") from None
        return self._spawn(
            [
                str(interpreter),
                "-I",
                "-m",
                "bluefire.runner_watchdog",
                str(config_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            receiver_environment=receiver_environment,
        )

    def _await_watchdog(
        self,
        process: subprocess.Popen[bytes],
        *,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
        destination: Path,
        pending: Path,
        cancel_event: threading.Event,
    ) -> Mapping[str, Any]:
        deadline = (
            time.monotonic()
            + self.timeout_seconds
            + _WATCHDOG_START_GRACE_SECONDS
            + _WATCHDOG_EXIT_GRACE_SECONDS
        )
        cancellation_requested = False
        while True:
            return_code = process.poll()
            if return_code is not None:
                if os.name == "nt" and not self._finish_windows_job(process.pid):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                break
            if cancel_event.is_set() and not cancellation_requested:
                request_runner_task_cancel(destination, task_id)
                cancellation_requested = True
            if time.monotonic() >= deadline:
                if not cancellation_requested:
                    request_runner_task_cancel(destination, task_id)
                    cancellation_requested = True
                grace_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while process.poll() is None and time.monotonic() < grace_deadline:
                    time.sleep(_PROCESS_POLL_SECONDS)
                if process.poll() is None:
                    if os.name != "nt":
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        )
                    if not self._terminate_process_tree(process):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        )
                if os.name == "nt" and not self._finish_windows_job(process.pid):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                raise RunnerTransportError("Runner watchdog exceeded its terminal deadline")
            time.sleep(_PROCESS_POLL_SECONDS)

        status_path = runner_watchdog_status_path(destination, task_id)
        status: Mapping[str, Any] | None = None
        try:
            with _PinnedPrivateDirectory(status_path.parent) as pinned:
                payload = pinned.read(status_path.name, maximum=4096)
            status = self._decode_json(payload, "runner watchdog status")
        except (OSError, RunnerTransportError):
            status = None
        if status is not None and (
            status.get("schema_version") != "bluefire.runner-watchdog-status.v1"
            or status.get("task_id") != task_id
        ):
            status = None
        code = status.get("error_code") if status is not None else None
        state = status.get("state") if status is not None else None
        if code == "cancelled":
            raise RunnerTaskCancelled("Runner task was cancelled after its process tree stopped.")
        if code == "timed_out":
            raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
        if code == "output_limit":
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if code == "durable_result_exists":
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            )
        pending_present = self._private_name_exists(pending)
        destination_present = self._private_name_exists(destination)
        if code == "pending_result_exists" or pending_present:
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            )
        if code == "unsupported_result_schema":
            raise RunnerTransportError("runner returned an unsupported result schema")
        if code == "invalid_json":
            raise RunnerTransportError("runner result is not valid UTF-8 JSON")
        if code == "invalid_result":
            raise RunnerTransportError("runner returned a result that did not match its request")
        if state == "succeeded" or (status is None and destination_present):
            output = self._read_private_result(destination)
            return self._validate_result(output, manifest, profile)
        raise RunnerTransportError("Runner watchdog failed before publishing a valid result")

    def _read_private_result(self, path: Path) -> bytes:
        try:
            with _PinnedPrivateDirectory(path.parent) as pinned:
                return pinned.read(path.name, maximum=self.output_limit_bytes)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    @staticmethod
    def _private_name_exists(path: Path) -> bool:
        try:
            with _PinnedPrivateDirectory(path.parent) as pinned:
                return pinned.has_name(path.name)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    @staticmethod
    def _cleanup_watchdog_control(root: Path) -> None:
        try:
            with _PinnedPrivateDirectory(root, delete=True) as pinned:
                names = pinned.names()
                if any(name not in _WATCHDOG_CONTROL_NAMES for name in names):
                    return
                identities = {
                    name: pinned.file_identity(
                        name,
                        maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                        apply_permissions=False,
                    )
                    for name in names
                }
                for name, identity in identities.items():
                    pinned.unlink(
                        name,
                        maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                        expected_identity=identity,
                    )
                pinned.remove()
        except (OSError, RunnerTransportError):
            return

    def _validate_result(
        self,
        output: bytes,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = self._decode_json(output, "runner result")
        expected: dict[str, Any] = {"schema_version": "bluefire.runner-result.v1"}
        for field in (
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "runner_id",
            "runner_profile_id",
            "platform",
            "request_hash",
            "policy_digest",
        ):
            if field in manifest:
                expected[field] = manifest[field]
        profile_bindings = {
            "runner_id": "runner_id",
            "runner_profile_id": "profile_id",
            "platform": "platform",
            "policy_digest": "policy_digest",
        }
        for result_field, profile_field in profile_bindings.items():
            if profile_field not in profile:
                continue
            profile_value = profile[profile_field]
            manifest_value = manifest.get(result_field)
            if result_field in manifest and manifest_value != profile_value:
                raise RunnerTransportError(
                    f"runner request {result_field} does not match its profile"
                )
            expected[result_field] = profile_value
        for field, value in expected.items():
            if result.get(field) != value:
                if field == "schema_version":
                    raise RunnerTransportError("runner returned an unsupported result schema")
                raise RunnerTransportError(f"runner result {field} does not match the request")
        return result

    def _invoke(self, argv: list[str]) -> bytes:
        process = self._spawn(argv, stdout=subprocess.PIPE)
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()

        def drain(stream, destination: bytearray) -> None:
            if stream is None:
                return
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = self.output_limit_bytes - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            return_code = self._monitor_process(process, overflow=overflow)
        finally:
            for reader in readers:
                reader.join(timeout=5)

        if overflow.is_set():
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        # The runner deliberately uses 3 for policy refusal/control blocking
        # and 4 for an action-level failed/partial result. Both still carry a
        # valid, signed-by-content JSON TaskResult on stdout and must reach the
        # evidence layer intact. Exit code 2 (or anything unexpected) is a
        # transport/CLI failure.
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError(f"Rust runner exited with unexpected status {return_code}")
        return bytes(stdout)

    def _invoke_task(
        self,
        argv: list[str],
        *,
        cancel_event: threading.Event,
        pending_result_path: Path,
        identity_sink: list[tuple[int, int]],
        receiver_environment: Mapping[str, str] | None,
    ) -> tuple[bytes, tuple[int, int]]:
        output = self._open_pending_result(pending_result_path)
        guarded_output = cast(_GuardedBinaryFile, output)
        identity_sink.append(guarded_output.identity())
        stderr = bytearray()
        overflow = threading.Event()
        process: subprocess.Popen[bytes] | None = None
        try:
            process = self._spawn(
                argv,
                stdout=output,
                receiver_environment=receiver_environment,
            )

            def drain_stderr(stream: BinaryIO | None) -> None:
                if stream is None:
                    return
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    remaining = self.output_limit_bytes - len(stderr)
                    if remaining > 0:
                        stderr.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()

            reader = threading.Thread(
                target=drain_stderr,
                args=(process.stderr,),
                name="bluefire-runner-stderr",
                daemon=True,
            )
            reader.start()
            try:
                return_code = self._monitor_process(
                    process,
                    cancel_event=cancel_event,
                    overflow=overflow,
                    output_descriptor=output.fileno(),
                )
            finally:
                reader.join(timeout=_PROCESS_KILL_GRACE_SECONDS)
            output.flush()
            os.fsync(output.fileno())
            guarded_output.validate_identity()
            pending_identity = guarded_output.identity()
            output.seek(0)
            result_output = output.read(self.output_limit_bytes + 1)
        except BaseException as exc:
            if process is not None and process.poll() is None:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError(
                        "Runner process tree could not be stopped safely"
                    ) from None
            if isinstance(exc, RunnerTransportError):
                raise
            if isinstance(exc, OSError):
                raise RunnerTransportError("Rust runner transport failed") from None
            raise
        finally:
            output.close()

        if overflow.is_set() or len(result_output) > self.output_limit_bytes:
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError("Rust runner exited with an unexpected status")
        return result_output, pending_identity

    def _spawn(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None = subprocess.PIPE,
        receiver_environment: Mapping[str, str] | None = None,
    ) -> subprocess.Popen[bytes]:
        environment: dict[str, str] = {"LC_ALL": "C", "LANG": "C"}
        environment.update(_validated_receiver_task_environment(receiver_environment))
        options: dict[str, Any] = {}
        windows_job: int | None = None
        windows_suspended = False
        if os.name == "nt":
            system_directory = self._windows_system_directory()
            windows_root = system_directory.parent
            environment.update({"SYSTEMROOT": str(windows_root), "WINDIR": str(windows_root)})
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
            if self._kill_child_on_job_close:
                # The inner Rust process must not execute even one instruction
                # until it is a member of the watchdog-owned kill-on-close Job.
                options["creationflags"] |= getattr(subprocess, "CREATE_SUSPENDED", 0x0000_0004)
                windows_suspended = True
            windows_job = self._create_windows_job()
        else:
            options["start_new_session"] = True
        try:
            # argv[0] is a validated absolute executable path and the grammar is fixed.
            process = subprocess.Popen(  # nosec B603
                argv,
                cwd=self.work_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                **options,
            )
            if windows_job is not None:
                self._assign_windows_job(windows_job, process)
                windows_job = None  # ownership moved to `_windows_jobs`
            if windows_suspended:
                try:
                    self._resume_windows_process(process)
                except RunnerTransportError:
                    if not self._terminate_windows_process_tree(process):
                        raise RunnerTransportError(
                            "Windows process containment could not stop a suspended child"
                        ) from None
                    raise
            return process
        except (OSError, ValueError):
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise RunnerTransportError("Rust runner could not be started") from None
        except RunnerTransportError:
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise

    def _monitor_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        cancel_event: threading.Event | None = None,
        overflow: threading.Event,
        output_descriptor: int | None = None,
    ) -> int:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            return_code = process.poll()
            if return_code is not None:
                released = (
                    self._finish_windows_job(process.pid)
                    if os.name == "nt"
                    else self._finish_posix_process_group(process)
                )
                if not released and self._kill_child_on_job_close:
                    self._retain_failed_process_tree(process)
                    released = True
                if not released:
                    raise RunnerTransportError("Runner process tree state could not be released")
                return return_code
            output_unsafe = False
            if output_descriptor is not None:
                try:
                    details = os.fstat(output_descriptor)
                    output_unsafe = (
                        not stat.S_ISREG(details.st_mode)
                        or details.st_nlink != 1
                        or details.st_size > self.output_limit_bytes
                    )
                except OSError:
                    output_unsafe = True
            if overflow.is_set() or output_unsafe:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner exceeded the transport output limit")
            if cancel_event is not None and cancel_event.is_set():
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped."
                )
            if time.monotonic() >= deadline:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner transport timed out")
            time.sleep(_PROCESS_POLL_SECONDS)

    def _stop_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        """Stop a tree, retaining watchdog containment until emptiness is certain."""

        if self._terminate_process_tree(process):
            return True
        if not self._kill_child_on_job_close:
            return False
        self._retain_failed_process_tree(process)
        return True

    def _retain_failed_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        """Fail closed while a watchdog-owned Job or process group is unresolved.

        This intentionally has no local deadline.  The request host can still
        cancel the outer watchdog containment on Windows; on POSIX it leaves the
        watchdog running as indeterminate recovery state.  Publishing a terminal
        task status while Rust descendants remain unconfirmed would be unsafe.
        """

        while not self._terminate_process_tree(process):
            time.sleep(_PROCESS_POLL_SECONDS)

    def _terminate_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name == "nt":
            return self._terminate_windows_process_tree(process)
        return self._terminate_posix_process_tree(process)

    @staticmethod
    def _posix_process_group_exists(process_group: int) -> bool:
        if not callable(_KILL_PROCESS_GROUP):
            return False
        try:
            _KILL_PROCESS_GROUP(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _terminate_posix_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if not callable(_KILL_PROCESS_GROUP):
            return False
        process_group = process.pid
        try:
            _KILL_PROCESS_GROUP(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= graceful_deadline:
                break
            process.poll()
            time.sleep(_PROCESS_POLL_SECONDS)
        if self._posix_process_group_exists(process_group):
            try:
                _KILL_PROCESS_GROUP(process_group, _FORCE_KILL_SIGNAL)
            except ProcessLookupError:
                pass
            except OSError:
                return False
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False
        stopped_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= stopped_deadline:
                return False
            time.sleep(_PROCESS_POLL_SECONDS)
        return process.poll() is not None

    def _finish_posix_process_group(self, process: subprocess.Popen[bytes]) -> bool:
        if not self._posix_process_group_exists(process.pid):
            return process.poll() is not None
        return self._terminate_posix_process_tree(process)

    def _terminate_windows_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process.pid)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            terminated = bool(terminate_job(job, 1))
            if terminated:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except (AttributeError, OSError, subprocess.SubprocessError, ValueError):
            terminated = False
        if not terminated or not self._wait_for_empty_windows_job(job):
            return False
        return self._release_windows_job(process.pid) and process.poll() is not None

    def _create_windows_job(self) -> int:
        job = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_job = kernel32.CreateJobObjectW
            create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            create_job.restype = wintypes.HANDLE

            raw_job = create_job(None, None)
            if not raw_job:
                raise OSError("job creation failed")
            job = int(raw_job)
            # The request-server's outer watchdog job intentionally survives
            # handle closure. Inside the watchdog, the Rust child job uses
            # KILL_ON_JOB_CLOSE so a watchdog crash cannot orphan execution.
            if self._kill_child_on_job_close:
                self._set_windows_job_kill_on_close(job)
            return job
        except (AttributeError, OSError, TypeError, ValueError):
            if job:
                self._close_windows_handle(job)
            raise RunnerTransportError("Windows process containment is unavailable") from None
        except RunnerTransportError:
            if job:
                self._close_windows_handle(job)
            raise

    @staticmethod
    def _set_windows_job_kill_on_close(job: int) -> None:
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("per_process_user_time_limit", ctypes.c_longlong),
                    ("per_job_user_time_limit", ctypes.c_longlong),
                    ("limit_flags", wintypes.DWORD),
                    ("minimum_working_set_size", ctypes.c_size_t),
                    ("maximum_working_set_size", ctypes.c_size_t),
                    ("active_process_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t),
                    ("priority_class", wintypes.DWORD),
                    ("scheduling_class", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    ("read_operation_count", ctypes.c_ulonglong),
                    ("write_operation_count", ctypes.c_ulonglong),
                    ("other_operation_count", ctypes.c_ulonglong),
                    ("read_transfer_count", ctypes.c_ulonglong),
                    ("write_transfer_count", ctypes.c_ulonglong),
                    ("other_transfer_count", ctypes.c_ulonglong),
                ]

            class ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("basic_limit_information", BasicLimitInformation),
                    ("io_info", IoCounters),
                    ("process_memory_limit", ctypes.c_size_t),
                    ("job_memory_limit", ctypes.c_size_t),
                    ("peak_process_memory_used", ctypes.c_size_t),
                    ("peak_job_memory_used", ctypes.c_size_t),
                ]

            details = ExtendedLimitInformation()
            details.basic_limit_information.limit_flags = 0x0000_2000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            set_information = kernel32.SetInformationJobObject
            set_information.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_information.restype = wintypes.BOOL
            if not set_information(
                job,
                9,
                ctypes.byref(details),
                ctypes.sizeof(details),
            ):
                raise OSError("job close containment is unavailable")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows process containment is unavailable") from None

    @staticmethod
    def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
        """Resume the one primary thread of a CREATE_SUSPENDED child."""

        snapshot = 0
        thread_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            class ThreadEntry32(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("usage", wintypes.DWORD),
                    ("thread_id", wintypes.DWORD),
                    ("owner_process_id", wintypes.DWORD),
                    ("base_priority", wintypes.LONG),
                    ("priority_delta", wintypes.LONG),
                    ("flags", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_snapshot = kernel32.CreateToolhelp32Snapshot
            create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            create_snapshot.restype = wintypes.HANDLE
            first_thread = kernel32.Thread32First
            first_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            first_thread.restype = wintypes.BOOL
            next_thread = kernel32.Thread32Next
            next_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            next_thread.restype = wintypes.BOOL
            open_thread = kernel32.OpenThread
            open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_thread.restype = wintypes.HANDLE
            resume_thread = kernel32.ResumeThread
            resume_thread.argtypes = [wintypes.HANDLE]
            resume_thread.restype = wintypes.DWORD

            raw_snapshot = create_snapshot(0x0000_0004, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if not raw_snapshot or int(raw_snapshot) == invalid_handle:
                raise OSError("thread snapshot unavailable")
            snapshot = int(raw_snapshot)
            entry = ThreadEntry32()
            entry.size = ctypes.sizeof(entry)
            available = bool(first_thread(snapshot, ctypes.byref(entry)))
            candidates: list[int] = []
            while available:
                if entry.owner_process_id == process.pid:
                    candidates.append(int(entry.thread_id))
                available = bool(next_thread(snapshot, ctypes.byref(entry)))
            if len(candidates) != 1:
                raise OSError("suspended child thread identity is ambiguous")
            raw_thread = open_thread(0x0002, False, candidates[0])
            if not raw_thread:
                raise OSError("suspended child thread is unavailable")
            thread_handle = int(raw_thread)
            previous_count = int(resume_thread(thread_handle))
            if previous_count != 1:
                raise OSError("suspended child was not resumed exactly once")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows suspended process start failed") from None
        finally:
            if thread_handle:
                SubprocessRustRunner._close_windows_handle(thread_handle)
            if snapshot:
                SubprocessRustRunner._close_windows_handle(snapshot)

    def _assign_windows_job(
        self,
        job: int,
        process: subprocess.Popen[bytes],
    ) -> None:
        process_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            assign_process = kernel32.AssignProcessToJobObject
            assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            assign_process.restype = wintypes.BOOL
            terminate_process = kernel32.TerminateProcess
            terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_process.restype = wintypes.BOOL

            raw_process_handle = open_process(0x0001 | 0x0100 | 0x1000, False, process.pid)
            if not raw_process_handle:
                raise OSError("process handle unavailable")
            process_handle = int(raw_process_handle)
            if not assign_process(job, process_handle):
                terminate_process(process_handle, 1)
                raise OSError("job assignment failed")
            with self._windows_jobs_lock:
                self._windows_jobs[process.pid] = job
        except (AttributeError, OSError, TypeError, ValueError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            raise RunnerTransportError("Windows process containment is unavailable") from None
        finally:
            if process_handle:
                self._close_windows_handle(process_handle)

    def _release_windows_job(self, process_id: int) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.pop(process_id, None)
        return job is None or self._close_windows_handle(job)

    def _finish_windows_job(self, process_id: int) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process_id)
        if job is None:
            return True
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            descendants_stopped = bool(terminate_job(job, 1))
        except (AttributeError, TypeError, ValueError):
            descendants_stopped = False
        if not descendants_stopped or not self._wait_for_empty_windows_job(job):
            return False
        return self._release_windows_job(process_id)

    @staticmethod
    def _wait_for_empty_windows_job(job: int) -> bool:
        try:
            import ctypes
            from ctypes import wintypes

            class BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("total_user_time", ctypes.c_longlong),
                    ("total_kernel_time", ctypes.c_longlong),
                    ("period_user_time", ctypes.c_longlong),
                    ("period_kernel_time", ctypes.c_longlong),
                    ("total_page_fault_count", wintypes.DWORD),
                    ("total_processes", wintypes.DWORD),
                    ("active_processes", wintypes.DWORD),
                    ("total_terminated_processes", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.QueryInformationJobObject
            query.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            query.restype = wintypes.BOOL
            deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
            while True:
                details = BasicAccountingInformation()
                returned = wintypes.DWORD()
                if not query(
                    job,
                    1,
                    ctypes.byref(details),
                    ctypes.sizeof(details),
                    ctypes.byref(returned),
                ):
                    return False
                if details.active_processes == 0:
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(_PROCESS_POLL_SECONDS)
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def _close_windows_handle(handle: int) -> bool:
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            return bool(close_handle(handle))
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def _windows_system_directory() -> Path:
        if os.name != "nt":
            raise RunnerTransportError("Windows process control is unavailable")
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer)
            )
            if length <= 0 or length >= len(buffer):
                raise OSError("system directory lookup failed")
            directory = Path(buffer.value).resolve(strict=True)
            if not directory.is_dir():
                raise OSError("system directory is unavailable")
            return directory
        except (AttributeError, OSError, ValueError):
            raise RunnerTransportError("Windows process control is unavailable") from None

    def _durable_paths(
        self,
        durable_result_path: str | Path,
        task_id: str,
    ) -> tuple[Path, Path]:
        from .runner_trust import _is_link_or_reparse

        destination = Path(durable_result_path).expanduser()
        if not destination.is_absolute() or destination.name in {"", ".", ".."}:
            raise RunnerTransportError("runner durable result destination is invalid")
        try:
            requested_parent = destination.parent
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if _is_link_or_reparse(destination.parent):
                raise OSError("durable result parent is linked")
            metadata = destination.parent.stat(follow_symlinks=False)
            parent = destination.parent.resolve(strict=True)
            if (
                os.path.normcase(os.path.normpath(str(requested_parent)))
                != os.path.normcase(os.path.normpath(str(parent)))
                or not parent.is_dir()
                or _is_link_or_reparse(parent)
            ):
                raise OSError("durable result parent is not a directory")
            destination = parent / destination.name
            pending = runner_pending_result_path(destination, task_id)
            with _PinnedPrivateDirectory(
                parent,
                expected_identity=(metadata.st_dev, metadata.st_ino),
            ) as pinned:
                if pinned.has_name(destination.name):
                    raise RunnerDurableResultExists(
                        "Runner durable result already exists and requires reconciliation."
                    )
                if pinned.has_name(pending.name):
                    raise RunnerPendingResultExists(
                        "Runner pending result requires recovery before the task can start."
                    )
        except RunnerDurableResultExists:
            raise
        except RunnerPendingResultExists:
            raise
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result destination is unavailable") from None
        return destination, pending

    @staticmethod
    def _open_pending_result(path: Path) -> BinaryIO:
        pinned = _PinnedPrivateDirectory(path.parent)
        try:
            pinned.__enter__()
            return cast(
                BinaryIO,
                pinned.open_new(path.name, maximum=_WATCHDOG_CONFIG_LIMIT_BYTES),
            )
        except FileExistsError:
            pinned.close()
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            pinned.close()
            raise RunnerTransportError("runner pending result is unavailable") from None

    @staticmethod
    def _promote_pending_result(
        pending: Path,
        destination: Path,
        *,
        pending_expected: bytes,
        pending_identity: tuple[int, int],
        final_payload: bytes,
    ) -> None:
        final_created = False
        try:
            if pending.parent != destination.parent:
                raise OSError("durable result directories differ")
            with _PinnedPrivateDirectory(destination.parent) as pinned:
                checked, checked_identity = pinned.read_with_identity(
                    pending.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected_identity=pending_identity,
                )
                if checked != pending_expected or checked_identity != pending_identity:
                    raise OSError("runner pending result identity changed")
                pinned.create(
                    destination.name,
                    final_payload,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                )
                final_created = True
                pinned.unlink(
                    pending.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected=pending_expected,
                    expected_identity=pending_identity,
                )
        except FileExistsError:
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            ) from None
        except (OSError, RunnerTransportError):
            if final_created:
                raise RunnerDurableResultExists(
                    "Runner durable result may be committed and requires reconciliation."
                ) from None
            raise RunnerTransportError("runner durable result could not be committed") from None

    @staticmethod
    def _remove_pending_result(
        path: Path,
        *,
        expected_identity: tuple[int, int] | None,
    ) -> None:
        if expected_identity is None:
            return
        try:
            with _PinnedPrivateDirectory(path.parent) as pinned:
                pinned.unlink(
                    path.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected_identity=expected_identity,
                )
        except (OSError, RunnerTransportError):
            pass

    @staticmethod
    def _decode_json(payload: bytes, label: str) -> Mapping[str, Any]:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, child in pairs:
                if key in value:
                    raise ValueError("duplicate JSON object key")
                value[key] = child
            return value

        def finite_float(raw: str) -> float:
            value = float(raw)
            if not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            return value

        def reject_constant(_raw: str) -> Any:
            raise ValueError("non-standard JSON constant")

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
                parse_float=finite_float,
            )
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise RunnerTransportError(f"{label} is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise RunnerTransportError(f"{label} must be a JSON object")
        return value


__all__ = [
    "InventoryBoundRunner",
    "RunnerTransport",
    "RunnerTransportError",
    "RunnerReadinessError",
    "RunnerDurableResultExists",
    "RunnerPendingResultExists",
    "RunnerTaskCancelled",
    "RunnerTaskTimedOut",
    "SubprocessRustRunner",
    "TaskAwareRunnerTransport",
    "canonical_runner_inventory",
    "reject_forbidden_execution_keys",
    "runner_inventory_digest",
    "runner_pending_result_path",
    "runner_transport_identity",
    "request_runner_task_cancel",
    "cleanup_runner_watchdog_terminal_state",
    "runner_watchdog_cancel_path",
    "runner_watchdog_control_root",
    "runner_watchdog_ready_path",
    "runner_watchdog_status_path",
]
