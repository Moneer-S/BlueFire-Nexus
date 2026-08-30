"""Descriptor-pinned owner-private filesystem operations for runner state."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import BinaryIO

from .runner_transport_errors import RunnerTransportError

_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_WRITE_DAC = 0x00040000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_CREATE_NEW = 1
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_DISPOSITION_INFO = 4
_WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT = 240


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


def _windows_extended_path(path: Path) -> Path:
    raw_path = os.path.abspath(os.fspath(path))
    if raw_path.startswith("\\\\?\\"):
        return Path(raw_path)
    if raw_path.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw_path[2:])
    return Path("\\\\?\\" + raw_path)


def _windows_open_descriptor(
    path: Path,
    *,
    directory: bool,
    write: bool = False,
    write_dac: bool = False,
    delete: bool = False,
    share_delete: bool = False,
    create: bool = False,
) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    api_path = os.fspath(_windows_extended_path(path))

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
    if write_dac:
        access |= _WINDOWS_WRITE_DAC
    if delete:
        access |= _WINDOWS_DELETE
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    share = (
        _WINDOWS_FILE_SHARE_READ
        | (_WINDOWS_FILE_SHARE_WRITE if directory or share_delete else 0)
        | (_WINDOWS_FILE_SHARE_DELETE if share_delete else 0)
    )
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
        share_delete: bool = False,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        self.path = path
        self.delete = delete
        self.share_delete = share_delete
        self.expected_identity = expected_identity
        self._descriptor: int | None = None
        self._parent_descriptor: int | None = None
        self._identity: tuple[int, int] | None = None

    def __enter__(self) -> _PinnedPrivateDirectory:
        from .runner_trust import (
            RunnerTrustError,
            _is_link_or_reparse,
            _owner_private_handle,
        )

        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise RunnerTransportError("private directory identity is invalid")
        try:
            if os.name == "nt":
                self._descriptor = _windows_open_descriptor(
                    self.path,
                    directory=True,
                    write_dac=True,
                    delete=self.delete,
                    share_delete=self.share_delete,
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
                or _is_link_or_reparse(
                    _windows_extended_path(self.path) if os.name == "nt" else self.path
                )
                or (
                    self.expected_identity is not None
                    and (details.st_dev, details.st_ino) != self.expected_identity
                )
            ):
                raise OSError("unsafe private directory")
            self._identity = details.st_dev, details.st_ino
            if os.name == "nt":
                _owner_private_handle(self._require_descriptor(), directory=True)
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
        validation_path = _windows_extended_path(self.path) if os.name == "nt" else self.path
        current = validation_path.stat(follow_symlinks=False)
        if (
            self._identity is None
            or _is_link_or_reparse(validation_path)
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
            os.scandir(_windows_extended_path(self.path))
            if os.name == "nt"
            else os.scandir(self._require_descriptor())
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
                _windows_extended_path(self.path / name).stat(follow_symlinks=False)
            else:
                os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
        except FileNotFoundError:
            self._validate_directory()
            return False
        self._validate_directory()
        return True

    def _open_existing(
        self,
        name: str,
        *,
        delete: bool = False,
        write_dac: bool = True,
    ) -> int:
        name = self._name(name)
        self._validate_directory()
        if os.name == "nt":
            return _windows_open_descriptor(
                self.path / name,
                directory=False,
                write_dac=write_dac,
                delete=delete,
                share_delete=self.share_delete,
            )
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
                write_dac=True,
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
        from .runner_trust import _is_link_or_reparse, _owner_private_handle

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
                _owner_private_handle(descriptor, directory=False)
            else:
                getattr(os, "fchmod")(descriptor, 0o600)  # noqa: B009 - absent on Windows
        validation_path = (
            _windows_extended_path(self.path / name) if os.name == "nt" else self.path / name
        )
        current = (
            validation_path.stat(follow_symlinks=False)
            if os.name == "nt"
            else os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
        )
        final = os.fstat(descriptor)
        if (
            _is_link_or_reparse(validation_path)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or final.st_nlink != 1
            or (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino)
            or (final.st_dev, final.st_ino) != (details.st_dev, details.st_ino)
            or final.st_size > maximum
        ):
            raise OSError("private file identity changed")
        return final

    def read(self, name: str, *, maximum: int, apply_permissions: bool = True) -> bytes:
        payload, _identity = self.read_with_identity(
            name,
            maximum=maximum,
            apply_permissions=apply_permissions,
        )
        return payload

    def read_with_identity(
        self,
        name: str,
        *,
        maximum: int,
        expected_identity: tuple[int, int] | None = None,
        apply_permissions: bool = True,
    ) -> tuple[bytes, tuple[int, int]]:
        descriptor = self._open_existing(name, write_dac=apply_permissions)
        try:
            before = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=apply_permissions,
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


__all__ = [
    "_GuardedBinaryFile",
    "_PinnedPrivateDirectory",
    "_WINDOWS_CREATE_NEW",
    "_WINDOWS_DELETE",
    "_WINDOWS_FILE_DISPOSITION_INFO",
    "_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS",
    "_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT",
    "_WINDOWS_FILE_SHARE_DELETE",
    "_WINDOWS_FILE_SHARE_READ",
    "_WINDOWS_FILE_SHARE_WRITE",
    "_WINDOWS_GENERIC_READ",
    "_WINDOWS_GENERIC_WRITE",
    "_WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT",
    "_WINDOWS_OPEN_EXISTING",
    "_WINDOWS_WRITE_DAC",
    "_read_descriptor_bounded",
    "_windows_extended_path",
    "_windows_mark_delete_descriptor",
    "_windows_open_descriptor",
    "_windows_rename_descriptor",
]
