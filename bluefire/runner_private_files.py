"""Descriptor-pinned owner-private filesystem operations for runner state."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path
from typing import BinaryIO, Sequence

from . import windows_owner_acl as _windows_owner_acl
from .runner_transport_errors import RunnerTransportError
from .windows_owner_acl import (
    _WINDOWS_CREATE_NEW as _WINDOWS_CREATE_NEW,
)
from .windows_owner_acl import (
    _WINDOWS_DELETE as _WINDOWS_DELETE,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_DISPOSITION_INFO as _WINDOWS_FILE_DISPOSITION_INFO,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS as _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT as _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_SHARE_DELETE as _WINDOWS_FILE_SHARE_DELETE,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_SHARE_READ as _WINDOWS_FILE_SHARE_READ,
)
from .windows_owner_acl import (
    _WINDOWS_FILE_SHARE_WRITE as _WINDOWS_FILE_SHARE_WRITE,
)
from .windows_owner_acl import (
    _WINDOWS_GENERIC_READ as _WINDOWS_GENERIC_READ,
)
from .windows_owner_acl import (
    _WINDOWS_GENERIC_WRITE as _WINDOWS_GENERIC_WRITE,
)
from .windows_owner_acl import (
    _WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT as _WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT,
)
from .windows_owner_acl import (
    _WINDOWS_OPEN_EXISTING as _WINDOWS_OPEN_EXISTING,
)
from .windows_owner_acl import (
    _WINDOWS_WRITE_DAC as _WINDOWS_WRITE_DAC,
)
from .windows_owner_acl import (
    _windows_extended_path as _windows_extended_path,
)
from .windows_owner_acl import (
    _windows_mark_delete_descriptor as _windows_mark_delete_descriptor,
)
from .windows_owner_acl import (
    _windows_open_descriptor as _windows_open_descriptor,
)
from .windows_owner_acl import (
    _windows_rename_descriptor as _windows_rename_descriptor,
)

_LINUX_AT_EMPTY_PATH = 0x1000
_LINUX_STATX_MNT_ID = 0x1000
_TEMPORARY_NAME_ATTEMPTS = 4


def _is_link_or_reparse(path: Path) -> bool:
    """Fail closed for links and Windows reparse points."""

    try:
        if path.is_symlink():
            return True
        if os.name == "nt" and path.exists():
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return bool(attributes & reparse)
        return False
    except OSError:
        return True


def _owner_private_handle(descriptor: int, *, directory: bool) -> None:
    """Apply the standard-library-only Windows ACL boundary to one handle."""

    if os.name != "nt":
        raise OSError("Windows private-object permissions are unavailable")
    try:
        _windows_owner_acl.apply_owner_private_acl(descriptor, directory=directory)
    except (OSError, _windows_owner_acl.WindowsOwnerAclError):
        raise OSError("Windows private-object permissions are unavailable") from None


def _descriptor_mount_identity(descriptor: int) -> int | None:
    """Return Linux's mount ID for an already-open descriptor."""

    if not sys.platform.startswith("linux"):
        return None
    import ctypes
    import errno

    buffer = (ctypes.c_ubyte * 256)()
    try:
        statx = ctypes.CDLL(None, use_errno=True).statx
    except AttributeError:
        raise OSError(errno.ENOSYS, "descriptor mount identity is unavailable") from None
    statx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
    )
    statx.restype = ctypes.c_int
    if (
        statx(
            descriptor,
            b"",
            _LINUX_AT_EMPTY_PATH,
            _LINUX_STATX_MNT_ID,
            ctypes.byref(buffer),
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, "descriptor mount identity is unavailable")
    mask = int.from_bytes(bytes(buffer[0:4]), "little")
    mount_id = int.from_bytes(bytes(buffer[144:152]), "little")
    if not mask & _LINUX_STATX_MNT_ID or mount_id <= 0:
        raise OSError(errno.ENOSYS, "descriptor mount identity is unavailable")
    return mount_id


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


class _PrivateFileCleanupError(RunnerTransportError):
    """Retain every failure when a private handle cannot close cleanly."""

    def __init__(self, failures: Sequence[BaseException]) -> None:
        self.failures = tuple(failures)
        super().__init__("private file operation and cleanup had multiple failures")


def _extend_private_file_failures(
    failures: list[BaseException],
    failure: BaseException,
) -> None:
    if isinstance(failure, _PrivateFileCleanupError):
        for nested in failure.failures:
            _extend_private_file_failures(failures, nested)
    else:
        failures.append(failure)


def _raise_private_file_failures(failures: Sequence[BaseException]) -> None:
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise _PrivateFileCleanupError(failures) from failures[0]


class _PinnedPrivateDirectory:
    """Pin one exact private directory for bounded child-file operations."""

    def __init__(
        self,
        path: Path,
        *,
        delete: bool = False,
        share_delete: bool = False,
        expected_identity: tuple[int, int] | None = None,
        expected_mount_identity: int | None = None,
        parent: _PinnedPrivateDirectory | None = None,
    ) -> None:
        self.path = path
        self.delete = delete
        self.share_delete = share_delete
        self.expected_identity = expected_identity
        self.expected_mount_identity = expected_mount_identity
        self._pinned_parent = parent
        self._descriptor: int | None = None
        self._parent_descriptor: int | None = None
        self._identity: tuple[int, int] | None = None
        self._mount_identity: int | None = None
        self._authorized_cleanup_entries: dict[str, tuple[int, int]] = {}

    def __enter__(self) -> _PinnedPrivateDirectory:
        if (
            not self.path.is_absolute()
            or self.path.name in {"", ".", ".."}
            or (self._pinned_parent is not None and self.path.parent != self._pinned_parent.path)
        ):
            raise RunnerTransportError("private directory identity is invalid")
        try:
            if self._pinned_parent is not None:
                self._pinned_parent._validate_directory()
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
                self._parent_descriptor = (
                    os.dup(self._pinned_parent._require_descriptor())
                    if self._pinned_parent is not None
                    else os.open(self.path.parent, flags)
                )
                self._descriptor = os.open(self.path.name, flags, dir_fd=self._parent_descriptor)
            details = os.fstat(self._require_descriptor())
            mount_identity = _descriptor_mount_identity(self._require_descriptor())
            linked = (
                _is_link_or_reparse(_windows_extended_path(self.path))
                if os.name == "nt"
                else stat.S_ISLNK(details.st_mode)
            )
            if (
                not stat.S_ISDIR(details.st_mode)
                or linked
                or (
                    self.expected_identity is not None
                    and (details.st_dev, details.st_ino) != self.expected_identity
                )
                or (
                    self.expected_mount_identity is not None
                    and mount_identity != self.expected_mount_identity
                )
            ):
                raise OSError("unsafe private directory")
            self._identity = details.st_dev, details.st_ino
            self._mount_identity = mount_identity
            if os.name == "nt":
                _owner_private_handle(self._require_descriptor(), directory=True)
            else:
                getattr(os, "fchmod")(  # noqa: B009 - absent on Windows
                    self._require_descriptor(), 0o700
                )
            self._validate_directory()
            if self._pinned_parent is not None:
                self._pinned_parent._validate_directory()
            return self
        except FileNotFoundError as exc:
            self._close_after_failure(exc)
            raise
        except OSError as exc:
            self._close_after_failure(exc)
            raise RunnerTransportError("private directory is unavailable or unsafe") from None

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except BaseException as close_exc:
            if exc is None:
                raise
            failures: list[BaseException] = []
            _extend_private_file_failures(failures, exc)
            _extend_private_file_failures(failures, close_exc)
            _raise_private_file_failures(failures)

    def _close_after_failure(self, failure: BaseException) -> None:
        try:
            self.close()
        except BaseException as close_exc:
            failures: list[BaseException] = []
            _extend_private_file_failures(failures, failure)
            _extend_private_file_failures(failures, close_exc)
            _raise_private_file_failures(failures)

    def _require_descriptor(self) -> int:
        if self._descriptor is None:
            raise OSError("private directory is closed")
        return self._descriptor

    def _validate_directory(self) -> None:
        descriptor = self._require_descriptor()
        details = os.fstat(descriptor)
        validation_path = _windows_extended_path(self.path) if os.name == "nt" else self.path
        if os.name == "nt":
            current = validation_path.stat(follow_symlinks=False)
            linked = _is_link_or_reparse(validation_path)
            current_mount_identity = None
        else:
            if self._parent_descriptor is None:
                raise OSError("private parent directory is unavailable")
            if sys.platform.startswith("linux"):
                current_descriptor = os.open(
                    self.path.name,
                    getattr(os, "O_PATH", os.O_RDONLY)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self._parent_descriptor,
                )
                try:
                    current = os.fstat(current_descriptor)
                    current_mount_identity = _descriptor_mount_identity(current_descriptor)
                finally:
                    os.close(current_descriptor)
            else:
                current = os.stat(
                    self.path.name,
                    dir_fd=self._parent_descriptor,
                    follow_symlinks=False,
                )
                current_mount_identity = None
            linked = stat.S_ISLNK(current.st_mode)
        if (
            self._identity is None
            or linked
            or not stat.S_ISDIR(details.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (details.st_dev, details.st_ino) != self._identity
            or (current.st_dev, current.st_ino) != self._identity
            or current_mount_identity != self._mount_identity
        ):
            raise OSError("private directory identity changed")

    def directory_identity(self) -> tuple[int, int]:
        self._validate_directory()
        if self._identity is None:
            raise OSError("private directory identity is unavailable")
        return self._identity

    def directory_mount_identity(self) -> int | None:
        self._validate_directory()
        return self._mount_identity

    def parent_mount_identity(self) -> int | None:
        self._validate_directory()
        if self._parent_descriptor is None:
            return None
        return _descriptor_mount_identity(self._parent_descriptor)

    def close(self) -> None:
        descriptors = (self._descriptor, self._parent_descriptor)
        self._descriptor = None
        self._parent_descriptor = None
        self._identity = None
        self._mount_identity = None
        failures: list[BaseException] = []
        for descriptor in descriptors:
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except BaseException as exc:
                _extend_private_file_failures(failures, exc)
        _raise_private_file_failures(failures)

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

    def create_directory(self, name: str) -> tuple[tuple[int, int], int | None]:
        """Create one private child directory relative to this exact parent."""

        name = self._name(name)
        self._validate_directory()
        if os.name == "nt":
            (self.path / name).mkdir(mode=0o700, parents=False, exist_ok=False)
        else:
            os.mkdir(name, mode=0o700, dir_fd=self._require_descriptor())
        details, mount_identity = self.entry_metadata_with_mount_identity(name)
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise OSError("created private directory identity is invalid")
        return (int(details.st_dev), int(details.st_ino)), mount_identity

    def authorize_cleanup_entry(self, name: str, *, maximum: int) -> tuple[int, int]:
        """Remember one exact, verified child identity for later owned cleanup."""

        name = self._name(name)
        identity = self.file_identity(name, maximum=maximum, apply_permissions=False)
        existing = self._authorized_cleanup_entries.get(name)
        if existing is not None and existing != identity:
            raise OSError("authorized cleanup entry identity changed")
        self._authorized_cleanup_entries[name] = identity
        return identity

    def authorized_cleanup_entries(self) -> dict[str, tuple[int, int]]:
        """Return the exact child identities authorized by completed operations."""

        self._validate_directory()
        return dict(self._authorized_cleanup_entries)

    def entry_metadata(self, name: str) -> os.stat_result:
        """Return no-follow metadata for one child of this pinned directory."""

        details, _mount_identity = self.entry_metadata_with_mount_identity(name)
        return details

    def entry_metadata_with_mount_identity(
        self,
        name: str,
    ) -> tuple[os.stat_result, int | None]:
        """Bind child metadata to its Linux mount identity when available."""

        name = self._name(name)
        self._validate_directory()
        if os.name == "nt":
            details = _windows_extended_path(self.path / name).stat(follow_symlinks=False)
            mount_identity = None
        elif sys.platform.startswith("linux"):
            descriptor = os.open(
                name,
                getattr(os, "O_PATH", os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._require_descriptor(),
            )
            try:
                details = os.fstat(descriptor)
                mount_identity = _descriptor_mount_identity(descriptor)
            finally:
                os.close(descriptor)
        else:
            details = os.stat(
                name,
                dir_fd=self._require_descriptor(),
                follow_symlinks=False,
            )
            mount_identity = None
        self._validate_directory()
        return details, mount_identity

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
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
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
        expected_mount_identity: int | None = None,
    ) -> os.stat_result:
        name = self._name(name)
        details = os.fstat(descriptor)
        descriptor_mount_identity = _descriptor_mount_identity(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size < 0
            or details.st_size > maximum
            or (
                expected_identity is not None
                and (details.st_dev, details.st_ino) != expected_identity
            )
            or (
                expected_mount_identity is not None
                and descriptor_mount_identity != expected_mount_identity
            )
        ):
            raise OSError("unsafe private file")
        if apply_permissions:
            if os.name == "nt":
                _owner_private_handle(descriptor, directory=False)
            else:
                getattr(os, "fchmod")(descriptor, 0o600)  # noqa: B009 - absent on Windows
        validation_path = _windows_extended_path(self.path / name) if os.name == "nt" else None
        if os.name == "nt":
            if validation_path is None:  # pragma: no cover - narrowed by os.name
                raise OSError("private file path is unavailable")
            current = validation_path.stat(follow_symlinks=False)
            linked = _is_link_or_reparse(validation_path)
            current_mount_identity = None
        else:
            if sys.platform.startswith("linux"):
                current_descriptor = os.open(
                    name,
                    getattr(os, "O_PATH", os.O_RDONLY)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self._require_descriptor(),
                )
                try:
                    current = os.fstat(current_descriptor)
                    current_mount_identity = _descriptor_mount_identity(current_descriptor)
                finally:
                    os.close(current_descriptor)
            else:
                current = os.stat(name, dir_fd=self._require_descriptor(), follow_symlinks=False)
                current_mount_identity = None
            linked = stat.S_ISLNK(current.st_mode)
        final = os.fstat(descriptor)
        if (
            linked
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or final.st_nlink != 1
            or (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino)
            or (final.st_dev, final.st_ino) != (details.st_dev, details.st_ino)
            or final.st_size > maximum
            or current_mount_identity != descriptor_mount_identity
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
        payload, identity, _snapshot = self.read_with_snapshot_identity(
            name,
            maximum=maximum,
            expected_identity=expected_identity,
            apply_permissions=apply_permissions,
        )
        return payload, identity

    def read_with_snapshot_identity(
        self,
        name: str,
        *,
        maximum: int,
        expected_identity: tuple[int, int] | None = None,
        apply_permissions: bool = True,
    ) -> tuple[bytes, tuple[int, int], tuple[int, int, int]]:
        """Read one file with an ABA-resistant metadata snapshot."""

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
            return (
                payload,
                (after.st_dev, after.st_ino),
                (after.st_ctime_ns, after.st_mtime_ns, after.st_size),
            )
        finally:
            os.close(descriptor)

    def file_identity(
        self,
        name: str,
        *,
        maximum: int,
        apply_permissions: bool = True,
    ) -> tuple[int, int]:
        descriptor = self._open_existing(name, write_dac=apply_permissions)
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

    def create(
        self,
        name: str,
        payload: bytes,
        *,
        maximum: int,
        executable: bool = False,
        consumable: bool = False,
    ) -> None:
        if not 0 <= len(payload) <= maximum:
            raise OSError("private payload exceeds its size limit")
        name = self._name(name)
        # Keep the Win32-facing ACL path short even when the pinned directory
        # itself is near the legacy path limit. CREATE_NEW still makes the
        # random 48-bit temporary name collision-safe. Exhaustion is reported
        # distinctly from a destination collision so callers cannot mistake a
        # staging failure for a published consumable marker.
        descriptor: int | None = None
        temporary = ""
        for _attempt in range(_TEMPORARY_NAME_ATTEMPTS):
            temporary = f".t-{secrets.token_hex(6)}"
            try:
                descriptor = self._open_new(temporary)
                break
            except FileExistsError:
                continue
        if descriptor is None:
            raise OSError("private temporary name collisions exhausted")
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
            if executable and os.name != "nt":
                getattr(os, "fchmod")(descriptor, 0o700)  # noqa: B009 - absent on Windows
            os.fsync(descriptor)
            details = self._validate_file(
                temporary,
                descriptor,
                maximum=maximum,
                apply_permissions=False,
            )
            if executable and os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o700:
                raise OSError("private executable mode is invalid")
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
            if consumable:
                self.promote(
                    temporary,
                    name,
                    maximum=maximum,
                    expected=payload,
                    permissions_already_private=True,
                    expected_identity=temporary_identity,
                    consumable=True,
                )
            else:
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
        expected_mount_identity: int | None = None,
        expected_snapshot: tuple[int, int, int] | None = None,
        apply_permissions: bool = True,
    ) -> None:
        descriptor = self._open_existing(name, delete=True, write_dac=apply_permissions)
        try:
            opened = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=apply_permissions,
                expected_identity=expected_identity,
                expected_mount_identity=expected_mount_identity,
            )
            if expected is not None and _read_descriptor_bounded(descriptor, maximum) != expected:
                raise OSError("private file content changed")
            final = self._validate_file(
                name,
                descriptor,
                maximum=maximum,
                apply_permissions=False,
                expected_identity=(opened.st_dev, opened.st_ino),
            )
            if (
                expected_snapshot is not None
                and (final.st_ctime_ns, final.st_mtime_ns, final.st_size) != expected_snapshot
            ):
                raise OSError("private file metadata changed")
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
        consumable: bool = False,
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
                # handle-relative publication. Consumable markers may be
                # removed by their trusted reader at that point, so the
                # validated non-replacing rename is their publication commit.
                os.close(descriptor)
                descriptor = -1
                if consumable:
                    self._validate_directory()
                else:
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
                if not consumable:
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
        if self.names(maximum=1):
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
        failures: list[BaseException] = []
        try:
            self._handle.close()
        except BaseException as exc:
            _extend_private_file_failures(failures, exc)
        try:
            self._directory.close()
        except BaseException as exc:
            _extend_private_file_failures(failures, exc)
        _raise_private_file_failures(failures)


__all__ = [
    "_GuardedBinaryFile",
    "_PinnedPrivateDirectory",
    "_PrivateFileCleanupError",
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
