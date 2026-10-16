"""Original root creator's fixed generated namespace, never reloadable custody.

Nothing in this module runs on import. Creation belongs to explicit privileged
setup, not a model capability, workspace request, or historical receipt import.
"""

from __future__ import annotations

import _thread
import ctypes
import hashlib
import os
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, cast

from .macos_file_access_contract import (
    BINDING_SCHEMA,
    LEAF,
    MAX_BYTES,
    MAX_ENROLLMENT_MS,
    MacOSFileAccessContractError,
    validate_binding,
    validate_credentials,
)
from .macos_file_access_peer import _supported_runtime, darwin_clock_ns
from .secret_store import (
    _darwin_security_api,
    _DarwinStatFs,
    _validate_darwin_descriptor_security,
)
from .util import canonical_json_bytes

_ANCESTORS = ("private", "var", "db")
_ANCHOR = "bluefire-file-access"


def _refuse() -> MacOSFileAccessContractError:
    return MacOSFileAccessContractError("The original sealed Darwin namespace is unavailable.")


def _root() -> None:
    getuid = getattr(os, "getuid", None)
    geteuid = getattr(os, "geteuid", None)
    getgid = getattr(os, "getgid", None)
    getegid = getattr(os, "getegid", None)
    if (
        not _supported_runtime()
        or not callable(getuid)
        or not callable(geteuid)
        or not callable(getgid)
        or not callable(getegid)
        or getuid() != 0
        or geteuid() != 0
        or getgid() != 0
        or getegid() != 0
    ):
        raise _refuse()


def _os_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        raise _refuse()
    return cast(int, value)


def _fchmod(descriptor: int, mode: int) -> None:
    operation = getattr(os, "fchmod", None)
    if not callable(operation):
        raise _refuse()
    operation(descriptor, mode)


def _fchown(descriptor: int, owner: int, group: int) -> None:
    operation = getattr(os, "fchown", None)
    if not callable(operation):
        raise _refuse()
    operation(descriptor, owner, group)


def _security(descriptor: int) -> None:
    _validate_darwin_descriptor_security(descriptor)
    filesystem = _DarwinStatFs()
    if (
        _darwin_security_api().fstatfs(descriptor, ctypes.byref(filesystem)) != 0
        or bytes(filesystem.f_fstypename) != b"apfs"
        or not filesystem.f_flags & 0x1000
        or filesystem.f_flags & 0x00200000
    ):
        raise _refuse()


def _directory(descriptor: int, *, mode: int | None = None, group: int | None = None):
    facts = os.fstat(descriptor)
    if (
        descriptor < 3
        or not stat.S_ISDIR(facts.st_mode)
        or facts.st_uid != 0
        or stat.S_IMODE(facts.st_mode) & 0o022
        or (mode is not None and stat.S_IMODE(facts.st_mode) != mode)
        or (group is not None and facts.st_gid != group)
    ):
        raise _refuse()
    _security(descriptor)
    return facts


def _identity(facts) -> tuple[int, int]:
    return facts.st_dev, facts.st_ino


def _records() -> bytes:
    return b"".join(
        canonical_json_bytes(
            {"category": "generated-validation", "record_id": number, "value": f"sample-{number}"}
        )
        + b"\n"
        for number in range(1, 9)
    )


class SealedMacOSNamespace:
    """Keep original descriptors and creation state; no receipt can construct it."""

    _creator: int
    _owner: dict[str, Any]
    _reader: dict[str, Any]
    _group: int
    _generation: str
    _enrollment: str
    _issued_ms: int
    _deadline_ns: int
    _expires_ms: int
    _lock: _thread.RLock
    _active: bool
    _state: str
    _handle_cleanup_unknown: bool
    _descriptors: list[int]
    _chain: list[tuple[int, str, int, tuple[int, int]]]
    _anchor_fd: int
    _directory_fd: int
    _leaf_fd: int
    _created_directory: bool
    _created_leaf: bool
    _payload: bytes
    _directory_identity: tuple[int, int]
    _leaf_identity: tuple[int, int]
    _resource: dict[str, Any]

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("Explicit original Darwin setup is required.")

    @classmethod
    def create(
        cls,
        *,
        owner: dict[str, Any],
        reader: dict[str, Any],
        retained: list[SealedMacOSNamespace],
    ) -> SealedMacOSNamespace:
        _root()
        owner, reader = validate_credentials(owner), validate_credentials(reader)
        group = reader["effective_gid"]
        if owner["effective_uid"] == reader["effective_uid"] or group not in owner["groups"]:
            raise _refuse()
        value = cast(SealedMacOSNamespace, object.__new__(cls))
        value._creator = os.getpid()
        value._owner, value._reader, value._group = owner, reader, group
        value._generation = "file-generation-" + secrets.token_hex(16)
        value._enrollment = "file-enrollment-" + secrets.token_hex(16)
        value._issued_ms = time.time_ns() // 1_000_000
        value._deadline_ns = darwin_clock_ns() + MAX_ENROLLMENT_MS * 1_000_000
        value._expires_ms = value._issued_ms + MAX_ENROLLMENT_MS
        value._lock = threading.RLock()
        value._active = False
        value._state = "creating"
        value._handle_cleanup_unknown = False
        value._descriptors = []
        value._chain = []
        value._anchor_fd = value._directory_fd = value._leaf_fd = -1
        value._created_directory = value._created_leaf = False
        value._payload = _records()
        if not 0 < len(value._payload) <= MAX_BYTES:
            raise _refuse()
        # Retain partial creation before the first filesystem effect. A failed
        # setup is not automatically deleted or adopted by a later process.
        with value._lock:
            retained.append(value)
            try:
                value._create()
                value._state = "sealed"
                value.assert_current()
                return value
            except BaseException:
                value._state = "unknown"
                raise

    def _open_directory(self, name: str, parent: int | None = None) -> int:
        descriptor = os.open(
            name,
            os.O_RDONLY | _os_flag("O_DIRECTORY") | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"),
            dir_fd=parent,
        )
        self._descriptors.append(descriptor)
        facts = _directory(descriptor)
        if parent is not None:
            visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not os.path.samestat(facts, visible):
                raise _refuse()
            self._chain.append((parent, name, descriptor, _identity(facts)))
        return descriptor

    def _create(self) -> None:
        parent = self._open_directory("/")
        for name in _ANCESTORS:
            parent = self._open_directory(name, parent)
        created_anchor = False
        try:
            os.mkdir(_ANCHOR, mode=0o700, dir_fd=parent)
            created_anchor = True
        except FileExistsError:
            pass
        self._anchor_fd = self._open_directory(_ANCHOR, parent)
        if created_anchor:
            _fchmod(self._anchor_fd, 0o700)
        _directory(self._anchor_fd, mode=0o700, group=0)
        os.mkdir(self._generation, mode=0o700, dir_fd=self._anchor_fd)
        self._created_directory = True
        self._directory_fd = self._open_directory(self._generation, self._anchor_fd)
        write_fd = os.open(
            LEAF,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"),
            0o600,
            dir_fd=self._directory_fd,
        )
        self._descriptors.append(write_fd)
        self._created_leaf = True
        remaining = memoryview(self._payload)
        while remaining:
            if darwin_clock_ns() >= self._deadline_ns:
                raise _refuse()
            count = os.write(write_fd, remaining)
            if not 0 < count <= len(remaining):
                raise _refuse()
            remaining = remaining[count:]
        os.fsync(write_fd)
        _fchown(write_fd, self._owner["effective_uid"], self._group)
        _fchmod(write_fd, 0o640)
        self._leaf_fd = os.open(
            LEAF,
            os.O_RDONLY | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"),
            dir_fd=self._directory_fd,
        )
        self._descriptors.append(self._leaf_fd)
        if not os.path.samestat(os.fstat(write_fd), os.fstat(self._leaf_fd)):
            raise _refuse()
        os.close(write_fd)
        self._descriptors.remove(write_fd)
        _fchown(self._directory_fd, 0, self._group)
        # Bound-group traversal of this root-owned directory; no write or world access.
        _fchmod(self._directory_fd, 0o550)  # nosec B103
        self._directory_identity = _identity(os.fstat(self._directory_fd))
        self._leaf_identity = _identity(os.fstat(self._leaf_fd))
        self._resource = {
            "device": self._leaf_identity[0],
            "inode": self._leaf_identity[1],
            "owner_uid": self._owner["effective_uid"],
            "group_gid": self._group,
            "size_bytes": len(self._payload),
            "record_count": 8,
            "sha256": "sha256:" + hashlib.sha256(self._payload).hexdigest(),
        }

    def assert_current(self) -> None:
        _root()
        if (
            self._creator != os.getpid()
            or self._state != "sealed"
            or not self._issued_ms <= time.time_ns() // 1_000_000 < self._expires_ms
            or darwin_clock_ns() >= self._deadline_ns
        ):
            raise _refuse()
        for parent, name, descriptor, identity in self._chain:
            _directory(parent)
            actual = _directory(descriptor)
            if _identity(actual) != identity or not os.path.samestat(
                actual, os.stat(name, dir_fd=parent, follow_symlinks=False)
            ):
                raise _refuse()
        _directory(self._anchor_fd, mode=0o700, group=0)
        parent = _directory(self._directory_fd, mode=0o550, group=self._group)
        leaf = os.fstat(self._leaf_fd)
        if (
            _identity(parent) != self._directory_identity
            or _identity(leaf) != self._leaf_identity
            or not stat.S_ISREG(leaf.st_mode)
            or leaf.st_nlink != 1
            or leaf.st_uid != self._owner["effective_uid"]
            or leaf.st_gid != self._group
            or leaf.st_size != len(self._payload)
            or stat.S_IMODE(leaf.st_mode) not in (0o640, 0o600)
            or not os.path.samestat(
                leaf, os.stat(LEAF, dir_fd=self._directory_fd, follow_symlinks=False)
            )
        ):
            raise _refuse()
        _security(self._leaf_fd)

    @contextmanager
    def operation(self) -> Iterator[None]:
        """Prevent creator namespace mutation for the entire admitted exchange."""
        with self._lock:
            if self._active:
                raise _refuse()
            self.assert_current()
            self._active = True
            try:
                yield
                self.assert_current()
            except BaseException:
                self._state = "unknown"
                raise
            finally:
                self._active = False

    def binding(self, *, custody_digest: str, revision: int) -> dict[str, Any]:
        self.assert_current()
        mode = format(stat.S_IMODE(os.fstat(self._leaf_fd).st_mode), "04o")
        return validate_binding(
            {
                "schema_version": BINDING_SCHEMA,
                "enrollment_id": self._enrollment,
                "generation": self._generation,
                "custody_digest": custody_digest,
                "issued_at_ms": self._issued_ms,
                "expires_at_ms": self._expires_ms,
                "original_deadline_ns": self._deadline_ns,
                "owner": self._owner,
                "reader": self._reader,
                "directory": {
                    "device": self._directory_identity[0],
                    "inode": self._directory_identity[1],
                    "owner_uid": 0,
                    "group_gid": self._group,
                    "mode": "0550",
                },
                "resource": self._resource,
                "control_revision": revision,
                "mode": mode,
            }
        )

    def descriptor(self, role: str) -> int:
        self.assert_current()
        if role not in {"reader", "owner", "control"}:
            raise _refuse()
        return self._leaf_fd if role == "control" else self._directory_fd

    def close_handles(self) -> bool:
        """Retire local handles only; this never asserts child or fixture cleanup."""
        _root()
        with self._lock:
            if self._creator != os.getpid() or self._active or self._state == "creating":
                raise _refuse()
            if self._state != "unknown":
                self._state = "closed"
            complete = not self._handle_cleanup_unknown
            while self._descriptors:
                descriptor = self._descriptors.pop()
                try:
                    os.close(descriptor)
                except BaseException as error:
                    complete = False
                    self._handle_cleanup_unknown = True
                    self._state = "unknown"
                    if not isinstance(error, OSError):
                        raise
            if not complete:
                self._state = "unknown"
            return complete
