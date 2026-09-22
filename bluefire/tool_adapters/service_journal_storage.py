"""Owner-private storage admission for service intent metadata, never effects."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .. import windows_owner_acl as acl
from ..local_lock import owner_private_database_lock, prepare_owner_private_database_file
from ..runner_trust import (
    _PinnedDirectory,
    _windows_file_information,
    _windows_information_identity,
)
from ..secret_store import _validate_darwin_descriptor_security


def _verify_windows_private(descriptor: int, *, directory: bool) -> None:
    """Reuse native DACL validation without its permission-repair operation."""
    access, owner = acl._current_token_sids()
    advapi32, kernel32 = acl._configure_apis()
    pointers: list[ctypes.c_void_p] = []
    try:
        access_sid = acl._converted_sid(advapi32, access)
        pointers.append(access_sid)
        owner_sid = acl._converted_sid(advapi32, owner)
        pointers.append(owner_sid)
        handle = acl._handle_from_descriptor(descriptor)
        observed_owner = acl._select_current_owner(
            advapi32,
            kernel32,
            handle=handle,
            access_sid=access_sid,
            default_owner_sid=owner_sid,
        )
        pointers.append(
            acl._verify_owner_private_acl(
                advapi32,
                kernel32,
                handle=handle,
                observed_owner_sid=observed_owner,
                access_sid=access_sid,
                directory=directory,
            )
        )
    finally:
        for pointer in reversed(pointers):
            if pointer.value:
                kernel32.LocalFree(pointer)


def _check_private(path: Path, *, directory: bool) -> tuple[int, int]:
    descriptor: int | None = None
    try:
        if sys.platform == "win32":
            descriptor = acl._windows_open_descriptor(path, directory=directory, share_write=True)
        else:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC
                | (os.O_DIRECTORY if directory else 0),
            )
        details = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
        if (
            (stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode)) is False
            or not os.path.samestat(details, named)
            or (not directory and details.st_nlink != 1)
            or bool(getattr(named, "st_file_attributes", 0) & 0x400)
        ):
            raise OSError("journal storage must use stable regular private objects")
        if sys.platform == "win32":
            _verify_windows_private(descriptor, directory=directory)
            return _windows_information_identity(
                _windows_file_information(acl._handle_from_descriptor(descriptor))
            )
        else:
            if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != (
                0o700 if directory else 0o600
            ):
                raise OSError("journal storage must be owner-private")
            _validate_darwin_descriptor_security(descriptor)
        return details.st_dev, details.st_ino
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _check_posix_ancestors(path: Path) -> None:
    """Refuse directory entries another unprivileged owner could replace.

    SQLite opens a pathname rather than our pinned directory descriptor. Every
    ancestor must therefore be owned by this user or root and protect its child
    entry. A sticky shared directory is safe only because the child owners are
    checked by this same walk. Same-owner and privileged changes remain outside
    this boundary; no permissions are repaired here.
    """
    if sys.platform == "win32":
        return
    for ancestor in reversed(path.parents):
        descriptor = os.open(ancestor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(details.st_mode)
                or not os.path.samestat(details, ancestor.stat(follow_symlinks=False))
                or details.st_uid not in {0, os.getuid()}
                or (details.st_mode & 0o022 and not details.st_mode & stat.S_ISVTX)
            ):
                raise OSError("journal ancestor permits untrusted entry replacement")
            _validate_darwin_descriptor_security(descriptor)
        finally:
            os.close(descriptor)


class PrivateJournalStorage:
    """Check existing permissions; exclusively create only inside a private parent.

    Parent/file identities and permissions are rechecked for every transaction.
    These checks do not defend against a malicious process with the same owner
    credentials, privileged path swaps, or restoring an older private database.
    """

    def __init__(self, path: Path):
        self.path = path
        self._check_links()
        self.parent_identity = _check_private(path.parent, directory=True)
        with _PinnedDirectory(path.parent, private=False) as parent:
            if parent.identity != self.parent_identity:
                raise OSError("journal parent changed")
            # Exclusive creation supplies 0600 or a real private Windows DACL.
            # A Windows child inherits only owner access from the checked parent
            # even before the existing creation helper protects its own DACL.
            self.path, self.identity = prepare_owner_private_database_file(path)
            self.check()

    def _check_links(self) -> None:
        _check_posix_ancestors(self.path)
        for item in (self.path, *self.path.parents):
            if item.is_symlink() or (
                item.exists() and bool(getattr(item.lstat(), "st_file_attributes", 0) & 0x400)
            ):
                raise OSError("journal storage cannot use links or reparse points")

    def check(self) -> None:
        self._check_links()
        if _check_private(self.path.parent, directory=True) != self.parent_identity:
            raise OSError("journal parent changed")
        if _check_private(self.path, directory=False) != self.identity:
            raise OSError("journal database changed")

    @contextmanager
    def lease(self) -> Iterator[None]:
        with _PinnedDirectory(self.path.parent, private=False) as parent:
            if parent.identity != self.parent_identity:
                raise OSError("journal parent changed")
            self.check()
            with owner_private_database_lock(
                self.path,
                expected=self.identity,
                deadline=time.monotonic() + 5,
            ):
                self.check()
                yield
                self.check()
