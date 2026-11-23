"""Host checks mirrored from the self-contained pretrust workspace bootstrap.

The bootstrap must verify the installation before importing product modules, so
it cannot import these predicates. AST regression tests bind this exact copy to
its standalone definitions without moving the launch target or endpoint class.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn, cast


def _refuse(value: bool) -> None:
    if not value:
        raise RuntimeError("The original Darwin workspace bootstrap is unavailable.")


def _os_flag(name: str) -> int:
    value = getattr(os, name, None)
    _refuse(type(value) is int)
    return cast(int, value)


class _FsId(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _StatFs(ctypes.Structure):
    # Same public 64-bit layout as secret_store._DarwinStatFs, before imports.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _FsId),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _descriptor_security(descriptor: int) -> None:
    """Bootstrap's standalone copy of the existing positive no-ACL policy."""
    _refuse(
        sys.platform == "darwin" and ctypes.sizeof(_StatFs) == 2168 and _StatFs.f_flags.offset == 64
    )
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    filesystem = library.fstatfs
    filesystem.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFs)]
    filesystem.restype = ctypes.c_int
    details = _StatFs()
    _refuse(filesystem(descriptor, ctypes.byref(details)) == 0 and not details.f_flags & 0x00200000)
    query = library.acl_get_fd_np
    query.argtypes = [ctypes.c_int, ctypes.c_int]
    query.restype = ctypes.c_void_p
    entry = library.acl_get_entry
    entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    entry.restype = ctypes.c_int
    release = library.acl_free
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = query(descriptor, 0x100)
    error = ctypes.get_errno()
    if not acl:
        _refuse(error == errno.ENOENT)
        return
    item = ctypes.c_void_p()
    try:
        ctypes.set_errno(0)
        result = entry(acl, 0, ctypes.byref(item))
        error = ctypes.get_errno()
    finally:
        _refuse(release(acl) == 0)
    _refuse(result == -1 and error == errno.EINVAL and item.value is None)


def _directory(path: Path, *, owner: int = 0) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | _os_flag("O_DIRECTORY") | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC")
    )
    try:
        details = os.fstat(descriptor)
        _refuse(
            stat.S_ISDIR(details.st_mode)
            and details.st_uid == owner
            and not details.st_mode & 0o022
            and os.path.samestat(details, path.lstat())
        )
        _descriptor_security(descriptor)
    finally:
        os.close(descriptor)


def _parents(path: Path) -> None:
    _refuse(path.is_absolute())
    for directory in (path, *path.parents):
        _directory(directory)


def _import_inventory(roots: list[str], expected: dict[str, str]) -> None:
    """No-site import roots contain only individually pinned importable files."""
    _refuse(
        type(roots) is list
        and 0 < len(roots) <= 8
        and len(set(roots)) == len(roots)
        and type(expected) is dict
        and 0 < len(expected) <= 4096
    )
    seen = set()
    directories = 0
    total = 0

    def walk_error(error: OSError) -> NoReturn:
        raise error

    for name in roots:
        root = Path(name)
        _refuse(root.is_absolute())
        _parents(root.parent)
        try:
            root.lstat()
        except FileNotFoundError:
            # CPython's fixed zip search path may be absent below protected parents.
            _refuse(root.suffix == ".zip" and str(root) not in expected)
            continue
        if root.is_file():
            _refuse(root.suffix == ".zip" and str(root) in expected)
            _protected_file(root, expected[str(root)])
            seen.add(str(root))
            total += root.lstat().st_size
            continue
        _directory(root)
        for directory, children, files in os.walk(root, followlinks=False, onerror=walk_error):
            directories += 1
            _refuse(directories <= 4096)
            _directory(Path(directory))
            for child in children:
                _directory(Path(directory) / child)
            for leaf in files:
                path = Path(directory) / leaf
                if path.suffix not in (".py", ".pyc", ".so", ".zip"):
                    continue
                _refuse(str(path) in expected)
                if str(path) in seen:
                    continue
                _protected_file(path, expected[str(path)])
                seen.add(str(path))
                total += path.lstat().st_size
                _refuse(total <= 256 * 1024 * 1024)
    _refuse(seen == set(expected) and total <= 256 * 1024 * 1024)


def _protected_file(path: Path, digest: str, *, links: int = 1) -> None:
    descriptor = os.open(path, os.O_RDONLY | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"))
    try:
        before = os.fstat(descriptor)
        _refuse(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and not before.st_mode & 0o6022
            and before.st_nlink == links
            and before.st_size <= 256 * 1024 * 1024
            and os.path.samestat(before, path.lstat())
        )
        _descriptor_security(descriptor)
        checksum = hashlib.sha256()
        size = 0
        while True:
            raw = os.read(descriptor, 64 * 1024)
            if not raw:
                break
            size += len(raw)
            _refuse(size <= before.st_size)
            checksum.update(raw)
        after = os.fstat(descriptor)
        _refuse(
            size == before.st_size
            and checksum.hexdigest() == digest
            and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
            )
        )
    finally:
        os.close(descriptor)
