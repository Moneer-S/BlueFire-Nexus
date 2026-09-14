"""Create missing default POSIX state directories without adopting user directories."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from .runner_bootstrap import managed_product_root


def prepare_default_managed_root(root: Path) -> None:
    """Prepare a fresh default root through pinned, unlinked directory handles.

    Explicit custom roots keep their existing-parent requirement. Existing home
    and state directories are inspected, never chmodded or treated as product
    storage. Only the missing components receive private creation permissions.
    """

    if sys.platform == "win32" or os.name != "posix" or root != managed_product_root():
        return
    if not root.is_absolute() or ".." in root.parts:
        raise OSError("invalid default state path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors: list[int] = []
    links: list[tuple[int, str, int]] = []
    try:
        parent = os.open(root.anchor, flags)
        descriptors.append(parent)
        created_path = False
        for name in root.parts[1:]:
            _validate_links(links)
            try:
                child = os.open(name, flags, dir_fd=parent)
            except FileNotFoundError:
                _validate_creation_parent(parent)
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    # Another bootstrap may create the same directory. Open it
                    # without following links and validate its ownership below.
                    pass
                child = os.open(name, flags, dir_fd=parent)
                created_path = True
            descriptors.append(child)
            links.append((parent, name, child))
            if created_path:
                _validate_creation_parent(child)
            _validate_links(links)
            parent = child
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validate_creation_parent(descriptor: int) -> None:
    if sys.platform == "win32":
        raise OSError("POSIX state directory ownership is unavailable")
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise OSError("default state parent is not controlled by this user")


def _validate_links(links: list[tuple[int, str, int]]) -> None:
    for parent, name, child in links:
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        pinned = os.fstat(child)
        if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (
            pinned.st_dev,
            pinned.st_ino,
        ):
            raise OSError("default state directory changed during preparation")
