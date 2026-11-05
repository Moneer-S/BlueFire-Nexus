"""Pin the literal owned workspace chain for restart recovery."""

from __future__ import annotations

import os
import sys
from contextlib import ExitStack
from pathlib import Path

from .native_filesystem_identity import descriptor_identity, identity_format
from .windows_owner_acl import _windows_open_descriptor


def workspace_identity(path: str | Path) -> dict[str, int | str]:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise OSError("owned workspace path is not absolute")
    chain = (*reversed(candidate.parents), candidate)
    with ExitStack() as stack:
        parent = None
        pinned = []
        for item in chain:
            if sys.platform == "win32":
                descriptor = _windows_open_descriptor(item, directory=True)
            else:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                descriptor = os.open(item if parent is None else item.name, flags, dir_fd=parent)
            stack.callback(os.close, descriptor)
            identity = descriptor_identity(descriptor, directory=True)
            pinned.append((item, parent, identity))
            parent = descriptor
        for item, ancestor, identity in pinned:
            if sys.platform == "win32":
                reopened = _windows_open_descriptor(item, directory=True)
            else:
                reopened = os.open(
                    item if ancestor is None else item.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=ancestor,
                )
            try:
                if descriptor_identity(reopened, directory=True) != identity:
                    raise OSError("owned workspace path changed")
            finally:
                os.close(reopened)
        if candidate.resolve(strict=True) != candidate:
            raise OSError("owned workspace path is not literal")
        volume, file_id = pinned[-1][2]
        return {"format": identity_format(), "volume": volume, "file_id": file_id}
