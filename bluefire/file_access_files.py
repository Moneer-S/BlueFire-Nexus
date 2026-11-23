"""Descriptor-pinned file inspection shared by the reader and enrollment verifier."""

from __future__ import annotations

import os

from .file_access_contract import FileAccessContractError, linux_attr


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _directory(path: str) -> int:
    # Every component is freshly resolved by the probe, never through an owner FD.
    flags = (
        linux_attr(os, "O_PATH")
        | linux_attr(os, "O_DIRECTORY")
        | linux_attr(os, "O_NOFOLLOW")
        | linux_attr(os, "O_CLOEXEC")
    )
    descriptor = os.open("/", flags)
    try:
        for name in path.split("/")[1:]:
            if not name or name in (".", ".."):
                raise FileAccessContractError("probe root is not canonical")
            child = os.open(name, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result, descriptor = descriptor, -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
