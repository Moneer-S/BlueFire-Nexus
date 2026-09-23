"""Read-only Linux setup inspection; never dispatch or execution authorization.

This filesystem primitive compares asserted metadata to exact executable bytes;
it does not identify GNU software or establish tool readiness. Product setup and
execution use the Rust adapter's independently reviewed build allowlist. This
does not run ``--version``, discover tools on PATH, install anything, or make an
untrusted installation record trusted. The runner must repeat its own checks on
the held executable immediately before any approved operation.
"""

from __future__ import annotations

import errno
import hashlib
import os
import platform
import stat
import sys
import time
from dataclasses import dataclass
from typing import Callable, NoReturn

from .native_tool_installations import NativeToolInstallation


class NativeToolInspectionError(ValueError):
    """Path-free setup refusal suitable for an operator readiness result."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class NativeToolInspection:
    installation_digest: str
    content_sha256: str
    size_bytes: int


def _refuse(code: str, message: str) -> NoReturn:
    raise NativeToolInspectionError(code, message)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def _protected(value: os.stat_result, *, directory: bool) -> None:
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(value.st_mode)
        or value.st_uid != 0
        or value.st_mode & (0o022 if directory else 0o7022)
        or (not directory and not value.st_mode & 0o111)
        or value.st_nlink < 1
    ):
        _refuse("unsafe_installation", "The tool installation is not protected.")


def _without_capabilities(descriptor: int) -> None:
    getxattr = getattr(os, "getxattr", None)
    if not callable(getxattr):
        _refuse("capabilities_unknown", "File capability inspection is unavailable.")
    try:
        capabilities = getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return
        _refuse("capabilities_unknown", "File capability inspection is unavailable.")
    else:
        if capabilities:
            _refuse("unexpected_privilege", "The tool has unreviewed file capabilities.")


def _flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        _refuse("unsupported_runtime", "Protected descriptor inspection is unavailable.")
    return value


def inspect_native_tool(
    installation: NativeToolInstallation,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> NativeToolInspection:
    """Compare one trusted setup record to protected, descriptor-held bytes.

    The five-second budget and cancellation check are cooperative between local
    filesystem calls. A successful inspection is a snapshot, not runtime trust.
    """
    # Revalidate even manually constructed instances before touching a path.
    record = NativeToolInstallation.from_mapping(installation.to_dict())
    data = record.to_dict()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if sys.platform != "linux" or data["platform"] != "linux":
        _refuse("unsupported_platform", "Tool inspection requires its supported Linux host.")
    if data["architecture"] != machine:
        _refuse("architecture_mismatch", "The tool installation targets another architecture.")
    started = time.monotonic()

    def check_interruption() -> None:
        if cancelled is not None and cancelled():
            _refuse("cancelled", "Tool inspection was cancelled.")
        if time.monotonic() - started >= 5:
            _refuse("inspection_timeout", "Tool inspection exceeded its setup budget.")

    descriptors: list[int] = []
    edges: list[tuple[int, str, int]] = []
    try:
        check_interruption()
        directory_flags = (
            os.O_RDONLY | _flag("O_DIRECTORY") | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC")
        )
        parent = os.open("/", directory_flags)
        descriptors.append(parent)
        _protected(os.fstat(parent), directory=True)
        components = data["installation_location"].split("/")[1:]
        for component in components[:-1]:
            check_interruption()
            child = os.open(component, directory_flags, dir_fd=parent)
            descriptors.append(child)
            _protected(os.fstat(child), directory=True)
            edges.append((parent, component, child))
            parent = child
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC") | _flag("O_NONBLOCK"),
            dir_fd=parent,
        )
        descriptors.append(descriptor)
        edges.append((parent, components[-1], descriptor))
        before = os.fstat(descriptor)
        _protected(before, directory=False)
        if before.st_size != data["size_bytes"]:
            _refuse("size_mismatch", "The installed tool differs from its reviewed size.")
        _without_capabilities(descriptor)
        digest = hashlib.sha256()
        count = 0
        header = bytearray()
        while count <= data["size_bytes"]:
            check_interruption()
            chunk = os.read(descriptor, min(65536, data["size_bytes"] + 1 - count))
            if not chunk:
                break
            header.extend(chunk[: max(0, 64 - len(header))])
            count += len(chunk)
            digest.update(chunk)
        if count != data["size_bytes"] or _identity(before) != _identity(os.fstat(descriptor)):
            _refuse("installation_changed", "The tool changed during inspection.")
        expected_machine = {"x86_64": 62, "aarch64": 183}[data["architecture"]]
        if (
            len(header) < 64
            or header[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(header[16:18], "little") not in (2, 3)
            or int.from_bytes(header[18:20], "little") != expected_machine
        ):
            _refuse("unsupported_binary", "The tool is not a supported native executable.")
        actual = "sha256:" + digest.hexdigest()
        if actual != data["content_sha256"]:
            _refuse("digest_mismatch", "The installed tool differs from its reviewed digest.")
        _without_capabilities(descriptor)
        for owner, component, child in edges:
            current = os.stat(component, dir_fd=owner, follow_symlinks=False)
            held = os.fstat(child)
            _protected(held, directory=child != descriptor)
            if _identity(current) != _identity(held):
                _refuse("installation_changed", "The tool installation changed during inspection.")
        _protected(os.fstat(descriptors[0]), directory=True)
        if _identity(before) != _identity(os.fstat(descriptor)):
            _refuse("installation_changed", "The tool changed after its bytes were inspected.")
        check_interruption()
        return NativeToolInspection(record.digest, actual, count)
    except OSError as exc:
        raise NativeToolInspectionError(
            "inspection_unavailable", "The protected tool installation could not be inspected."
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
