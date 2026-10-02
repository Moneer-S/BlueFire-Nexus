"""Retain the configured application's Linux venv during a pinned Python exec.

The application environment and its installed import closure remain trusted.
This identity check does not authenticate arbitrary dependency package contents.
No request, environment variable, or supplied module path selects this context.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .runner_transport_errors import RunnerTransportError

_CONFIG_LIMIT = 32 * 1024
_STAT_FIELDS = (
    "st_dev st_ino st_mode st_nlink st_uid st_gid st_size st_mtime_ns st_ctime_ns".split()
)
_DIRECTORY_FIELDS = "st_dev st_ino st_mode st_uid st_gid".split()


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return tuple(int(getattr(details, field)) for field in _STAT_FIELDS)


def _directory_identity(details: os.stat_result) -> tuple[int, ...]:
    return tuple(int(getattr(details, field)) for field in _DIRECTORY_FIELDS)


def _protected_directory(
    details: os.stat_result, owner_uid: int, *, allow_sticky_root: bool
) -> bool:
    sticky_root = details.st_uid == 0 and bool(details.st_mode & stat.S_ISVTX)
    return (
        stat.S_ISDIR(details.st_mode)
        and details.st_uid in {0, owner_uid}
        and not (stat.S_IMODE(details.st_mode) & 0o022 and not (allow_sticky_root and sticky_root))
    )


def _open_directory_chain(directory: Path, owner_uid: int) -> tuple[tuple[object, ...], int]:
    """Open every directory component without following replaceable links."""
    if not directory.is_absolute() or ".." in directory.parts:
        raise OSError("application environment path is not canonical")
    flags = 0
    for name in ("O_PATH", "O_DIRECTORY", "O_NOFOLLOW"):
        flag = getattr(os, name, None)
        if not isinstance(flag, int) or flag == 0:
            raise OSError("application environment identity is unavailable")
        flags |= flag
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(directory.anchor, flags)
    identities: list[object] = []
    try:
        root = os.fstat(descriptor)
        if not _protected_directory(root, owner_uid, allow_sticky_root=len(directory.parts) > 1):
            raise OSError("application environment is not protected")
        identities.append((directory.anchor, _directory_identity(root)))
        components = directory.parts[1:]
        for index, component in enumerate(components):
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if not _protected_directory(
                details, owner_uid, allow_sticky_root=index < len(components) - 1
            ):
                raise OSError("application environment is not protected")
            identities.append((component, _directory_identity(details)))
        return tuple(identities), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _launcher_chain(launcher: Path, runtime: Path, owner_uid: int) -> tuple[object, ...]:
    """Pin safe launcher and interpreter symlinks, plus the final executable."""
    current = launcher
    links: list[object] = []
    for _ in range(40):
        parents, parent_fd = _open_directory_chain(current.parent, owner_uid)
        try:
            details = os.stat(current.name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(details.st_mode):
                if details.st_uid not in {0, owner_uid}:
                    raise OSError("application interpreter link is not protected")
                target = os.readlink(current.name, dir_fd=parent_fd)
                if _identity(
                    os.stat(current.name, dir_fd=parent_fd, follow_symlinks=False)
                ) != _identity(details):
                    raise OSError("application interpreter link changed")
                links.append((str(current), parents, _identity(details), target))
            else:
                mode = stat.S_IMODE(details.st_mode)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_uid not in {0, owner_uid}
                    or mode & 0o022
                    or current != runtime
                ):
                    raise OSError("application interpreter target is not protected")
                return (*links, (str(current), parents, _identity(details)))
        finally:
            os.close(parent_fd)
        target_path = Path(target)
        if ".." in target_path.parts:
            raise OSError("application interpreter link target is ambiguous")
        current = target_path if target_path.is_absolute() else current.parent / target_path
        if not current.is_absolute():
            raise OSError("application interpreter target is not absolute")
    raise OSError("application interpreter link chain is too long")


def _snapshot(launcher: Path, prefix: Path, runtime: Path) -> tuple[object, ...]:
    getuid = getattr(os, "getuid", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not callable(getuid) or not isinstance(nofollow, int) or nofollow == 0:
        raise OSError("application environment identity is unavailable")
    owner_uid = int(getuid())
    if (
        not launcher.is_absolute()
        or launcher.parent.name != "bin"
        or launcher.parent.parent != prefix
    ):
        raise OSError("application interpreter context changed")
    directory_identities, bin_fd = _open_directory_chain(launcher.parent, owner_uid)
    try:
        prefix_identities, prefix_fd = _open_directory_chain(prefix, owner_uid)
        try:
            descriptor = os.open(
                "pyvenv.cfg",
                os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=prefix_fd,
            )
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_uid not in {0, owner_uid}
                    or stat.S_IMODE(details.st_mode) & 0o022
                    or not 0 < details.st_size <= _CONFIG_LIMIT
                ):
                    raise OSError("application environment configuration is unsafe")
                with os.fdopen(os.dup(descriptor), "rb") as source:
                    payload = source.read(_CONFIG_LIMIT + 1)
                if (
                    len(payload) != details.st_size
                    or _identity(os.fstat(descriptor)) != _identity(details)
                    or _identity(os.stat("pyvenv.cfg", dir_fd=prefix_fd, follow_symlinks=False))
                    != _identity(details)
                ):
                    raise OSError("application environment configuration changed")
                return (
                    (prefix_identities, directory_identities),
                    _launcher_chain(launcher, runtime, owner_uid),
                    _identity(details),
                    hashlib.sha256(payload).hexdigest(),
                )
            finally:
                os.close(descriptor)
        finally:
            os.close(prefix_fd)
    finally:
        os.close(bin_fd)


@dataclass(frozen=True)
class ActivePythonEnvironment:
    launcher: Path
    prefix: Path
    snapshot: tuple[object, ...]

    @classmethod
    def capture(cls, runtime: Path) -> ActivePythonEnvironment | None:
        if (
            os.name != "posix"
            or not sys.platform.startswith("linux")
            or sys.prefix == sys.base_prefix
        ):
            return None
        try:
            launcher = Path(sys.executable).absolute()
            prefix = Path(sys.prefix).resolve(strict=True)
            return cls(launcher, prefix, _snapshot(launcher, prefix, runtime))
        except (OSError, ValueError):
            raise RunnerTransportError(
                "Runner watchdog application environment is unavailable."
            ) from None

    def recheck(self, runtime: Path) -> str:
        try:
            if _snapshot(self.launcher, self.prefix, runtime) != self.snapshot:
                raise OSError("application environment identity changed")
            return str(self.launcher)
        except (OSError, ValueError):
            raise RunnerTransportError("Runner watchdog application environment changed.") from None

    def validate_exec(
        self, argv: list[str], executable: str, descriptors: tuple[int, ...], runtime: Path
    ) -> None:
        """Allow the pinned executable override only for the fixed watchdog call."""
        try:
            prefix = "/proc/self/fd/"
            descriptor = executable.removeprefix(prefix)
            if (
                not executable.startswith(prefix)
                or not descriptor.isdecimal()
                or int(descriptor) not in descriptors
                or len(argv) != 7
                or argv[0] != self.recheck(runtime)
                or argv[1:5] != ["-I", "-B", "-X", "utf8"]
                or not argv[5].startswith(prefix)
                or not argv[5].removeprefix(prefix).isdecimal()
                or int(argv[5].removeprefix(prefix)) not in descriptors
                or Path(argv[6]).name != "config.json"
                or not Path(argv[6]).is_absolute()
                or not os.path.samefile(executable, runtime)
            ):
                raise OSError("invalid pinned watchdog executable")
        except (OSError, ValueError):
            raise RunnerTransportError(
                "Runner watchdog executable context is unavailable."
            ) from None
