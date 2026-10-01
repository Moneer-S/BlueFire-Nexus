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


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return tuple(int(getattr(details, field)) for field in _STAT_FIELDS)


def _snapshot(launcher: Path, prefix: Path, runtime: Path) -> tuple[object, ...]:
    getuid = getattr(os, "getuid", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not callable(getuid) or not isinstance(nofollow, int) or nofollow == 0:
        raise OSError("application environment identity is unavailable")
    owner_uid = int(getuid())
    if (
        not launcher.is_absolute()
        or launcher.parent.name != "bin"
        or launcher.parent.parent.resolve(strict=True) != prefix
        or launcher.resolve(strict=True) != runtime
    ):
        raise OSError("application interpreter context changed")
    directories = (prefix, launcher.parent.resolve(strict=True))
    directory_identities = []
    for directory in directories:
        details = directory.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid not in {0, owner_uid}
            or stat.S_IMODE(details.st_mode) & 0o022
        ):
            raise OSError("application environment is not protected")
        directory_identities.append(_identity(details))
    config = prefix / "pyvenv.cfg"
    descriptor = os.open(config, os.O_RDONLY | nofollow)
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
            or _identity(config.lstat()) != _identity(details)
        ):
            raise OSError("application environment configuration changed")
        return (
            tuple(directory_identities),
            _identity(launcher.lstat()),
            _identity(details),
            hashlib.sha256(payload).hexdigest(),
        )
    finally:
        os.close(descriptor)


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
