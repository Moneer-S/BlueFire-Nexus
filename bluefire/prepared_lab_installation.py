"""Verify the fixed installed code and interpreter before any broker handoff."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from .prepared_lab_runtime import PYTHON, ROOT


def _root_owned(path: Path) -> None:
    for entry in (path, *path.parents):
        details = entry.lstat()
        if details.st_uid != 0 or (not stat.S_ISLNK(details.st_mode) and details.st_mode & 0o022):
            raise ValueError("the installed inference path is not exclusively root-owned")
        if not any(
            (
                stat.S_ISDIR(details.st_mode),
                stat.S_ISREG(details.st_mode),
                stat.S_ISLNK(details.st_mode),
            )
        ):
            raise ValueError("the installed inference path has an unsupported file type")


def verify_installation() -> None:
    venv = ROOT / "venv"
    interpreter = PYTHON.resolve(strict=True)
    if sys.platform != "linux" or Path(sys.executable).resolve(strict=True) != interpreter:
        raise ValueError("the fixed installed Linux interpreter is required")
    for path in (ROOT, venv, PYTHON, interpreter, Path(__file__).resolve(strict=True)):
        _root_owned(path)
    if not Path(__file__).resolve(strict=True).is_relative_to(venv):
        raise ValueError("the inference module is outside the installed environment")
    count = 0
    for directory, directories, files in os.walk(venv, followlinks=False):
        for entry in (Path(directory), *(Path(directory) / name for name in directories + files)):
            count += 1
            if count > 50_000:
                raise ValueError("the installed environment exceeds its inventory bound")
            details = entry.lstat()
            if details.st_uid != 0 or (not entry.is_symlink() and details.st_mode & 0o022):
                raise ValueError("the installed environment contains writable code")
            if entry.is_symlink():
                resolved = entry.resolve(strict=True)
                # Standard venv Python symlinks and its internal lib64 alias
                # are permitted; no link may borrow a mutable external package.
                if not resolved.is_relative_to(venv) and resolved != interpreter:
                    raise ValueError("the installed environment links to unreviewed external code")
                _root_owned(resolved)
