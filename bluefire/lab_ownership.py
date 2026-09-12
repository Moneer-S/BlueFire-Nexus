"""Stable host identities and exact registration ownership for disposable labs."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .runner_descriptor_io import _ordinary
from .runner_descriptor_io import _windows_file_identity as _windows_file_identity
from .runner_descriptor_io import descriptor_identity as descriptor_identity
from .runner_descriptor_io import identity_format as identity_format
from .windows_owner_acl import _windows_mark_delete_descriptor, _windows_open_descriptor

REGISTRY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"


def identity(path: Path, *, directory: bool) -> tuple[int, int]:
    _ordinary(path.lstat(), directory=directory)
    if sys.platform == "win32":
        descriptor = _windows_open_descriptor(path, directory=directory, share_write=True)
    else:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | (getattr(os, "O_DIRECTORY", 0) if directory else 0),
        )
    try:
        return descriptor_identity(descriptor, directory=directory)
    finally:
        os.close(descriptor)


def registration(name: str) -> tuple[str, Path] | None:
    if sys.platform != "win32":
        raise ValueError("WSL registration requires Windows")
    import winreg

    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    matches = []
    with root:
        count = winreg.QueryInfoKey(root)[0]
        if not 0 <= count <= 256:
            raise ValueError("WSL registration inventory exceeds its bound")
        for index in range(count):
            key = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, key, 0, winreg.KEY_READ) as entry:
                if winreg.QueryValueEx(entry, "DistributionName")[0] != name:
                    continue
                version = winreg.QueryValueEx(entry, "Version")[0]
                base = winreg.QueryValueEx(entry, "BasePath")[0]
                if version != 2 or not isinstance(base, str):
                    raise ValueError("owned distribution registration is not WSL2")
                # Keep the literal absolute path: resolving a reparse point here
                # would conceal the unsafe object from the storage identity check.
                path = Path(base)
                if not path.is_absolute() or path != path.resolve(strict=True):
                    raise ValueError("owned distribution storage path is not canonical")
                matches.append((key, path))
    if len(matches) > 1:
        raise ValueError("owned distribution name is ambiguous")
    return matches[0] if matches else None


def path_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def remove_empty_storage(path: Path, expected: tuple[int, int]) -> bool:
    """Remove only the identified empty directory; retained files fail closed."""

    try:
        if path_absent(path):
            return True
        if sys.platform == "win32":
            descriptor = _windows_open_descriptor(
                path, directory=True, delete=True, share_write=True
            )
            try:
                if descriptor_identity(descriptor, directory=True) != expected:
                    return False
                # This operation targets the pinned directory, never a replacement
                # at its pathname. Windows refuses deletion while children remain.
                _windows_mark_delete_descriptor(descriptor)
            finally:
                os.close(descriptor)
        else:
            if identity(path, directory=True) != expected or any(path.iterdir()):
                return False
            path.rmdir()
        return path_absent(path)
    except (OSError, ValueError):
        return False
