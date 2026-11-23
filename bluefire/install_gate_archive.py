"""Portable committed-source archive validation and exclusive extraction."""

from __future__ import annotations

import os
import stat
import tarfile
import unicodedata
from pathlib import Path
from typing import Callable


def extract_validated_archive(
    archive: tarfile.TarFile, source: Path, *, is_link_or_reparse: Callable[[Path], bool]
) -> None:
    """Extract a Git archive without relying on the Python 3.12 tar filter API."""

    root = source.resolve()
    members: list[tuple[tarfile.TarInfo, Path, tuple[str, ...]]] = []
    targets: set[Path] = set()
    portable_spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for member in archive.getmembers():
        target = (source / member.name).resolve()
        if (
            target == root
            or not target.is_relative_to(root)
            or target in targets
            or member.size < 0
            or member.issym()
            or member.islnk()
            or not (member.isfile() or member.isdir())
        ):
            raise ValueError("committed source archive contains an unsafe member")
        relative_parts = target.relative_to(root).parts
        portable_key = tuple(
            unicodedata.normalize("NFC", part).casefold() for part in relative_parts
        )
        for length in range(1, len(portable_key) + 1):
            prefix = portable_key[:length]
            spelling = relative_parts[:length]
            previous = portable_spellings.setdefault(prefix, spelling)
            if previous != spelling:
                raise ValueError("committed source archive contains an unsafe member")
        targets.add(target)
        members.append((member, target, portable_key))

    member_keys = {key for _member, _target, key in members}
    for member, _target, key in members:
        if member.isfile() and any(
            len(other) > len(key) and other[: len(key)] == key for other in member_keys
        ):
            raise ValueError("committed source archive contains an unsafe member")

    for member, target, _key in members:
        if member.isdir():
            target.mkdir(parents=True, mode=0o700, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    for _member, target, _key in members:
        parent = target if target.is_dir() else target.parent
        while parent != root:
            try:
                details = parent.lstat()
            except OSError:
                raise ValueError("committed source archive contains an unsafe member") from None
            if not stat.S_ISDIR(details.st_mode) or is_link_or_reparse(parent):
                raise ValueError("committed source archive contains an unsafe member")
            parent = parent.parent

    for member, target, _key in members:
        if member.isdir():
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ValueError("committed source archive contains an unsafe member")
        descriptor: int | None = None
        try:
            mode = 0o700 if member.mode & 0o111 else 0o600
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with extracted, os.fdopen(descriptor, "wb") as output:
                descriptor = None
                remaining = member.size
                while remaining:
                    chunk = extracted.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("committed source archive contains an unsafe member")
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            details = target.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size != member.size
                or is_link_or_reparse(target)
            ):
                raise ValueError("committed source archive contains an unsafe member")
        except OSError:
            raise ValueError("committed source archive contains an unsafe member") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
