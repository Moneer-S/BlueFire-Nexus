"""Explicit fixed-linker selection for the pinned Windows GNU release toolchain."""

from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Mapping

RUST_LINKER_ENV = "BLUEFIRE_ACCEPTANCE_RUST_LINKER"
WINDOWS_GNU_LINKER = "windows-gnu-self-contained"
_TARGET = "x86_64-pc-windows-gnu"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def rust_suite_environment(repository: Path, environment: Mapping[str, str]) -> dict[str, str]:
    """Consume the enclosing gate's selection without forwarding its authority."""
    result = dict(environment)
    result.update(
        fixed_rust_linker_environment(repository, os.environ.get(RUST_LINKER_ENV), environment)
    )
    return result


def _direct_path(path: Path, *, directory: bool = False) -> Path:
    """Refuse aliases anywhere in an explicitly selected toolchain path."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("the selected release toolchain path is not canonical")
    for entry in (path, *path.parents):
        metadata = entry.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT
        ):
            raise ValueError("the selected release toolchain contains an alias")
        is_directory = directory if entry == path else True
        if not (stat.S_ISDIR if is_directory else stat.S_ISREG)(metadata.st_mode):
            raise ValueError("the selected release toolchain has an invalid entry")
    return path


def _channel(repository: Path) -> str:
    path = _direct_path(repository / "rust-toolchain.toml")
    if path.stat().st_size > 4096:
        raise ValueError("the pinned release toolchain document is invalid")
    document = path.read_text(encoding="utf-8")
    sections = re.findall(r"(?m)^\s*\[([^\]\r\n]+)\]\s*$", document)
    channels: list[str] = re.findall(
        r'(?m)^\s*channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', document
    )
    if sections != ["toolchain"] or len(channels) != 1:
        raise ValueError("an exact repository-pinned Rust release is required")
    return channels[0]


def fixed_rust_linker_environment(
    repository: Path, mode: str | None, environment: Mapping[str, str]
) -> dict[str, str]:
    """Generate known flags only; this does not install or execute a toolchain."""
    if mode is None:
        return {}
    if mode != WINDOWS_GNU_LINKER or sys.platform != "win32":
        raise ValueError("the explicit release Rust linker configuration is unsupported")
    if any(
        key in environment
        for key in (
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        )
    ):
        raise ValueError("custom compiler flags or wrappers are not a release linker configuration")
    cargo_raw = shutil.which("cargo", path=environment.get("PATH", ""))
    if cargo_raw is None:
        raise ValueError("the explicitly selected release GNU Cargo is unavailable")
    cargo = _direct_path(Path(cargo_raw))
    toolchain = cargo.parent.parent
    channel = _channel(repository)
    expected = f"{channel}-{_TARGET}"
    if cargo.name != "cargo.exe" or cargo.parent.name != "bin" or toolchain.name != expected:
        raise ValueError("the selected Cargo does not match the pinned Windows GNU toolchain")
    selected = environment.get("RUSTUP_TOOLCHAIN")
    if selected not in {None, channel, expected}:
        raise ValueError("the selected rustup toolchain conflicts with the release linker")
    rustc = _direct_path(toolchain / "bin" / "rustc.exe")
    linker = _direct_path(toolchain / "lib" / "rustlib" / _TARGET / "bin" / "rust-lld.exe")
    arguments = (
        "-C",
        f"linker={linker}",
        "-C",
        "linker-flavor=ld.lld",
        "-C",
        "link-self-contained=yes",
        "-C",
        "target-feature=+crt-static",
    )
    return {
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(arguments),
        "RUSTC": os.fspath(rustc),
        "RUSTUP_TOOLCHAIN": expected,
    }
