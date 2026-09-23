"""Static audit of the reviewed Rust command and process inventory."""

from __future__ import annotations

import re
from pathlib import Path

from tools.atomic_chmod_source_audit import reviewed_atomic_chmod_source
from tools.atomic_gzip_source_audit import reviewed_gzip_source
from tools.provider_gate_common import _sha256_bytes

_REVIEWED_PROCESS_SOURCE_SIZE = 25_856
_REVIEWED_PROCESS_SOURCE_SHA256 = (
    "sha256:4720059fa4289b994d7ba05df36e2de22efff9cc4c0b09fe07509dc972c4694b"
)
_REVIEWED_CANCELLATION_SOURCE_SIZE = 31_960
_REVIEWED_CANCELLATION_SOURCE_SHA256 = (
    "sha256:4b3aaebb36b496e8ba2af5fe64eeb3b9925af031a8e2ff42741ad80b8ba07854"
)


def _macos_process_inventory_is_in_process(process_text: str) -> bool:
    start = process_text.find('#[cfg(target_os = "macos")]\nmod macos_process_api')
    end = process_text.find('#[cfg(target_os = "windows")]\nmod windows_process_api', start)
    if start < 0 or end <= start:
        return False
    macos = process_text[start:end]
    return (
        "proc_listallpids" in macos
        and "proc_pidinfo" in macos
        and "MAX_PROCESS_COUNT" in macos
        and "limits.max_stdout_bytes" in macos
        and "max_entries" in macos
        and "Command::new(" not in macos
        and ".spawn(" not in macos
        and "/bin/ps" not in macos
        and "/usr/bin/ps" not in macos
    )


def _native_process_inventory_is_fixed(process_source: bytes) -> bool:
    """Bind the complete reviewed Rust process boundary before checking its shape."""

    if (
        type(process_source) is not bytes
        or len(process_source) != _REVIEWED_PROCESS_SOURCE_SIZE
        or _sha256_bytes(process_source) != _REVIEWED_PROCESS_SOURCE_SHA256
    ):
        return False
    try:
        process_text = process_source.decode("utf-8")
    except UnicodeError:
        return False
    return (
        process_text.count("Command::new(") == 3
        and process_text.count("Command::new(&spec.executable)") == 1
        and process_text.count('Command::new("/bin/sleep")') == 1
        and process_text.count("Command::new(std::env::current_exe().unwrap())") == 1
        and process_text.count(".spawn()") == 2
        and process_text.count(".status()") == 1
        and process_text.count("use std::process::{Command, Stdio};") == 1
        and process_text.count("struct FixedProcessSpec") == 1
        and process_text.count('first_reviewed_program(&["/usr/bin/ps", "/bin/ps"])') == 1
        and process_text.count('args: vec!["-eo", "pid=,ppid=,comm="]') == 1
        and process_text.count(".env_clear()") == 2
        and _macos_process_inventory_is_in_process(process_text)
        and all(
            token not in process_text.casefold()
            for token in ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "sh -c")
        )
    )


def _native_command_source_inventory_is_fixed(repository: Path) -> bool:
    source_root = repository / "runner" / "src"
    command_sources: dict[str, bytes] = {}
    for path in source_root.rglob("*.rs"):
        source = path.read_bytes()
        if re.search(rb"\bCommand\b", source) is not None:
            command_sources[path.relative_to(source_root).as_posix()] = source
    if set(command_sources) != {
        "process.rs",
        "cancellation_witness.rs",
        "atomic_gzip.rs",
        "atomic_chmod.rs",
    }:
        return False
    if not reviewed_gzip_source(command_sources["atomic_gzip.rs"]):
        return False
    if not reviewed_atomic_chmod_source(command_sources["atomic_chmod.rs"]):
        return False
    cancellation_source = command_sources["cancellation_witness.rs"]
    if (
        len(cancellation_source) != _REVIEWED_CANCELLATION_SOURCE_SIZE
        or _sha256_bytes(cancellation_source) != _REVIEWED_CANCELLATION_SOURCE_SHA256
    ):
        return False
    try:
        cancellation_text = cancellation_source.decode("utf-8")
    except UnicodeError:
        return False
    return (
        cancellation_text.count("Command::new(") == 1
        and cancellation_text.count("Command::new(&executable)") == 1
        and "#[cfg(windows)]\nstruct DescendantGuard" in cancellation_text
        and "#[cfg(windows)]\nimpl DescendantGuard" in cancellation_text
        and "the process-tree cancellation witness is available only on Windows"
        in cancellation_text
        and _native_process_inventory_is_fixed(command_sources["process.rs"])
    )


__all__ = [
    "_REVIEWED_CANCELLATION_SOURCE_SHA256",
    "_REVIEWED_CANCELLATION_SOURCE_SIZE",
    "_REVIEWED_PROCESS_SOURCE_SHA256",
    "_REVIEWED_PROCESS_SOURCE_SIZE",
    "_macos_process_inventory_is_in_process",
    "_native_command_source_inventory_is_fixed",
    "_native_process_inventory_is_fixed",
]
