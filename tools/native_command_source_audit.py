"""Static audit of the reviewed Rust command and process inventory."""

from __future__ import annotations

import re
from pathlib import Path

from tools.atomic_chmod_source_audit import reviewed_atomic_chmod_source
from tools.atomic_gzip_source_audit import reviewed_gzip_source
from tools.provider_gate_common import _sha256_bytes
from tools.s3_worker_source_audit import reviewed_s3_worker_source

_REVIEWED_PROCESS_SOURCE_SIZE = 25_856
_REVIEWED_PROCESS_SOURCE_SHA256 = (
    "sha256:4720059fa4289b994d7ba05df36e2de22efff9cc4c0b09fe07509dc972c4694b"
)
_REVIEWED_CANCELLATION_SOURCE_SIZE = 34_354
_REVIEWED_CANCELLATION_SOURCE_SHA256 = (
    "sha256:2c787df1148ed2b6ba0e00394e9fb3651d4172275d2c2e3be125ebde92614c07"
)
_REVIEWED_QUERY_PROCESS_SOURCE = (
    11_756,
    "sha256:db4d1d39b3940ada12e95747d5d11d20b9853e2f4e9d9b63f8b2606d2b0777de",
)
_REVIEWED_QUERY_FIXTURE_SOURCE = (
    13_948,
    "sha256:1618215891cb404d5b419051013b404f6081d15cb55c51ea43dfaebd4643c721",
)
_REVIEWED_S3_CONNECTED_TEST_SOURCE = (
    23_246,
    "sha256:f1b2586b4f2f913612e0f7bcd0779a569e1afa244e602a72b4800c5e233b5522",
)
_S3_CONNECTED_TEST_REGISTRATION = (
    b'#[cfg(all(test, target_os = "linux"))]\n'
    b'#[path = "s3_audit_connected_tests.rs"]\n'
    b"mod connected_tests;"
)

# Independent source review only. Rust compilation, authored Rust tests and
# installed native proof remain pending. This does not admit any tool binary,
# create a private capability or populate the empty compiled SFTP build table.
_REVIEWED_OWNED_SFTP_SOURCES = (
    (
        "owned_sftp.rs",
        12_220,
        "sha256:6e9d0aaeb0fa17271a13404148b380085f7361189b3e9b5102469b0603fb3015",
    ),
    (
        "owned_sftp_process.rs",
        17_359,
        "sha256:58d80a725c3ab3fe65cee7d4e93dc9080d9dec6a1c4be8617e026e043b2adcd5",
    ),
    (
        "actions/owned_sftp_action.rs",
        20_495,
        "sha256:2123b33f380b8ee5591e11e3ddb0113e18401dd385342ea122288455224f5212",
    ),
)


def _reviewed_owned_sftp_sources(sources: dict[str, bytes]) -> bool:
    """Bind exact reviewed consumer, private admission and fixed launch bytes."""
    if set(sources) != {name for name, _size, _digest in _REVIEWED_OWNED_SFTP_SOURCES}:
        return False
    return all(
        type(sources[name]) is bytes
        and len(sources[name]) == size
        and _sha256_bytes(sources[name]) == digest
        for name, size, digest in _REVIEWED_OWNED_SFTP_SOURCES
    )


def _reviewed_service_query_sources(process: bytes, fixture: bytes) -> bool:
    """Bind the reviewed private driver and its separately gated self-ELF fixture.

    These pins describe reviewed source, not permission to run a manager query.
    The production call retains the inspected descriptor's close-on-exec policy;
    it never substitutes a searched executable or widens descriptor inheritance.
    """

    for source, (size, digest) in (
        (process, _REVIEWED_QUERY_PROCESS_SOURCE),
        (fixture, _REVIEWED_QUERY_FIXTURE_SOURCE),
    ):
        if type(source) is not bytes or len(source) != size or _sha256_bytes(source) != digest:
            return False
    try:
        process_text, fixture_text = process.decode("utf-8"), fixture.decode("utf-8")
    except UnicodeError:
        return False
    fixed_process = (
        'Command::new(format!("/proc/self/fd/{}", manager.fd()))',
        '.arg0("systemctl")',
        ".args(target.query_arguments(query))",
        ".envs(target.user_bus_environment())",
        "Self::spawn_configured(command, manager.deadline())",
        "fn spawn_configured(mut command: Command, deadline: Instant)",
        "if Instant::now() >= deadline",
        "setpgid(0, 0) != 0",
        "prctl(1, 9, 0_usize, 0_usize, 0_usize) != 0",
        "prctl(38, 1, 0_usize, 0_usize, 0_usize) != 0",
        "MAX_QUERY_BYTES.saturating_sub(capture.bytes.len())",
        "capture.stderr_bytes > STDERR_LIMIT",
        "while child.now() < cleanup_end",
        "if self.signalled || self.reaped",
        "kill(-(self.child.id() as i32), 9)",
        "self.child.kill()",
        "group_signalled && child_signalled",
        "fcntl(fd, 3)",
        "fcntl(fd, 4, flags | 0x800)",
        "if signalled && reaped && ended == [true, true] && child.group_absent()",
        '#[cfg(test)]\n#[path = "service_query_process_tests.rs"]\nmod tests;',
    )
    fixed_fixture = (
        'File::open("/proc/self/exe")',
        'Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))',
        '.arg0("bluefire-owned-query-fixture")',
        '.args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])',
        ".env(FIXTURE_ENV, mode.name())",
        "LinuxChild::spawn_configured(command, deadline)",
        '"complete" | "stdout-limit" | "stderr-limit" | "wait" | "escape-group"',
        '"service_query_reader::process::tests::authored_query_child"',
    )
    common = (
        "Command::new(",
        ".env_clear()",
        '.env("LC_ALL", "C")',
        '.current_dir("/")',
        ".stdin(Stdio::null())",
        ".stdout(Stdio::piped())",
        ".stderr(Stdio::piped())",
    )
    return (
        all(process_text.count(token) == 1 for token in fixed_process + common)
        and all(fixture_text.count(token) == 1 for token in fixed_fixture + common)
        and process_text.count(".spawn()") == 1
        and process_text.count("fcntl(") == 3
        and process_text.count("getppid() != expected_parent") == 2
        and process_text.index("let signalled = child.terminate_group();")
        < process_text.index("match child.reap()")
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
        "service_query_process.rs",
        "service_query_process_tests.rs",
        "s3_worker_process.rs",
        "s3_audit_connected_tests.rs",
        "owned_sftp_process.rs",
    }:
        return False
    try:
        sftp_sources = {
            name: (source_root / name).read_bytes()
            for name, _size, _digest in _REVIEWED_OWNED_SFTP_SOURCES
        }
    except OSError:
        return False
    if not _reviewed_owned_sftp_sources(sftp_sources):
        return False
    bridge = command_sources["s3_audit_connected_tests.rs"]
    if (
        len(bridge) != _REVIEWED_S3_CONNECTED_TEST_SOURCE[0]
        or _sha256_bytes(bridge) != _REVIEWED_S3_CONNECTED_TEST_SOURCE[1]
    ):
        return False
    try:
        registration = (source_root / "s3_reservation.rs").read_bytes()
    except OSError:
        return False
    if registration.count(_S3_CONNECTED_TEST_REGISTRATION) != 1:
        return False
    if not _reviewed_service_query_sources(
        command_sources["service_query_process.rs"],
        command_sources["service_query_process_tests.rs"],
    ):
        return False
    if not reviewed_gzip_source(command_sources["atomic_gzip.rs"]):
        return False
    if not reviewed_atomic_chmod_source(command_sources["atomic_chmod.rs"]):
        return False
    if not reviewed_s3_worker_source(command_sources["s3_worker_process.rs"]):
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
