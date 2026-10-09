"""Source-only regressions for the reviewed property-query process inventory."""

from pathlib import Path

import pytest

from tools.native_command_source_audit import (
    _native_command_source_inventory_is_fixed,
    _reviewed_service_query_sources,
)

ROOT = Path(__file__).resolve().parents[1]
PROCESS = "service_query_process.rs"
FIXTURE = "service_query_process_tests.rs"
REVIEWED_FILES = (
    "process.rs",
    "cancellation_witness.rs",
    "atomic_gzip.rs",
    "atomic_chmod.rs",
    PROCESS,
    FIXTURE,
)


def _source(name: str) -> bytes:
    return (ROOT / "runner/src" / name).read_bytes()


def _inventory(tmp_path: Path) -> Path:
    source = tmp_path / "runner/src"
    source.mkdir(parents=True)
    for name in REVIEWED_FILES:
        (source / name).write_bytes(_source(name))
    assert _native_command_source_inventory_is_fixed(tmp_path)
    return source


def test_reviewed_query_sources_are_registered_in_the_full_native_inventory() -> None:
    assert _reviewed_service_query_sources(_source(PROCESS), _source(FIXTURE))
    assert _native_command_source_inventory_is_fixed(ROOT)


@pytest.mark.parametrize(
    ("name", "before", "after"),
    (
        (PROCESS, b"manager.fd()", b"caller.fd()"),
        (PROCESS, b".args(target.query_arguments(query))", b".args(caller_arguments)"),
        (PROCESS, b".env_clear()", b".envs(std::env::vars())"),
        (PROCESS, b"fn spawn_configured(", b"pub fn spawn_configured("),
        (
            PROCESS,
            b"Self::spawn_configured(command, manager.deadline())",
            b"Self::spawn_configured(command, Instant::now() + Duration::from_secs(2))",
        ),
        (PROCESS, b"prctl(1, 9,", b"prctl(1, 0,"),
        (PROCESS, b"prctl(38, 1,", b"prctl(38, 0,"),
        (PROCESS, b"fcntl(fd, 4, flags | 0x800)", b"fcntl(fd, 2, 0)"),
        (PROCESS, b"capture.stderr_bytes > STDERR_LIMIT", b"capture.stderr_bytes > usize::MAX"),
        (
            PROCESS,
            b"let signalled = child.terminate_group();",
            b"let _ = child.reap(); let signalled = child.terminate_group();",
        ),
        (PROCESS, b"if self.signalled || self.reaped", b"if self.signalled"),
        (PROCESS, b"kill(-(self.child.id() as i32), 9)", b"kill(-(std::process::id() as i32), 9)"),
        (PROCESS, b"self.child.kill()", b"Ok::<(), io::Error>(())"),
        (
            PROCESS,
            b'#[cfg(test)]\n#[path = "service_query_process_tests.rs"]',
            b'#[path = "service_query_process_tests.rs"]',
        ),
        (FIXTURE, b'File::open("/proc/self/exe")', b'File::open("/usr/bin/systemctl")'),
        (
            FIXTURE,
            b'["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"]',
            b"caller_arguments",
        ),
        (FIXTURE, b".env_clear()", b".envs(std::env::vars())"),
    ),
)
def test_changed_query_boundaries_refuse_the_existing_full_inventory(
    tmp_path: Path, name: str, before: bytes, after: bytes
) -> None:
    source = _inventory(tmp_path)
    path = source / name
    original = path.read_bytes()
    assert original.count(before) == 1
    path.write_bytes(original.replace(before, after))
    assert not _native_command_source_inventory_is_fixed(tmp_path)


@pytest.mark.parametrize("name", (PROCESS, FIXTURE))
def test_unchanged_shape_does_not_allow_unreviewed_bytes(tmp_path: Path, name: str) -> None:
    source = _inventory(tmp_path)
    path = source / name
    original = path.read_bytes()
    # Mutate only the first comment while preserving byte length and command shape.
    assert original.startswith(b"//!")
    path.write_bytes(b"// " + original[3:])
    assert not _native_command_source_inventory_is_fixed(tmp_path)


@pytest.mark.parametrize("change", ("additional", "missing", "renamed", "swapped"))
def test_query_registration_does_not_open_the_inventory(tmp_path: Path, change: str) -> None:
    source = _inventory(tmp_path)
    if change == "additional":
        (source / "unreviewed.rs").write_bytes(b'fn launch() { Command::new("caller"); }')
    elif change == "missing":
        (source / FIXTURE).unlink()
    elif change == "renamed":
        (source / FIXTURE).rename(source / "renamed_fixture.rs")
    else:
        (source / PROCESS).write_bytes(_source(FIXTURE))
        (source / FIXTURE).write_bytes(_source(PROCESS))
    assert not _native_command_source_inventory_is_fixed(tmp_path)
