"""The fixed worker is an exact reviewed command boundary, not a general launcher."""

from pathlib import Path

import pytest

from tools.native_command_source_audit import _native_command_source_inventory_is_fixed
from tools.s3_worker_source_audit import reviewed_s3_worker_source

ROOT = Path(__file__).resolve().parents[1]
WORKER = "s3_worker_process.rs"
COMMAND_SOURCES = (
    "process.rs",
    "cancellation_witness.rs",
    "atomic_gzip.rs",
    "atomic_chmod.rs",
    "service_query_process.rs",
    "service_query_process_tests.rs",
    WORKER,
)


def _source(name: str) -> bytes:
    return (ROOT / "runner/src" / name).read_bytes()


def _inventory(tmp_path: Path) -> Path:
    target = tmp_path / "runner/src"
    target.mkdir(parents=True)
    for name in COMMAND_SOURCES:
        (target / name).write_bytes(_source(name))
    assert _native_command_source_inventory_is_fixed(tmp_path)
    return target


def test_fixed_worker_is_reviewed_without_becoming_general_command_authority():
    assert reviewed_s3_worker_source(_source(WORKER))
    assert _native_command_source_inventory_is_fixed(ROOT)


@pytest.mark.parametrize(
    "before,after",
    [
        (b"runtime.python.fd()", b"caller.fd()"),
        (b"runtime.python.recheck().map_err(|_| ())?;", b"Ok::<(), ()>(())?;"),
        (b'.args(["-I", "-S", "-B"])', b".args(caller_arguments)"),
        (b".arg(&runtime.entry)", b".arg(caller_script)"),
        (b".env_clear()", b".envs(std::env::vars())"),
        (b"libc::PR_SET_PDEATHSIG", b"0"),
        (b"libc::PR_SET_NO_NEW_PRIVS", b"0"),
        (b"libc::RLIMIT_AS", b"libc::RLIMIT_DATA"),
        (b"libc::RLIMIT_CPU", b"libc::RLIMIT_DATA"),
        (b"libc::RLIMIT_NOFILE", b"libc::RLIMIT_DATA"),
        (b"libc::RLIMIT_CORE", b"libc::RLIMIT_DATA"),
        (b"libc::RLIMIT_FSIZE", b"libc::RLIMIT_DATA"),
        (b"if self.reaped || self.signalled", b"if self.signalled"),
        (b"libc::kill(-(self.child.id() as i32), libc::SIGKILL)", b"libc::kill(0, libc::SIGKILL)"),
        (b"bytes.len() > 4096", b"bytes.len() > usize::MAX"),
        (b"[0_u8; 4096]", b"[0_u8; 65536]"),
    ],
)
def test_changed_fixed_worker_refuses_complete_native_inventory(tmp_path, before, after):
    target = _inventory(tmp_path) / WORKER
    source = target.read_bytes()
    assert source.count(before) == 1
    changed = source.replace(before, after)
    assert not reviewed_s3_worker_source(changed)
    target.write_bytes(changed)
    assert not _native_command_source_inventory_is_fixed(tmp_path)


@pytest.mark.parametrize("change", ["missing", "renamed", "added", "comment_only"])
def test_fixed_worker_bytes_and_inventory_cannot_be_substituted(tmp_path, change):
    source = _inventory(tmp_path)
    worker = source / WORKER
    if change == "missing":
        worker.unlink()
    elif change == "renamed":
        worker.rename(source / "another_worker.rs")
    elif change == "added":
        (source / "unexpected.rs").write_bytes(b'fn launch() { Command::new("caller"); }')
    else:
        original = worker.read_bytes()
        assert original.startswith(b"//!")
        worker.write_bytes(b"// " + original[3:])
    assert not _native_command_source_inventory_is_fixed(tmp_path)


@pytest.mark.parametrize("source", [b"", b"\xff", "not bytes", None])
def test_invalid_worker_source_is_refused(source):
    assert not reviewed_s3_worker_source(source)
