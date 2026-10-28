"""Pure privacy, ownership and failure-isolation checks; never run DTrace."""

from __future__ import annotations

import io
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import macos_owned_startup_trace as trace_support
from tools import verify_macos_file_access_lifecycle as verifier


def _complete_trace(stack: str = "") -> bytes:
    return (
        "BFTRACE_READY\nBFTRACE_EXEC\n"
        "BFTRACE_EVENT 1 1 2 0 3 0\n"
        "BFTRACE_STACK\n" + stack + "BFTRACE_STACK_END\n"
        "BFTRACE_EVENT 2 3 2 1 0 0\n"
        "BFTRACE_EVENT 2 3 1 0 1 0\n"
        "BFTRACE_EVENT 3 3 0 0 0 0\nBFTRACE_EXIT\n"
    ).encode("ascii")


def test_positive_owned_activity_retains_only_allowlisted_frames_per_socket():
    raw = _complete_trace(
        "  libsystem_kernel.dylib`__socket+0x8\n"
        "  dyld`socket_syslogv+0x10\n"
        "  /private/secret/libsecret.dylib`credential_value+0x20\n"
        "  .bluefire-verified-launch-abcdef`private_symbol+0x18\n"
        "  0x123456789abcdef\n"
    )
    projected = trace_support._trace_projection(raw, impaired=False)
    assert projected["status"] == "owned_syscalls_observed"
    assert projected["descriptor_authority"] == "none"
    assert projected["absence_interpretation"] == "none"
    assert projected["creator_attribution"] == "inconclusive"
    assert projected["entry_boundary"] == "not_traced_native_snapshot_remains_separate"
    assert projected["events"][0]["system_caller_frames"] == [
        {"image": "libsystem_kernel.dylib", "symbol": "__socket"},
        {"image": "dyld", "symbol": "socket_syslogv"},
    ]
    serialized = json.dumps(projected)
    for forbidden in ("/private", "credential", "abcdef", "private_symbol", "0x"):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "raw,impaired",
    [
        (_complete_trace(), True),
        (_complete_trace().replace(b"BFTRACE_EXIT", b"BFTRACE_TIMEOUT"), False),
        (_complete_trace().replace(b"BFTRACE_EXIT", b"BFTRACE_CAP"), False),
        (_complete_trace().replace(b"BFTRACE_EXIT", b"BFTRACE_ERROR"), False),
        (_complete_trace().replace(b"BFTRACE_EXEC\n", b""), False),
        (_complete_trace().replace(b"BFTRACE_EVENT 2 3 1 0 1 0\n", b""), False),
        (_complete_trace().replace(b"BFTRACE_EVENT 3 3 0 0 0 0\n", b""), False),
        (b"untrusted path /private/credential\n", False),
        (b"x" * (trace_support._TRACE_BYTES + 1), False),
    ],
    ids=[
        "loss",
        "timeout",
        "event-cap",
        "probe-error",
        "no-exec",
        "no-fcntl",
        "no-fstat",
        "untrusted",
        "byte-cap",
    ],
)
def test_unsupported_missing_lossy_or_capped_trace_is_always_inconclusive(raw, impaired):
    projected = trace_support._trace_projection(raw, impaired=impaired)
    assert projected["status"] == "inconclusive"
    assert projected["absence_interpretation"] == "none"
    assert "credential" not in json.dumps(projected)


def test_no_socket_event_is_never_inheritance_attribution():
    raw = _complete_trace().replace(
        b"BFTRACE_EVENT 1 1 2 0 3 0\nBFTRACE_STACK\nBFTRACE_STACK_END\n", b""
    )
    projected = trace_support._trace_projection(raw, impaired=False)
    assert projected["status"] == "owned_syscalls_observed"
    assert projected["absence_interpretation"] == "none"
    assert all(event["syscall"] != "socket" for event in projected["events"])
    assert projected["creator_attribution"] == "inconclusive"


def test_script_scope_captures_neither_argv_environment_payload_nor_paths():
    script = trace_support._owned_trace_script(12345, Path("/protected/bluefire/native"))
    assert "progenyof(12345)" in script
    prefix = "/protected/bluefire/native/.bluefire-verified-launch-"
    assert f"strlen(this->image) == {len(prefix) + 64}" in script
    assert script.count('strstr("0123456789abcdef"') == 64
    assert "pending[pid]" in script and "proc:::exec-success" in script
    assert "ustack(8)" in script and "events < 128" in script
    assert 'printf("BFTRACE_EXIT' in script and "ticks++ >= 30" in script
    for forbidden in (
        "execname",
        "pr_psargs",
        "copyinstr(arg1)",
        "copyinstr(arg2)",
        "tracemem",
        "system(",
        "raise(",
        "copyout",
    ):
        assert forbidden not in script
    assert all("image" not in line for line in script.splitlines() if "printf" in line)


def test_stream_overflow_immediately_stops_only_owned_tracer_without_retaining_more():
    read_fd, write_fd = os.pipe()
    signalled = []
    trace = trace_support._OwnedStartupTrace.__new__(trace_support._OwnedStartupTrace)
    trace.raw = bytearray(b"x" * trace_support._TRACE_BYTES)
    trace.impaired = False
    trace.ready = threading.Event()
    trace.process = SimpleNamespace(terminate=lambda: signalled.append("owned_tracer"))
    os.write(write_fd, b"overflow-private-value")
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        trace._drain(stream, False)
    assert trace.impaired and signalled == ["owned_tracer"]
    assert len(trace.raw) == trace_support._TRACE_BYTES
    assert b"private" not in trace.raw


def test_cleanup_clears_raw_and_removes_private_directory():
    cleaned = []
    process = SimpleNamespace(
        stdout=io.BytesIO(), stderr=io.BytesIO(), returncode=0, wait=lambda **_: 0
    )
    trace = trace_support._OwnedStartupTrace.__new__(trace_support._OwnedStartupTrace)
    trace.process = process
    trace.raw = bytearray(_complete_trace())
    trace.readers = []
    trace.impaired = False
    trace.temporary = SimpleNamespace(cleanup=lambda: cleaned.append(True))
    assert trace.stop()["status"] == "owned_syscalls_observed"
    assert trace.raw == b"" and cleaned == [True]
    assert process.stdout.closed and process.stderr.closed


def test_diagnostic_cleanup_error_cannot_hide_lifecycle_failure(monkeypatch, tmp_path):
    def fail(args):
        args._owned_startup_trace = SimpleNamespace(
            stop=lambda: (_ for _ in ()).throw(OSError("private diagnostic failure"))
        )
        raise verifier.QualificationError("lifecycle refused")

    monkeypatch.setattr(verifier, "_run", fail)
    monkeypatch.setattr(
        verifier.sys,
        "argv",
        [
            "verify",
            "--python",
            "unused",
            "--prefix",
            "unused",
            "--run-identity",
            "1-1",
            "--wheel",
            "unused",
            "--source-revision",
            "unused",
            "--output",
            str(tmp_path / "life.json"),
            "--owned-startup-trace-output",
            str(tmp_path / "trace.json"),
        ],
    )
    assert verifier.main() == 1
    assert json.loads((tmp_path / "life.json").read_text())["status"] == "failed"


def test_expected_sibling_loader_preserves_isolated_import_path(monkeypatch, tmp_path):
    monkeypatch.setattr(verifier, "__file__", str(tmp_path / "verifier.py"))
    helper = tmp_path / "macos_owned_startup_trace.py"
    helper.write_text("def _OwnedStartupTrace(parent):\n    return parent\n", encoding="ascii")
    helper.chmod(0o400)
    monkeypatch.setattr(verifier.os, "geteuid", lambda: helper.stat().st_uid, raising=False)
    previous_path = list(verifier.sys.path)
    try:
        assert verifier._start_owned_startup_trace().name == "native"
        assert verifier.sys.path == previous_path
    finally:
        helper.chmod(0o600)


@pytest.mark.parametrize("kind", ["missing", "directory", "oversized"])
def test_expected_sibling_loader_rejects_unavailable_nonregular_or_oversized(
    monkeypatch, tmp_path, kind
):
    monkeypatch.setattr(verifier, "__file__", str(tmp_path / "verifier.py"))
    helper = tmp_path / "macos_owned_startup_trace.py"
    if kind == "directory":
        helper.mkdir()
    elif kind == "oversized":
        helper.write_bytes(b"x" * 32769)
    with pytest.raises((OSError, ValueError)):
        verifier._start_owned_startup_trace()


@pytest.mark.parametrize("kind", ["wrong_owner", "other_writable"])
def test_expected_sibling_loader_rejects_unsafe_custody(monkeypatch, tmp_path, kind):
    monkeypatch.setattr(verifier, "__file__", str(tmp_path / "verifier.py"))
    helper = tmp_path / "macos_owned_startup_trace.py"
    helper.write_text("raise RuntimeError('must not execute')\n", encoding="ascii")
    helper.chmod(0o666 if kind == "other_writable" else 0o400)
    expected_owner = helper.stat().st_uid + (1 if kind == "wrong_owner" else 0)
    monkeypatch.setattr(verifier.os, "geteuid", lambda: expected_owner, raising=False)
    try:
        with pytest.raises(ValueError):
            verifier._start_owned_startup_trace()
    finally:
        helper.chmod(0o600)
