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


def _trace_double(process):
    trace = trace_support._OwnedStartupTrace.__new__(trace_support._OwnedStartupTrace)
    trace.raw = bytearray()
    trace.stderr_raw = bytearray()
    trace.failures = set()
    trace.impaired = False
    trace.stdout_bytes = trace.stderr_bytes = 0
    trace.script_line_count = 54
    trace._result = None
    trace.ready = threading.Event()
    trace.readers = []
    trace.process = process
    trace.temporary = None
    return trace


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
    # Apple cooks clauses in order; the first selector cannot read a scalar
    # whose first assignment occurs only in a later exec-success clause.
    assert "dtrace:::BEGIN { chosen = 0;" in script
    assert script.index("chosen = 0;") < script.index("!chosen")
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
    trace = _trace_double(SimpleNamespace(terminate=lambda: signalled.append("owned_tracer")))
    trace.raw = bytearray(b"x" * trace_support._TRACE_BYTES)
    os.write(write_fd, b"overflow-private-value")
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        trace._drain(stream, False)
    assert trace.impaired and signalled == ["owned_tracer"]
    assert trace.failures == {"stdout_byte_bound"}
    assert len(trace.raw) == trace_support._TRACE_BYTES
    assert b"private" not in trace.raw


def test_cleanup_clears_raw_and_removes_private_directory():
    cleaned = []
    process = SimpleNamespace(
        stdout=io.BytesIO(), stderr=io.BytesIO(), returncode=0, wait=lambda **_: 0
    )
    trace = _trace_double(process)
    trace.raw = bytearray(_complete_trace())
    trace.temporary = SimpleNamespace(cleanup=lambda: cleaned.append(True))
    assert trace.stop()["status"] == "owned_syscalls_observed"
    assert trace.raw == b"" and cleaned == [True]
    assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            b"dtrace: failed to compile script /private/credential/owned.d: line 4: syntax error\n",
            "dtrace_compile_failure",
        ),
        (
            b"dtrace: failed to compile script /private/owned.d: line 5: probe description syscall::socket:entry does not match any probes\n",
            "dtrace_probe_unavailable",
        ),
        (
            b"dtrace: failed to initialize dtrace: DTrace requires additional privileges\n",
            "dtrace_permission_error",
        ),
        (b"dtrace: could not enable tracing: Operation not permitted\n", "dtrace_permission_error"),
        (
            b"dtrace: system integrity protection is on, some features will not be available\n",
            "dtrace_advisory",
        ),
        (b"private credential: permission denied by something else\n", "unknown_stderr"),
    ],
    ids=["compiler", "probe", "init-policy", "enable-policy", "advisory", "unknown"],
)
def test_stderr_classification_uses_only_fixed_forms_and_exports_no_text(raw, expected):
    codes = trace_support._stderr_failure_codes(raw)
    assert codes == {expected}
    projected = trace_support._trace_projection(b"", impaired=True, failure_codes=codes)
    assert projected["reason"] == "tracer_error_loss_or_output_bound"
    assert expected in projected["failure_codes"]
    assert projected["status"] == "inconclusive"
    assert projected["creator_attribution"] == "inconclusive"
    for forbidden in ("credential", "/private", "socket:entry", "permission denied"):
        assert forbidden not in json.dumps(projected)


def test_truncated_or_mixed_stderr_stays_unknown_without_sip_refusal_inference():
    advisory = b"dtrace: system integrity protection is on, some features will not be available\n"
    assert trace_support._stderr_failure_codes(advisory + b"private unknown message\n") == {
        "dtrace_advisory",
        "unknown_stderr",
    }
    assert trace_support._stderr_failure_codes(advisory, truncated=True) == {
        "stderr_byte_bound",
        "unknown_stderr",
    }


@pytest.mark.parametrize(
    "tag,detail,token",
    [
        ("D_IDENT_UNDEF", "failed to resolve chosen: Unknown variable name", "chosen"),
        ("D_VAR_UNDEF", "self->op has not yet been declared or assigned", "self->op"),
        ("D_FUNC_UNDEF", "undefined function name: substr", "substr"),
        ("D_SYNTAX", "expected actions { } following probe description and predicate", "unknown"),
        ("D_OP_INCOMPAT", 'operands have incompatible types: "private" != "long"', "unknown"),
        ("D_IDENT_UNDEF", "failed to resolve private_credential: Unknown variable name", "unknown"),
    ],
)
def test_compiler_diagnostic_exports_only_allowed_tag_line_and_generated_token(tag, detail, token):
    raw = (
        f"dtrace: failed to compile script /private/credential/owned.d: [{tag}] "
        f'"/private/credential/owned.d", line 6: {detail}\n'
    ).encode("ascii")
    result = trace_support._compiler_diagnostic(raw, line_count=54)
    assert result == {"tag": tag, "line": 6, "token": token}
    assert "private" not in json.dumps(result) and "credential" not in json.dumps(result)
    assert trace_support._stderr_failure_codes(raw) == {"dtrace_compile_failure"}


@pytest.mark.parametrize(
    "tag,line", [("D_PRIVATE", 6), ("D_IDENT_UNDEF", 0), ("D_IDENT_UNDEF", 55)]
)
def test_unknown_compiler_tags_and_outside_script_lines_are_withheld(tag, line):
    raw = (
        f"dtrace: failed to compile script /private/owned.d: [{tag}] "
        f"line {line}: failed to resolve chosen: Unknown variable name\n"
    ).encode("ascii")
    assert trace_support._compiler_diagnostic(raw, line_count=54) is None
    assert trace_support._compiler_diagnostic(raw, line_count=54, truncated=True) is None


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"", "missing_ready_marker"),
        (b"BFTRACE_READY\n", "missing_owned_exec_marker"),
        (b"BFTRACE_READY\nBFTRACE_EXEC\n", "missing_owned_exit_marker"),
        (b"BFTRACE_TIMEOUT\n", "runtime_bound_reached"),
        (b"BFTRACE_CAP\n", "event_bound_reached"),
        (b"BFTRACE_ERROR\n", "dtrace_runtime_error"),
    ],
    ids=["no-ready", "no-owned-exec", "no-owned-exit", "timeout", "event-cap", "runtime-error"],
)
def test_missing_prerequisites_and_trace_bounds_are_finite_inconclusive_codes(raw, code):
    result = trace_support._trace_projection(raw, impaired=False)
    assert code in result["failure_codes"]
    assert result["status"] == "inconclusive"
    assert "events" not in result


def test_stderr_chunks_are_bounded_and_first_cleanup_result_survives_second_stop():
    signalled = []
    trace = _trace_double(
        SimpleNamespace(
            terminate=lambda: signalled.append("owned_tracer"),
            wait=lambda **_: -15,
            returncode=-15,
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
    )
    read_fd, write_fd = os.pipe()
    os.write(
        write_fd,
        b"dtrace: failed to compile script /private/credential/owned.d: "
        b"[D_IDENT_UNDEF] line 6: failed to resolve chosen: Unknown variable name\n",
    )
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        trace._drain(stream, True)
    assert signalled == ["owned_tracer"]
    result = trace.stop()
    assert result["status"] == "inconclusive"
    assert {"dtrace_compile_failure", "nonzero_tracer_exit"} <= set(result["failure_codes"])
    assert result["tracer"]["stderr_bytes"] > 0
    assert result["compiler"] == {"tag": "D_IDENT_UNDEF", "line": 6, "token": "chosen"}
    assert trace.stop() == result
    assert not trace.raw and not trace.stderr_raw
    assert "credential" not in json.dumps(result)


def test_read_io_failure_is_distinct_without_actual_process_or_trace(monkeypatch):
    trace = _trace_double(SimpleNamespace())
    monkeypatch.setattr(
        trace_support.os, "read", lambda *_: (_ for _ in ()).throw(OSError("private"))
    )
    trace._drain(SimpleNamespace(fileno=lambda: 123), False)
    assert trace.impaired and trace.failures == {"read_io_failed"}


def test_stderr_storage_and_counts_are_capped_before_cleanup(monkeypatch):
    chunks = iter((b"private" * 1000, b"more" * 1000, b""))
    trace = _trace_double(
        SimpleNamespace(
            terminate=lambda: None,
            wait=lambda **_: 0,
            returncode=0,
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
    )
    monkeypatch.setattr(trace_support.os, "read", lambda *_: next(chunks))
    trace._drain(SimpleNamespace(fileno=lambda: 123), True)
    assert len(trace.stderr_raw) == trace_support._TRACE_STDERR_BYTES
    result = trace.stop()
    assert result["tracer"]["stderr_bytes"] == trace_support._TRACE_STDERR_BYTES + 1
    assert result["tracer"]["stderr_count_capped"] is True
    assert {"stderr_byte_bound", "unknown_stderr"} <= set(result["failure_codes"])
    assert not trace.stderr_raw and "private" not in json.dumps(result)


def test_known_failure_cannot_upgrade_complete_activity_or_export_unknown_codes():
    result = trace_support._trace_projection(
        _complete_trace(),
        impaired=False,
        failure_codes={"dtrace_compile_failure", "/private/untrusted-code"},
    )
    assert result["status"] == "inconclusive"
    assert "events" not in result
    assert result["failure_codes"] == ["dtrace_compile_failure"]


@pytest.mark.parametrize(
    "where,expected", [("ready", "readiness_timeout"), ("reader", "reader_start_failed")]
)
def test_readiness_and_reader_start_failures_are_distinct_without_process_launch(
    monkeypatch, where, expected
):
    process = SimpleNamespace(
        wait=lambda **_: 0, returncode=0, stdout=io.BytesIO(), stderr=io.BytesIO()
    )
    captured = []

    def spawn(args, **_options):
        captured.append(args)
        return process

    monkeypatch.setattr(trace_support.subprocess, "Popen", spawn)

    def start():
        if where == "reader":
            raise RuntimeError("private reader initialization")

    monkeypatch.setattr(
        trace_support.threading,
        "Thread",
        lambda **_: SimpleNamespace(start=start, join=lambda **_: None, is_alive=lambda: False),
    )
    monkeypatch.setattr(
        trace_support.threading, "Event", lambda: SimpleNamespace(wait=lambda **_: False)
    )
    trace = trace_support._OwnedStartupTrace(Path("/protected/native"))
    result = trace.stop()
    assert expected in result["failure_codes"]
    assert result["tracer"]["process_created"] is True
    assert captured[0][:5] == ["/usr/sbin/dtrace", "-q", "-x", "errtags", "-s"]
    assert result["tracer"]["reader_threads_drained"] is (where == "ready")
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize(
    "where,expected", [("setup", "internal_setup_failed"), ("spawn", "spawn_failed")]
)
def test_setup_and_spawn_failures_are_distinct_and_never_launch_dtrace(
    monkeypatch, tmp_path, where, expected
):
    if where == "setup":
        monkeypatch.setattr(
            trace_support.tempfile,
            "TemporaryDirectory",
            lambda **_: (_ for _ in ()).throw(OSError("private setup")),
        )
    else:
        monkeypatch.setattr(
            trace_support.subprocess,
            "Popen",
            lambda *_a, **_k: (_ for _ in ()).throw(OSError("private spawn")),
        )
    trace = trace_support._OwnedStartupTrace(Path("/protected/native"))
    result = trace.stop()
    assert expected in result["failure_codes"]
    assert result["tracer"]["process_created"] is False
    assert result["tracer"]["reader_threads_drained"] is False
    assert "private" not in json.dumps(result)


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
