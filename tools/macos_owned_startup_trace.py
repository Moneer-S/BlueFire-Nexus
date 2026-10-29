"""Optional owned macOS startup trace; never lifecycle or descriptor authority."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

# A separate, optional observation. These bounds never change lifecycle authority.
_TRACE_BYTES = 65536
_TRACE_EVENTS = 128
_TRACE_SECONDS = 30
_TRACE_STDERR_BYTES = 8192
# Apple's xnu/bsd/sys/dtrace.h DTRACEFLT values; dt_error.c supplies the
# corresponding text. Do not retain arg5: several faults use it for an address.
_TRACE_FAULTS = (
    "unknown fault",
    "invalid address",
    "invalid alignment",
    "illegal operation",
    "divide-by-zero",
    "out of scratch space",
    "invalid kernel access",
    "invalid user access",
    "tuple stack overflow",
    "bad stack",
)
_TRACE_ERROR_PROBES = frozenset(
    {
        "dtrace:::BEGIN",
        "dtrace:::ERROR",
        "proc:::exec",
        "proc:::exec-success",
        "proc:::exec-failure",
        "proc:::exit",
        "profile:::tick-1sec",
        "syscall::execve:entry",
    }
    | {
        f"syscall::{call}:{phase}"
        for call in (
            "socket",
            "fcntl",
            "fcntl_nocancel",
            "fstat",
            "fstat64",
            "connect",
            "connect_nocancel",
            "close",
            "close_nocancel",
        )
        for phase in ("entry", "return")
    }
)
_TRACE_COMPILER_TAGS = frozenset(
    {"D_IDENT_UNDEF", "D_VAR_UNDEF", "D_OP_INCOMPAT", "D_FUNC_UNDEF", "D_SYNTAX"}
)
_TRACE_COMPILER_TOKENS = frozenset(
    {
        "chosen",
        "native",
        "pending",
        "events",
        "ticks",
        "this->image",
        "self->op",
        "self->a",
        "self->b",
        "self->c",
        "self->socket",
        "progenyof",
        "copyinstr",
        "strlen",
        "substr",
        "strstr",
        "printf",
        "ustack",
        "exit",
    }
)
_TRACE_FAILURE_CODES = frozenset(
    {
        "internal_setup_failed",
        "spawn_failed",
        "reader_start_failed",
        "read_io_failed",
        "readiness_timeout",
        "stdout_byte_bound",
        "stderr_byte_bound",
        "nonzero_tracer_exit",
        "forced_tracer_shutdown",
        "reader_drain_unconfirmed",
        "unknown_stderr",
        "dtrace_compile_failure",
        "dtrace_probe_unavailable",
        "dtrace_permission_error",
        "dtrace_advisory",
        "missing_ready_marker",
        "missing_owned_exec_marker",
        "missing_owned_exit_marker",
        "event_bound_reached",
        "runtime_bound_reached",
        "dtrace_runtime_error",
        "owned_reexec_observed",
    }
)
_TRACE_SYSTEM_IMAGES = frozenset(
    {
        "dyld",
        "libdyld.dylib",
        "libsystem_kernel.dylib",
        "libsystem_c.dylib",
        "libsystem_pthread.dylib",
        "libsystem_platform.dylib",
        "libsystem_trace.dylib",
        "libSystem.B.dylib",
        "libobjc.A.dylib",
    }
)


def _runtime_error_line(line: bytes) -> dict[str, Any] | None:
    """Recognize Apple's dt_handle.c format, withholding addresses and IDs."""
    match = re.fullmatch(
        rb"dtrace: error on enabled probe ID [0-9]{1,10} "
        rb"\(ID [0-9]{1,10}: ([A-Za-z0-9_:-]{1,96})\): "
        rb"([a-z -]{1,40})( \(0x[0-9a-fA-F]{1,16}\))? "
        rb"in (predicate|action #[0-9]{1,3})(?: at DIF offset ([0-9]{1,5}))?",
        line,
    )
    if not match:
        return None
    fault = match[2].decode("ascii")
    if fault not in _TRACE_FAULTS or (
        match[3] is not None and fault not in {"invalid address", "invalid alignment", "bad stack"}
    ):
        return None
    action = 0 if match[4] == b"predicate" else int(match[4][8:])
    offset = -1 if match[5] is None else int(match[5])
    if not 0 <= action <= 128 or not -1 <= offset <= 65535:
        return None
    probe = match[1].decode("ascii")
    return {
        "fault": fault.replace("-", "_").replace(" ", "_"),
        "action": action,
        "dif_offset": offset,
        "probe": probe if probe in _TRACE_ERROR_PROBES else "unknown",
    }


def _runtime_diagnostic(
    raw: bytes, stderr: bytes, *, truncated: bool = False
) -> dict[str, Any] | None:
    """Project one ERROR arg4/arg2/arg3 record; never export arg1 or arg5.

    Probe identity is used only when one fixed-form stderr report agrees with
    all three numeric fields. Missing, ambiguous or unknown probes stay unknown.
    Apple's ERROR test and xnu fault definitions document the argument mapping.
    """
    if truncated or len(raw) > _TRACE_BYTES or len(stderr) > _TRACE_STDERR_BYTES:
        return None
    lines = raw.splitlines()
    records = [line for line in lines if line.startswith(b"BFTRACE_FAULT")]
    if b"BFTRACE_ERROR" not in lines or len(records) != 1:
        return None
    match = re.fullmatch(rb"BFTRACE_FAULT ([0-9]{1,2}) ([0-9]{1,3}) (-1|[0-9]{1,5})", records[0])
    if not match:
        return None
    fault, action, offset = map(int, match.groups())
    if fault >= len(_TRACE_FAULTS) or action > 128 or offset > 65535:
        return None
    result = {
        "fault": _TRACE_FAULTS[fault].replace("-", "_").replace(" ", "_"),
        "action": action,
        "dif_offset": offset,
        "probe": "unknown",
    }
    reports = [line for line in stderr.splitlines() if line.startswith(b"dtrace: error on ")]
    report = _runtime_error_line(reports[0]) if len(reports) == 1 else None
    if report is not None and all(report[key] == result[key] for key in result if key != "probe"):
        result["probe"] = report["probe"]
    return result


def _stderr_failure_codes(raw: bytes, *, truncated: bool = False) -> set[str]:
    """Recognize fixed DTrace diagnostic forms without returning their text.

    Apple's cmd/dtrace/dtrace.c prefixes script compilation, initialization and
    enabling errors. These are diagnostic classes, not proof that this platform
    cannot trace an owned process. A generic SIP advisory never means refusal.
    """
    codes = set()
    if truncated or len(raw) > _TRACE_STDERR_BYTES:
        return {"stderr_byte_bound", "unknown_stderr"}
    for line in raw.splitlines():
        if (
            line
            == b"dtrace: system integrity protection is on, some features will not be available"
        ):
            codes.add("dtrace_advisory")
        elif line.startswith(
            (b"dtrace: failed to compile script ", b"dtrace: invalid probe specifier ")
        ):
            codes.add(
                "dtrace_probe_unavailable"
                if b": probe description " in line and line.endswith(b" does not match any probes")
                else "dtrace_compile_failure"
            )
        elif line in {
            prefix + detail
            for prefix in (
                b"dtrace: failed to initialize dtrace: ",
                b"dtrace: could not enable tracing: ",
            )
            for detail in (
                b"DTrace requires additional privileges",
                b"Permission denied",
                b"Operation not permitted",
            )
        }:
            codes.add("dtrace_permission_error")
        elif _runtime_error_line(line) is not None:
            codes.add("dtrace_runtime_error")
        else:
            codes.add("unknown_stderr")
    return codes or ({"unknown_stderr"} if raw else set())


def _compiler_diagnostic(
    raw: bytes, *, line_count: int, truncated: bool = False
) -> dict[str, Any] | None:
    """Parse Apple's errtags/line format; return no arbitrary error text.

    dt_error.c:dt_set_errmsg prefixes [tag], optional filename, then line number.
    Only tags and identifier spellings already present in this generator escape
    this transient buffer. Unknown tags/lines are withheld; unknown tokens stay
    the fixed enum "unknown". This detail never changes failure classification.
    """
    if (
        truncated
        or len(raw) > _TRACE_STDERR_BYTES
        or type(line_count) is not int
        or not 1 <= line_count <= 128
    ):
        return None
    for message in raw.splitlines():
        match = re.fullmatch(
            rb"dtrace: failed to compile script [^\r\n]{1,2048}: \[([A-Z_]{1,32})\] "
            rb'(?:"[^"\r\n]{1,2048}", )?line ([0-9]{1,3}): ([^\r\n]{1,2048})',
            message,
        )
        if not match:
            continue
        tag = match[1].decode("ascii")
        line = int(match[2])
        if tag not in _TRACE_COMPILER_TAGS or not 1 <= line <= line_count:
            continue
        token = "unknown"
        for pattern in (
            rb"failed to resolve ((?:self->|this->)?[A-Za-z_][A-Za-z0-9_]*): [^\r\n]+",
            rb"((?:self->|this->)?[A-Za-z_][A-Za-z0-9_]*) has not yet been declared or assigned",
            rb"undefined function name: ([A-Za-z_][A-Za-z0-9_]*)",
        ):
            identifier = re.fullmatch(pattern, match[3])
            if identifier and identifier[1].decode("ascii") in _TRACE_COMPILER_TOKENS:
                token = identifier[1].decode("ascii")
                break
        return {"tag": tag, "line": line, "token": token}
    return None


def _owned_trace_script(owner: int, native_parent: Path) -> str:
    """Use Apple's progenyof(), with no process-name or global data collection.

    Apple sources: dtrace/cmd/dtrace/dtrace.1 (progenyof, ustack, exit status),
    DTTk/dtruss (descendant syscall filtering), xnu/bsd/kern/kern_exec.c
    (proc exec receives the already copied-in pathname), and
    xnu/bsd/dev/dtrace/sdt_subr.c (proc exec args[0] is a D string).
    Unlike copyinstr at syscall entry, this does not reread user pathname memory.
    Only the filename is inspected, privately; argv/environment are untouched.
    """
    prefix = native_parent.as_posix() + "/.bluefire-verified-launch-"
    if type(owner) is not int or owner <= 1 or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,700}", prefix):
        raise ValueError("Trace scope is unavailable")
    # The installed root-owned native directory contains the verified native
    # resource; helper interpreter pins are in a different directory. Require
    # the same fixed hexadecimal pin grammar as the maintained launcher.
    hex_tests = " && ".join(
        f'strstr("0123456789abcdef", substr(this->image, {len(prefix) + i}, 1)) != NULL'
        for i in range(64)
    )
    return f"""#pragma D option quiet
#pragma D option strsize=1024
#pragma D option bufsize=256k
#pragma D option dynvarsize=256k
dtrace:::BEGIN {{ chosen = 0; printf("BFTRACE_READY\\n"); }}
proc:::exec /progenyof({owner}) && !chosen/ {{
    this->image = args[0];
    pending[pid] = strlen(this->image) == {len(prefix) + 64} &&
        substr(this->image, 0, {len(prefix)}) == "{prefix}" && {hex_tests};
}}
proc:::exec-success /progenyof({owner}) && pending[pid] && !chosen/ {{
    chosen = 1; native = pid; pending[pid] = 0;
    printf("BFTRACE_EXEC\\n");
}}
proc:::exec-failure /progenyof({owner}) && pending[pid]/ {{ pending[pid] = 0; }}
proc:::exit /progenyof({owner}) && pending[pid]/ {{ pending[pid] = 0; }}
syscall::execve:entry /pid == native/ {{ printf("BFTRACE_REEXEC\\n"); exit(0); }}
syscall::socket:entry,
syscall::fcntl*:entry,
syscall::fstat*:entry,
syscall::connect*:entry,
syscall::close*:entry
/pid == native && progenyof({owner})/ {{
    self->op = probefunc == "socket" ? 1 :
        (probefunc == "fcntl" || probefunc == "fcntl_nocancel") ? 2 :
        (probefunc == "fstat" || probefunc == "fstat64") ? 3 :
        (probefunc == "connect" || probefunc == "connect_nocancel") ? 4 :
        (probefunc == "close" || probefunc == "close_nocancel") ? 5 : 0;
    self->a = arg0;
    self->b = self->op == 1 || self->op == 2 ? arg1 : 0;
    self->c = self->op == 1 || (self->op == 2 && arg1 == 2) ? arg2 : 0;
}}
syscall::socket:return,
syscall::fcntl*:return,
syscall::fstat*:return,
syscall::connect*:return,
syscall::close*:return
/pid == native && progenyof({owner}) && self->op && events < {_TRACE_EVENTS}/ {{
    events++;
    printf("BFTRACE_EVENT %d %d %d %d %d %d\\n", self->op,
        (int)self->a, (int)self->b, (int)self->c, (int)arg0, errno);
    self->socket = self->op == 1;
    self->op = 0;
}}
syscall::socket:return /pid == native && self->socket/ {{
    printf("BFTRACE_STACK\\n"); ustack(8); printf("BFTRACE_STACK_END\\n");
    self->socket = 0;
}}
syscall:::return /pid == native && events >= {_TRACE_EVENTS}/ {{
    printf("BFTRACE_CAP\\n"); exit(0);
}}
proc:::exit /pid == native/ {{ printf("BFTRACE_EXIT\\n"); native = 0; exit(0); }}
profile:::tick-1sec /ticks++ >= {_TRACE_SECONDS}/ {{ printf("BFTRACE_TIMEOUT\\n"); exit(0); }}
dtrace:::ERROR {{
    printf("BFTRACE_ERROR\\nBFTRACE_FAULT %d %d %d\\n", (int)arg4, (int)arg2, (int)arg3);
    exit(0);
}}
"""


def _trace_projection(
    raw: bytes, *, impaired: bool, failure_codes: set[str] | None = None
) -> dict[str, Any]:
    """Export only fixed records and allowlisted normalized system frames.

    A complete positive observation still says nothing about an absent socket
    creation: unsupported probes, stack unwinding and event loss cannot prove
    inheritance. Entry remains the native diagnostic's separate observation.
    """
    result: dict[str, Any] = {
        "schema_version": "bluefire.macos-owned-startup-trace.v1",
        "status": "inconclusive",
        "scope": "first_owned_native_child_final_exec_until_exit_or_bound",
        "entry_boundary": "not_traced_native_snapshot_remains_separate",
        "creator_attribution": "inconclusive",
        "absence_interpretation": "none",
        "descriptor_authority": "none",
    }
    # Additive finite fields preserve the v1 status/reason family. Even when raw
    # event decoding is withheld, distinguish the unmet tracing prerequisites.
    marker_set = set(raw.splitlines()) if len(raw) <= _TRACE_BYTES else set()
    codes = (failure_codes or set()) & _TRACE_FAILURE_CODES
    if len(raw) > _TRACE_BYTES:
        codes.add("stdout_byte_bound")
    for marker, code in (
        (b"BFTRACE_READY", "missing_ready_marker"),
        (b"BFTRACE_EXEC", "missing_owned_exec_marker"),
    ):
        if marker not in marker_set:
            codes.add(code)
    if b"BFTRACE_EXEC" in marker_set and b"BFTRACE_EXIT" not in marker_set:
        codes.add("missing_owned_exit_marker")
    for marker, code in (
        (b"BFTRACE_CAP", "event_bound_reached"),
        (b"BFTRACE_TIMEOUT", "runtime_bound_reached"),
        (b"BFTRACE_ERROR", "dtrace_runtime_error"),
        (b"BFTRACE_REEXEC", "owned_reexec_observed"),
    ):
        if marker in marker_set:
            codes.add(code)
    result["failure_codes"] = sorted(codes)
    result["markers"] = {
        "ready": b"BFTRACE_READY" in marker_set,
        "owned_exec": b"BFTRACE_EXEC" in marker_set,
        "owned_exit": b"BFTRACE_EXIT" in marker_set,
    }
    if impaired or (failure_codes or set()) & _TRACE_FAILURE_CODES or len(raw) > _TRACE_BYTES:
        result["reason"] = "tracer_error_loss_or_output_bound"
        return result
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        result["reason"] = "unrecognized_trace"
        return result
    events: list[dict[str, Any]] = []
    frames: list[dict[str, str]] = []
    markers = []
    in_stack = False
    for line in lines:
        if line == "BFTRACE_STACK":
            if in_stack or not events or events[-1]["syscall"] != "socket":
                break
            in_stack = True
            frames = []
        elif line == "BFTRACE_STACK_END":
            if not in_stack:
                break
            in_stack = False
            events[-1]["system_caller_frames"] = frames
            events[-1]["caller_stack_status"] = (
                "symbolized_system_frames_observed" if frames else "unproven"
            )
        elif in_stack:
            # Never export addresses, image paths, generated pin names, or
            # arbitrary native symbols. Unknown frames only lower usefulness.
            match = re.fullmatch(
                r"\s*([^`\s]+)`([A-Za-z_][A-Za-z0-9_.$:<>-]{0,120})(?:\+0x[0-9a-fA-F]+)?\s*", line
            )
            if match and match[1] in _TRACE_SYSTEM_IMAGES:
                frame = {"image": match[1], "symbol": match[2]}
                if frame not in frames and len(frames) < 16:
                    frames.append(frame)
        elif line.startswith("BFTRACE_EVENT "):
            values = line.split()[1:]
            if len(values) != 6 or not all(re.fullmatch(r"-?[0-9]{1,10}", x) for x in values):
                break
            op, a, b, c, returned, error = map(int, values)
            if not 1 <= op <= 5 or not 0 <= error <= 4096 or len(events) >= _TRACE_EVENTS:
                break
            events.append(
                {
                    "syscall": ("socket", "fcntl", "fstat", "connect", "close")[op - 1],
                    "arg0": a,
                    "arg1": b,
                    "arg2": c,
                    "return": returned,
                    "errno": error,
                }
            )
        elif line in {"BFTRACE_READY", "BFTRACE_EXEC", "BFTRACE_EXIT"}:
            markers.append(line)
        elif line.strip():
            break
    else:
        expected = ["BFTRACE_READY", "BFTRACE_EXEC", "BFTRACE_EXIT"]
        if markers == expected and not in_stack:
            result["events"] = events
            observed = any(
                e["syscall"] == "fcntl" and e["arg0"] == 3 and e["arg1"] == 1 and e["return"] >= 0
                for e in events
            )
            observed = observed and any(
                e["syscall"] == "fstat" and e["arg0"] == 3 and e["return"] == 0 for e in events
            )
            result["status"] = "owned_syscalls_observed" if observed else "inconclusive"
            result["reason"] = (
                "positive_target_activity" if observed else "expected_activity_unproven"
            )
            return result
    result["reason"] = "incomplete_or_unrecognized_trace"
    return result


class _OwnedStartupTrace:
    """One owned tracer with bounded in-memory raw data and explicit cleanup."""

    def __init__(self, native_parent: Path):
        self.raw = bytearray()
        self.impaired = False
        self.failures: set[str] = set()
        self.stderr_raw = bytearray()
        self.stdout_bytes = self.stderr_bytes = 0
        self.script_line_count = 0
        self._result: dict[str, Any] | None = None
        self.ready = threading.Event()
        self.process = None
        self.readers: list[threading.Thread] = []
        self.temporary = None
        phase = "internal_setup_failed"
        try:
            self.temporary = tempfile.TemporaryDirectory(prefix="bluefire-owned-trace-")
            os.chmod(self.temporary.name, 0o700)
            script = Path(self.temporary.name) / "owned.d"
            source = _owned_trace_script(os.getpid(), native_parent)
            self.script_line_count = len(source.splitlines())
            script.write_text(source, encoding="ascii")
            os.chmod(script, 0o600)
            phase = "spawn_failed"
            self.process = subprocess.Popen(
                ["/usr/sbin/dtrace", "-q", "-x", "errtags", "-s", str(script)],
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            phase = "reader_start_failed"
            for stream, is_error in ((self.process.stdout, False), (self.process.stderr, True)):
                reader = threading.Thread(target=self._drain, args=(stream, is_error), daemon=True)
                reader.start()
                self.readers.append(reader)
            if not self.ready.wait(timeout=4):
                self._fail("readiness_timeout")
                self.stop()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            self._fail(phase)
            self.stop()

    def _fail(self, code: str) -> None:
        self.failures.add(code)
        self.impaired = True

    def _drain(self, stream, is_error: bool) -> None:
        process = self.process
        if process is None:
            self._fail("read_io_failed")
            return
        try:
            while chunk := os.read(stream.fileno(), 4096):
                if is_error:
                    self.stderr_bytes = min(self.stderr_bytes + len(chunk), _TRACE_STDERR_BYTES + 1)
                    self.stderr_raw.extend(
                        chunk[: max(0, _TRACE_STDERR_BYTES - len(self.stderr_raw))]
                    )
                else:
                    self.stdout_bytes = min(self.stdout_bytes + len(chunk), _TRACE_BYTES + 1)
                if is_error or len(self.raw) + len(chunk) > _TRACE_BYTES:
                    self.impaired = True
                    if not is_error:
                        self._fail("stdout_byte_bound")
                    # Never reap here: the retained Popen continues to pin the
                    # original tracer PID. Signal that child only, never a group.
                    try:
                        process.terminate()
                    except OSError:
                        pass
                    continue
                self.raw.extend(chunk)
                if b"BFTRACE_READY\n" in self.raw:
                    self.ready.set()
        except OSError:
            self._fail("read_io_failed")

    def stop(self) -> dict[str, Any]:
        if self._result is not None:
            return self._result
        if self.process is not None:
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._fail("forced_tracer_shutdown")
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            for reader in self.readers:
                reader.join(timeout=1)
            if self.process.returncode != 0:
                self._fail("nonzero_tracer_exit")
            if any(r.is_alive() for r in self.readers):
                self._fail("reader_drain_unconfirmed")
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        self.failures.update(
            _stderr_failure_codes(
                bytes(self.stderr_raw), truncated=self.stderr_bytes > _TRACE_STDERR_BYTES
            )
        )
        result = _trace_projection(
            bytes(self.raw), impaired=self.impaired, failure_codes=self.failures
        )
        compiler = _compiler_diagnostic(
            bytes(self.stderr_raw),
            line_count=self.script_line_count,
            truncated=self.stderr_bytes > _TRACE_STDERR_BYTES,
        )
        if compiler is not None:
            result["compiler"] = compiler
        runtime = _runtime_diagnostic(
            bytes(self.raw),
            bytes(self.stderr_raw),
            truncated=self.stdout_bytes > _TRACE_BYTES or self.stderr_bytes > _TRACE_STDERR_BYTES,
        )
        if runtime is not None:
            result["runtime_error"] = runtime
        result["tracer"] = {
            "process_created": self.process is not None,
            "returncode": self.process.returncode if self.process is not None else None,
            "stdout_bytes": self.stdout_bytes,
            "stdout_count_capped": self.stdout_bytes > _TRACE_BYTES,
            "stderr_bytes": self.stderr_bytes,
            "stderr_count_capped": self.stderr_bytes > _TRACE_STDERR_BYTES,
            "reader_threads_drained": len(self.readers) == 2
            and all(not r.is_alive() for r in self.readers),
        }
        self.raw.clear()
        self.stderr_raw.clear()
        if self.temporary is not None:
            self.temporary.cleanup()
        self._result = result
        return result
