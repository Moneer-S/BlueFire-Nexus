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


def _owned_trace_script(owner: int, native_parent: Path) -> str:
    """Use Apple's progenyof(), with no process-name or global data collection.

    Apple sources: dtrace/cmd/dtrace/dtrace.1 (progenyof, ustack, exit status),
    DTTk/dtruss (descendant syscall filtering), and xnu/bsd/kern/kern_exec.c
    (exec-success on the new thread before returning to userspace).
    Only execve's filename is inspected, privately; argv/environment are untouched.
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
dtrace:::BEGIN {{ printf("BFTRACE_READY\\n"); }}
syscall::execve:entry /progenyof({owner}) && !chosen/ {{
    this->image = copyinstr(arg0);
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
dtrace:::ERROR {{ printf("BFTRACE_ERROR\\n"); exit(0); }}
"""


def _trace_projection(raw: bytes, *, impaired: bool) -> dict[str, Any]:
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
    if impaired or len(raw) > _TRACE_BYTES:
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
        self.ready = threading.Event()
        self.process = None
        self.readers: list[threading.Thread] = []
        self.temporary = tempfile.TemporaryDirectory(prefix="bluefire-owned-trace-")
        os.chmod(self.temporary.name, 0o700)
        try:
            script = Path(self.temporary.name) / "owned.d"
            script.write_text(_owned_trace_script(os.getpid(), native_parent), encoding="ascii")
            os.chmod(script, 0o600)
            self.process = subprocess.Popen(
                ["/usr/sbin/dtrace", "-q", "-s", str(script)],
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            for stream, is_error in ((self.process.stdout, False), (self.process.stderr, True)):
                reader = threading.Thread(target=self._drain, args=(stream, is_error), daemon=True)
                self.readers.append(reader)
                reader.start()
            if not self.ready.wait(timeout=4):
                self.impaired = True
                self.stop()
        except (OSError, ValueError, subprocess.SubprocessError):
            self.impaired = True
            self.stop()

    def _drain(self, stream, is_error: bool) -> None:
        process = self.process
        if process is None:
            self.impaired = True
            return
        try:
            while chunk := os.read(stream.fileno(), 4096):
                if is_error or len(self.raw) + len(chunk) > _TRACE_BYTES:
                    self.impaired = True
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
            self.impaired = True

    def stop(self) -> dict[str, Any]:
        if self.process is not None:
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.impaired = True
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            for reader in self.readers:
                reader.join(timeout=1)
            self.impaired |= self.process.returncode != 0 or any(r.is_alive() for r in self.readers)
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        result = _trace_projection(bytes(self.raw), impaired=self.impaired)
        self.raw.clear()
        self.temporary.cleanup()
        return result
