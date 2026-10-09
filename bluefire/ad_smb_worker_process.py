"""One fixed AD worker under an owned Windows Job; no listener or scheduler.

The caller must already hold the authenticated original-task ledger reservation.
This component does not mint enrollment, readiness, remote-principal proof or
independent evidence, and is never used by original-result recovery.
"""

from __future__ import annotations

import struct
import subprocess  # nosec B404
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Callable

from .ad_smb_contract import AdSmbError, timestamp
from .ad_smb_credentials import OneUseCredential
from .ad_smb_worker_wire import (
    BEGIN_MAX,
    READY_MAX,
    WorkerPacket,
    begin_prefix,
    frame,
    ready,
    terminal,
)
from .runner_client import _pinned_launch_file
from .runner_trust import _PinnedDirectory, _validated_enrollment_root
from .runner_windows_containment import WindowsJobContainment


@dataclass(frozen=True)
class WorkerOutcome:
    terminal: dict[str, Any] | None = field(repr=False)
    dispatch: str
    cleanup: str
    issue: str | None


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _read_exact(stream: IO[bytes], length: int) -> bytes:
    value = bytearray()
    while len(value) < length:
        part = stream.read(min(65536, length - len(value)))
        if not isinstance(part, bytes) or not part:
            raise AdSmbError("AD worker output ended before its bounded frame.")
        value.extend(part)
    return bytes(value)


def _read_frame(stream: IO[bytes], maximum: int) -> bytes:
    length = struct.unpack("<I", _read_exact(stream, 4))[0]
    if not 0 < length <= maximum:
        raise AdSmbError("AD worker output frame exceeds its bound.")
    return _read_exact(stream, length)


def _write(stream: IO[bytes], payload: bytearray) -> None:
    view = memoryview(payload)
    while view:
        count = stream.write(view)
        if type(count) is not int or not 0 < count <= len(view):
            raise AdSmbError("AD worker private input delivery failed.")
        view = view[count:]
    stream.flush()


def _exchange(
    process: subprocess.Popen[bytes],
    packet: WorkerPacket,
    credential: OneUseCredential | None,
    admit: Callable[[], None],
    current: Callable[[], None],
    state: dict[str, Any],
    done: threading.Event,
) -> None:
    private = bytearray()
    public = bytearray()
    try:
        if process.stdin is None or process.stdout is None:
            raise AdSmbError("AD worker pipes are unavailable.")
        current()
        admit()
        current()
        public = packet.public_frame()
        _write(process.stdin, public)
        ready(packet, _read_frame(process.stdout, READY_MAX), process.pid)
        current()
        # Exact ledger, channel, native and reservation revalidation is local
        # and occurs after Ready, before any protected credential resolution.
        admit()
        current()
        private = (
            credential.begin()
            if credential is not None
            else frame(begin_prefix(packet, reader=False), BEGIN_MAX)
        )
        current()
        state["began"] = True
        _write(process.stdin, private)
        process.stdin.close()
        state["terminal"] = terminal(packet, _read_frame(process.stdout, packet.output_limit))
        if process.stdout.read(1) != b"":
            raise AdSmbError("AD worker returned additional output.")
    except Exception:
        state["issue"] = state["issue"] or "protocol_refused"
        state["terminal"] = None
    finally:
        private[:] = b"\0" * len(private)
        public[:] = b"\0" * len(public)
        done.set()


def _stderr(stream: IO[bytes], maximum: int, state: dict[str, Any]) -> None:
    count = 0
    try:
        while True:
            chunk = stream.read(min(65536, maximum + 1 - count))
            if not chunk:
                return
            count += len(chunk)
            state["stderr"] = True
            if count > maximum:
                state["issue"] = state["issue"] or "output_bound"
                return
    except Exception:
        state["issue"] = state["issue"] or "pipe_failed"


def _close_pipes(process: subprocess.Popen[bytes]) -> bool:
    closed = True
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:
                closed = False
    return closed


def _supervise(
    process: subprocess.Popen[bytes],
    containment: WindowsJobContainment,
    packet: WorkerPacket,
    credential: OneUseCredential | None,
    admit: Callable[[], None],
    cancellation: threading.Event,
    *,
    started: float,
) -> WorkerOutcome:
    state: dict[str, Any] = {"began": False, "terminal": None, "issue": None, "stderr": False}
    done, stopped = threading.Event(), threading.Event()
    deadline = min(started, packet.prepared_monotonic) + packet.to_dict()["remaining_ms"] / 1000
    absolute = timestamp(packet.request["deadline"])

    def current() -> None:
        if (
            stopped.is_set()
            or cancellation.is_set()
            or time.monotonic() >= deadline
            or _utc() >= absolute
        ):
            raise AdSmbError("AD original worker interval ended.")

    exchange = threading.Thread(
        target=_exchange,
        args=(process, packet, credential, admit, current, state, done),
        daemon=True,
        name="ad-worker-pipe",
    )
    if process.stderr is None:
        stopped.set()
        clean = containment.terminate(process)
        clean = _close_pipes(process) and clean
        return WorkerOutcome(None, "not_started", "verified" if clean else "unknown", "pipe_failed")
    errors = threading.Thread(
        target=_stderr,
        args=(process.stderr, packet.to_dict()["manifest"]["limits"]["max_stderr_bytes"], state),
        daemon=True,
        name="ad-worker-stderr",
    )
    cleanup = False
    try:
        exchange.start()
        errors.start()
        while True:
            if cancellation.is_set():
                state["issue"] = "cancelled"
                break
            if time.monotonic() >= deadline or _utc() >= absolute:
                state["issue"] = "deadline"
                break
            if state["issue"] or state["stderr"]:
                state["issue"] = state["issue"] or "unexpected_stderr"
                break
            if done.is_set() and process.poll() is not None:
                result = state["terminal"]
                worker_error = (
                    isinstance(result, dict)
                    and result["result"].get("schema_version") == "bluefire.ad-smb-worker-error.v1"
                )
                if process.returncode == 4 and worker_error:
                    state["issue"] = "native_error"
                elif process.returncode != 0 or worker_error:
                    state["issue"] = "worker_failed"
                break
            stopped.wait(0.01)
    except Exception:
        state["issue"] = "supervision_failed"
    finally:
        stopped.set()
        try:
            cleanup = (
                containment.finish(process)
                if process.poll() is not None
                else containment.terminate(process)
            )
            process.wait(timeout=5)
        except Exception:
            cleanup = False
        for thread in (exchange, errors):
            if thread.ident is not None:
                thread.join(timeout=1)
            if thread.is_alive():
                cleanup = False
        # Only close drained pipes: closing a stream still owned by a blocked
        # Python thread can itself block, so that case remains cleanup unknown.
        if not exchange.is_alive() and not errors.is_alive():
            cleanup = _close_pipes(process) and cleanup
        if state["stderr"]:
            state["issue"] = "unexpected_stderr"
        if not cleanup:
            state["issue"] = "cleanup_unknown"
    observed = state["terminal"] if cleanup and state["issue"] in {None, "native_error"} else None
    return WorkerOutcome(
        observed,
        "attempted" if observed is not None else ("unknown" if state["began"] else "not_started"),
        "verified" if cleanup else "unknown",
        state["issue"],
    )


def run_worker(
    packet: WorkerPacket,
    *,
    runner_binary: Path,
    runner_digest: str,
    work_root: Path,
    credential: OneUseCredential | None,
    revalidate_original: Callable[[], None],
    cancellation_event: threading.Event,
) -> WorkerOutcome:
    """Launch only the pinned fixed worker; caller reservations precede this call."""
    if sys.platform != "win32" or not runner_binary.is_absolute():
        raise AdSmbError("AD native Windows supervision is unavailable.")
    if (packet.to_dict()["host_role"] == "client") != (type(credential) is OneUseCredential) or (
        credential is not None and not credential.matches(packet)
    ):
        raise AdSmbError("AD worker credential role is invalid.")
    started = time.monotonic()
    if cancellation_event.is_set():
        return WorkerOutcome(None, "not_started", "verified", "cancelled")
    if started >= packet.prepared_monotonic + packet.to_dict()[
        "remaining_ms"
    ] / 1000 or _utc() >= timestamp(packet.request["deadline"]):
        return WorkerOutcome(None, "not_started", "verified", "deadline")
    containment = WindowsJobContainment(kill_on_close=True)
    process: subprocess.Popen[bytes] | None = None
    job: int | None = None
    assigned = False
    try:
        root = _validated_enrollment_root(work_root)
        with (
            _PinnedDirectory(root, private=True),
            _pinned_launch_file(runner_binary, runner_digest) as (executable, inherited),
        ):
            if inherited:
                raise AdSmbError("AD Windows launch must not inherit extra descriptors.")
            system = containment.system_directory().parent
            environment = {
                "SYSTEMROOT": str(system),
                "WINDIR": str(system),
                "TEMP": str(root),
                "TMP": str(root),
                "LC_ALL": "C",
                "LANG": "C",
            }
            job = containment.create_job()
            process = subprocess.Popen(  # nosec B603 - pinned fixed worker, no shell or ambient environment
                [executable, "ad-smb-worker"],
                cwd=root,
                env=environment,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                bufsize=0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004),
            )
            containment.assign(job, process)
            assigned = True
            containment.resume_suspended(process)
            return _supervise(
                process,
                containment,
                packet,
                credential,
                revalidate_original,
                cancellation_event,
                started=started,
            )
    except Exception:
        cleanup = process is None
        if process is not None:
            try:
                if assigned:
                    cleanup = containment.terminate(process)
                else:
                    # It has not been resumed; assign() also attempts this
                    # bounded cleanup on failure, but its result is rechecked.
                    process.kill()
                    process.wait(timeout=5)
                    cleanup = process.poll() is not None
            except Exception:
                cleanup = False
        if job is not None and not assigned:
            cleanup = containment.close_handle(job) and cleanup
        if process is not None:
            cleanup = _close_pipes(process) and cleanup
        return WorkerOutcome(
            None, "not_started", "verified" if cleanup else "unknown", "launch_refused"
        )
