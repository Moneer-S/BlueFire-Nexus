"""One fixed setup child under a retained Job for the explicit local CLI.

The original five-second work interval never restarts. Cleanup gets a separate
bounded allowance and unresolved ownership is retained, never called settled.
Stopping processes does not remove or reconcile accounts or published objects.
"""

from __future__ import annotations

import contextlib
import os
import stat
import struct
import subprocess  # nosec B404
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _windows_file_access_native_contract as contract
from . import _windows_file_access_setup_binding as binding
from . import windows_file_access_admission as admission
from . import windows_file_access_child as child
from . import windows_file_access_setup_child as entry
from .runner_client import _pinned_launch_file
from .runner_private_files import _is_link_or_reparse
from .runner_trust import _PinnedDirectory
from .runner_windows_containment import WindowsJobContainment
from .util import canonical_json_bytes, file_hash

_CLEANUP_SECONDS = 2.0
_STAGES = frozenset(
    "authority preflight bootstrap_storage original_intent account_creation account_receipt "
    "resource_creation credential_protection protected_receipt enrollment_publication "
    "anchor_publication cleanup".split()
)


@dataclass(frozen=True)
class SetupProcessOutcome:
    terminal: dict[str, Any] | None = field(repr=False)
    dispatch: str
    process_cleanup: str
    issue: str | None
    cleanup_owner: SetupCleanupOwner | None = field(repr=False)
    settled: bool = field(default=False, init=False)


def _terminal(raw: bytes, returncode: int) -> dict[str, Any]:
    return _terminal_for(raw, returncode, admission._READER_SETUP)


def _terminal_for(
    raw: bytes, returncode: int, protocol: admission._SetupProtocol
) -> dict[str, Any]:
    admission._setup_protocol(protocol)
    row = contract._document(raw, entry.OUTPUT_MAX)
    contract._exact(row, "schema_version result error")
    contract._require(row["schema_version"] == protocol.schema("setup-child-result"))
    if row["result"] is not None:
        result = contract._exact(
            row["result"],
            "schema_version generation setup_receipt_digest publication context_available "
            "account_cleanup_required external_hard_deadline_required settled",
        )
        contract._require(returncode == 0 and row["error"] is None)
        contract._hex(result["generation"], 32)
        contract._digest(result["setup_receipt_digest"])
        contract._require(
            result["schema_version"] == protocol.schema("local-setup-result")
            and result["publication"] == "complete"
            and result["context_available"] is False
            and result["account_cleanup_required"] is True
            and result["external_hard_deadline_required"] is True
            and result["settled"] is False
        )
    else:
        contract._require(returncode == 4)
        if row["error"] is not None:
            error = contract._exact(row["error"], "stage bootstrap_mutated intent_persisted")
            contract._require(
                error["stage"] in _STAGES
                and type(error["bootstrap_mutated"]) is bool
                and type(error["intent_persisted"]) is bool
                and (not error["intent_persisted"] or error["bootstrap_mutated"])
            )
    return row


class SetupCleanupOwner:
    """Retain exact process, Job, pins and pipes; retries only attempt closure."""

    def __init__(
        self, profile: str, cancellation: threading.Event, *, _protocol=admission._READER_SETUP
    ) -> None:
        admission._setup_protocol(_protocol)
        self.protocol = _protocol
        self.cancellation = cancellation
        self.issued = time.time_ns() // 1_000_000
        self.deadline = time.monotonic_ns() + entry.INTERVAL_MS * 1_000_000
        self.request = canonical_json_bytes(
            {
                "schema_version": self.protocol.schema("setup-child-request"),
                "profile_id": profile,
                "confirm_create": True,
                "original_issued_at_ms": self.issued,
                "original_deadline_ns": self.deadline,
                "supervision": None,
            }
        )
        self.containment = WindowsJobContainment(kill_on_close=True)
        self.pins = contextlib.ExitStack()
        self.process: subprocess.Popen[bytes] | None = None
        self.job: int | None = None
        self.handle: Any = None
        self.pid: int | None = None
        self.adopted = self.resumed = self.verified = False
        self.parent_exited = self.job_closed = self.start_closed = self.handle_closed = False
        self.handle_ambiguous = False
        self.pins_closed = self.pins_ambiguous = False
        self.closed_pipes: set[str] = set()
        self.ambiguous_pipes: set[str] = set()
        self.pipe_fds: set[int] = set()
        self.fd_ambiguous = False
        self.parent_pipes: dict[str, Any] = {}
        self.stopped, self.done, self.errors_done = (threading.Event() for _ in range(3))
        self.exchange: threading.Thread | None = None
        self.errors: threading.Thread | None = None
        self.closer: threading.Thread | None = None
        self.lock = threading.Lock()
        self.issue: str | None = None
        self.terminal: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return "<WindowsSetupCleanupOwner retained>"

    def current(self) -> None:
        if self.stopped.is_set() or self.issue is not None:
            raise RuntimeError("Setup stopped")
        if self.cancellation.is_set():
            self.issue = "cancelled"
            raise RuntimeError("Setup cancelled")
        if (
            time.monotonic_ns() >= self.deadline
            or not self.issued <= time.time_ns() // 1_000_000 < self.issued + entry.INTERVAL_MS
        ):
            self.issue = "deadline"
            raise RuntimeError("Original setup interval ended")

    def _handle(self) -> int:
        process = self.process
        contract._require(
            process is not None
            and process.pid == self.pid
            and self.handle is getattr(process, "_handle", None)
            and isinstance(self.handle, int)
            and not isinstance(self.handle, bool)
            and 0 < int(self.handle) < (1 << (struct.calcsize("P") * 8)) - 0x10000
            and getattr(self.handle, "closed", None) is False
            and callable(getattr(self.handle, "Close", None))
        )
        return int(self.handle)

    def _launch(self) -> None:
        root = entry._managed_root().resolve(strict=True)
        self.pins.enter_context(_PinnedDirectory(root, private=True, verify_permissions_only=True))
        runtime = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        script = Path(__file__).resolve(strict=True).with_name("windows_file_access_setup_child.py")
        for path in (runtime, script):
            details = path.lstat()
            contract._require(
                path.is_absolute()
                and stat.S_ISREG(details.st_mode)
                and details.st_nlink == 1
                and not _is_link_or_reparse(path)
            )
        executable, inherited = self.pins.enter_context(
            _pinned_launch_file(runtime, file_hash(runtime))
        )
        helper, extra = self.pins.enter_context(_pinned_launch_file(script, file_hash(script)))
        contract._require(not inherited and not extra)
        system = str(self.containment.system_directory().parent)
        self.current()
        self.job = self.containment.create_job()
        self.current()
        ends = []
        for name in ("stdin", "stdout", "stderr"):
            self.current()
            read, write = os.pipe()
            self.pipe_fds.update((read, write))
            owned, passed = (write, read) if name == "stdin" else (read, write)
            self.parent_pipes[name] = os.fdopen(
                owned, "wb" if name == "stdin" else "rb", buffering=0
            )
            self.pipe_fds.remove(owned)
            ends.append(passed)
        self.current()
        self.process = subprocess.Popen(  # nosec B603 - fixed pinned packaged entry, no shell
            [executable, "-I", "-B", "-X", "utf8", helper]
            + (["--pair-baseline-v2"] if self.protocol is admission._PAIR_SETUP else []),
            cwd=root,
            env={"SYSTEMROOT": system, "WINDIR": system, "TEMP": str(root), "TMP": str(root)},
            stdin=ends[0],
            stdout=ends[1],
            stderr=ends[2],
            shell=False,
            close_fds=True,
            bufsize=0,
            # A hidden console still adds conhost to the single-child Job.
            creationflags=0x00000008 | 0x00000200 | 0x00000004,
        )
        self.handle, self.pid = getattr(self.process, "_handle", None), self.process.pid
        for name, stream in self.parent_pipes.items():
            setattr(self.process, name, stream)
        self.containment.adopt_retained_job(self.job, self.process)
        self.adopted = True
        self.current()
        self.containment.assign_retained(self.job, self.process)
        self.current()
        generation = child.capture_retained_child(self._handle(), self.job, expected_pid=self.pid)
        self.current()
        supervision = binding.transfer_to_child(self._handle(), (ends[0], ends[1], ends[2]))
        row = contract._document(self.request, entry.INPUT_MAX)
        row["supervision"] = supervision
        self.request = canonical_json_bytes(row)
        contract._require(self._close_fds())
        self.current()
        # A failed resume may have taken effect. From here partial effects are unknown.
        self.resumed = True
        self.containment.resume_retained(self.process, self.job, generation)
        self.current()

    def _read(self, stream: Any, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            self.current()
            part = stream.read(size - len(result))
            self.current()
            contract._require(type(part) is bytes and 0 < len(part) <= size - len(result))
            result.extend(part)
        return bytes(result)

    def _stderr(self) -> None:
        try:
            assert self.process is not None and self.process.stderr is not None
            if self.process.stderr.read(1) != b"":
                self.issue = self.issue or "unexpected_stderr"
        except BaseException:
            self.issue = self.issue or "pipe_failed"
        finally:
            self.errors_done.set()

    def _exchange(self) -> None:
        try:
            self.current()
            self._launch()
            process = self.process
            contract._require(process is not None)
            assert process is not None
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise RuntimeError("Setup private pipes are unavailable")
            self.errors = threading.Thread(target=self._stderr, daemon=True, name="setup-stderr")
            self.errors.start()
            data = memoryview(struct.pack("<I", len(self.request)) + self.request)
            while data:
                self.current()
                written = process.stdin.write(data)
                self.current()
                contract._require(type(written) is int and 0 < written <= len(data))
                data = data[written:]
            process.stdin.flush()
            self.current()
            contract._require(self._close_pipe("stdin"))
            size = struct.unpack("<I", self._read(process.stdout, 4))[0]
            contract._require(0 < size <= entry.OUTPUT_MAX)
            raw = self._read(process.stdout, size)
            contract._require(process.stdout.read(1) == b"")
            while not self.errors_done.is_set() or process.poll() is None:
                self.current()
                self.stopped.wait(0.01)
            self.current()
            self.terminal = _terminal_for(raw, process.returncode, self.protocol)
        except BaseException:
            self.issue = self.issue or "setup_refused"
        finally:
            self.done.set()

    def _close_pipe(self, name: str) -> bool:
        if name in self.closed_pipes:
            return True
        stream = self.parent_pipes.get(name, getattr(self.process, name, None))
        if stream is None or name in self.ambiguous_pipes:
            return False
        try:
            stream.close()
            if getattr(stream, "closed", None) is not True:
                return False
            self.closed_pipes.add(name)
            return True
        except Exception:
            if getattr(stream, "closed", None) is True:
                self.ambiguous_pipes.add(name)
            return False

    def _close_fds(self) -> bool:
        for descriptor in list(self.pipe_fds):
            self.pipe_fds.remove(descriptor)
            try:
                os.close(descriptor)
            except Exception:
                # Never retry a raw FD whose close may have succeeded.
                self.fd_ambiguous = True
        return not self.fd_ambiguous

    def _cleanup(self) -> None:
        try:
            process, job = self.process, self.job
            if process is not None:
                try:
                    self._handle()
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=0.5)
                    self.parent_exited = process.poll() is not None
                except Exception:
                    pass
                if self.adopted and job is not None:
                    self.containment.drain_retained(process, job)
            for thread in (self.exchange, self.errors):
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=0.25)
                if thread is not None and thread.is_alive():
                    return
            # Launch may have finished during the join. Never release its Job using
            # an earlier no-child snapshot, and never mistake Job-empty for exit.
            if process is not self.process or job != self.job:
                return
            if process is not None:
                if not self.parent_exited:
                    return
                if not self.job_closed:
                    if not self.adopted or job is None:
                        return
                    self.job_closed = self.containment.finish_retained(process, job) is True
                if not self.job_closed:
                    return
                self.start_closed = self.containment.close_retained_start_handles(process) is True
                if not self.start_closed:
                    return
                if not all([self._close_pipe(name) for name in ("stdin", "stdout", "stderr")]):
                    return
                if self.handle_ambiguous:
                    return
                if not self.handle_closed:
                    self._handle()
                    try:
                        self.handle.Close()
                    except Exception:
                        self.handle_ambiguous = True
                        return
                    if getattr(self.handle, "closed", None) is not True:
                        self.handle_ambiguous = True
                        return
                    self.handle_closed = True
            elif job is not None and not self.job_closed:
                self.job_closed = self.containment.close_handle(job) is True
                if not self.job_closed:
                    return
            pipes_closed = [self._close_pipe(name) for name in self.parent_pipes]
            if not self._close_fds() or not all(pipes_closed):
                return
            if self.pins_ambiguous:
                return
            if not self.pins_closed:
                try:
                    self.pins.close()
                except Exception:
                    self.pins_ambiguous = True
                    return
                self.pins_closed = True
            self.verified = True
        except Exception:
            return

    def retry_cleanup(self) -> bool:
        """Bounded cleanup only; never create, resume, retry setup or renew time."""
        self.stopped.set()
        with self.lock:
            if self.closer is None or (not self.closer.is_alive() and not self.verified):
                self.closer = threading.Thread(
                    target=self._cleanup, daemon=True, name="setup-cleanup"
                )
                self.closer.start()
            closer = self.closer
        closer.join(timeout=_CLEANUP_SECONDS)
        return self.verified and not closer.is_alive()


def run_setup_process(
    profile_id: str, *, cancellation_event: threading.Event
) -> SetupProcessOutcome:
    """Fixed contained entry; publication never establishes runtime admission."""
    return _run_setup_process_for(profile_id, cancellation_event, admission._READER_SETUP)


def run_pair_setup_process(
    profile_id: str, *, cancellation_event: threading.Event
) -> SetupProcessOutcome:
    return _run_setup_process_for(profile_id, cancellation_event, admission._PAIR_SETUP)


def _run_setup_process_for(
    profile_id: str, cancellation_event: threading.Event, protocol: admission._SetupProtocol
) -> SetupProcessOutcome:
    admission._setup_protocol(protocol)
    if sys.platform != "win32":
        raise RuntimeError("Windows contained setup is unavailable")
    contract._identifier(profile_id)
    owner = (
        SetupCleanupOwner(profile_id, cancellation_event)
        if protocol is admission._READER_SETUP
        else SetupCleanupOwner(profile_id, cancellation_event, _protocol=protocol)
    )
    owner.exchange = threading.Thread(target=owner._exchange, daemon=True, name="setup-exchange")
    try:
        owner.current()
        owner.exchange.start()
        while not owner.done.is_set():
            owner.current()
            owner.stopped.wait(0.01)
    except BaseException:
        owner.issue = owner.issue or "setup_refused"
    finally:
        clean = owner.retry_cleanup()
    terminal = owner.terminal if clean and owner.issue is None else None
    unknown = terminal is not None and terminal["result"] is None and terminal["error"] is None
    return SetupProcessOutcome(
        terminal,
        (
            "completed"
            if terminal is not None and not unknown
            else ("unknown" if owner.resumed else "not_started")
        ),
        "verified" if clean else "unknown",
        ("child_outcome_unknown" if unknown else owner.issue) if clean else "cleanup_unknown",
        None if clean else owner,
    )


def setup_windows_file_access_local(profile_id: str) -> dict[str, Any]:
    """Explicit CLI setup only; neither publication nor process exit is admission.

    The contained child derives its lifecycle from the OS-token managed root.
    Unknown cleanup has only this CLI's in-memory lifetime, not durable recovery.
    """
    outcome = run_setup_process(profile_id, cancellation_event=threading.Event())
    return _setup_projection(outcome, admission._READER_SETUP)


def setup_windows_file_baseline_local(profile_id: str) -> dict[str, Any]:
    """Explicit paired setup only; unchanged CLI-lifetime cleanup limitations."""
    outcome = run_pair_setup_process(profile_id, cancellation_event=threading.Event())
    return _setup_projection(outcome, admission._PAIR_SETUP)


def _setup_projection(
    outcome: SetupProcessOutcome, protocol: admission._SetupProtocol
) -> dict[str, Any]:
    admission._setup_protocol(protocol)
    clean = outcome.process_cleanup == "verified" and outcome.cleanup_owner is None
    terminal = outcome.terminal if clean else None
    result = terminal["result"] if terminal is not None else None
    partial = terminal["error"] if terminal is not None else None
    complete = result is not None and outcome.dispatch == "completed" and outcome.issue is None
    cleanup = (
        "required"
        if complete or (partial is not None and partial["bootstrap_mutated"])
        else ("unknown" if outcome.dispatch == "unknown" or not clean else "not_required")
    )
    return {
        "schema_version": protocol.schema("local-setup-command"),
        "dispatch": outcome.dispatch,
        "publication": "complete" if complete else "not_established",
        "result": result if complete else None,
        "partial_state": partial,
        "issue": outcome.issue,
        "process_cleanup": outcome.process_cleanup,
        "cleanup_owner_lifetime": None if clean else "cli_process_only",
        "cleanup_retry_available": False,
        "cleanup_limitation": (
            None
            if clean
            else "Unverified process cleanup is local to this CLI invocation. After CLI exit, "
            "there is no retained retry handle or verified whole-Job closure. Inspect the "
            "original protected intent and receipts; never replay setup to recover."
        ),
        "account_object_cleanup": cleanup,
        "context_available": False,
        "native_read_proof": False,
        "settled": False,
    }
