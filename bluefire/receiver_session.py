"""Own one fixed Linux receiver worker and its independent terminal observation."""

from __future__ import annotations

import os
import secrets
import subprocess  # nosec B404
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, cast

from .receiver_session_channel import read_frame, require_eof, write_frame
from .receiver_session_contract import (
    SESSION_SECONDS,
    ReceiverSessionError,
    exact,
    prepare_frame,
    task_frame,
    validate_ready,
    validate_terminal,
    worker_generation,
)
from .runner_bootstrap import managed_product_root
from .runner_client import _pinned_launch_file
from .runner_linux_containment import LinuxPrivateProcessContainment
from .runner_transport_errors import RunnerTransportError
from .util import content_hash, file_hash

_RETAINED: dict[str, OwnedReceiverSession] = {}
_RETAINED_LOCK = threading.Lock()


def reconcile_retained_receiver_sessions() -> Mapping[str, int]:
    """Retry only exact child objects retained after a failed cleanup."""
    with _RETAINED_LOCK:
        sessions = tuple(_RETAINED.values())
    reconciled = sum(session.close() for session in sessions)
    with _RETAINED_LOCK:
        remaining = len(_RETAINED)
    return {"reconciled": reconciled, "remaining": remaining}


def _spawn_owned_worker(
    launch_id: str, process_sink: list[subprocess.Popen[bytes]]
) -> subprocess.Popen[bytes]:
    if process_sink:
        raise ReceiverSessionError("owned receiver process sink is already occupied")
    interpreter = Path(sys.executable).resolve(strict=True)
    worker = Path(__file__).resolve(strict=True).with_name("receiver_session_worker.py")
    environment = {
        "HOME": str(Path.home().resolve(strict=True)),
        "XDG_STATE_HOME": str(managed_product_root().parent.resolve(strict=True)),
        "LANG": "C",
        "LC_ALL": "C",
    }
    # Only these installed inodes and this exact grammar may be launched.
    with (
        _pinned_launch_file(interpreter, file_hash(interpreter)) as (executable, exec_fds),
        _pinned_launch_file(worker, file_hash(worker)) as (script, script_fds),
    ):
        process = cast(subprocess.Popen[bytes], subprocess.Popen.__new__(subprocess.Popen))
        process_sink.append(process)  # Retain ownership even if construction is interrupted.
        subprocess.Popen.__init__(
            process,
            [str(interpreter), "-I", script, "--parent", str(os.getpid()), "--launch", launch_id],
            executable=executable,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=tuple(sorted(set(exec_fds + script_fds))),
            start_new_session=True,
            env=environment,
            bufsize=0,
        )
        return process


class OwnedReceiverSession:
    """Single-use review identity; no process/evidence reconstruction from callers."""

    def __init__(self) -> None:
        self._launch_id = secrets.token_hex(32)
        self._process: subprocess.Popen[bytes] | None = None
        self._containment = LinuxPrivateProcessContainment()
        self._process_lock = threading.Lock()
        self._changed = threading.Condition(threading.RLock())
        self._binding: dict[str, Any] | None = None
        self._task: dict[str, Any] | None = None
        self._bound = False
        self._finished = False
        self._failure: str | None = None
        self._observation: Mapping[str, Any] | None = None
        self._monitor_thread: threading.Thread | None = None

    @classmethod
    def prepare(
        cls,
        policy_id: str,
        *,
        port: int = 4317,
        _owner_sink: list[OwnedReceiverSession] | None = None,
    ) -> OwnedReceiverSession:
        if _owner_sink:
            raise ReceiverSessionError("owned receiver attempt sink is already occupied")
        if not sys.platform.startswith("linux") or not LinuxPrivateProcessContainment.available():
            raise ReceiverSessionError("owned receiver sessions require Linux pidfd containment")
        session = cls()
        if _owner_sink is not None:
            _owner_sink.append(session)  # Exact attempt retained before any possible launch.
        spawned: list[subprocess.Popen[bytes]] = []
        prepared = prepare_frame(
            launch_id=session._launch_id,
            policy_id=policy_id,
            port=port,
            generation=worker_generation(),
            deadline_ns=time.monotonic_ns() + SESSION_SECONDS * 1_000_000_000,
            expires_at_ms=time.time_ns() // 1_000_000 + SESSION_SECONDS * 1000,
        )
        try:
            process = _spawn_owned_worker(session._launch_id, spawned)
            session._process = process
            session._containment.register(process)
            identity = session._containment.process_identity(process.pid)
            if process.stdin is None or process.stdout is None:
                raise ReceiverSessionError("owned receiver channel is unavailable")
            deadline = time.monotonic_ns() + 10_000_000_000
            armed = exact(
                read_frame(process.stdout.fileno(), deadline_ns=deadline),
                {"kind", "launch_id", "process_id", "parent_process_id"},
            )
            if dict(armed) != {
                "kind": "armed",
                "launch_id": session._launch_id,
                "process_id": process.pid,
                "parent_process_id": os.getpid(),
            }:
                raise ReceiverSessionError("owned receiver did not establish parent-death binding")
            write_frame(process.stdin.fileno(), prepared)
            session._binding = validate_ready(
                read_frame(process.stdout.fileno(), deadline_ns=deadline),
                prepared,
                process_id=process.pid,
                creation_identity=str(identity[1]),
            )
            if time.monotonic_ns() >= prepared["deadline_ns"]:
                raise ReceiverSessionError("owned receiver readiness expired")
            session._monitor_thread = threading.Thread(
                target=session._monitor, name="bluefire-owned-receiver", daemon=True
            )
            session._monitor_thread.start()
            return session
        except BaseException:
            if session._process is None and spawned:
                session._process = spawned[0]
            session.close()
            raise

    @property
    def review_binding(self) -> Mapping[str, Any]:
        with self._changed:
            if self._binding is None:
                raise ReceiverSessionError("owned receiver readiness is unavailable")
            # Return a deep copy so a caller cannot replace review authority.
            import copy

            return copy.deepcopy(self._binding)

    def require_current(self, review_digest: str) -> None:
        """Check retained live ownership; persisted process metadata grants no authority."""
        with self._process_lock:
            with self._changed:
                binding, process = self._binding, self._process
                if (
                    binding is None
                    or binding["review_digest"] != review_digest
                    or time.monotonic_ns() >= binding["deadline_ns"]
                    or self._finished
                    or self._failure is not None
                    or process is None
                    or not self._containment.contains(process)
                    or process.poll() is not None
                    or worker_generation() != binding["worker_generation"]
                ):
                    raise ReceiverSessionError("owned receiver review is no longer current")

    def bind_task(self, task_id: str, *, digest: str, size: int, review_digest: str) -> None:
        try:
            with self._changed:
                if (
                    self._binding is None
                    or self._task is not None
                    or self._finished
                    or self._failure is not None
                ):
                    raise ReceiverSessionError(
                        "owned receiver task binding is unavailable or consumed"
                    )
                if worker_generation() != self._binding["worker_generation"]:
                    raise ReceiverSessionError("owned receiver worker generation changed")
                task = task_frame(
                    self._binding,
                    task_id=task_id,
                    digest=digest,
                    size=size,
                    review_digest=review_digest,
                    now_ns=time.monotonic_ns(),
                )
                self._task = task  # Never retry an ambiguous write or reuse this capability.
                process = self._process
                if process is None or process.stdin is None:
                    raise ReceiverSessionError("owned receiver channel is unavailable")
                write_frame(process.stdin.fileno(), task)
                self._changed.wait_for(
                    lambda: self._bound or self._finished or self._failure is not None, timeout=5.0
                )
                if not self._bound or self._finished or self._failure is not None:
                    raise ReceiverSessionError("owned receiver did not acknowledge the exact task")
        except BaseException:
            self.close()
            raise

    def _monitor(self) -> None:
        try:
            process = self._process
            binding = self._binding
            if process is None or process.stdout is None or binding is None:
                raise ReceiverSessionError("owned receiver monitor is unavailable")
            bound = exact(
                read_frame(process.stdout.fileno(), deadline_ns=binding["deadline_ns"]),
                {"kind", "review_digest", "task_digest"},
            )
            with self._changed:
                task = self._task
                if task is None or dict(bound) != {
                    "kind": "bound",
                    "review_digest": binding["review_digest"],
                    "task_digest": content_hash(task),
                }:
                    raise ReceiverSessionError("owned receiver task acknowledgement changed")
                self._bound = True
                self._changed.notify_all()
            terminal = validate_terminal(
                read_frame(
                    process.stdout.fileno(), deadline_ns=binding["deadline_ns"] + 1_000_000_000
                ),
                binding,
                task,
            )
            require_eof(process.stdout.fileno())
            if not self._reconcile(terminate=False) or process.returncode != 0:
                raise ReceiverSessionError("owned receiver exit is unverified")
            with self._changed:
                decision = terminal["decision"]
                self._observation = {
                    "schema_version": "bluefire.owned-receiver-observation.v1",
                    "state": (
                        "verified"
                        if decision is not None and decision["decision"] != "invalid_content"
                        else "insufficient_evidence"
                    ),
                    "review_binding": dict(binding),
                    "task_binding": dict(task),
                    "terminal": dict(terminal),
                    "process_exit": {
                        "process_id": process.pid,
                        "creation_identity": binding["creation_identity"],
                        "returncode": process.returncode,
                        "observed_at_ms": time.time_ns() // 1_000_000,
                    },
                }
        except (Exception, KeyboardInterrupt):
            with self._changed:
                self._failure = "owned receiver observation is unavailable or incomplete"
        finally:
            self._reconcile(terminate=True)
            with self._changed:
                self._finished = True
                self._changed.notify_all()

    def _reconcile(self, *, terminate: bool) -> bool:
        with self._process_lock:
            process = self._process
            if process is None:
                return True
            try:
                stdin = getattr(process, "stdin", None)
                if terminate and stdin is not None and not stdin.closed:
                    stdin.close()
                if self._containment.was_released(process):
                    released = process.returncode is not None
                elif self._containment.contains(process):
                    released = self._containment.release(process, terminate=terminate)
                else:
                    if not getattr(process, "_child_created", True):
                        released = True
                    elif getattr(process, "returncode", None) is not None:
                        released = True
                    else:
                        # Construction may have been interrupted immediately
                        # after the child was created. Pin before signalling it.
                        self._containment.register(process)
                        released = self._containment.release(process, terminate=True)
                if released:
                    for stream in (
                        getattr(process, "stdin", None),
                        getattr(process, "stdout", None),
                    ):
                        if stream is not None and not stream.closed:
                            stream.close()
                    with _RETAINED_LOCK:
                        _RETAINED.pop(self._launch_id, None)
                    return True
            except (OSError, AttributeError, RunnerTransportError, subprocess.SubprocessError):
                pass
            with _RETAINED_LOCK:
                _RETAINED[self._launch_id] = self
            return False

    def wait_observation(self, *, timeout_seconds: float = 10.0) -> Mapping[str, Any]:
        if not 0 <= timeout_seconds <= 15:
            raise ValueError("receiver observation wait must be between zero and fifteen seconds")
        with self._changed:
            self._changed.wait_for(lambda: self._finished, timeout=timeout_seconds)
            if self._observation is None:
                return {
                    "schema_version": "bluefire.owned-receiver-observation.v1",
                    "state": "insufficient_evidence",
                    "reason": self._failure or "receiver observation is pending",
                    "launch_id": self._launch_id,
                }
            import copy

            return copy.deepcopy(self._observation)

    def close(self) -> bool:
        success = self._reconcile(terminate=True)
        thread = self._monitor_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        return success

    def __enter__(self) -> OwnedReceiverSession:
        return self

    def __exit__(self, *_args: Any) -> None:
        if not self.close():
            raise ReceiverSessionError("owned receiver cleanup requires reconciliation")
