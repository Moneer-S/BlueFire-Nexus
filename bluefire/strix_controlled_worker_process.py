"""Supervise one fixed Strix worker fixture over private pipes.

The controller owns the child, both pipe ends, and a fresh channel nonce. This
module proves local process framing and three typed, inert fixture dispatches.
It does not accept a caller transport or launch Strix, Docker, a model, or a
recovery path. The caller must have checked claim, plan, and fence custody
first. POSIX cleanup owns the fixture's new process group. The Python source
and interpreter are trusted development inputs, not pinned launch files.

The inert fixture handler runs in this controller process. Cleanup waits for
it to settle after stopping the child, including under repeated cancellation.
"""

from __future__ import annotations

import asyncio
import math
import os
import queue
import re
import secrets
import signal
import subprocess  # nosec B404 - fixed isolated Python fixture only
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any, Iterator, Protocol

# An isolated script has no script directory on sys.path. Add only this fixed
# sibling's package parent; neither an environment variable nor argv selects it.
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "bluefire"

from . import strix_controlled_backend as backend  # noqa: E402
from . import strix_controlled_worker_channel as channel  # noqa: E402

_BOOTSTRAP_VERSION = "bluefire.strix-controlled-worker-bootstrap.v1"
_SCRIPT = Path(__file__).resolve()
_MAX_RUNTIME_SECONDS = 300.0
_POLL_SECONDS = 0.01
_FIXTURE_MODES = frozenset(
    {
        "create",
        "create_exec_cancel",
        "wrong_nonce",
        "wrong_fence",
        "wrong_sequence",
        "replay",
        "oversized_header",
        "partial_header",
        "partial_body",
        "exit",
        "hang",
        "stderr",
        "descendant",
        "resistant_create",
    }
)
_PROFILE_FIELDS = frozenset(field.name for field in fields(backend.ControlledRuntimeProfile))
_BINDING_FIELDS = frozenset(field.name for field in fields(channel.ControlledWorkerBinding))
_FIXTURE_ENVIRONMENT_NAMES = frozenset({"LANG", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"})
_DARWIN_CF_BUNDLE_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_DARWIN_CF_TEXT_ENCODING_VALUE = re.compile(
    r"0x[0-9A-Fa-f]{1,8}:0x[0-9A-Fa-f]{1,8}:0x[0-9A-Fa-f]{1,8}\Z"
)
_DARWIN_VERSIONER_PYTHON_VALUE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}\Z")
_DARWIN_VERSIONER_PREFERENCE_VALUES = frozenset({"0", "1", "false", "no", "true", "yes"})


class CancellationSignal(Protocol):
    def is_set(self) -> bool: ...


class ControlledWorkerProcessError(RuntimeError):
    """Sanitized local process refusal with no child or effect exception text."""


@dataclass(frozen=True, slots=True)
class ControlledWorkerProcessOutcome:
    methods: tuple[str, ...]
    exit_code: int


def _refuse() -> ControlledWorkerProcessError:
    return ControlledWorkerProcessError("controlled worker process refused")


def _environment(private_directory: str, windows_root: str | None = None) -> dict[str, str]:
    result = {"LANG": "C.UTF-8"}
    if os.name == "nt":
        if windows_root is None:
            raise _refuse()
        result["SystemRoot"] = windows_root
        result["WINDIR"] = windows_root
        result["TEMP"] = private_directory
        result["TMP"] = private_directory
    return result


def _darwin_injected_environment_value_is_valid(name: str, value: str) -> bool:
    """Recognize only bounded values injected by the Darwin process runtime."""

    if not value or len(value) > 255 or not value.isascii():
        return False
    if name == "__CFBundleIdentifier":
        return _DARWIN_CF_BUNDLE_VALUE.fullmatch(value) is not None
    if name == "__CF_USER_TEXT_ENCODING":
        return _DARWIN_CF_TEXT_ENCODING_VALUE.fullmatch(value) is not None
    if name == "VERSIONER_PYTHON_VERSION":
        return _DARWIN_VERSIONER_PYTHON_VALUE.fullmatch(value) is not None
    if name == "VERSIONER_PYTHON_PREFER_32_BIT":
        return value.lower() in _DARWIN_VERSIONER_PREFERENCE_VALUES
    if name == "LC_CTYPE":
        return value == "UTF-8"
    return False


def _fixture_environment_is_valid(environment: Mapping[str, str], platform: str) -> bool:
    for name, value in environment.items():
        if name.upper() in _FIXTURE_ENVIRONMENT_NAMES:
            continue
        if platform == "darwin" and _darwin_injected_environment_value_is_valid(name, value):
            continue
        return False
    return True


@contextmanager
def _private_directory() -> Iterator[str]:
    try:
        directory = tempfile.TemporaryDirectory(prefix="bluefire-strix-worker-")
    except OSError:
        directory = None
    if directory is None:
        raise ControlledWorkerProcessError("controlled worker process cleanup uncertain")
    try:
        yield directory.name
    finally:
        try:
            directory.cleanup()
        except OSError:
            cleanup_failed = True
        else:
            cleanup_failed = False
        if cleanup_failed:
            raise ControlledWorkerProcessError("controlled worker process cleanup uncertain")


def _read_exact(descriptor: int, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = os.read(descriptor, min(65536, size - len(result)))
        if not part:
            raise EOFError
        result.extend(part)
    return bytes(result)


def _read_frame(descriptor: int) -> bytes | None:
    first = os.read(descriptor, 4)
    if not first:
        return None
    if len(first) < 4:
        first += _read_exact(descriptor, 4 - len(first))
    size = int.from_bytes(first, "little")
    if not 0 < size <= channel.MAX_FRAME_BYTES:
        raise ValueError
    return first + _read_exact(descriptor, size)


def _write_frame(descriptor: int, frame: bytes) -> None:
    view = memoryview(frame)
    while view:
        count = os.write(descriptor, view[:65536])
        if not 0 < count <= len(view):
            raise OSError
        view = view[count:]


class _Pipes:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdin is None or process.stdout is None:
            raise _refuse()
        self.process = process
        self.events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=4)
        self.outbound: queue.Queue[bytes] = queue.Queue(maxsize=4)
        self.stop = threading.Event()
        self.reader = threading.Thread(
            target=self._read, name="strix-worker-pipe-reader", daemon=True
        )
        self.writer = threading.Thread(
            target=self._write, name="strix-worker-pipe-writer", daemon=True
        )

    def _offer(self, kind: str, payload: bytes | None = None) -> None:
        while not self.stop.is_set():
            try:
                self.events.put((kind, payload), timeout=0.05)
                return
            except queue.Full:
                continue

    def _read(self) -> None:
        assert self.process.stdout is not None
        descriptor = self.process.stdout.fileno()
        try:
            while not self.stop.is_set():
                frame = _read_frame(descriptor)
                if frame is None:
                    self._offer("eof")
                    return
                self._offer("frame", frame)
        except (EOFError, OSError, ValueError):
            self._offer("partial")

    def _write(self) -> None:
        assert self.process.stdin is not None
        descriptor = self.process.stdin.fileno()
        while not self.stop.is_set():
            try:
                frame = self.outbound.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                _write_frame(descriptor, frame)
            except (OSError, ValueError):
                self._offer("write_failed")
                return
            self._offer("written")

    def start(self) -> None:
        self.reader.start()
        self.writer.start()

    def send(self, frame: bytes) -> None:
        try:
            self.outbound.put_nowait(frame)
        except queue.Full:
            full = True
        else:
            full = False
        if full:
            raise _refuse()


def _terminate(process: subprocess.Popen[bytes]) -> bool:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=2)
        return process.poll() is not None
    except (OSError, subprocess.SubprocessError):
        return False


def _reap_terminated(process: subprocess.Popen[bytes]) -> bool:
    try:
        process.wait(timeout=0.3)
    except subprocess.TimeoutExpired:
        return _terminate(process)
    except (OSError, subprocess.SubprocessError):
        return False
    return process.poll() is not None


def _terminate_posix_group(process: subprocess.Popen[bytes]) -> bool:
    """Stop the child-owned session before reaping its leader."""
    if os.name == "nt":
        return False
    kill_group = getattr(os, "killpg", None)
    sigkill = getattr(signal, "SIGKILL", None)
    if kill_group is None or sigkill is None:
        return False
    clean = True
    for sig in (signal.SIGTERM, sigkill):
        try:
            kill_group(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            clean = False
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        clean = False
    return clean and process.poll() is not None


def _cleanup(
    process: subprocess.Popen[bytes] | None,
    pipes: _Pipes | None,
    containment: Any,
    job: int | None,
    assigned: bool,
    creation_started: bool,
) -> bool:
    if process is None:
        job_closed = job is None or bool(containment.close_handle(job))
        return job_closed and not creation_started
    clean = True
    if os.name == "nt" and containment is not None:
        if assigned:
            try:
                clean = bool(containment.finish(process))
            except Exception:
                clean = False
            if not clean:
                try:
                    clean = bool(containment.terminate(process))
                except Exception:
                    clean = False
            if not clean:
                # A failed Job drain still requires a best-effort direct-child
                # kill and release of the owned kill-on-close Job handle. This
                # never upgrades an unconfirmed drain to verified.
                _terminate(process)
                try:
                    containment._release_job(process.pid)
                except Exception:
                    pass
            else:
                clean = _reap_terminated(process)
        else:
            clean = _terminate(process)
            if job is not None:
                clean = bool(containment.close_handle(job)) and clean
    else:
        clean = _terminate_posix_group(process)
    if pipes is not None:
        pipes.stop.set()
        for thread in (pipes.reader, pipes.writer):
            if thread.ident is not None:
                thread.join(timeout=2)
            clean = not thread.is_alive() and clean
    if pipes is None or (not pipes.reader.is_alive() and not pipes.writer.is_alive()):
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    clean = False
    return clean


class _InertFixtureTransport:
    """Exactly three deterministic, non-executing controller fixture methods."""

    def __init__(self, profile: backend.ControlledRuntimeProfile, mode: str) -> None:
        self.profile = profile
        self.mode = mode
        self.handle = backend.ControlledSandboxHandle(
            attempt_id=profile.attempt_id,
            resource_id="sandbox-" + "b" * 32,
            resource_digest="sha256:" + "c" * 64,
            opaque_ref=object(),
        )
        self.cancel_seen = asyncio.Event()

    async def create_exact(
        self, request: backend.ControlledCreateRequest
    ) -> backend.ControlledCreateReceipt:
        if self.mode == "resistant_create":
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                await asyncio.sleep(0.25)
                raise
        return backend.ControlledCreateReceipt(
            schema_version="bluefire.strix-controlled-create-receipt.v1",
            request_digest=request.request_digest,
            identity_digest=self.profile.identity_digest,
            handle=self.handle,
            lifecycle="running",
        )

    async def exec_exact(
        self, request: backend.ControlledExecRequest
    ) -> backend.ControlledExecReceipt:
        await self.cancel_seen.wait()
        output = b"fixture"
        return backend.ControlledExecReceipt(
            schema_version="bluefire.strix-controlled-exec-receipt.v1",
            request_digest=request.request_digest,
            identity_digest=self.profile.identity_digest,
            resource_digest=self.handle.resource_digest,
            exit_code=0,
            stdout_digest=backend._sha256_bytes(output),
            stderr_digest=backend._sha256_bytes(b""),
            stdout=output,
            stderr=b"",
        )

    async def cancel_exact(
        self, request: backend.ControlledLifecycleRequest
    ) -> backend.ControlledLifecycleReceipt:
        self.cancel_seen.set()
        return backend.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            request_digest=request.request_digest,
            identity_digest=self.profile.identity_digest,
            resource_digest=self.handle.resource_digest,
            lifecycle="cancelled",
            relay_lifecycle="active",
            operation_lifecycle="terminal",
        )


def _calls(transport: _InertFixtureTransport) -> dict[str, Any]:
    # The fixture never dispatches an injected host method or a general RPC.
    return {
        "create_exact": transport.create_exact,
        "exec_exact": transport.exec_exact,
        "cancel_exact": transport.cancel_exact,
    }


async def run_controlled_worker_fixture(
    profile: backend.ControlledRuntimeProfile,
    *,
    claim_digest: str,
    plan_digest: str,
    controller_fence: str,
    timeout_seconds: float = 5.0,
    cancel_event: CancellationSignal | None = None,
    fixture_mode: str = "create",
) -> ControlledWorkerProcessOutcome:
    """Run only the fixed fixture script with a controller-created private channel.

    The caller supplies already-verified claim/plan/fence digests. No admission
    check or live backend is synthesized here. Only the fixed inert controller
    fixture methods can be reached from this entry point.
    """
    if (
        type(profile) is not backend.ControlledRuntimeProfile
        or type(fixture_mode) is not str
        or fixture_mode not in _FIXTURE_MODES
        or (os.name == "nt" and fixture_mode == "descendant")
        or type(timeout_seconds) not in (float, int)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= _MAX_RUNTIME_SECONDS
    ):
        raise _refuse()
    started = time.monotonic_ns()
    deadline = started + int(timeout_seconds * 1_000_000_000)
    preflight_valid = True
    try:
        binding = channel.ControlledWorkerBinding(
            attempt_id=profile.attempt_id,
            claim_digest=claim_digest,
            plan_digest=plan_digest,
            profile_digest=profile.profile_digest,
            identity_digest=profile.identity_digest,
            controller_fence=controller_fence,
            deadline_ns=deadline,
            nonce=secrets.token_hex(16),
        )
        controller = channel.ControllerChannel(profile, binding)
        transport = _InertFixtureTransport(profile, fixture_mode)
        calls = _calls(transport)
        bootstrap = channel.encode_frame(
            {
                "schema_version": _BOOTSTRAP_VERSION,
                "profile": asdict(profile),
                "binding": binding.wire(),
            }
        )
    except (channel.ControlledWorkerChannelError, AttributeError, TypeError, ValueError):
        preflight_valid = False
    if not preflight_valid:
        raise _refuse()
    if cancel_event is not None and cancel_event.is_set():
        raise ControlledWorkerProcessError("controlled worker process cancelled")

    process: subprocess.Popen[bytes] | None = None
    pipes: _Pipes | None = None
    containment: Any = None
    job: int | None = None
    assigned = False
    creation_started = False
    failure: ControlledWorkerProcessError | None = None
    outcome: ControlledWorkerProcessOutcome | None = None
    tasks: dict[str, asyncio.Task[Any]] = {}
    methods: list[str] = []
    writes_pending = 0
    eof_seen = False
    with _private_directory() as private_dir:
        try:
            flags = 0
            windows_root: str | None = None
            if os.name == "nt":
                from .runner_windows_containment import WindowsJobContainment

                containment = WindowsJobContainment(kill_on_close=True)
                job = containment.create_job()
                windows_root = str(containment.system_directory().parent)
                flags = (
                    getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                    | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
                )
            creation_started = True
            process = subprocess.Popen(  # nosec B603 - fixed isolated fixture script
                [
                    getattr(sys, "_base_executable", sys.executable),
                    "-I",
                    "-B",
                    str(_SCRIPT),
                    fixture_mode,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=private_dir,
                env=_environment(private_dir, windows_root),
                close_fds=True,
                shell=False,
                bufsize=0,
                creationflags=flags,
                start_new_session=os.name != "nt",
            )
            if containment is not None:
                containment.assign(job, process)
                assigned = True
                containment.resume_suspended(process)
            pipes = _Pipes(process)
            pipes.start()
            pipes.send(bootstrap)
            writes_pending += 1
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    controller.abandon()
                    raise ControlledWorkerProcessError("controlled worker process cancelled")
                if time.monotonic_ns() >= deadline:
                    controller.timeout()
                    raise ControlledWorkerProcessError("controlled worker process timed out")
                for request_id, task in tuple(tasks.items()):
                    if not task.done():
                        continue
                    del tasks[request_id]
                    if task.cancelled() or task.exception() is not None:
                        controller.abandon()
                        raise _refuse()
                    response = controller.response(
                        request_id, task.result(), now_ns=time.monotonic_ns()
                    )
                    pipes.send(response)
                    writes_pending += 1
                try:
                    event = pipes.events.get_nowait()
                except queue.Empty:
                    event = None
                if event is None:
                    if eof_seen and process.poll() is not None:
                        if process.returncode != 0 or controller.pending_count:
                            controller.eof()
                            raise _refuse()
                        if writes_pending:
                            await asyncio.sleep(_POLL_SECONDS)
                            continue
                        controller.eof()
                        outcome = ControlledWorkerProcessOutcome(tuple(methods), process.returncode)
                        break
                    await asyncio.sleep(_POLL_SECONDS)
                    continue
                kind, payload = event
                if kind == "written":
                    writes_pending -= 1
                    if writes_pending < 0:
                        controller.partial()
                        raise _refuse()
                elif kind == "frame":
                    if payload is None or eof_seen:
                        controller.partial()
                        raise _refuse()
                    method, request_id, request = controller.request(
                        payload, now_ns=time.monotonic_ns()
                    )
                    methods.append(method)
                    tasks[request_id] = asyncio.create_task(calls[method](request))
                elif kind == "eof":
                    eof_seen = True
                    if controller.pending_count:
                        controller.eof()
                        raise _refuse()
                else:
                    controller.partial()
                    raise _refuse()
            expected = (
                ("create_exact", "exec_exact", "cancel_exact")
                if fixture_mode == "create_exec_cancel"
                else ("create_exact",)
            )
            if tuple(methods) != expected:
                raise _refuse()
        except asyncio.CancelledError:
            controller.abandon()
            failure = ControlledWorkerProcessError("controlled worker process cancelled")
        except ControlledWorkerProcessError as exc:
            controller.abandon()
            failure = exc
        except channel.ControlledWorkerChannelError:
            controller.abandon()
            failure = _refuse()
        except BaseException:
            controller.abandon()
            failure = _refuse()
        finally:
            for task in tasks.values():
                task.cancel()
            try:
                clean = _cleanup(process, pipes, containment, job, assigned, creation_started)
            except BaseException:
                clean = False
            if tasks:
                remaining = set(tasks.values())
                while remaining:
                    try:
                        _done, remaining = await asyncio.wait(remaining, timeout=0.05)
                    except asyncio.CancelledError:
                        # A second caller cancellation must not release live
                        # controller effects into the background.
                        continue
                for task in tasks.values():
                    if not task.cancelled():
                        task.exception()
    if not clean:
        raise ControlledWorkerProcessError("controlled worker process cleanup uncertain") from None
    if failure is not None:
        raise failure from None
    if outcome is None:
        raise _refuse()
    return outcome


def _fixture_request(method: str, profile: backend.ControlledRuntimeProfile, **values: Any) -> Any:
    spec = channel.METHODS[method]
    draft = spec.request_type(
        schema_version=f"bluefire.strix-controlled-{spec.kind}-request.v1",
        request_digest="sha256:" + "0" * 64,
        identity_digest=profile.identity_digest,
        **values,
    )
    digest = backend._request_digest(spec.kind, profile, channel._request_body(spec, draft))
    return replace(draft, request_digest=digest)


def _fixture_main() -> int:
    # This entry is fixed and intentionally has no general command or import.
    if len(sys.argv) != 2 or sys.argv[1] not in _FIXTURE_MODES:
        return 2
    if not _fixture_environment_is_valid(os.environ, sys.platform):
        return 3
    try:
        bootstrap_frame = _read_frame(sys.stdin.fileno())
        if bootstrap_frame is None:
            return 4
        bootstrap = channel.decode_frame(bootstrap_frame)
        if (
            set(bootstrap) != {"schema_version", "profile", "binding"}
            or bootstrap["schema_version"] != _BOOTSTRAP_VERSION
            or type(bootstrap["profile"]) is not dict
            or set(bootstrap["profile"]) != _PROFILE_FIELDS
            or type(bootstrap["binding"]) is not dict
            or set(bootstrap["binding"]) != _BINDING_FIELDS
        ):
            return 4
        profile = backend.ControlledRuntimeProfile(**bootstrap["profile"])
        binding = channel.ControlledWorkerBinding(**bootstrap["binding"])
        worker = channel.WorkerChannel(profile, binding)
        mode = sys.argv[1]
        if mode == "exit":
            return 5
        if mode == "hang":
            time.sleep(_MAX_RUNTIME_SECONDS + 1)
            return 6
        if mode == "stderr":
            os.write(sys.stderr.fileno(), b"SENSITIVE_CHILD_TEXT" * 65536)
            return 7
        if mode == "descendant":
            subprocess.Popen(  # nosec B603 - fixed sleeping fixture descendant
                [
                    getattr(sys, "_base_executable", sys.executable),
                    "-I",
                    "-B",
                    "-c",
                    "import time; time.sleep(60)",
                ],
                stdin=subprocess.DEVNULL,
                stdout=sys.stdout,
                stderr=subprocess.DEVNULL,
                env={},
                close_fds=True,
                shell=False,
                cwd=os.getcwd(),
            )
            _write_frame(sys.stdout.fileno(), b"\x08\x00")
            return 0
        if mode == "oversized_header":
            _write_frame(sys.stdout.fileno(), (channel.MAX_FRAME_BYTES + 1).to_bytes(4, "little"))
            return 0
        if mode == "partial_header":
            _write_frame(sys.stdout.fileno(), b"\x08\x00")
            return 0
        if mode == "partial_body":
            _write_frame(sys.stdout.fileno(), b"\x08\x00\x00\x00{}")
            return 0
        create = backend.ControlledCreateRequest.create(profile)
        frame = worker.request(
            "create_exact", create, request_id="1" * 32, now_ns=time.monotonic_ns()
        )
        if mode in {"wrong_nonce", "wrong_fence", "wrong_sequence"}:
            envelope = channel.decode_frame(frame)
            if mode == "wrong_nonce":
                envelope["binding"]["nonce"] = "0" * 32
            elif mode == "wrong_fence":
                envelope["binding"]["controller_fence"] = "sha256:" + "0" * 64
            else:
                envelope["sequence"] = 2
            frame = channel.encode_frame(envelope)
        _write_frame(sys.stdout.fileno(), frame)
        if mode == "replay":
            _write_frame(sys.stdout.fileno(), frame)
            return 0
        if mode in {"wrong_nonce", "wrong_fence", "wrong_sequence"}:
            return 0
        response = _read_frame(sys.stdin.fileno())
        if response is None:
            return 8
        _method, _request_id, receipt = worker.response(response, now_ns=time.monotonic_ns())
        if mode == "create_exec_cancel":
            handle = receipt.handle
            execution = _fixture_request(
                "exec_exact",
                profile,
                operation_id="operation-" + "e" * 32,
                handle=handle,
                argv=("echo", "fixture"),
                timeout_seconds=120.0,
                working_directory="/workspace",
                stdin_mode="disabled",
                pty=False,
            )
            cancellation = _fixture_request(
                "cancel_exact",
                profile,
                attempt_id=profile.attempt_id,
                relay_digest=profile.relay_digest,
                relay_upstream_digest=profile.relay_upstream_digest,
                relay_channel_digest=profile.relay_channel_digest,
                relay_retry_digest=profile.relay_retry_digest,
                observation_id=None,
                handle=handle,
                operation_digest=execution.request_digest,
            )
            _write_frame(
                sys.stdout.fileno(),
                worker.request(
                    "exec_exact",
                    execution,
                    request_id="2" * 32,
                    now_ns=time.monotonic_ns(),
                ),
            )
            _write_frame(
                sys.stdout.fileno(),
                worker.request(
                    "cancel_exact",
                    cancellation,
                    request_id="3" * 32,
                    now_ns=time.monotonic_ns(),
                ),
            )
            for _ in range(2):
                next_response = _read_frame(sys.stdin.fileno())
                if next_response is None:
                    return 8
                worker.response(next_response, now_ns=time.monotonic_ns())
        return 0
    except (OSError, EOFError, ValueError, TypeError, backend.ControlledBackendError):
        return 9


if __name__ == "__main__":
    raise SystemExit(_fixture_main())
