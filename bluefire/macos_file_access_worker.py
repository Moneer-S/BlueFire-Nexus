"""One fixed creator-owned Darwin primitive, never a custody minter."""

from __future__ import annotations

import os
import socket
import subprocess  # nosec B404
import sys
import threading
import time
from typing import Any, NoReturn, cast

from . import macos_setup_failure_diagnostics as _setup_failure_diagnostics
from . import runner_client as runner
from .macos_file_access_channel import MacOSPrimitiveChannel
from .macos_file_access_contract import (
    MacOSFileAccessContractError,
    decode_request,
    validate_binding,
    validate_request,
)
from .macos_file_access_peer import MacOSChildConsistency, darwin_clock_ns, observe_owned_child
from .runner_darwin_containment import spawn_no_fork_exec
from .util import canonical_json_bytes

_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_IDS = ("real_uid", "effective_uid", "saved_uid", "real_gid", "effective_gid", "saved_gid")
_POLL_SECONDS = 0.025


def _refuse() -> MacOSFileAccessContractError:
    return MacOSFileAccessContractError("The original Darwin primitive worker is unavailable.")


class MacOSFileAccessWorker:
    """Retain the exact launcher/runtime objects; historical DTOs cannot join.

    Construct and retain this owner before calling start. The original creator
    owns the borrowed resource descriptor and sealed namespace throughout.
    Neither a close response nor this wrapper establishes whole-setup cleanup.
    """

    def __init__(
        self,
        runtime: runner.SubprocessRustRunner,
        binding: dict[str, Any],
        *,
        role: str,
        resource_fd: int,
        channel: socket.socket,
        child_channel: socket.socket,
    ) -> None:
        original = validate_binding(binding)
        if (
            type(runtime) is not runner.SubprocessRustRunner
            or runtime._kill_child_on_job_close  # noqa: SLF001
            or type(role) is not str
            or role not in ("reader", "owner", "control")
            or type(resource_fd) is not int
            or resource_fd < 3
            or not isinstance(channel, socket.socket)
            or not isinstance(child_channel, socket.socket)
            or child_channel.family != getattr(socket, "AF_UNIX", None)
            or child_channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or child_channel.fileno() < 3
            or resource_fd in (channel.fileno(), child_channel.fileno())
            or channel.fileno() == child_channel.fileno()
        ):
            raise _refuse()
        child_channel.getpeername()
        self._runtime = runtime
        self._binding = original
        self._role = role
        self._resource_fd = resource_fd
        self._channel = MacOSPrimitiveChannel(channel, original, role=role)
        self._child_channel = child_channel
        self._processes: list[subprocess.Popen[bytes]] = []
        self._proven: list[subprocess.Popen[bytes]] = []
        self._process: subprocess.Popen[bytes] | None = None
        self._consistency: MacOSChildConsistency | None = None
        self._slot = object()
        self._started = False
        self._creation_started = False
        self._factory_entered = False
        self._poisoned = False
        self._settled = False
        self._local_cleanup_unknown = False
        self._child_close_attempted = False
        self._last_clock = (0, 0)
        self._startup_observation_summary: tuple[int, str | None, str | None, bool] = (
            0,
            None,
            None,
            False,
        )
        self._launch_copy_rows: list[dict[str, Any]] = []
        self._native_diagnostic_bytes = bytearray()
        self._native_diagnostic_overflow = False
        self._native_diagnostic_complete = False
        self._native_diagnostic_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _drain_native_diagnostic(self, descriptor: int) -> None:
        """Drain throughout launch so helper output cannot block containment."""
        read_failed = False
        try:
            while True:
                chunk = os.read(descriptor, 1024)
                if not chunk:
                    break
                remaining = _setup_failure_diagnostics.MAX_NATIVE_FD_FRAME_BYTES - len(
                    self._native_diagnostic_bytes
                )
                self._native_diagnostic_bytes.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._native_diagnostic_overflow = True
        except OSError:
            read_failed = True
        finally:
            try:
                os.close(descriptor)
            except OSError:
                read_failed = True
            self._native_diagnostic_complete = not read_failed

    def _retained_descriptor_observation(self) -> tuple[dict[str, Any] | None, str | None]:
        if self._native_diagnostic_thread is None:
            return None, "no_frame"
        self._native_diagnostic_thread.join(timeout=0.1)
        if self._native_diagnostic_overflow:
            return None, "overflow"
        if not self._native_diagnostic_complete:
            return None, "eof_incomplete"
        raw = bytes(self._native_diagnostic_bytes)
        self._native_diagnostic_bytes.clear()
        if not raw:
            return None, "no_frame"
        native_rows = _setup_failure_diagnostics.native_fd_rows_from_frame(raw)
        if native_rows is None:
            return None, "invalid_frame"
        observation = {
            "schema_version": _setup_failure_diagnostics.NATIVE_FD_OBSERVATION_SCHEMA,
            "scope": "diagnostic_only_no_descriptor_admission",
            "launch_copy_rows": self._launch_copy_rows,
            "native_rows": native_rows,
        }
        if not _setup_failure_diagnostics.valid_native_fd_observation(observation):
            return None, "invalid_launch_rows"
        return observation, None

    def _guard(self, deadline: int | None = None) -> float:
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        limit = (
            min(cast(int, self._binding["original_deadline_ns"]), deadline)
            if deadline is not None
            else cast(int, self._binding["original_deadline_ns"])
        )
        if not self._binding["issued_at_ms"] <= wall < self._binding["expires_at_ms"]:
            raise _refuse()
        if monotonic >= limit:
            raise _refuse()
        if wall < self._last_clock[0]:
            raise _refuse()
        if monotonic < self._last_clock[1]:
            raise _refuse()
        self._last_clock = wall, monotonic
        return min(
            (limit - monotonic) / 1_000_000_000,
            (cast(int, self._binding["expires_at_ms"]) - wall) / 1000,
        )

    def _registered(self, process: subprocess.Popen[bytes]) -> None:
        with runner._DARWIN_INDETERMINATE_LOCK:  # noqa: SLF001
            if runner._DARWIN_ACTIVE_PROCESSES.get(process) is not self._runtime:  # noqa: SLF001
                self._refuse_observation("worker_active_process_missing")
            if self._runtime._darwin_process_is_indeterminate(process):  # noqa: SLF001
                self._refuse_observation("worker_process_indeterminate")
            if not self._runtime._refresh_darwin_no_fork_proof(process):  # noqa: SLF001
                self._refuse_observation("worker_nofork_proof_refresh_failed")

    @staticmethod
    def _refuse_observation(site: str) -> NoReturn:
        error = _refuse()
        setattr(error, "_safe_startup_observation_site", site)  # noqa: B010
        raise error from None

    def _remember_startup_observation_failure(self, error: MacOSFileAccessContractError) -> None:
        site = _setup_failure_diagnostics.normalize_startup_observation_site(
            getattr(error, "_safe_startup_observation_site", None)
        )
        self._startup_observation_summary = (
            _setup_failure_diagnostics.record_startup_observation_failure(
                self._startup_observation_summary, site
            )
        )

    def _request_guard(self, request: dict[str, Any]) -> None:
        self._guard(request["deadline_ns"])
        validate_request(request, now_ms=self._last_clock[0], now_ns=self._last_clock[1])

    def _observe(self, *, startup: bool = False) -> None:
        process = self._process
        if process is None:
            self._refuse_observation("worker_process_missing")
        if not any(original is process for original in self._processes):
            self._refuse_observation("worker_process_not_retained")
        self._registered(process)
        credentials = self._binding["reader" if self._role == "reader" else "owner"]
        observed = observe_owned_child(
            process,
            expected_ids={key: credentials[key] for key in _IDS},
            expected_start=(
                None if startup else self._consistency.start if self._consistency else None
            ),
        )
        if self._consistency is not None and observed != self._consistency:
            self._refuse_observation("worker_consistency_changed")
        self._consistency = observed
        self._registered(process)

    def _quarantine(self) -> None:
        for process in tuple(self._processes):
            self._runtime._quarantine_interrupted_darwin_launch(process)  # noqa: SLF001

    def _remember_channel_cleanup(self) -> None:
        try:
            if self._channel.local_cleanup_unknown is not False:
                self._local_cleanup_unknown = True
        except BaseException:
            self._local_cleanup_unknown = True

    def _close_channel(self) -> None:
        try:
            self._channel.abandon()
        except BaseException:
            self._local_cleanup_unknown = True
            raise
        finally:
            self._remember_channel_cleanup()

    def _close_child_channel(self) -> None:
        if self._child_close_attempted:
            return
        self._child_close_attempted = True
        try:
            self._child_channel.close()
        except BaseException:
            self._local_cleanup_unknown = True
            raise

    def start(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise _refuse()
        reserved = False
        diagnostic_write = -1
        try:
            if self._started or self._settled:
                raise _refuse()
            self._started = True
            if sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0:
                raise _refuse()
            self._guard()
            if self._binding["original_deadline_ns"] - self._last_clock[1] > 900_000_000_000:
                raise _refuse()
            startup_deadline = min(
                self._binding["original_deadline_ns"], darwin_clock_ns() + 5_000_000_000
            )
            reserved = self._runtime._reserve_darwin_process_slot(self._slot)  # noqa: SLF001
            if not reserved:
                raise _refuse()
            selected = self._binding["reader" if self._role == "reader" else "owner"]
            command = (
                "macos-file-access-owner-control"
                if self._role == "control"
                else "macos-file-access-reader"
            )
            resource_flag = "--leaf-fd" if self._role == "control" else "--directory-fd"
            child_fd = self._child_channel.fileno()
            diagnostic_read, diagnostic_write = os.pipe()
            self._native_diagnostic_thread = threading.Thread(
                target=self._drain_native_diagnostic,
                args=(diagnostic_read,),
                name="bluefire-macos-fd-diagnostic",
                daemon=True,
            )
            try:
                self._native_diagnostic_thread.start()
            except BaseException:
                os.close(diagnostic_read)
                raise
            with runner._pinned_launch_file(
                self._runtime.runner_binary, self._runtime.runner_binary_digest
            ) as launch:  # noqa: SLF001
                target = [
                    launch[0],
                    command,
                    resource_flag,
                    str(self._resource_fd),
                    "--channel-fd",
                    str(child_fd),
                    "--original-deadline-ns",
                    str(self._binding["original_deadline_ns"]),
                    "--uid",
                    str(selected["effective_uid"]),
                    "--gid",
                    str(selected["effective_gid"]),
                    "--groups",
                    ",".join(str(group) for group in selected["groups"]),
                ]

                def registered(arguments: list[str], **options: Any) -> subprocess.Popen[bytes]:
                    if (
                        self._factory_entered
                        or arguments[16:] != target
                        or tuple(options.get("_bluefire_descriptor_argument_indexes", ()))
                        != (7, 12, 13)
                        or tuple(options.get("_bluefire_descriptor_list_argument_indexes", ()))
                        != (15,)
                        or self._resource_fd not in options.get("pass_fds", ())
                        or child_fd not in options.get("pass_fds", ())
                    ):
                        raise _refuse()
                    self._guard(startup_deadline)
                    self._factory_entered = True
                    options["_bluefire_descriptor_argument_indexes"] = (7, 12, 13, 19, 21)
                    roles = {fd: "launch_auxiliary" for fd in options["pass_fds"]}
                    roles[self._resource_fd] = "resource"
                    roles[child_fd] = "primitive_channel"
                    options["_bluefire_descriptor_roles"] = roles
                    options["_bluefire_descriptor_observation_sink"] = self._launch_copy_rows
                    return self._runtime._spawn_registered_darwin_popen(  # noqa: SLF001
                        self._slot, self._processes, arguments, **options
                    )

                def before_go(process: subprocess.Popen[bytes]) -> None:
                    if not any(original is process for original in self._processes):
                        raise _refuse()
                    with runner._DARWIN_INDETERMINATE_LOCK:  # noqa: SLF001
                        if (
                            runner._DARWIN_ACTIVE_PROCESSES.get(process) is not self._runtime
                        ):  # noqa: SLF001
                            raise _refuse()
                    self._runtime._darwin_no_fork_proven.add(process)  # noqa: SLF001
                    self._guard(startup_deadline)

                self._creation_started = True
                try:
                    self._process = spawn_no_fork_exec(
                        target,
                        stdout=subprocess.DEVNULL,
                        stderr=diagnostic_write,
                        environment=dict(_ENVIRONMENT),
                        inherited_descriptors=(self._resource_fd, child_fd),
                        options={"start_new_session": True, "close_fds": True, "umask": 0o077},
                        runner_binary=self._runtime.runner_binary,
                        runner_binary_digest=self._runtime.runner_binary_digest,
                        work_root=self._runtime.work_root,
                        watchdog_interpreter=self._runtime._watchdog_interpreter,  # noqa: SLF001
                        watchdog_interpreter_digest=self._runtime._watchdog_interpreter_digest,  # noqa: SLF001
                        parent_death_script=self._runtime.parent_death_script,
                        parent_death_script_digest=self._runtime.parent_death_script_digest,
                        pinned_launch_file=runner._pinned_launch_file,  # noqa: SLF001
                        start_grace_seconds=self._guard(startup_deadline),
                        popen_factory=registered,
                        proof_sink=self._proven,
                        proof_callback=before_go,
                    )
                finally:
                    closing = diagnostic_write
                    diagnostic_write = -1
                    try:
                        os.close(closing)
                    except OSError:
                        self._local_cleanup_unknown = True
                        raise
            if not any(original is self._process for original in self._processes):
                raise _refuse()
            self._close_child_channel()
            while True:
                self._guard(startup_deadline)
                try:
                    self._observe(startup=True)
                    break
                except MacOSFileAccessContractError as exc:
                    try:
                        self._remember_startup_observation_failure(exc)
                    except BaseException:
                        pass
                    time.sleep(min(_POLL_SECONDS, self._guard(startup_deadline)))
            self._guard(startup_deadline)
        except BaseException as exc:
            self._poisoned = True
            self._quarantine()
            self._close_channel()
            if type(exc) is MacOSFileAccessContractError:
                summary = self._startup_observation_summary
                if summary[0] > 0:
                    try:
                        setattr(exc, "_safe_startup_observation_summary", summary)  # noqa: B010
                    except Exception:
                        pass
            raise
        finally:
            try:
                if diagnostic_write >= 0:
                    closing = diagnostic_write
                    diagnostic_write = -1
                    try:
                        os.close(closing)
                    except OSError:
                        self._local_cleanup_unknown = True
                for process in self._proven:
                    self._runtime._darwin_no_fork_proven.add(process)  # noqa: SLF001
                if reserved:
                    self._runtime._cancel_darwin_process_slot(self._slot)  # noqa: SLF001
            finally:
                self._lock.release()

    def exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise _refuse()
        try:
            self._remember_channel_cleanup()
            if (
                self._poisoned
                or self._settled
                or self._local_cleanup_unknown
                or self._process is None
                or self._consistency is None
            ):
                raise _refuse()
            original = decode_request(canonical_json_bytes(validate_request(request)))
            self._request_guard(original)
            self._observe()
            self._request_guard(original)
            observation = self._channel.exchange(original)
            self._request_guard(original)
            # A close response ends primitive handles, not original child custody.
            if observation["operation"] != "close":
                self._observe()
            else:
                self._registered(self._process)
            self._request_guard(original)
            if not self._channel.usable:
                self._poisoned = True
            return observation
        except BaseException:
            self._poisoned = True
            self._quarantine()
            self._close_channel()
            raise
        finally:
            self._lock.release()

    def settle(self) -> bool:
        """Existing runtime physical release only; never reset/enrollment authority."""
        with self._lock:
            self._remember_channel_cleanup()
            if self._settled:
                return not self._local_cleanup_unknown
            self._poisoned = True
            try:
                self._close_channel()
            except BaseException:
                pass
            try:
                self._close_child_channel()
            except BaseException:
                pass
            processes = tuple(self._processes)
            if self._creation_started and not processes:
                return False
            released = not self._local_cleanup_unknown
            for process in processes:
                try:
                    if self._runtime._darwin_process_is_indeterminate(process):  # noqa: SLF001
                        closed = self._runtime._reconcile_indeterminate_darwin_process(
                            process, terminate=True
                        )  # noqa: SLF001
                    else:
                        closed = self._runtime._release_darwin_process_group(
                            process
                        )  # noqa: SLF001
                    released = bool(closed) and released
                except BaseException:
                    released = False
                    self._runtime._quarantine_interrupted_darwin_launch(process)  # noqa: SLF001
            self._settled = released
            return released

    def retained_native_startup_exit_code(self) -> int | None:
        """Read one original cached Popen status only after physical settlement."""
        if not self._lock.acquire(blocking=False):
            return None
        try:
            if (
                self._settled is not True
                or self._local_cleanup_unknown is not False
                or self._creation_started is not True
                or self._factory_entered is not True
                or len(self._processes) != 1
                or len(self._proven) != 1
            ):
                return None
            process = self._processes[0]
            if (
                type(process) is not subprocess.Popen
                or self._proven[0] is not process
                or (self._process is not None and self._process is not process)
            ):
                return None
            code = vars(process).get("returncode")
            return code if type(code) is int else None
        finally:
            self._lock.release()

    def retained_native_startup_status(self) -> dict[str, Any]:
        """Describe cached startup status, or the exact fixed gate that withheld it."""
        if not self._lock.acquire(blocking=False):
            return _setup_failure_diagnostics.unavailable_native_startup_status("worker_lock_busy")
        try:
            if self._settled is not True:
                return _setup_failure_diagnostics.unavailable_native_startup_status("not_settled")
            if self._local_cleanup_unknown is not False:
                return _setup_failure_diagnostics.unavailable_native_startup_status(
                    "cleanup_unknown"
                )
            if self._creation_started is not True:
                return _setup_failure_diagnostics.unavailable_native_startup_status("not_started")
            if self._factory_entered is not True:
                return _setup_failure_diagnostics.unavailable_native_startup_status(
                    "factory_not_entered"
                )
            if len(self._processes) != 1:
                return _setup_failure_diagnostics.unavailable_native_startup_status(
                    "process_count_mismatch"
                )
            if len(self._proven) != 1:
                return _setup_failure_diagnostics.unavailable_native_startup_status(
                    "proof_count_mismatch"
                )
            process = self._processes[0]
            if (
                type(process) is not subprocess.Popen
                or self._proven[0] is not process
                or (self._process is not None and self._process is not process)
            ):
                return _setup_failure_diagnostics.unavailable_native_startup_status(
                    "process_identity_mismatch"
                )
            code = vars(process).get("returncode")
            status = _setup_failure_diagnostics.native_startup_status_from_returncode(code)
            if type(code) is int and code == 96 and self._native_diagnostic_thread is not None:
                observation, withheld = self._retained_descriptor_observation()
                if observation is not None:
                    status["descriptor_observation"] = observation
                elif withheld is not None:
                    status["descriptor_observation_withheld"] = withheld
            return status
        finally:
            self._lock.release()
