"""One fixed creator-owned Darwin primitive, never a custody minter."""

from __future__ import annotations

import os
import socket
import subprocess  # nosec B404
import sys
import threading
import time
from typing import Any, cast

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
        self._lock = threading.Lock()

    def _guard(self, deadline: int | None = None) -> float:
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        limit = (
            min(cast(int, self._binding["original_deadline_ns"]), deadline)
            if deadline is not None
            else cast(int, self._binding["original_deadline_ns"])
        )
        if (
            not self._binding["issued_at_ms"] <= wall < self._binding["expires_at_ms"]
            or monotonic >= limit
            or wall < self._last_clock[0]
            or monotonic < self._last_clock[1]
        ):
            raise _refuse()
        self._last_clock = wall, monotonic
        return min(
            (limit - monotonic) / 1_000_000_000,
            (cast(int, self._binding["expires_at_ms"]) - wall) / 1000,
        )

    def _registered(self, process: subprocess.Popen[bytes]) -> None:
        with runner._DARWIN_INDETERMINATE_LOCK:  # noqa: SLF001
            if (
                runner._DARWIN_ACTIVE_PROCESSES.get(process) is not self._runtime  # noqa: SLF001
                or self._runtime._darwin_process_is_indeterminate(process)  # noqa: SLF001
                or not self._runtime._refresh_darwin_no_fork_proof(process)
            ):  # noqa: SLF001
                raise _refuse()

    def _request_guard(self, request: dict[str, Any]) -> None:
        self._guard(request["deadline_ns"])
        validate_request(request, now_ms=self._last_clock[0], now_ns=self._last_clock[1])

    def _observe(self, *, startup: bool = False) -> None:
        process = self._process
        if process is None or not any(original is process for original in self._processes):
            raise _refuse()
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
            raise _refuse()
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
                self._process = spawn_no_fork_exec(
                    target,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
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
            if not any(original is self._process for original in self._processes):
                raise _refuse()
            self._close_child_channel()
            while True:
                self._guard(startup_deadline)
                try:
                    self._observe(startup=True)
                    break
                except MacOSFileAccessContractError:
                    time.sleep(min(_POLL_SECONDS, self._guard(startup_deadline)))
            self._guard(startup_deadline)
        except BaseException:
            self._poisoned = True
            self._quarantine()
            self._close_channel()
            raise
        finally:
            try:
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
