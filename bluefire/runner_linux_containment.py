"""Linux private-session ownership through pinned pidfds and unreaped leaders."""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404
import time
import weakref
from pathlib import Path

from .runner_transport_errors import RunnerTransportError

_PIDFD_OPEN = getattr(os, "pidfd_open", None)
_PIDFD_SEND_SIGNAL = getattr(signal, "pidfd_send_signal", None)
_WAIT_ID = getattr(os, "waitid", None)
_PIDFD_ID_TYPE = getattr(os, "P_PIDFD", None)
_WAIT_EXITED = getattr(os, "WEXITED", 0)
_WAIT_NO_HANG = getattr(os, "WNOHANG", 0)
_WAIT_NO_REAP = getattr(os, "WNOWAIT", 0)
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


class LinuxPrivateProcessContainment:
    """Keep process identities pinned until the private session is drained."""

    def __init__(self) -> None:
        self._processes: weakref.WeakKeyDictionary[
            subprocess.Popen[bytes], tuple[int, int, int, int, int]
        ] = weakref.WeakKeyDictionary()
        self._released_processes: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()

    @staticmethod
    def available() -> bool:
        return bool(
            callable(_PIDFD_OPEN)
            and callable(_PIDFD_SEND_SIGNAL)
            and callable(_WAIT_ID)
            and _PIDFD_ID_TYPE is not None
            and _WAIT_EXITED
            and _WAIT_NO_HANG
            and _WAIT_NO_REAP
        )

    def contains(self, process: subprocess.Popen[bytes]) -> bool:
        return process in self._processes

    def was_released(self, process: subprocess.Popen[bytes]) -> bool:
        return process in self._released_processes

    def exited_without_reap(self, process: subprocess.Popen[bytes]) -> bool:
        if process in self._released_processes:
            return process.returncode is not None
        containment = self._processes.get(process)
        if containment is None:
            return process.poll() is not None
        if (
            not callable(_WAIT_ID)
            or _PIDFD_ID_TYPE is None
            or not _WAIT_EXITED
            or not _WAIT_NO_HANG
            or not _WAIT_NO_REAP
        ):
            raise RunnerTransportError("Linux unreaped process observation is unavailable")
        try:
            observed = _WAIT_ID(
                _PIDFD_ID_TYPE,
                containment[4],
                _WAIT_EXITED | _WAIT_NO_HANG | _WAIT_NO_REAP,
            )
        except (ChildProcessError, OSError):
            raise RunnerTransportError("Linux process was reaped before containment") from None
        if observed is None:
            return False
        if int(getattr(observed, "si_pid", 0)) != process.pid:
            raise RunnerTransportError("Linux exit identity is invalid")
        return True

    @staticmethod
    def process_identity(process_id: int) -> tuple[int, int, int, int]:
        try:
            payload = (Path("/proc") / str(process_id) / "stat").read_bytes()
        except FileNotFoundError:
            raise ProcessLookupError(process_id) from None
        except OSError:
            raise RunnerTransportError("Linux process identity is unavailable") from None
        close = payload.rfind(b")")
        fields = payload[close + 2 :].split() if 0 < close < len(payload) - 2 else []
        try:
            identity = (
                process_id,
                int(fields[19]),
                int(fields[2]),
                int(fields[3]),
            )
        except (IndexError, ValueError):
            raise RunnerTransportError("Linux process identity is invalid") from None
        if (
            not 0 < len(payload) <= 4096
            or identity[0] <= 0
            or identity[1] <= 0
            or identity[2] < 0
            or identity[3] < 0
        ):
            raise RunnerTransportError("Linux process identity is invalid")
        return identity

    def register(self, process: subprocess.Popen[bytes]) -> None:
        descriptor = -1
        try:
            if not callable(_PIDFD_OPEN):
                raise OSError("pidfd_open unavailable")
            before = self.process_identity(process.pid)
            descriptor = int(_PIDFD_OPEN(process.pid, 0))
            after = self.process_identity(process.pid)
            if before != after or before[2:] != (process.pid, process.pid):
                raise OSError("private process identity mismatch")
            self._processes[process] = (*before, descriptor)
            descriptor = -1
        except (OSError, ProcessLookupError, RunnerTransportError):
            try:
                process.kill()
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except (OSError, subprocess.SubprocessError):
                pass
            raise RunnerTransportError("Linux private process containment is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _session_identities(
        self,
        containment: tuple[int, int, int, int, int],
    ) -> list[tuple[int, int, int, int]] | None:
        identities: list[tuple[int, int, int, int]] = []
        try:
            with os.scandir("/proc") as entries:
                for entry in entries:
                    if not entry.name.isdecimal():
                        continue
                    try:
                        identity = self.process_identity(int(entry.name))
                    except ProcessLookupError:
                        continue
                    if identity[3] == containment[3]:
                        identities.append(identity)
        except (OSError, RunnerTransportError):
            return None
        if containment[:4] not in identities:
            return None
        return identities

    @staticmethod
    def _signal_identity(
        identity: tuple[int, int, int, int],
        signum: int,
    ) -> bool:
        descriptor = -1
        try:
            if not callable(_PIDFD_OPEN) or not callable(_PIDFD_SEND_SIGNAL):
                return False
            before = LinuxPrivateProcessContainment.process_identity(identity[0])
            if before != identity:
                return False
            descriptor = int(_PIDFD_OPEN(identity[0], 0))
            try:
                after = LinuxPrivateProcessContainment.process_identity(identity[0])
            except ProcessLookupError:
                return True
            if after != identity:
                return False
            _PIDFD_SEND_SIGNAL(descriptor, signum, None, 0)
            return True
        except ProcessLookupError:
            return True
        except (OSError, RunnerTransportError):
            return False
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _signal_leader(
        self,
        containment: tuple[int, int, int, int, int],
        signum: int,
    ) -> bool:
        try:
            if (
                not callable(_PIDFD_SEND_SIGNAL)
                or self.process_identity(containment[0]) != containment[:4]
            ):
                return False
            _PIDFD_SEND_SIGNAL(containment[4], signum, None, 0)
            return True
        except ProcessLookupError:
            return True
        except (OSError, RunnerTransportError):
            return False

    def release(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: bool,
    ) -> bool:
        containment = self._processes.get(process)
        if containment is None:
            return False
        if terminate and not self.exited_without_reap(process):
            if not self._signal_leader(containment, signal.SIGTERM):
                return False
            graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
            while not self.exited_without_reap(process) and time.monotonic() < graceful_deadline:
                time.sleep(_PROCESS_POLL_SECONDS)
            if not self.exited_without_reap(process):
                if not self._signal_leader(containment, _FORCE_KILL_SIGNAL):
                    return False
        exit_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
        while not self.exited_without_reap(process) and time.monotonic() < exit_deadline:
            time.sleep(_PROCESS_POLL_SECONDS)
        if not self.exited_without_reap(process):
            return False

        descendant_grace = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        descendant_deadline = descendant_grace + _PROCESS_KILL_GRACE_SECONDS
        while True:
            identities = self._session_identities(containment)
            if identities is None:
                return False
            targets = [identity for identity in identities if identity != containment[:4]]
            if not targets:
                break
            now = time.monotonic()
            if now >= descendant_deadline:
                return False
            signum = _FORCE_KILL_SIGNAL if now >= descendant_grace else signal.SIGTERM
            if not all(self._signal_identity(identity, signum) for identity in targets):
                return False
            time.sleep(_PROCESS_POLL_SECONDS)
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False
        self._processes.pop(process, None)
        self._released_processes.add(process)
        os.close(containment[4])
        return process.returncode is not None
