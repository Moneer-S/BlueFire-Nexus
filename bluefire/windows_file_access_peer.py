"""Bind a reported pipe peer to a setup-retained process generation.

No process is opened, signaled or impersonated here. Trusted setup must supply
the borrowed noninherited handle with QUERY_LIMITED_INFORMATION and SYNCHRONIZE
rights only, and retain ownership of its lifetime. This module does not create a
pipe or establish a peer's account identity from a self-reported PID.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

from .windows_session_facts import _Filetime


class WindowsPeerBindingError(RuntimeError):
    """The live connection cannot be bound to the retained process generation."""


@dataclass(frozen=True)
class WindowsPeerGeneration:
    process_id: int
    created_filetime: int

    def validate(self) -> None:
        if (
            type(self.process_id) is not int
            or not 1 <= self.process_id <= 0xFFFFFFFF
            or type(self.created_filetime) is not int
            or not 1 <= self.created_filetime <= 0xFFFFFFFFFFFFFFFF
        ):
            raise WindowsPeerBindingError("Windows peer generation is invalid")


class _Api:
    kernel: ctypes.CDLL

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WindowsPeerBindingError("Windows peer binding is unavailable")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetProcessId.argtypes = (wintypes.HANDLE,)
        self.kernel.GetProcessId.restype = wintypes.DWORD
        self.kernel.GetProcessTimes.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
        )
        self.kernel.GetProcessTimes.restype = wintypes.BOOL
        self.kernel.GetHandleInformation.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.kernel.GetHandleInformation.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.GetFileType.argtypes = (wintypes.HANDLE,)
        self.kernel.GetFileType.restype = wintypes.DWORD
        self.kernel.GetNamedPipeInfo.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        )
        self.kernel.GetNamedPipeInfo.restype = wintypes.BOOL
        for name in ("GetNamedPipeClientProcessId", "GetNamedPipeServerProcessId"):
            operation = getattr(self.kernel, name)
            operation.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
            operation.restype = wintypes.BOOL

    def pipe_peer(self, handle: int, *, server_end: bool) -> int:
        flags, instances, process_id = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        if (
            self.kernel.GetFileType(handle) != 3
            or not self.kernel.GetNamedPipeInfo(
                handle, ctypes.byref(flags), None, None, ctypes.byref(instances)
            )
            # Some Windows builds also return the configured remote-client bit.
            # This query is not a substitute for trusted local-only creation.
            or flags.value & ~8 != (4 | int(server_end))
            or instances.value != 1
        ):
            raise WindowsPeerBindingError("Windows connection is not the expected message pipe end")
        operation = (
            self.kernel.GetNamedPipeClientProcessId
            if server_end
            else self.kernel.GetNamedPipeServerProcessId
        )
        if not operation(handle, ctypes.byref(process_id)) or not process_id.value:
            raise WindowsPeerBindingError("Windows pipe peer identity is unavailable")
        return int(process_id.value)

    def generation(self, handle: int) -> WindowsPeerGeneration:
        created, exited, kernel, user = (_Filetime() for _ in range(4))
        process_id = int(self.kernel.GetProcessId(handle))
        if not self.kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise WindowsPeerBindingError("Windows peer process generation is unavailable")
        result = WindowsPeerGeneration(process_id, (int(created.high) << 32) | int(created.low))
        result.validate()
        return result

    def require_running(self, handle: int) -> None:
        # A zero-time wait reads process state without terminating or waiting for
        # it. Unknown, failed and already-signaled handles all refuse admission.
        if self.kernel.WaitForSingleObject(handle, 0) != 258:
            raise WindowsPeerBindingError("Windows peer process is exited or unavailable")

    def require_noninherited(self, handle: int) -> None:
        flags = wintypes.DWORD()
        if not self.kernel.GetHandleInformation(handle, ctypes.byref(flags)) or flags.value & 1:
            raise WindowsPeerBindingError("Windows peer handle ownership is unavailable")


def _validate(api: _Api, handle: int, expected: WindowsPeerGeneration, reported_pid: int) -> None:
    api.require_noninherited(handle)
    api.require_running(handle)
    if api.generation(handle) != expected or reported_pid != expected.process_id:
        raise WindowsPeerBindingError("Windows pipe peer differs from the retained generation")
    api.require_running(handle)
    if api.generation(handle) != expected:
        raise WindowsPeerBindingError("Windows peer generation changed during observation")


def require_live_pipe_peer(
    process_handle: int, pipe_handle: int, *, expected: WindowsPeerGeneration, server_end: bool
) -> None:
    """Query the connected pipe's OS peer and check its retained process handle.

    No peer PID from the wire is accepted. Recheck around exchanges. This observation
    cannot promise future liveness, prove account identity or validate a pipe's
    descriptor, creator, locality, source image or enrollment by itself.
    """
    if (
        type(process_handle) is not int
        or not 0 < process_handle < (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        or type(pipe_handle) is not int
        or not 0 < pipe_handle < (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        or type(expected) is not WindowsPeerGeneration
        or type(server_end) is not bool
    ):
        raise WindowsPeerBindingError("Windows peer binding input is invalid")
    expected.validate()
    try:
        api = _Api()
        reported_pid = api.pipe_peer(pipe_handle, server_end=server_end)
        _validate(api, process_handle, expected, reported_pid)
        if api.pipe_peer(pipe_handle, server_end=server_end) != reported_pid:
            raise WindowsPeerBindingError("Windows connection peer changed during observation")
    except WindowsPeerBindingError:
        raise
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        raise WindowsPeerBindingError("Windows peer binding observation failed") from None
