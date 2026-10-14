"""Bind a borrowed suspended worker handle to its process generation and Job."""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from . import windows_file_access_peer as peer

WindowsPeerGeneration = peer.WindowsPeerGeneration


class WindowsChildBindingError(RuntimeError):
    """The retained child is not the expected live member of its owned Job."""


class _Api(peer._Api):
    def __init__(self) -> None:
        super().__init__()
        self.kernel.IsProcessInJob.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        )
        self.kernel.IsProcessInJob.restype = wintypes.BOOL

    def require_member(self, process_handle: int, job_handle: int) -> None:
        member = wintypes.BOOL()
        if (
            not self.kernel.IsProcessInJob(process_handle, job_handle, ctypes.byref(member))
            or not member.value
        ):
            raise WindowsChildBindingError("Windows child Job membership is unavailable")


def _valid_handle(value: object) -> bool:
    bits = ctypes.sizeof(ctypes.c_void_p) * 8
    maximum = (1 << bits) - 1
    # Reject pseudo-handle encodings as well as zero and out-of-range values.
    return type(value) is int and 0 < value < maximum - 0xFFFF


def _inputs(process_handle: object, job_handle: object) -> None:
    if not _valid_handle(process_handle) or not _valid_handle(job_handle):
        raise WindowsChildBindingError("Windows child binding handles are invalid")


def _observe(
    api: _Api,
    process_handle: int,
    job_handle: int,
    expected: WindowsPeerGeneration,
) -> None:
    api.require_noninherited(process_handle)
    api.require_noninherited(job_handle)
    api.require_running(process_handle)
    if api.generation(process_handle) != expected:
        raise WindowsChildBindingError("Windows child generation changed")
    api.require_member(process_handle, job_handle)
    api.require_running(process_handle)
    if api.generation(process_handle) != expected:
        raise WindowsChildBindingError("Windows child generation changed")
    api.require_member(process_handle, job_handle)


def capture_retained_child(
    process_handle: int, job_handle: int, *, expected_pid: int
) -> WindowsPeerGeneration:
    """Capture a spawned child's generation using borrowed handles only.

    The launcher owns both handles and must keep them open through cleanup. This
    observation does not establish Job ownership or authenticated authority.
    """
    _inputs(process_handle, job_handle)
    if type(expected_pid) is not int or not 1 <= expected_pid <= 0xFFFFFFFF:
        raise WindowsChildBindingError("Windows child process ID is invalid")
    try:
        api = _Api()
        api.require_noninherited(process_handle)
        api.require_noninherited(job_handle)
        api.require_running(process_handle)
        observed = api.generation(process_handle)
        if observed.process_id != expected_pid:
            raise WindowsChildBindingError("Windows child process ID differs")
        observed.validate()
        api.require_member(process_handle, job_handle)
        api.require_running(process_handle)
        if api.generation(process_handle) != observed:
            raise WindowsChildBindingError("Windows child generation changed")
        api.require_member(process_handle, job_handle)
        return observed
    except WindowsChildBindingError:
        raise
    except Exception:
        raise WindowsChildBindingError("Windows child binding observation failed") from None


def require_retained_child(
    process_handle: int, job_handle: int, *, expected: WindowsPeerGeneration
) -> None:
    """Recheck the borrowed child handle, generation, and exact Job membership.

    This bounded observation does not guarantee future liveness.
    """
    _inputs(process_handle, job_handle)
    if type(expected) is not WindowsPeerGeneration:
        raise WindowsChildBindingError("Windows child generation is invalid")
    try:
        expected.validate()
        _observe(_Api(), process_handle, job_handle, expected)
    except WindowsChildBindingError:
        raise
    except Exception:
        raise WindowsChildBindingError("Windows child binding observation failed") from None
