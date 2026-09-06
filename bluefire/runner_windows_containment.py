"""Own Windows Job Object assignment, termination, and verified handle release."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import threading
import time
import weakref
from pathlib import Path

from .runner_transport_errors import RunnerTransportError

_PROCESS_POLL_SECONDS = 0.025
_PROCESS_KILL_GRACE_SECONDS = 5.0


class WindowsJobContainment:
    """Contain children in instance-owned jobs through confirmed tree drainage."""

    def __init__(self, *, kill_on_close: bool) -> None:
        self._kill_on_close = kill_on_close
        self._jobs: dict[int, int] = {}
        self._jobs_lock = threading.Lock()
        self._released_processes: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()

    def terminate(self, process: subprocess.Popen[bytes]) -> bool:
        if sys.platform != "win32":
            return False
        if process in self._released_processes:
            return self._release_job(process.pid) and process.poll() is not None
        with self._jobs_lock:
            job = self._jobs.get(process.pid)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            terminated = bool(terminate_job(job, 1))
            if terminated:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except (AttributeError, OSError, subprocess.SubprocessError, ValueError):
            terminated = False
        if not terminated or not self._wait_for_empty_job(job):
            return False
        self._released_processes.add(process)
        return self._release_job(process.pid) and process.poll() is not None

    def create_job(self) -> int:
        if sys.platform != "win32":
            raise RunnerTransportError("Windows process containment is unavailable")
        job = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_job = kernel32.CreateJobObjectW
            create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            create_job.restype = wintypes.HANDLE

            raw_job = create_job(None, None)
            if not raw_job:
                raise OSError("job creation failed")
            job = int(raw_job)
            # The request-server's outer watchdog job intentionally survives
            # handle closure. Inside the watchdog, the Rust child job uses
            # KILL_ON_JOB_CLOSE so a watchdog crash cannot orphan execution.
            if self._kill_on_close:
                self._set_kill_on_close(job)
            return job
        except (AttributeError, OSError, TypeError, ValueError):
            if job:
                self.close_handle(job)
            raise RunnerTransportError("Windows process containment is unavailable") from None
        except RunnerTransportError:
            if job:
                self.close_handle(job)
            raise

    @staticmethod
    def _set_kill_on_close(job: int) -> None:
        if sys.platform != "win32":
            raise RunnerTransportError("Windows process containment is unavailable")
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("per_process_user_time_limit", ctypes.c_longlong),
                    ("per_job_user_time_limit", ctypes.c_longlong),
                    ("limit_flags", wintypes.DWORD),
                    ("minimum_working_set_size", ctypes.c_size_t),
                    ("maximum_working_set_size", ctypes.c_size_t),
                    ("active_process_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t),
                    ("priority_class", wintypes.DWORD),
                    ("scheduling_class", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    ("read_operation_count", ctypes.c_ulonglong),
                    ("write_operation_count", ctypes.c_ulonglong),
                    ("other_operation_count", ctypes.c_ulonglong),
                    ("read_transfer_count", ctypes.c_ulonglong),
                    ("write_transfer_count", ctypes.c_ulonglong),
                    ("other_transfer_count", ctypes.c_ulonglong),
                ]

            class ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("basic_limit_information", BasicLimitInformation),
                    ("io_info", IoCounters),
                    ("process_memory_limit", ctypes.c_size_t),
                    ("job_memory_limit", ctypes.c_size_t),
                    ("peak_process_memory_used", ctypes.c_size_t),
                    ("peak_job_memory_used", ctypes.c_size_t),
                ]

            details = ExtendedLimitInformation()
            details.basic_limit_information.limit_flags = 0x0000_2000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            set_information = kernel32.SetInformationJobObject
            set_information.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_information.restype = wintypes.BOOL
            if not set_information(
                job,
                9,
                ctypes.byref(details),
                ctypes.sizeof(details),
            ):
                raise OSError("job close containment is unavailable")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows process containment is unavailable") from None

    @staticmethod
    def resume_suspended(process: subprocess.Popen[bytes]) -> None:
        """Resume the one primary thread of a CREATE_SUSPENDED child."""

        if sys.platform != "win32":
            raise RunnerTransportError("Windows suspended process start failed")
        snapshot = 0
        thread_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            class ThreadEntry32(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("usage", wintypes.DWORD),
                    ("thread_id", wintypes.DWORD),
                    ("owner_process_id", wintypes.DWORD),
                    ("base_priority", wintypes.LONG),
                    ("priority_delta", wintypes.LONG),
                    ("flags", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_snapshot = kernel32.CreateToolhelp32Snapshot
            create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            create_snapshot.restype = wintypes.HANDLE
            first_thread = kernel32.Thread32First
            first_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            first_thread.restype = wintypes.BOOL
            next_thread = kernel32.Thread32Next
            next_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            next_thread.restype = wintypes.BOOL
            open_thread = kernel32.OpenThread
            open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_thread.restype = wintypes.HANDLE
            resume_thread = kernel32.ResumeThread
            resume_thread.argtypes = [wintypes.HANDLE]
            resume_thread.restype = wintypes.DWORD

            raw_snapshot = create_snapshot(0x0000_0004, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if not raw_snapshot or int(raw_snapshot) == invalid_handle:
                raise OSError("thread snapshot unavailable")
            snapshot = int(raw_snapshot)
            entry = ThreadEntry32()
            entry.size = ctypes.sizeof(entry)
            available = bool(first_thread(snapshot, ctypes.byref(entry)))
            candidates: list[int] = []
            while available:
                if entry.owner_process_id == process.pid:
                    candidates.append(int(entry.thread_id))
                available = bool(next_thread(snapshot, ctypes.byref(entry)))
            if len(candidates) != 1:
                raise OSError("suspended child thread identity is ambiguous")
            raw_thread = open_thread(0x0002, False, candidates[0])
            if not raw_thread:
                raise OSError("suspended child thread is unavailable")
            thread_handle = int(raw_thread)
            previous_count = int(resume_thread(thread_handle))
            if previous_count != 1:
                raise OSError("suspended child was not resumed exactly once")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows suspended process start failed") from None
        finally:
            if thread_handle:
                WindowsJobContainment.close_handle(thread_handle)
            if snapshot:
                WindowsJobContainment.close_handle(snapshot)

    def assign(
        self,
        job: int,
        process: subprocess.Popen[bytes],
    ) -> None:
        process_handle = 0
        try:
            if sys.platform != "win32":
                raise OSError("Windows Job Objects are unavailable")
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            assign_process = kernel32.AssignProcessToJobObject
            assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            assign_process.restype = wintypes.BOOL
            terminate_process = kernel32.TerminateProcess
            terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_process.restype = wintypes.BOOL

            raw_process_handle = open_process(0x0001 | 0x0100 | 0x1000, False, process.pid)
            if not raw_process_handle:
                raise OSError("process handle unavailable")
            process_handle = int(raw_process_handle)
            if not assign_process(job, process_handle):
                terminate_process(process_handle, 1)
                raise OSError("job assignment failed")
            with self._jobs_lock:
                self._jobs[process.pid] = job
        except (AttributeError, OSError, TypeError, ValueError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            raise RunnerTransportError("Windows process containment is unavailable") from None
        finally:
            if process_handle:
                self.close_handle(process_handle)

    def _release_job(self, process_id: int) -> bool:
        with self._jobs_lock:
            job = self._jobs.pop(process_id, None)
        return job is None or self.close_handle(job)

    def finish(self, process: subprocess.Popen[bytes]) -> bool:
        if sys.platform != "win32":
            return False
        process_id = process.pid
        if process in self._released_processes:
            return self._release_job(process_id) and process.poll() is not None
        with self._jobs_lock:
            job = self._jobs.get(process_id)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            descendants_stopped = bool(terminate_job(job, 1))
        except (AttributeError, TypeError, ValueError):
            descendants_stopped = False
        if not descendants_stopped or not self._wait_for_empty_job(job):
            return False
        self._released_processes.add(process)
        return self._release_job(process_id)

    @staticmethod
    def _wait_for_empty_job(job: int) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            class BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("total_user_time", ctypes.c_longlong),
                    ("total_kernel_time", ctypes.c_longlong),
                    ("period_user_time", ctypes.c_longlong),
                    ("period_kernel_time", ctypes.c_longlong),
                    ("total_page_fault_count", wintypes.DWORD),
                    ("total_processes", wintypes.DWORD),
                    ("active_processes", wintypes.DWORD),
                    ("total_terminated_processes", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.QueryInformationJobObject
            query.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            query.restype = wintypes.BOOL
            deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
            while True:
                details = BasicAccountingInformation()
                returned = wintypes.DWORD()
                if not query(
                    job,
                    1,
                    ctypes.byref(details),
                    ctypes.sizeof(details),
                    ctypes.byref(returned),
                ):
                    return False
                if details.active_processes == 0:
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(_PROCESS_POLL_SECONDS)
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def close_handle(handle: int) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            return bool(close_handle(handle))
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def system_directory() -> Path:
        if os.name != "nt":
            raise RunnerTransportError("Windows process control is unavailable")
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer)
            )
            if length <= 0 or length >= len(buffer):
                raise OSError("system directory lookup failed")
            directory = Path(buffer.value).resolve(strict=True)
            if not directory.is_dir():
                raise OSError("system directory is unavailable")
            return directory
        except (AttributeError, OSError, ValueError):
            raise RunnerTransportError("Windows process control is unavailable") from None
