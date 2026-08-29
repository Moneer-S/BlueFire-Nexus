"""Isolated bounded subprocess execution for product acceptance workflows."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

_MAX_WORKFLOW_LOG_BYTES = 4 * 1024 * 1024
_PLAYWRIGHT_BROWSER_RESOURCE_ENV = "BLUEFIRE_ACCEPTANCE_PLAYWRIGHT_BROWSERS_PATH"
_SENSITIVE_ENV_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
_PREFIXED_TOKEN = re.compile(r"\b(?:sk-|gh[oprsu]_)[A-Za-z0-9_-]{12,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)"
    r"(\s*[:=]\s*)[^\s,;]{8,}"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_WORKFLOW_ENV_ALLOWLIST = frozenset(
    {
        "APPDATA",
        "CC",
        "CI",
        "COMSPEC",
        "CXX",
        "HOME",
        "INCLUDE",
        "LANG",
        "LC_ALL",
        "LIB",
        "LIBPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "PATH",
        "PATHEXT",
        "PKG_CONFIG_PATH",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WINDIR",
    }
)


@dataclass(frozen=True)
class WorkflowOutcome:
    exit_code: int | None
    failure_reason: str | None


class _WorkflowIsolationError(OSError):
    pass


def _workflow_environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items() if key.upper() in _WORKFLOW_ENV_ALLOWLIST
    }


def _playwright_browsers_path(
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    """Resolve one existing host browser cache without trusting isolated home aliases."""

    values = os.environ if environ is None else environ
    raw = values.get(_PLAYWRIGHT_BROWSER_RESOURCE_ENV) or values.get("PLAYWRIGHT_BROWSERS_PATH")
    if not raw:
        if os.name == "nt":
            base = values.get("LOCALAPPDATA")
            raw = os.fspath(Path(base) / "ms-playwright") if base else None
        elif sys.platform == "darwin":
            base = values.get("HOME")
            raw = os.fspath(Path(base) / "Library" / "Caches" / "ms-playwright") if base else None
        else:
            base = values.get("XDG_CACHE_HOME")
            if base:
                raw = os.fspath(Path(base) / "ms-playwright")
            else:
                home = values.get("HOME")
                raw = os.fspath(Path(home) / ".cache" / "ms-playwright") if home else None
    if not isinstance(raw, str) or not raw or len(raw) > 4_096 or "\0" in raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        return None
    try:
        unresolved = Path(os.path.abspath(candidate))
        candidate_metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError:
        return None
    candidate_attributes = int(getattr(candidate_metadata, "st_file_attributes", 0))
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if (
        not stat.S_ISDIR(candidate_metadata.st_mode)
        or candidate.is_symlink()
        or bool(candidate_attributes & 0x400)
        or unresolved != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved.is_symlink()
        or bool(attributes & 0x400)
    ):
        return None
    return resolved


def _isolated_workflow_environment(
    *,
    runtime_home: Path,
    runtime_temp: Path,
    cargo_target: Path,
) -> dict[str, str]:
    cargo_home = runtime_home / "cargo"
    cargo_home.mkdir()
    cargo_target.mkdir()
    environment = _workflow_environment()
    environment.update(
        {
            "APPDATA": os.fspath(runtime_home),
            "CARGO_HOME": os.fspath(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": os.fspath(cargo_target),
            "HOME": os.fspath(runtime_home),
            "LOCALAPPDATA": os.fspath(runtime_home),
            "PYTHONUTF8": "1",
            "TEMP": os.fspath(runtime_temp),
            "TMP": os.fspath(runtime_temp),
            "TMPDIR": os.fspath(runtime_temp),
            "USERPROFILE": os.fspath(runtime_home),
            "XDG_CONFIG_HOME": os.fspath(runtime_home),
        }
    )
    return environment


def _process_containment_limitations() -> tuple[str, ...]:
    if os.name == "nt" or sys.platform.startswith("linux"):
        return ()
    return ("This platform has no kernel-backed whole-tree containment for acceptance workflows.",)


def _linux_direct_children() -> set[int]:
    task_root = Path("/proc/self/task")
    if not task_root.is_dir():
        raise _WorkflowIsolationError("Linux /proc child tracking is unavailable")
    children: set[int] = set()
    try:
        tasks = list(task_root.iterdir())
    except OSError as exc:
        raise _WorkflowIsolationError(f"Linux child tracking failed: {exc}") from exc
    for task in tasks:
        try:
            raw = (task / "children").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as exc:
            raise _WorkflowIsolationError(f"Linux child tracking failed: {exc}") from exc
        try:
            children.update(int(item) for item in raw.split())
        except ValueError as exc:  # pragma: no cover - kernel contract
            raise _WorkflowIsolationError("Linux child tracking returned an invalid PID") from exc
    return children


@contextmanager
def _linux_subreaper_scope() -> Iterator[frozenset[int] | None]:
    if not sys.platform.startswith("linux"):
        yield None
        return
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()

    def prctl(option: int, argument: Any) -> None:
        if libc.prctl(option, argument, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise _WorkflowIsolationError(error, os.strerror(error))

    prctl(37, ctypes.byref(previous))
    prctl(36, 1)
    try:
        yield frozenset(_linux_direct_children())
    finally:
        prctl(36, previous.value)


def _kill_linux_adopted_descendants(
    baseline: frozenset[int],
    leader_pid: int,
) -> str | None:
    deadline = time.monotonic() + 5
    stable_empty_scans = 0
    while time.monotonic() < deadline:
        try:
            candidates = _linux_direct_children() - set(baseline) - {leader_pid}
        except _WorkflowIsolationError as exc:
            return f"workflow descendant tracking failed: {exc}"
        if not candidates:
            stable_empty_scans += 1
            if stable_empty_scans >= 10:
                return None
        else:
            stable_empty_scans = 0
            for pid in candidates:
                try:
                    os.kill(pid, signal.SIGKILL)  # type: ignore[attr-defined]
                except ProcessLookupError:
                    pass
            for pid in candidates:
                try:
                    os.waitpid(pid, os.WNOHANG)  # type: ignore[attr-defined]
                except (ChildProcessError, OSError):
                    pass
        time.sleep(0.02)
    survivors = _linux_direct_children() - set(baseline) - {leader_pid}
    return (
        "workflow descendants survived forced cleanup: "
        + ", ".join(str(pid) for pid in sorted(survivors))
        if survivors
        else None
    )


def _redact_runtime_paths(text: str, *, repository: Path, run_dir: Path) -> str:
    replacements = {
        os.fspath(Path(sys.executable).resolve()): "{python}",
        os.fspath(repository.resolve()): "{repository}",
        os.fspath(run_dir.resolve()): "{run_dir}",
        os.fspath(Path.home().resolve()): "{home}",
    }
    result = text
    for value, replacement in sorted(
        replacements.items(), key=lambda item: len(item[0]), reverse=True
    ):
        variants = {value, value.replace("\\", "/"), value.replace("/", "\\")}
        for variant in variants:
            result = re.sub(
                re.escape(variant),
                lambda _match, token=replacement: token,
                result,
                flags=re.IGNORECASE if os.name == "nt" else 0,
            )
    for name, value in os.environ.items():
        if len(value) >= 8 and any(marker in name.upper() for marker in _SENSITIVE_ENV_MARKERS):
            result = result.replace(value, "{redacted-secret}")
    result = _PRIVATE_KEY_BLOCK.sub("{redacted-private-key}", result)
    result = _BEARER_TOKEN.sub("Bearer {redacted-secret}", result)
    result = _PREFIXED_TOKEN.sub("{redacted-secret}", result)
    result = _SECRET_ASSIGNMENT.sub(
        lambda match: match.group(1) + match.group(2) + "{redacted-secret}",
        result,
    )
    return result


def _sanitize_workflow_log(path: Path, *, repository: Path, run_dir: Path) -> None:
    payload = path.read_bytes()
    text = payload.decode("utf-8", "replace")
    path.write_text(
        _redact_runtime_paths(text, repository=repository, run_dir=run_dir),
        encoding="utf-8",
    )


def _sanitize_gate_receipt(path: Path, *, repository: Path, run_dir: Path) -> None:
    """Redact public receipt strings before parsing and hashing the receipt."""

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        sanitized = _redact_runtime_paths(raw, repository=repository, run_dir=run_dir)
    else:

        def redact(item: Any) -> Any:
            if isinstance(item, str):
                return _redact_runtime_paths(item, repository=repository, run_dir=run_dir)
            if isinstance(item, list):
                return [redact(child) for child in item]
            if isinstance(item, dict):
                return {key: redact(child) for key, child in item.items()}
            return item

        sanitized = json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(path.name + ".sanitizing")
    temporary.write_text(sanitized, encoding="utf-8")
    os.replace(temporary, path)


def _write_gate_assessment(path: Path, assessment: Mapping[str, Any]) -> None:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("gate receipt cannot receive its harness assessment") from exc
    if (
        not isinstance(receipt, dict)
        or "harness_assessment" not in receipt
        or (
            receipt["harness_assessment"] is not None
            and not isinstance(receipt["harness_assessment"], Mapping)
        )
    ):
        raise ValueError("gate receipt harness assessment slot is invalid")
    receipt["harness_assessment"] = dict(assessment)
    temporary = path.with_name(path.name + ".assessing")
    temporary.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _failure_excerpt(path: Path) -> str:
    try:
        with path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - 4096))
            payload = source.read()
    except OSError:
        payload = b""
    lines = payload.decode("utf-8", "replace").strip().splitlines()
    return lines[-1][:500] if lines else "workflow returned no diagnostic output"


def _drain_bounded_stream(
    stream: Any,
    destination: Path,
    overflow: threading.Event,
) -> None:
    written = 0
    with destination.open("wb") as output:
        while True:
            block = stream.read(64 * 1024)
            if not block:
                break
            remaining = _MAX_WORKFLOW_LOG_BYTES - written
            if remaining > 0:
                chunk = block[:remaining]
                output.write(chunk)
                written += len(chunk)
            if len(block) > max(remaining, 0):
                overflow.set()


def _create_windows_kill_job(process: subprocess.Popen[bytes]) -> int:
    """Attach a child to a kill-on-close Job Object before it can do gate work."""

    if os.name != "nt":  # pragma: no cover - platform guard
        raise OSError("Windows Job Objects are unavailable")
    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        if not kernel32.SetInformationJobObject(
            job,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        process_handle = wintypes.HANDLE(process._handle)  # type: ignore[attr-defined]
        if not kernel32.AssignProcessToJobObject(job, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException:
        kernel32.CloseHandle(job)
        raise
    return int(job)


def _close_windows_job(job_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(wintypes.HANDLE(job_handle))


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    """Resume a process only after its kill-on-close Job Object is attached."""

    import ctypes

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    resume = ntdll.NtResumeProcess
    resume.argtypes = [ctypes.c_void_p]
    resume.restype = ctypes.c_long
    status = int(resume(ctypes.c_void_p(process._handle)))  # type: ignore[attr-defined]
    if status != 0:
        raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    windows_job: int | None = None,
    linux_baseline: frozenset[int] | None = None,
) -> str | None:
    if os.name == "nt":
        if windows_job is not None:
            _close_windows_job(windows_job)
        elif process.poll() is None:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    if linux_baseline is not None:
        return _kill_linux_adopted_descendants(linux_baseline, process.pid)
    return None


def _execute_workflow_inner(
    command: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
    linux_baseline: frozenset[int] | None,
) -> WorkflowOutcome:
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | 0x00000004 if os.name == "nt" else 0
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=repository,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        stdout_path.write_bytes(b"")
        stderr_path.write_text(str(exc), encoding="utf-8")
        return WorkflowOutcome(None, f"workflow could not start: {exc}")

    windows_job: int | None = None
    if os.name == "nt":
        try:
            windows_job = _create_windows_kill_job(process)
            _resume_windows_process(process)
        except OSError as exc:
            _terminate_process_tree(process, windows_job, linux_baseline)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - OS-level failure
                pass
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            stdout_path.write_bytes(b"")
            stderr_path.write_text(str(exc), encoding="utf-8")
            return WorkflowOutcome(None, f"workflow isolation could not start: {exc}")

    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        _terminate_process_tree(process, windows_job, linux_baseline)
        raise RuntimeError("workflow output pipes are unavailable")
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    readers = [
        threading.Thread(
            target=_drain_bounded_stream,
            args=(process.stdout, stdout_path, stdout_overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded_stream,
            args=(process.stderr, stderr_path, stderr_overflow),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    failure: str | None = None
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        failure = f"workflow exceeded its {timeout_seconds}-second timeout"
        cleanup_failure = _terminate_process_tree(process, windows_job, linux_baseline)
        if cleanup_failure:
            failure += "; " + cleanup_failure
        windows_job = None
        try:
            exit_code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - OS-level process failure
            exit_code = None
    finally:
        if os.name != "nt" or windows_job is not None:
            cleanup_failure = _terminate_process_tree(process, windows_job, linux_baseline)
            if cleanup_failure:
                failure = f"{failure}; {cleanup_failure}" if failure else cleanup_failure
            windows_job = None
        for reader in readers:
            reader.join(timeout=10)
        process.stdout.close()
        process.stderr.close()

    if any(reader.is_alive() for reader in readers):
        failure = failure or "workflow output streams did not close after termination"
    if stdout_overflow.is_set() or stderr_overflow.is_set():
        overflow_reason = (
            f"workflow output exceeded the {_MAX_WORKFLOW_LOG_BYTES}-byte per-stream limit"
        )
        failure = f"{failure}; {overflow_reason}" if failure else overflow_reason
    if exit_code not in (0, None):
        exit_reason = f"workflow exited with code {exit_code}: {_failure_excerpt(stderr_path)}"
        failure = f"{failure}; {exit_reason}" if failure else exit_reason
    return WorkflowOutcome(exit_code, failure)


def _execute_workflow(
    command: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
) -> WorkflowOutcome:
    try:
        with _linux_subreaper_scope() as linux_baseline:
            return _execute_workflow_inner(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=timeout_seconds,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                linux_baseline=linux_baseline,
            )
    except _WorkflowIsolationError as exc:
        stdout_path.write_bytes(b"")
        stderr_path.write_text(str(exc), encoding="utf-8")
        return WorkflowOutcome(None, f"workflow isolation could not start: {exc}")


__all__ = [
    "_PLAYWRIGHT_BROWSER_RESOURCE_ENV",
    "WorkflowOutcome",
    "_execute_workflow",
    "_isolated_workflow_environment",
    "_playwright_browsers_path",
    "_process_containment_limitations",
    "_redact_runtime_paths",
    "_sanitize_gate_receipt",
    "_sanitize_workflow_log",
    "_workflow_environment",
    "_write_gate_assessment",
]
