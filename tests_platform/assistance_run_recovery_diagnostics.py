"""Fixed tokens for the authored process-loss fixture; never child logs or data."""

import json
import os
import subprocess
from contextlib import contextmanager

PREFIX = b"BF_PROCESS_LOSS:"
PHASES = {
    "imports",
    "service_init",
    "authorization",
    "graph_context",
    "graph_prepare",
    "run_prepare",
    "hook_install",
    "review",
    "run_wait",
    "fallback_wait",
    "inspection",
    "crash_boundary",
    "marker_written",
}
ERRORS = {
    "JobWaitTimeout",
    "APIError",
    "AssertionError",
    "OSError",
    "PermissionError",
    "ValueError",
    "TypeError",
    "KeyError",
    "RuntimeError",
    "ImportError",
    "ModuleNotFoundError",
    "KeyboardInterrupt",
    "SystemExit",
    "unknown",
}


def _emit(kind, label):
    try:
        allowed = PHASES if kind == "phase" else ERRORS
        value = label if type(label) is str and label in allowed else "unknown"
        os.write(2, PREFIX + kind.encode("ascii") + b":" + value.encode("ascii") + b"\n")
    except BaseException:
        pass


def record_phase(phase):
    try:
        _emit("phase", phase)
    except BaseException:
        pass


@contextmanager
def record_child_failure():
    try:
        yield
    except BaseException as error:
        try:
            # Name-based diagnostic categories, not proof of exact exception identity.
            _emit("error", type(error).__name__)
        except BaseException:
            pass
        raise


def _summary(stderr):
    data = stderr if type(stderr) is bytes else b""
    parts = data[:4096].split(b"\n")
    lines, tail = parts[:-1], parts[-1]
    phases, errors = [], []
    rejected = tail.startswith(PREFIX)
    for line in lines[:32]:
        if not line.startswith(PREFIX):
            continue
        parts = line[len(PREFIX) :].split(b":")
        if len(parts) != 2:
            rejected = True
            continue
        kind, value = parts
        allowed = PHASES if kind == b"phase" else ERRORS if kind == b"error" else set()
        label = value.decode("ascii", errors="replace")
        if label not in allowed:
            rejected = True
            continue
        target = phases if kind == b"phase" else errors
        if label not in target:
            target.append(label)
    return {
        "fixture": "assistance_run_process_loss",
        "phases_seen": phases,
        "exception_categories": errors,
        "captured_stderr_available": bool(data),
        "capture_truncated": len(data) > 4096 or len(lines) > 32,
        "capture_incomplete": bool(tail),
        "rejected_event": rejected,
    }


def _report(timeout):
    print("Process-loss diagnostic: " + json.dumps(_summary(timeout.stderr), sort_keys=True))


@contextmanager
def process_loss_timeout_diagnostics():
    try:
        yield
    except subprocess.TimeoutExpired as timeout:
        try:
            _report(timeout)
        except BaseException:
            pass
        raise
