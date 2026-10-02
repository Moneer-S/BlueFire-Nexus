"""Proposed test-only finite evidence; no transport reads, polling, or locks."""

import json
import subprocess
import threading
from contextlib import contextmanager

PHASES = (
    "spawn_called",
    "spawn_returned",
    "handler_entered",
    "request_body_read",
    "slow_header_write_completed",
    "non_drip_headers_completed",
    "slow_body_write_completed",
)
_POPEN_TYPE = subprocess.Popen
_EVENT_TYPE = threading.Event


def new_phases():
    return dict.fromkeys(PHASES, False)


def _boolean(value):
    return value if type(value) is bool else None


def _count(value):
    if type(value) is not list:
        return "unknown"
    return "zero" if not value else "one" if len(value) == 1 else "multiple"


def _cached_worker_status(process):
    if type(process) is not _POPEN_TYPE:
        return "unknown"
    cache = process.__dict__
    if type(cache) is not dict or "returncode" not in cache:
        return "unknown"
    code = cache["returncode"]
    if code is None:
        return "none"
    if type(code) is not int:
        return "unknown"
    return "zero" if code == 0 else "negative" if code < 0 else "positive"


def evidence(route, phases, workers, entered, paths):
    # Phase flags are sampled independently; false means not observed by this
    # fixture, and a cached None return code does not prove a process is alive.
    state = phases if type(phases) is dict else {}
    return {
        "stage": "http_deadline_assertion",
        "observation": "cached_nonatomic",
        "route": (
            route if type(route) is str and route in {"slow-headers", "slow-body"} else "unknown"
        ),
        "phases": {name: _boolean(state.get(name)) for name in PHASES},
        "entered_flag_cached": _boolean(entered._flag) if type(entered) is _EVENT_TYPE else None,
        "recorded_path_count": _count(paths),
        "worker_count": _count(workers),
        "worker_returncode_categories": (
            [_cached_worker_status(process) for process in workers[:2]]
            if type(workers) is list
            else []
        ),
        "workers_truncated": len(workers) > 2 if type(workers) is list else None,
        "writer_progress": "not_observed",
        "tcp_accept_progress": "not_observed",
        "worker_import_progress": "not_observed",
    }


def _report(sink, route, phases, workers, entered, paths):
    payload = json.dumps(evidence(route, phases, workers, entered, paths), sort_keys=True)
    # The caller supplies pytest's add_report_section: an in-memory tuple append.
    # Do not write or flush stdout/stderr while fixture cleanup is still pending.
    sink("call", "HTTP deadline diagnostic", payload)


@contextmanager
def diagnose_http_deadline(sink, route, phases, workers, entered, paths):
    try:
        yield
    except AssertionError:
        try:
            _report(sink, route, phases, workers, entered, paths)
        except BaseException:
            # Diagnostic inspection/sink failure cannot replace the original failure.
            pass
        raise
