"""Finite test diagnostics; no process operations or raw error/identity output."""

from __future__ import annotations

import subprocess
from itertools import chain, islice
from typing import Any

_MISSING = object()
_LIMIT = 32
_ERRORS = {
    "Darwin process containment capacity is exhausted": "capacity_exhausted",
    "Darwin child status ownership is unavailable": "child_status_unavailable",
    "Runner watchdog exited before readiness": "watchdog_readiness_early_exit",
    "Runner watchdog did not become ready": "watchdog_readiness_deadline",
    "Runner watchdog readiness is unavailable": "watchdog_readiness_unavailable",
    "Runner watchdog readiness is invalid": "watchdog_readiness_invalid",
    "Runner watchdog containment is indeterminate and requires reconciliation.": "watchdog_indeterminate",
    "Runner watchdog remains active and requires reconciliation.": "watchdog_active",
    "Runner watchdog exceeded its terminal deadline": "watchdog_terminal_deadline",
    "Runner watchdog containment could not be released": "watchdog_containment_unreleased",
    "Runner watchdog failed before publishing a valid result": "watchdog_no_valid_result",
    "Runner process tree state could not be released": "process_cleanup_unreleased",
    "Runner process tree could not be stopped safely": "process_stop_unverified",
    "Runner watchdog process tree could not be stopped safely": "watchdog_stop_unverified",
    "Rust runner exceeded the transport output limit": "output_limit",
    "Runner pending result requires recovery before the task can start.": "pending_result",
    "runner result is not valid UTF-8 JSON": "invalid_json",
    "runner returned a result that did not match its request": "invalid_result",
    "runner returned an unsupported result schema": "unsupported_result_schema",
    "Rust runner transport timed out": "transport_deadline",
    "Rust runner transport failed": "transport_failure",
    "Rust runner could not be started": "launch_failed",
}


def _label(value: Any, allowed: dict[str, str]) -> str:
    if value is _MISSING:
        return "missing"
    if type(value) is not str or len(value) > 1024:
        return "unknown"
    return allowed.get(value, "unknown")


def transport_error_labels(container: Any, *, evidence: bool = False) -> dict[str, str]:
    """Classify stored fields, never infer an exception class from its message."""
    if type(container) is not dict:
        return {"code": "unknown", "category": "unknown"}
    return {
        "code": (
            "not_recorded"
            if evidence
            else _label(
                container.get("code", _MISSING),
                {"runner_transport_failed": "runner_transport_failed"},
            )
        ),
        "category": _label(container.get("error" if evidence else "message", _MISSING), _ERRORS),
    }


def darwin_governor_snapshot(
    active: Any, indeterminate: Any, pending: Any, *, owner: object
) -> dict[str, Any]:
    """Caller holds the governor lock; inspect at most 32 entries of supplied caches.

    Cached returncode=None is not evidence that a process is alive. Partial
    inspection is explicit, and no process method or operating-system read runs.
    """
    if type(active) is not dict or type(indeterminate) is not dict or type(pending) is not set:
        return {"available": False, "reason": "registry_shape_unknown"}
    try:
        sizes = {
            "active": len(active),
            "indeterminate": len(indeterminate),
            "pending": len(pending),
        }
        report: dict[str, Any] = {
            "available": True,
            "counts": {name: min(size, _LIMIT) for name, size in sizes.items()},
            "count_overflow": any(size > _LIMIT for size in sizes.values()),
            "inspection_overflow": sizes["active"] + sizes["indeterminate"] > _LIMIT,
            "inspected_entries": 0,
            "inspected_unique_processes": 0,
            "owned_by_current_runner": 0,
            "owned_by_other_runner": 0,
            "owner_unknown": 0,
            "non_popen_objects": 0,
            "popen_returncode_missing": 0,
            "popen_returncode_none": 0,
            "popen_returncode_int": 0,
            "popen_returncode_unknown": 0,
            "identity_lost": 0,
            "observe_only": 0,
            "indeterminate_state_unknown": 0,
        }
        # Key only our bounded local table by id; unknown registry keys may
        # implement __hash__ or __eq__, which diagnostics must not invoke.
        observations: dict[int, tuple[object, Any, Any]] = {}
        entries = chain(
            ((True, entry) for entry in active.items()),
            ((False, entry) for entry in indeterminate.items()),
        )
        for is_active, (process, value) in islice(entries, _LIMIT):
            report["inspected_entries"] += 1
            previous = observations.get(id(process), (process, _MISSING, _MISSING))
            observations[id(process)] = (
                process,
                value if is_active else previous[1],
                previous[2] if is_active else value,
            )
        for process, active_owner, state in observations.values():
            state_valid = (
                type(state) is tuple
                and len(state) == 4
                and all(type(value) is bool for value in state[1:])
            )
            process_owner = (
                active_owner
                if active_owner is not _MISSING
                else state[0] if state_valid else _MISSING
            )
            report[
                (
                    "owner_unknown"
                    if process_owner is _MISSING
                    else (
                        "owned_by_current_runner"
                        if process_owner is owner
                        else "owned_by_other_runner"
                    )
                )
            ] += 1
            if state is not _MISSING:
                if state_valid:
                    report["identity_lost"] += int(state[2])
                    report["observe_only"] += int(state[3])
                else:
                    report["indeterminate_state_unknown"] += 1
            if type(process) is subprocess.Popen:
                value = process.__dict__.get("returncode", _MISSING)
                category = (
                    "missing"
                    if value is _MISSING
                    else "none" if value is None else "int" if type(value) is int else "unknown"
                )
                report["popen_returncode_" + category] += 1
            else:
                report["non_popen_objects"] += 1
        report["inspected_unique_processes"] = len(observations)
        report["occupied"] = (
            "unknown"
            if report["inspection_overflow"] or report["count_overflow"]
            else len(observations) + sizes["pending"]
        )
        return report
    except BaseException:
        # Diagnostics cannot replace the original assertion on an unexpected cache.
        return {"available": False, "reason": "snapshot_unavailable"}
