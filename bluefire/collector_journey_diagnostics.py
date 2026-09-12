"""Failure-only, path-free diagnostics for the existing native collector journey.

These bounded summaries are neither run evidence nor gate success assertions.
The observer delegates each native call once, without changing its arguments.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from .run_store import RUN_ID_RE, RunStore
from .runner_client import SubprocessRustRunner

FAILURE_REPORT = "gate05-failure-diagnostic.json"
_STATUSES = frozenset(
    "success partial failed blocked refused control_blocked timed_out cancelled".split()
)
_ERROR_CODES = frozenset(
    "runner_transport_failed execution_interrupted run_budget_exhausted target_scope_refused "
    "action_not_allowed capability_missing platform_unsupported approval_required scope_refused "
    "timed_out execution_timeout timeout cleanup_failed artifact_limit_blocked "
    "collection_output_limit permission_denied io_error invalid_input action_failed "
    "invalid_action_params path_rejected filesystem_scope_blocked receipt_persistence_failed "
    "receipt_commit_failed fixture_create_timeout fixture_parse_failed fixture_write_failed "
    "transform_timeout transform_write_failed discovery_failed metadata_failed "
    "loopback_connect_failed loopback_read_failed loopback_timeout loopback_timeout_setup_failed "
    "loopback_write_failed network_scope_blocked receiver_authentication_failed "
    "receiver_authentication_unavailable export_write_failed cleanup_limit_blocked "
    "directory_depth_limit_blocked file_count_limit_blocked process_count_limit_blocked "
    "process_discovery_failed record_count_limit_blocked staged_bundle_ambiguous "
    "staged_bundle_rejected staged_bundle_unavailable staged_bundle_validation_failed "
    "windows_version_query_failed platform_blocked invalid_resource_limits".split()
)
_EXCEPTION_TYPES = frozenset(
    "APIError OrchestrationError CollectorError CollectorJourneyError DefenseFrontierError "
    "_RuntimeCleanupError _PrivateFileCleanupError RunnerTransportError RunnerTaskTimedOut "
    "RunnerTaskCancelled RunnerReadinessError RunnerContractError RunnerBootstrapError "
    "RunnerPendingResultExists RunnerDurableResultExists RunnerAuthenticationError "
    "RunnerConnectionError FileNotFoundError PermissionError OSError ValueError TypeError "
    "RuntimeError TimeoutError".split()
)
_CLEANUP_STAGES = frozenset(
    "runtime_close_remove runner_journal_remove receiver_stop receiver_join receiver_close child_stop".split()
)


def _known(value: Any, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _milliseconds(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 86_400_000 else None


def _exception_type(error: BaseException) -> str:
    return _known(type(error).__name__, _EXCEPTION_TYPES) or "other_exception"


class CollectorJourneyDiagnostic:
    def __init__(
        self, *, step_ids: frozenset[str], action_ids: frozenset[str], profile_ids: frozenset[str]
    ) -> None:
        self.step_ids, self.action_ids, self.profile_ids = step_ids, action_ids, profile_ids
        self.phase = "setup"
        self.attempt_count = 0
        self.last_attempt: dict[str, Any] | None = None
        self.last_unsuccessful_attempt: dict[str, Any] | None = None
        self.steps: dict[str, Any] = {"readback": "not_attempted"}
        self.cleanup_failures: list[dict[str, str]] = []
        self.cleanup_failure_count = 0
        self._run_id: str | None = None

    def begin(
        self, manifest: Mapping[str, Any], profile: Mapping[str, Any], timeout: float
    ) -> None:
        self.attempt_count += 1
        self.last_attempt = None
        limits = manifest.get("limits")
        profile_limits = profile.get("limits")
        self._run_id = manifest.get("run_id")
        self.last_attempt = {
            "phase": self.phase,
            "step_id": _known(manifest.get("step_id"), self.step_ids),
            "action_id": _known(manifest.get("action_id"), self.action_ids),
            "profile_id": _known(manifest.get("runner_profile_id"), self.profile_ids),
            "requested_timeout_ms": (
                _milliseconds(limits.get("timeout_ms")) if isinstance(limits, Mapping) else None
            ),
            "profile_timeout_ms": (
                _milliseconds(profile_limits.get("timeout_ms"))
                if isinstance(profile_limits, Mapping)
                else None
            ),
            "transport_timeout_ms": _milliseconds(int(timeout * 1000)),
            "transport_called": True,
            "result_returned": False,
            "runner_status": None,
            "error_code": None,
            "exception_type": None,
        }

    def finish(self, result: Mapping[str, Any] | None, error: BaseException | None) -> None:
        if self.last_attempt is None:
            return
        row = dict(self.last_attempt)
        if result is not None:
            row["result_returned"] = True
            row["runner_status"] = _known(result.get("status"), _STATUSES)
            raw_error = result.get("error")
            row["error_code"] = (
                _known(raw_error.get("code"), _ERROR_CODES) or "other_error"
                if isinstance(raw_error, Mapping)
                else None
            )
        if error is not None:
            row["exception_type"] = _exception_type(error)
        self.last_attempt = row
        if error is not None or row["runner_status"] != "success":
            self.last_unsuccessful_attempt = dict(row)

    def cleanup_failed(self, stage: str, error: BaseException) -> None:
        self.cleanup_failure_count += 1
        if len(self.cleanup_failures) < 8 and stage in _CLEANUP_STAGES:
            self.cleanup_failures.append({"stage": stage, "exception_type": _exception_type(error)})

    def capture_steps(self, store: RunStore) -> None:
        """Read at most two journey-owned results before runtime cleanup starts."""
        self.steps = {"readback": "unavailable"}
        entries = []
        for entry in store.root.iterdir():
            entries.append(entry)
            if len(entries) > 4:
                return
        run_ids = sorted(entry.name for entry in entries if RUN_ID_RE.fullmatch(entry.name))
        if not 1 <= len(run_ids) <= 2:
            return
        selected = (
            self._run_id if self._run_id in run_ids else (run_ids[0] if len(run_ids) == 1 else None)
        )
        if selected is None:
            return
        path = store._contained_child(store._run_path(selected, must_exist=True), "result.json")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > 1024 * 1024
            ):
                return
            data = bytearray()
            while len(data) <= 1024 * 1024:
                block = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or len(data) != before.st_size:
                return
        finally:
            os.close(descriptor)
        document = json.loads(data)
        rows = document.get("steps")
        if not isinstance(rows, list) or len(rows) > 256:
            return

        def summary(row: Any) -> dict[str, Any]:
            if not isinstance(row, Mapping):
                return {}
            error = row.get("error")
            return {
                "step_id": _known(row.get("step_id"), self.step_ids),
                "action_id": _known(row.get("action_id"), self.action_ids),
                "status": _known(row.get("status"), _STATUSES),
                "runner_status": _known(row.get("runner_status"), _STATUSES),
                "error_code": (
                    (_known(error.get("code"), _ERROR_CODES) or "other_error")
                    if isinstance(error, Mapping)
                    else None
                ),
            }

        unsuccessful = [
            row for row in rows if isinstance(row, Mapping) and row.get("status") != "success"
        ]
        self.steps = {
            "readback": "available",
            "observed_run_count": len(run_ids),
            "selection": "known_transport_run" if selected == self._run_id else "only_created_run",
            "matches_last_transport_run": selected == self._run_id,
            "completed_step_count": len(rows),
            "last_step": summary(rows[-1]) if rows else None,
            "last_unsuccessful_step": summary(unsuccessful[-1]) if unsuccessful else None,
        }

    def attach(
        self, error: BaseException, destination: Path, write_json: Callable[..., None]
    ) -> None:
        """Best-effort diagnostics never replace the original failure or cause."""
        try:
            report = {
                "schema_version": "bluefire.collector-journey-diagnostic.v1",
                "passed": False,
                "diagnostic_only": True,
                "phase": self.phase,
                "exception_type": _exception_type(error),
                "attempt_count": self.attempt_count,
                "last_attempt": self.last_attempt,
                "last_unsuccessful_attempt": self.last_unsuccessful_attempt,
                "steps": self.steps,
                "cleanup_failure_count": self.cleanup_failure_count,
                "cleanup_failures": self.cleanup_failures,
            }
            encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            if len(encoded) > 4096:
                return
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note("GATE-05 failure diagnostic: " + encoded)
            write_json(destination / FAILURE_REPORT, report)
        except BaseException:
            return


def observe(operation: Callable[..., Any], *args: Any) -> None:
    try:
        operation(*args)
    except BaseException:
        pass


class DiagnosticSubprocessRustRunner(SubprocessRustRunner):
    """Acceptance observer; native transport behavior remains in its superclass."""

    diagnostic: CollectorJourneyDiagnostic

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        observe(self.diagnostic.begin, manifest, profile, self.timeout_seconds)
        try:
            result = super().execute_task(
                manifest,
                profile,
                task_id=task_id,
                cancel_event=cancel_event,
                durable_result_path=durable_result_path,
            )
        except BaseException as error:
            observe(self.diagnostic.finish, None, error)
            raise
        observe(self.diagnostic.finish, result, None)
        return result
