"""Stable error taxonomy shared by all runner transport components."""

from __future__ import annotations

from typing import Any

from .domain_errors import RunnerTransportError as RunnerTransportError

_TRANSPORT_MESSAGES = {
    "runner cancellation control contract is invalid": "cancellation_contract_invalid",
    "runner cancellation state is unavailable": "cancellation_state_unavailable",
    "private directory is unavailable or unsafe": "private_state_unavailable",
    "runner watchdog state is unavailable": "watchdog_state_unavailable",
    "Runner identity could not be verified.": "runner_identity_unavailable",
    "Runner identity changed after construction.": "runner_identity_changed",
    "Runner identity changed before watchdog launch.": "runner_identity_changed",
    "Runner watchdog runtime is unavailable": "watchdog_runtime_unavailable",
    "Runner watchdog runtime is unavailable.": "watchdog_runtime_unavailable",
    "Packaged runner watchdog is unavailable": "watchdog_script_unavailable",
    "Packaged runner watchdog is unavailable.": "watchdog_script_unavailable",
    "Packaged runner watchdog identity changed": "watchdog_identity_changed",
    "verified launch input is unavailable": "launch_input_unavailable",
    "Windows process containment is unavailable": "windows_containment_unavailable",
    "Windows suspended process start failed": "windows_suspended_start_failed",
    "Windows suspended process handles remain open": "windows_suspended_start_failed",
    "Windows process control is unavailable": "windows_process_control_unavailable",
    "Rust runner could not be started": "process_launch_failed",
    "Rust runner transport failed": "runner_io_failed",
    "runner durable result is unavailable": "durable_result_unavailable",
    "runner durable result destination is unavailable": "durable_result_unavailable",
    "runner pending result is unavailable": "pending_result_unavailable",
    "runner durable result could not be committed": "durable_result_commit_failed",
    "Runner watchdog exited before readiness": "watchdog_exited_before_ready",
    "Runner watchdog readiness is invalid": "watchdog_readiness_invalid",
    "Runner watchdog readiness is unavailable": "watchdog_readiness_unavailable",
    "Runner watchdog did not become ready": "watchdog_readiness_timeout",
    "Runner watchdog exceeded its terminal deadline": "watchdog_terminal_timeout",
    "Rust runner exited with an unexpected status": "runner_unexpected_exit",
    "Runner watchdog failed before publishing a valid result": "watchdog_no_valid_result",
    "Runner process tree state could not be released": "process_tree_release_failed",
    "Runner watchdog containment could not be released": "process_tree_release_failed",
    "Runner process tree could not be stopped safely": "process_tree_stop_failed",
    "Rust runner transport timed out": "timed_out",
    "Rust runner exceeded the transport output limit": "output_limit",
    "runner returned an unsupported result schema": "unsupported_result_schema",
    "runner result is not valid UTF-8 JSON": "invalid_json",
    "runner returned a result that did not match its request": "invalid_result",
}
_WATCHDOG_FAILURE_REASONS = {
    "start_timeout": "watchdog_start_timeout",
    "runner_failure": "other_transport",
    "runner_identity_changed": "runner_identity_changed",
    "watchdog_failure": "watchdog_failure",
    "cancellation_cleanup_failed": "cancellation_cleanup_failed",
    "durable_result_exists": "durable_result_exists",
    "pending_result_exists": "pending_result_exists",
}
TRANSPORT_FAILURE_REASONS = frozenset(
    {*_TRANSPORT_MESSAGES.values(), *_WATCHDOG_FAILURE_REASONS.values(), "other_transport"}
)


class DiagnosedRunnerTransportError(RunnerTransportError):
    """An unchanged transport failure with one finite, diagnostic-only reason."""

    def __init__(self, message: str, *, transport_failure_reason: str) -> None:
        super().__init__(message)
        self.transport_failure_reason = (
            transport_failure_reason
            if isinstance(transport_failure_reason, str)
            and transport_failure_reason in TRANSPORT_FAILURE_REASONS
            else "other_transport"
        )


def transport_failure_reason(error: RunnerTransportError) -> str:
    """Never derive a published label from unrecognized exception text."""
    if isinstance(error, RunnerDurableResultExists):
        return "durable_result_exists"
    if isinstance(error, RunnerPendingResultExists):
        return "pending_result_exists"
    reason = getattr(error, "transport_failure_reason", None)
    if reason is not None:
        return (
            reason
            if isinstance(reason, str) and reason in TRANSPORT_FAILURE_REASONS
            else "other_transport"
        )
    return _TRANSPORT_MESSAGES.get(str(error), "other_transport")


def watchdog_transport_failure_reason(code: object) -> str:
    if not isinstance(code, str):
        return "other_transport"
    return _WATCHDOG_FAILURE_REASONS.get(
        code, code if code in TRANSPORT_FAILURE_REASONS else "other_transport"
    )


class RunnerReadinessError(RunnerTransportError):
    """A sanitized refusal raised before an Execute effect can be dispatched."""


class RunnerTaskCancelled(RunnerTransportError):
    """The complete runner process tree was confirmed stopped after cancellation."""

    def __init__(
        self,
        message: str,
        *,
        cooperative_requested: bool = False,
        cooperative_acknowledged: bool = False,
        forced_tree_termination: bool = False,
        control_cleanup_verified: bool = False,
    ) -> None:
        if cooperative_acknowledged and not cooperative_requested:
            raise ValueError("cancellation acknowledgement requires a cooperative request")
        super().__init__(message)
        self.cooperative_requested = bool(cooperative_requested)
        self.cooperative_acknowledged = bool(cooperative_acknowledged)
        self.forced_tree_termination = bool(forced_tree_termination)
        self.control_cleanup_verified = bool(control_cleanup_verified)


class RunnerTaskTimedOut(RunnerTransportError):
    """The complete runner process tree was confirmed stopped after a timeout."""


class RunnerPendingResultExists(RunnerTransportError):
    """A prior task attempt left crash-recovery output that must be reconciled."""


class RunnerDurableResultExists(RunnerTransportError):
    """A final task result already exists and was not overwritten."""


class AuthenticatedRunnerTransportError(RunnerTransportError):
    """A secret- and path-safe authenticated transport failure."""


class RunnerConnectionError(AuthenticatedRunnerTransportError):
    """The loopback transport could not complete an exchange."""


class RunnerAuthenticationError(AuthenticatedRunnerTransportError):
    """TLS, enrollment, framing, or message authentication failed."""


_CANCELLATION_PROOF_FIELDS = frozenset(
    {
        "cooperative_requested",
        "cooperative_acknowledged",
        "forced_tree_termination",
        "control_cleanup_verified",
    }
)


def validated_cancellation_proof(value: Any) -> dict[str, bool]:
    """Accept only explicit proof values, never truthiness or inferred state."""
    if (
        not isinstance(value, dict)
        or set(value) != _CANCELLATION_PROOF_FIELDS
        or any(type(value[field]) is not bool for field in _CANCELLATION_PROOF_FIELDS)
        or (value["cooperative_acknowledged"] and not value["cooperative_requested"])
    ):
        raise RunnerAuthenticationError("Runner cancellation proof is invalid.")
    return {field: value[field] for field in sorted(_CANCELLATION_PROOF_FIELDS)}


def cancellation_proof_from_cancelled(error: RunnerTaskCancelled) -> dict[str, bool]:
    return validated_cancellation_proof(
        {field: getattr(error, field, None) for field in _CANCELLATION_PROOF_FIELDS}
    )


__all__ = [
    "TRANSPORT_FAILURE_REASONS",
    "DiagnosedRunnerTransportError",
    "AuthenticatedRunnerTransportError",
    "RunnerAuthenticationError",
    "RunnerConnectionError",
    "RunnerDurableResultExists",
    "RunnerPendingResultExists",
    "RunnerReadinessError",
    "RunnerTaskCancelled",
    "RunnerTaskTimedOut",
    "RunnerTransportError",
    "cancellation_proof_from_cancelled",
    "transport_failure_reason",
    "validated_cancellation_proof",
    "watchdog_transport_failure_reason",
]
