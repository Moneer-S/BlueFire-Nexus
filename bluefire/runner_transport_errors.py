"""Stable error taxonomy shared by all runner transport components."""

from __future__ import annotations


class RunnerTransportError(RuntimeError):
    """A sanitized failure at the maintained runner transport boundary."""


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


__all__ = [
    "AuthenticatedRunnerTransportError",
    "RunnerAuthenticationError",
    "RunnerConnectionError",
    "RunnerDurableResultExists",
    "RunnerPendingResultExists",
    "RunnerReadinessError",
    "RunnerTaskCancelled",
    "RunnerTaskTimedOut",
    "RunnerTransportError",
]
