"""Result admission for new effects and explicitly retained cleanup ownership."""

from __future__ import annotations

from collections.abc import Sequence

from .runner_client import RunnerTransportError


def validate_result_receipts(
    *,
    returned: Sequence[str],
    prior_request_commits: Sequence[str],
    current_request_commits: Sequence[str],
    retained: Sequence[str],
    committed_ownership: Sequence[str],
    status: str,
    has_observable_paths: bool,
) -> None:
    """Retained IDs must come from the fixed metadata adapter, never a result.

    The coordinator verifies their membership in the run and the workspace's
    committed ownership before dispatch. This function verifies the post-effect
    commitment while preserving fresh current-request receipts for new files.
    """
    if any(receipt in prior_request_commits for receipt in returned):
        raise RunnerTransportError("runner returned a pre-existing receipt as a new effect")
    if retained:
        if not set(retained) <= set(committed_ownership):
            raise RunnerTransportError("metadata operation lost its committed source ownership")
        if status in {"success", "partial"} and tuple(returned) != tuple(retained):
            raise RunnerTransportError("metadata operation changed its cleanup authority")
    if any(receipt not in (*current_request_commits, *retained) for receipt in returned):
        raise RunnerTransportError(
            "runner returned a receipt without a committed current-request binding"
        )
    new_commits = set(current_request_commits) - set(prior_request_commits)
    if (
        has_observable_paths
        and status in {"success", "partial", "timed_out"}
        and not (new_commits or retained)
    ):
        raise RunnerTransportError(
            "runner reported a mutating outcome without a committed cleanup receipt"
        )
