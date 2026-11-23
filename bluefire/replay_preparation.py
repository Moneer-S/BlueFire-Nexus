"""Exact, non-authorizing review bindings for replay preparation."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Mapping, cast

from .replay import ReplayError
from .util import content_hash, json_clone

_FIELDS = frozenset(
    {
        "exact",
        "from_step_id",
        "swap_step_id",
        "swap_behavior_id",
        "parameter_overrides",
        "action_implementations",
        "autonomy",
        "ai_enabled",
        "ai_provider_id",
        "runner_profile_id",
        "defense_change",
        "target_scope",
        "collectors",
        "collector_runtime",
    }
)
_CONTEXT_SCHEMA = "bluefire.replay-preparation-context.v1"
_CONTEXT_MAX_BYTES = 64 * 1024


def replay_job_submission(
    source_run_id: str, request: Mapping[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    """Validate a retryable submission identity without accepting approval."""
    submission_id = request.get("submission_id")
    if not isinstance(submission_id, str):
        raise ReplayError("replay submission requires a canonical UUID submission_id")
    try:
        if str(uuid.UUID(submission_id)) != submission_id:
            raise ValueError("noncanonical UUID")
    except ValueError as exc:
        raise ReplayError("replay submission requires a canonical UUID submission_id") from exc
    if "approval" in request or not {"preparation_id", "preparation_context"}.issubset(request):
        raise ReplayError("replay jobs require preparation context and separate job approval")
    submitted = {key: value for key, value in request.items() if key != "submission_id"}
    reviewed_replay_readiness(submitted)
    return (
        submission_id,
        content_hash({"source_run_id": source_run_id, "request": submitted}),
        submitted,
    )


def replay_preparation_context(readiness: Mapping[str, Any] | None) -> dict[str, Any]:
    """Only ordinary public preflight metadata is echoed, never an approval."""
    context = {"schema_version": _CONTEXT_SCHEMA, "runner_readiness": readiness}
    if len(json.dumps(context, ensure_ascii=True).encode("utf-8")) > _CONTEXT_MAX_BYTES:
        raise ReplayError("replay preparation context exceeds its size limit")
    return dict(json_clone(context))


def reviewed_replay_readiness(request: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Read a bounded review hint; the service must independently re-probe it."""
    if "preparation_id" not in request and "preparation_context" not in request:
        return None
    identity = request.get("preparation_id")
    context = request.get("preparation_context")
    if (
        not isinstance(identity, str)
        or re.fullmatch(r"replay-preparation-[0-9a-f]{64}", identity) is None
        or not isinstance(context, Mapping)
        or set(context) != {"schema_version", "runner_readiness"}
        or context.get("schema_version") != _CONTEXT_SCHEMA
    ):
        raise ReplayError("replay preparation identity or context is invalid")
    readiness = context["runner_readiness"]
    if readiness is not None and not isinstance(readiness, Mapping):
        raise ReplayError("replay preparation readiness is invalid")
    replay_review_payload(
        {
            key: value
            for key, value in request.items()
            if key not in {"preparation_id", "preparation_context", "approval"}
        }
    )
    return cast(Mapping[str, Any] | None, replay_preparation_context(readiness)["runner_readiness"])


def replay_review_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the exact JSON options reviewed; approval is a separate operation."""
    if set(request) - _FIELDS:
        raise ReplayError("replay preparation contains unknown or authority-bearing fields")
    for name in (
        "from_step_id",
        "swap_step_id",
        "swap_behavior_id",
        "autonomy",
        "ai_provider_id",
        "runner_profile_id",
        "defense_change",
    ):
        if request.get(name) is not None and not isinstance(request[name], str):
            raise ReplayError(f"replay preparation {name} must be text or null")
    if "exact" in request and type(request["exact"]) is not bool:
        raise ReplayError("exact replay flag must be a boolean")
    return dict(json_clone(dict(request)))


def bind_replay_preparation(
    *,
    source: Mapping[str, Any],
    request: Mapping[str, Any],
    resolution: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the reviewed request to actual source and resolved execution state.

    This digest is only a stale-review check. It is neither persisted approval
    nor a capability and cannot release effects without the existing approval.
    """
    payload = replay_review_payload(request)
    binding = {
        "schema_version": "bluefire.replay-preparation-binding.v1",
        "source": {
            "run_id": source["run_id"],
            "run_digest": content_hash(source),
            "manifest_digest": content_hash(source["manifest"]),
            "evidence_digest": content_hash(source["evidence"]),
        },
        "replay_request": payload,
        "request_digest": content_hash(payload),
        "resolution": dict(resolution),
        "replay_extent": "from_step" if payload.get("from_step_id") is not None else "full",
    }
    return {
        "preparation_id": "replay-preparation-" + content_hash(binding)[7:],
        "binding": binding,
    }
