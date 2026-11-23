"""Canonical source-snapshot binding for materialized replay checkpoints."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .util import canonical_json_bytes, content_hash

SOURCE_BINDING_SCHEMA = "bluefire.checkpoint-source-binding.v1"
_MAX_BINDING_BYTES = 8 * 1024 * 1024


class CheckpointBindingError(ValueError):
    """Raised when a checkpoint source snapshot cannot be bound safely."""


def checkpoint_source_binding_hash(
    *,
    source_run_id: str,
    scenario: Mapping[str, Any],
    plan: Mapping[str, Any],
    approval_binding: Mapping[str, Any],
) -> str:
    """Hash the immutable source records needed to authenticate a checkpoint.

    The finalized run bundle cannot contain its own bundle hash without a hash
    cycle. This narrower record is reproducible from the independently verified
    source bundle and is therefore suitable for a checkpoint cross-check.
    """

    if (
        not isinstance(source_run_id, str)
        or not source_run_id.startswith("run-")
        or len(source_run_id) > 256
        or "\x00" in source_run_id
    ):
        raise CheckpointBindingError("checkpoint source run identity is invalid")
    if not all(isinstance(value, Mapping) for value in (scenario, plan, approval_binding)):
        raise CheckpointBindingError("checkpoint source binding records are invalid")
    try:
        encoded = [canonical_json_bytes(value) for value in (scenario, plan, approval_binding)]
        if sum(map(len, encoded)) > _MAX_BINDING_BYTES:
            raise CheckpointBindingError("checkpoint source binding exceeds its byte bound")
        binding = {
            "schema_version": SOURCE_BINDING_SCHEMA,
            "run_id": source_run_id,
            "scenario_digest": content_hash(scenario),
            "plan_digest": content_hash(plan),
            "approval_binding_digest": content_hash(approval_binding),
        }
        digest = content_hash(binding)
        if not isinstance(digest, str):  # pragma: no cover - utility contract guard
            raise CheckpointBindingError("checkpoint source binding digest is invalid")
        return digest
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, CheckpointBindingError):
            raise
        raise CheckpointBindingError("checkpoint source binding is not canonical") from exc


__all__ = ["CheckpointBindingError", "checkpoint_source_binding_hash"]
