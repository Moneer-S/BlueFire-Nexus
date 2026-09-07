"""Explicit public provider enrollment for one prepared-lab UI process."""

from __future__ import annotations

import secrets
import time
from dataclasses import replace
from importlib import resources
from typing import Any, Mapping

from .ai import PROPOSAL_JSON_SCHEMA
from .ai_assistance import OUTPUT_SCHEMA as ASSISTANCE_SCHEMA
from .ai_broker_contract import BrokerEnrollment, refusal
from .ai_detection_revision import _OUTPUT_SCHEMA as DETECTION_REVISION_SCHEMA
from .ai_drafts import AIGraphDraftRequest, graph_draft_json_schema
from .ai_method_comparison import OUTPUT_SCHEMA as METHOD_COMPARISON_SCHEMA
from .ai_probe import _SCHEMA as CONNECTION_SCHEMA
from .config import AIProviderConfig, BlueFireConfig, load_config
from .registry import load_builtin_registry
from .util import canonical_json_bytes, content_hash


def enroll(
    config: AIProviderConfig, destination_policy: str, *, max_nodes: int = 8, max_edges: int = 16
) -> BrokerEnrollment:
    request = AIGraphDraftRequest.from_registry(
        objective="Prepare a bounded experiment",
        registry=load_builtin_registry(),
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    return BrokerEnrollment.create(
        config,
        session_id=secrets.token_hex(32),
        expires_at_ms=time.time_ns() // 1_000_000 + 900_000,
        destination_policy=destination_policy,
        schemas=(
            ("bluefire_connection_check", content_hash(CONNECTION_SCHEMA)),
            ("bluefire_ai_proposal", content_hash(PROPOSAL_JSON_SCHEMA)),
            ("bluefire_ai_graph_draft", content_hash(graph_draft_json_schema(request))),
            ("bluefire_detection_source_revision", content_hash(DETECTION_REVISION_SCHEMA)),
            ("bluefire_method_comparison", content_hash(METHOD_COMPARISON_SCHEMA)),
            ("bluefire_experiment_assistance", content_hash(ASSISTANCE_SCHEMA)),
        ),
    )


def enrollment_document(enrollment: BrokerEnrollment) -> dict[str, Any]:
    return {
        "configuration": enrollment.config.to_dict(),
        "session_id": enrollment.session_id,
        "expires_at_ms": enrollment.expires_at_ms,
        "schemas": [list(row) for row in enrollment.schemas],
        "destination_policy": enrollment.destination_policy,
        "digest": enrollment.digest,
    }


def read_enrollment(value: Mapping[str, Any]) -> BrokerEnrollment:
    if set(value) != {
        "configuration",
        "session_id",
        "expires_at_ms",
        "schemas",
        "destination_policy",
        "digest",
    }:
        raise refusal()
    try:
        result = BrokerEnrollment(
            canonical_json_bytes(value["configuration"]),
            value["session_id"],
            value["expires_at_ms"],
            tuple(tuple(row) for row in value["schemas"]),
            value["destination_policy"],
        )
        if result.digest != value["digest"]:
            raise refusal()
        result.require_current(result.config)
        return result
    except (TypeError, ValueError, KeyError):
        raise refusal() from None


def product_config(enrollment: BrokerEnrollment) -> BlueFireConfig:
    """Use the shipped defaults; only the explicitly enrolled public provider is added."""
    resource = resources.files("bluefire.data").joinpath("bluefire.example.yaml")
    with resources.as_file(resource) as path:
        config = load_config(path)
    provider = enrollment.config
    fallback = config.ai.fallback
    if provider.id == fallback.id:
        raise refusal()
    return replace(
        config, ai=replace(config.ai, active_provider=provider.id, providers=(fallback, provider))
    )
