"""Finite operator consent for model data and wire-attempt usage, never execution authority."""

from __future__ import annotations

import ipaddress
import re
import time
import uuid
from dataclasses import replace
from typing import Any, Mapping
from urllib.parse import urlsplit

from .ai_broker_contract import schema_identity, strict_object
from .ai_wire import AIProviderTransportError, structured_request
from .config import AIProviderConfig, AIProviderKind
from .util import canonical_json_bytes, content_hash, json_clone

SCHEMA = "bluefire.ai-live-authorization.v1"
PURPOSES = frozenset(
    {
        "bluefire_connection_check",
        "bluefire_ai_proposal",
        "bluefire_experiment_assistance",
        "bluefire_detection_source_creation",
        "bluefire_detection_source_revision",
        "bluefire_run_evidence_inspection",
        "bluefire_method_comparison",
        "bluefire_ai_graph_draft",
        "bluefire_graph_step_edit",
        "bluefire_receiver_defense_inspection",
    }
)
LIMITS = {
    "max_requests": (1, 64),
    "max_request_bytes": (1, 16_777_216),
    "max_reserved_output_tokens": (64, 1_048_576),
}
COUNTERS = {
    "requests": "max_requests",
    "request_bytes": "max_request_bytes",
    "reserved_output_tokens": "max_reserved_output_tokens",
}
REQUIRED_REDACTION = {
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}
_ID = re.compile(r"^ai-authorization-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_DATA = {
    "raw_log",
    "raw_logs",
    "stdout",
    "stderr",
    "raw_evidence",
    "evidence_content",
    "raw_trace",
    "raw_response",
}
_CREDENTIAL = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----)"
)


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def refused(code: str = "live_authorization_required") -> AIProviderTransportError:
    return AIProviderTransportError(
        "Model request requires current matching data and usage authorization.",
        retryable=False,
        code=code,
    )


def _integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def validate_provider(config: AIProviderConfig, *, local_endpoint_authorized: bool) -> None:
    parsed = urlsplit(str(config.endpoint))
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if config.kind is AIProviderKind.DETERMINISTIC:
        raise refused("live_configuration_invalid")
    if (
        len(config.id) > 200
        or len(config.model) > 200
        or len(str(config.endpoint)) > 2048
        or any(
            _CREDENTIAL.search(value) for value in (config.id, config.model, str(config.endpoint))
        )
    ):
        raise refused("live_configuration_invalid")
    if loopback != local_endpoint_authorized or (not loopback and parsed.scheme != "https"):
        raise refused("live_configuration_invalid")
    if not loopback:
        try:
            literal = ipaddress.ip_address(str(parsed.hostname))
        except ValueError:
            literal = None
        if literal is not None and not literal.is_global:
            raise refused("live_configuration_invalid")
    if (
        not config.redaction.enabled
        or config.redaction.include_evidence_content
        or not REQUIRED_REDACTION.issubset(config.redaction.redact_keys)
    ):
        raise refused("live_data_policy_invalid")


def create_authorization(request: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "provider",
        "purposes",
        "data_scope",
        "limits",
        "expires_in_seconds",
        "approved_by",
        "usage_authorized",
        "local_endpoint_authorized",
    }
    if (
        not isinstance(request, Mapping)
        or set(request) != expected
        or request.get("usage_authorized") is not True
    ):
        raise refused("live_authorization_invalid")
    if type(request.get("local_endpoint_authorized")) is not bool:
        raise refused("live_authorization_invalid")
    try:
        config = AIProviderConfig.from_mapping(request["provider"])
    except ValueError:
        raise refused("live_configuration_invalid") from None
    validate_provider(config, local_endpoint_authorized=request["local_endpoint_authorized"])
    if request["data_scope"] != "reviewed_lab_context":
        raise refused("live_data_policy_invalid")
    purposes = request["purposes"]
    if (
        not isinstance(purposes, list)
        or not purposes
        or any(not isinstance(p, str) or p not in PURPOSES for p in purposes)
        or len(purposes) != len(set(purposes))
    ):
        raise refused("live_authorization_invalid")
    limits = request["limits"]
    if (
        not isinstance(limits, Mapping)
        or set(limits) != set(LIMITS)
        or any(not _integer(limits[k], *bounds) for k, bounds in LIMITS.items())
    ):
        raise refused("live_authorization_invalid")
    duration, actor = request["expires_in_seconds"], request["approved_by"]
    if (
        not _integer(duration, 1, 900)
        or not isinstance(actor, str)
        or not 1 <= len(actor.strip()) <= 128
        or any(ord(c) < 32 for c in actor)
    ):
        raise refused("live_authorization_invalid")
    created = now_ms()
    expiry = created + duration * 1000
    if context.get("expires_at_ms") is not None:
        expiry = min(expiry, context["expires_at_ms"])
    if (
        expiry <= created
        or context.get("kind") not in {"direct", "broker"}
        or not _DIGEST.fullmatch(str(context.get("binding_digest", "")))
    ):
        raise refused("live_context_unavailable")
    if context["kind"] == "broker" and context.get("provider") != config.to_dict():
        raise refused("live_context_unavailable")
    result = {
        "schema_version": SCHEMA,
        "authorization_id": "ai-authorization-" + uuid.uuid4().hex,
        "provider": config.to_dict(),
        "configuration_digest": content_hash(config.to_dict()),
        "purposes": sorted(purposes),
        "data_scope": "reviewed_lab_context",
        "limits": dict(limits),
        "created_at_ms": created,
        "expires_at_ms": expiry,
        "approved_by": actor.strip(),
        "usage_authorized": True,
        "local_endpoint_authorized": request["local_endpoint_authorized"],
        "context": {"kind": context["kind"], "binding_digest": context["binding_digest"]},
    }
    return {**result, "authorization_digest": content_hash(result)}


def validate_authorization(
    value: Mapping[str, Any],
    *,
    config: AIProviderConfig | None = None,
    context_digest: str | None = None,
    current: bool = True,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "authorization_id",
        "provider",
        "configuration_digest",
        "purposes",
        "data_scope",
        "limits",
        "created_at_ms",
        "expires_at_ms",
        "approved_by",
        "usage_authorized",
        "local_endpoint_authorized",
        "context",
        "authorization_digest",
    }
    try:
        if (
            not isinstance(value, Mapping)
            or set(value) != fields
            or value["schema_version"] != SCHEMA
            or not _ID.fullmatch(value["authorization_id"])
        ):
            raise ValueError
        body = {key: item for key, item in value.items() if key != "authorization_digest"}
        if content_hash(body) != value["authorization_digest"]:
            raise ValueError
        provider = AIProviderConfig.from_mapping(value["provider"])
        validate_provider(provider, local_endpoint_authorized=value["local_endpoint_authorized"])
        if (
            type(value["local_endpoint_authorized"]) is not bool
            or value["usage_authorized"] is not True
            or value["configuration_digest"] != content_hash(provider.to_dict())
            or provider.to_dict() != value["provider"]
            or (config is not None and config.to_dict() != provider.to_dict())
            or value["data_scope"] != "reviewed_lab_context"
            or not isinstance(value["purposes"], list)
            or not value["purposes"]
            or set(value["purposes"]) - PURPOSES
            or value["purposes"] != sorted(set(value["purposes"]))
        ):
            raise ValueError
        limits, context = value["limits"], value["context"]
        if (
            not isinstance(limits, Mapping)
            or set(limits) != set(LIMITS)
            or any(not _integer(limits[k], *bounds) for k, bounds in LIMITS.items())
            or not isinstance(context, Mapping)
            or set(context) != {"kind", "binding_digest"}
            or context["kind"] not in {"direct", "broker"}
            or not _DIGEST.fullmatch(context["binding_digest"])
            or (context_digest is not None and context["binding_digest"] != context_digest)
            or not _integer(value["created_at_ms"], 1, 2**63 - 1)
            or not _integer(
                value["expires_at_ms"], value["created_at_ms"] + 1, value["created_at_ms"] + 900_000
            )
            or not isinstance(value["approved_by"], str)
            or not 1 <= len(value["approved_by"].strip()) <= 128
            or any(ord(c) < 32 for c in value["approved_by"])
        ):
            raise ValueError
        if current and not value["created_at_ms"] <= now_ms() < value["expires_at_ms"]:
            raise refused("live_authorization_expired")
        if _CREDENTIAL.search(value["approved_by"]):
            raise ValueError
        return dict(json_clone(value))
    except AIProviderTransportError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError):
        raise refused("live_authorization_invalid") from None


def _schemas() -> Mapping[str, str]:
    from .ai import PROPOSAL_JSON_SCHEMA
    from .ai_assistance import OUTPUT_SCHEMA as assistance
    from .ai_detection_create import OUTPUT_SCHEMA as create
    from .ai_detection_revision import _OUTPUT_SCHEMA as revise
    from .ai_method_comparison import OUTPUT_SCHEMA as compare
    from .ai_probe import _SCHEMA as probe
    from .ai_receiver_inspection import OUTPUT_SCHEMA as receiver
    from .ai_run_inspection import OUTPUT_SCHEMA as inspect
    from .graph_ai_edit_contract import OUTPUT_SCHEMA as edit

    return {
        "bluefire_receiver_defense_inspection": content_hash(receiver),
        "bluefire_graph_step_edit": content_hash(edit),
        **dict(
            zip(
                (
                    "bluefire_connection_check",
                    "bluefire_ai_proposal",
                    "bluefire_experiment_assistance",
                    "bluefire_detection_source_creation",
                    "bluefire_detection_source_revision",
                    "bluefire_run_evidence_inspection",
                    "bluefire_method_comparison",
                ),
                map(
                    content_hash,
                    (probe, PROPOSAL_JSON_SCHEMA, assistance, create, revise, inspect, compare),
                ),
                strict=True,
            )
        ),
    }


def request_reservation(
    config: AIProviderConfig, body: bytes, authorization: Mapping[str, Any]
) -> dict[str, int]:
    """Validate the actual fixed-purpose wire bytes before reserving their conservative cost."""
    validate_authorization(authorization, config=config)
    if not isinstance(body, bytes) or not 1 <= len(body) <= 1_048_576:
        raise refused("live_request_out_of_scope")
    try:
        purpose, schema_digest = schema_identity(body, config.kind)
        if purpose not in authorization["purposes"] or (
            purpose != "bluefire_ai_graph_draft" and _schemas().get(purpose) != schema_digest
        ):
            raise ValueError
        wire = strict_object(body)
        if config.kind is AIProviderKind.OPENAI_RESPONSES:
            instructions, text, tokens, schema = (
                wire["instructions"],
                wire["input"],
                wire["max_output_tokens"],
                wire["text"]["format"]["schema"],
            )
        else:
            instructions, text, tokens, schema = (
                wire["messages"][0]["content"],
                wire["messages"][1]["content"],
                wire["max_completion_tokens"],
                wire["response_format"]["json_schema"]["schema"],
            )
        if (
            not _integer(tokens, 1, config.max_output_tokens)
            or not isinstance(instructions, str)
            or not isinstance(text, str)
        ):
            raise ValueError
        _validate_data(instructions)
        expected = structured_request(
            replace(config, max_output_tokens=tokens),
            instructions=instructions,
            input_text=text,
            name=purpose,
            schema=schema,
        )
        if canonical_json_bytes(wire) != canonical_json_bytes(expected):
            raise ValueError
        if purpose == "bluefire_connection_check":
            if text != "Synthetic connection test. No scenario or evidence is supplied.":
                raise ValueError
        else:
            projected = strict_object(text.encode("utf-8"))
            _validate_data(projected)
            if purpose == "bluefire_ai_graph_draft":
                from .ai_drafts import AIGraphDraftRequest, graph_draft_json_schema

                if (
                    set(projected)
                    != {"schema_version", "request_id", "objective", "bounds", "allowed_behaviors"}
                    or projected["schema_version"] != "bluefire.ai-graph-draft-request.v1"
                ):
                    raise ValueError
                draft = AIGraphDraftRequest(
                    objective=projected["objective"],
                    behavior_catalog=tuple(projected["allowed_behaviors"]),
                    max_nodes=projected["bounds"]["max_nodes"],
                    max_edges=projected["bounds"]["max_edges"],
                )
                if content_hash(graph_draft_json_schema(draft)) != schema_digest:
                    raise ValueError
        return {"requests": 1, "request_bytes": len(body), "reserved_output_tokens": tokens}
    except AIProviderTransportError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        raise refused("live_request_out_of_scope") from None


def _validate_data(value: Any, *, depth: int = 0) -> None:
    if depth > 24:
        raise ValueError
    if isinstance(value, str):
        if len(value) > 32_768 or _CREDENTIAL.search(value):
            raise ValueError
    elif isinstance(value, Mapping):
        if len(value) > 256:
            raise ValueError
        for key, child in value.items():
            normalized = key.casefold().replace("-", "_")
            if normalized in _FORBIDDEN_DATA and child not in (
                None,
                "[REDACTED]",
                "[EVIDENCE REDACTED]",
                "[EVIDENCE CONTENT OMITTED]",
            ):
                raise ValueError
            secret_shaped = any(
                normalized == key
                or normalized.startswith(key + "_")
                or normalized.endswith("_" + key)
                for key in REQUIRED_REDACTION
            )
            public_digest = (
                normalized.endswith("_digest")
                and isinstance(child, str)
                and _DIGEST.fullmatch(child)
            )
            public_state = (
                normalized.endswith(("_available", "_configured", "_present"))
                and type(child) is bool
            )
            public_reference = (
                normalized.endswith(("_reference", "_env"))
                and isinstance(child, str)
                and re.fullmatch(r"[A-Z][A-Z0-9_]*", child)
            )
            if (
                secret_shaped
                and not (public_digest or public_state or public_reference)
                and child
                not in (
                    None,
                    "[REDACTED]",
                    "[EVIDENCE REDACTED]",
                    "[EVIDENCE CONTENT OMITTED]",
                )
            ):
                raise ValueError
            _validate_data(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 2048:
            raise ValueError
        for child in value:
            _validate_data(child, depth=depth + 1)


def reserve_usage(
    usage: Mapping[str, int], limits: Mapping[str, int], reservation: Mapping[str, int]
) -> dict[str, int]:
    if (
        set(usage) != set(COUNTERS)
        or set(reservation) != set(COUNTERS)
        or any(not _integer(usage[name], 0, limits[limit]) for name, limit in COUNTERS.items())
        or reservation["requests"] != 1
        or type(reservation["requests"]) is not int
        or not _integer(reservation["request_bytes"], 1, 1_048_576)
        or not _integer(reservation["reserved_output_tokens"], 1, 1_048_576)
    ):
        raise refused("live_store_unavailable")
    result = {name: usage[name] + reservation[name] for name in COUNTERS}
    if any(result[name] > limits[limit] for name, limit in COUNTERS.items()):
        raise refused("live_usage_exhausted")
    return result
