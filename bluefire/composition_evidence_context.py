"""Selected historical reasoning context; never imports or current-state authority."""

from __future__ import annotations

from typing import Any

from .ai_composition_contract import REFRESH_PREREQUISITES
from .capability_grant import authority_id, digest, text
from .capability_packs import RECEIVER_PACK
from .capability_resources import CapabilityContractError, exact
from .composition_knowledge import QUERY_SCHEMA as KNOWLEDGE_QUERY_SCHEMA
from .composition_knowledge import _members, build_knowledge
from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash, json_clone

QUERY_SCHEMA = "bluefire.composition-evidence-context-query.v1"
REQUEST_SCHEMA = "bluefire.composition-evidence-proposal-request.v1"
CONTEXT_SCHEMA = "bluefire.composition-evidence-proposal-context.v1"
RESULT_SCHEMA = "bluefire.composition-ai-result.v2"
_SELECTION = {"prior_attempt_id", "attempt_ids", "knowledge_digest"}
_TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def selection(request: Any, *, submission=False) -> dict[str, Any]:
    fields = _SELECTION | {"schema_version"}
    if submission:
        fields |= {"submission_id", "provider_id", "context_digest"}
    exact(request, fields, "historical composition selection")
    if request["schema_version"] != (REQUEST_SCHEMA if submission else QUERY_SCHEMA):
        raise CapabilityContractError("unsupported historical composition request")
    authority_id(request["prior_attempt_id"], "attempt")
    digest(request["knowledge_digest"], "selected historical knowledge")
    ids = request["attempt_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 8:
        raise CapabilityContractError("select one to eight historical attempts")
    for item in ids:
        authority_id(item, "attempt")
    if len(set(ids)) != len(ids):
        raise CapabilityContractError("historical attempt selection contains duplicates")
    return {key: json_clone(request[key]) for key in _SELECTION}


def historical_context(jobs, owner_id, selected, current):
    """Reverify source membership and settlement before constructing model context."""
    if current["snapshot"].get("pack") != RECEIVER_PACK:
        raise ProductStoreError("Historical model context supports only the receiver pack.")
    children = [
        child
        for child in jobs.store.list_jobs()
        if child["kind"] == "composition.attempt"
        and child["request"].get("composition_attempt", {}).get("parent_job_id") == owner_id
    ]
    frontier = None
    frontier_key = None
    for child in children:
        if child["state"] not in _TERMINAL:
            raise ProductStoreError("Settle every owned attempt before reconsidering choices.")
        attempt_id = child["request"]["composition_attempt"]["attempt_id"]
        try:
            attempt = jobs.store.get_capability_attempt(attempt_id)
        except ProductStoreError:
            # A terminal admission failure without a lease acquired no attempt effects.
            with jobs.store._connection() as connection:
                present = connection.execute(
                    "SELECT 1 FROM capability_attempts WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
            if present is not None:
                raise
            if child["state"] == "completed":
                raise ProductStoreError("A completed attempt is missing its owned lease.") from None
            continue
        if attempt["state"] != "settled":
            raise ProductStoreError("Historical context cannot bypass unresolved owned effects.")
        key = (attempt["lease"]["created_at_ms"], child["created_at"])
        if key == frontier_key:
            raise ProductStoreError("The latest settled attempt ordering is ambiguous.")
        if frontier_key is None or key > frontier_key:
            frontier, frontier_key = attempt_id, key
    if frontier is None or frontier != selected["prior_attempt_id"]:
        raise ProductStoreError("Select the latest settled attempt as the continuation frontier.")
    query = {"schema_version": KNOWLEDGE_QUERY_SCHEMA, "attempt_ids": selected["attempt_ids"]}
    knowledge = build_knowledge(jobs, owner_id, query)
    if knowledge["knowledge_digest"] != selected["knowledge_digest"]:
        raise ProductStoreError("Selected historical knowledge changed; review it again.")
    if any(row["source_status"] != "verified" for row in knowledge["attempts"]):
        raise ProductStoreError("Every selected historical source must be verified.")
    if not any(row["findings"] for row in knowledge["attempts"]):
        raise ProductStoreError("Select historical sources with findings to reconsider.")
    choices = []
    for attempt, _child in _members(jobs, owner_id, selected["attempt_ids"]):
        compiled, lease = attempt["compiled"], attempt["lease"]
        if (
            compiled["compiled_digest"]
            != content_hash(
                {key: value for key, value in compiled.items() if key != "compiled_digest"}
            )
            or compiled["compiled_digest"] != lease["compiled_digest"]
        ):
            raise ProductStoreError("The original compiled historical choice changed.")
        digest(compiled["semantic_digest"], "historical graph")
        steps = compiled["scenario"]["steps"]
        if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
            raise ProductStoreError("Historical graph choices exceed their bound.")
        for step in steps:
            # Only the closed compiler's graph parameters and producer references are projected.
            choices.append(
                {
                    "attempt_id": lease["attempt_id"],
                    "compiled_digest": compiled["compiled_digest"],
                    "semantic_digest": compiled["semantic_digest"],
                    "step_id": step["id"],
                    "behavior_id": step["behavior_id"],
                    "parameters": json_clone(step["parameters"]),
                    "inputs": json_clone(step.get("inputs", {})),
                }
            )
    result = {
        "knowledge_digest": knowledge["knowledge_digest"],
        "attempt_ids": list(selected["attempt_ids"]),
        "attempts": knowledge["attempts"],
        "choices": choices,
    }
    if len(canonical_json_bytes(result)) > 1_048_576:
        raise ProductStoreError("Selected historical reasoning context exceeds its byte bound.")
    return result


def validate_reconsideration(value, context):
    """Validate citations and identities, never validate a model's causal explanation as fact."""
    exact(value, {"reconsidered_choices", "refresh_requirements"}, "reconsideration")
    history = context["historical_context"]
    choices = {
        (row["attempt_id"], row["compiled_digest"], row["step_id"]) for row in history["choices"]
    }
    findings = {
        finding["finding_id"]: finding
        for attempt in history["attempts"]
        for finding in attempt["findings"]
    }
    rows = value["reconsidered_choices"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
        raise CapabilityContractError("reconsideration choice count is invalid")
    seen = set()
    for row in rows:
        exact(
            row,
            {"attempt_id", "compiled_digest", "step_id", "finding_refs", "reason"},
            "reconsidered choice",
        )
        if any(
            not isinstance(row[name], str) for name in ("attempt_id", "compiled_digest", "step_id")
        ):
            raise CapabilityContractError("reconsidered choice identities must be strings")
        key = (row["attempt_id"], row["compiled_digest"], row["step_id"])
        if key not in choices or key in seen:
            raise CapabilityContractError(
                "reconsideration names an unavailable or duplicate choice"
            )
        seen.add(key)
        text(row["reason"], "reconsideration reason", 2000)
        refs = row["finding_refs"]
        if not isinstance(refs, list) or not 1 <= len(refs) <= 16:
            raise CapabilityContractError("historical citation count is invalid")
        cited = set()
        for ref in refs:
            exact(ref, {"finding_id", "record_ref"}, "historical finding citation")
            finding = (
                findings.get(ref["finding_id"]) if isinstance(ref["finding_id"], str) else None
            )
            if (
                finding is None
                or ref["finding_id"] in cited
                or ref["record_ref"] != finding["record_ref"]
            ):
                raise CapabilityContractError(
                    "historical citation differs from its sealed selected source"
                )
            cited.add(ref["finding_id"])
    refresh = value["refresh_requirements"]
    if not isinstance(refresh, list) or len(refresh) != len(REFRESH_PREREQUISITES):
        raise CapabilityContractError("every mutable prerequisite needs a refresh explanation")
    names = []
    for row in refresh:
        exact(row, {"prerequisite", "explanation"}, "refresh requirement")
        text(row["explanation"], "refresh explanation", 1000)
        names.append(row["prerequisite"])
    if any(not isinstance(name, str) for name in names) or set(names) != set(REFRESH_PREREQUISITES):
        raise CapabilityContractError("refresh requirements must name each fixed prerequisite once")
    return json_clone(value)
