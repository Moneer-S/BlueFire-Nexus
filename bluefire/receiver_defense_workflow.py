"""Versioned receiver workflows over the existing reviewed native methods."""

from __future__ import annotations

import re
from typing import Mapping

from .product_store_errors import ProductStoreError
from .receiver_defense_contract import WORKFLOW, phases, retained
from .receiver_policy import REDACTED_ONLY_POLICY, REVIEWED_RECORDS_POLICY, ReceiverContentPolicy
from .util import content_hash

OPTION_FIELDS = {"workflow", "source_control"}


def options(request):
    if "workflow" not in request:
        if "source_control" in request:
            raise ProductStoreError("A retained control requires its explicit workflow.")
        return {}
    if request["workflow"] != WORKFLOW:
        raise ProductStoreError("The receiver workflow is unavailable.")
    value = {"workflow": WORKFLOW}
    if "source_control" in request:
        source = request["source_control"]
        if not isinstance(source, Mapping) or set(source) != {"job_id", "control_digest"}:
            raise ProductStoreError("Select an exact retained receiver control.")
        if (
            not isinstance(source["job_id"], str)
            or re.fullmatch(r"job-[0-9a-f]{32}", source["job_id"]) is None
            or not isinstance(source["control_digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", source["control_digest"]) is None
        ):
            raise ProductStoreError("The retained receiver control identity is invalid.")
        value["source_control"] = dict(source)
    return value


def policy(context, phase):
    if phase not in phases(context):
        raise ProductStoreError("Select a phase from this receiver workflow.")
    if retained(context) and phase != "baseline" and context.get("control"):
        return context["control"]["policy_id"]
    return (
        REDACTED_ONLY_POLICY
        if phase == "protected" or (retained(context) and phase == "legitimate")
        else REVIEWED_RECORDS_POLICY
    )


def schema(context, name):
    return f"bluefire.receiver-defense{name}.v{2 if retained(context) else 1}"


def redaction_step(scenario, handoff):
    """Follow the actual bound producer chain, not an unrelated transform node."""
    steps = {step["id"]: step for step in scenario["steps"]}
    stage = steps[handoff["stage_step_id"]]
    binding = stage.get("inputs", {}).get("records", {})
    discovery = steps.get(binding.get("from_step"), {})
    if (
        binding.get("artifact") != "records"
        or discovery.get("behavior_id")
        not in {"sandbox.discovery.list.v1", "sandbox.discovery.metadata.v1"}
        or discovery.get("alternates")
    ):
        raise ProductStoreError("Bind staged records to the reviewed fixture discovery method.")
    binding = discovery.get("inputs", {}).get("fixture", {})
    transform = steps.get(binding.get("from_step"), {})
    if (
        binding.get("artifact") != "fixture"
        or transform.get("behavior_id") != "sandbox.fixture.transform.v1"
        or transform.get("parameters", {}).get("redact_values", True) is not False
        or transform.get("alternates")
    ):
        raise ProductStoreError("The baseline must retain values in its bound fixture transform.")
    binding = transform.get("inputs", {}).get("workspace", {})
    create = steps.get(binding.get("from_step"), {})
    if (
        binding.get("artifact") != "workspace"
        or create.get("behavior_id") != "sandbox.fixture.create.v1"
        or create.get("alternates")
    ):
        raise ProductStoreError("The retained control requires generated fixture records.")
    return transform["id"]


def control_descriptor(context, transform):
    target = ReceiverContentPolicy(REDACTED_ONLY_POLICY)
    value = {
        "schema_version": "bluefire.receiver-control.v1",
        "policy_id": target.policy_id,
        "policy_digest": target.digest,
        "redaction_step_id": transform,
        "scope": {
            "selection": context["selection"],
            "run_intent": context["run_intent"],
            "profile_digest": context["profile_digest"],
            "catalog_binding": context["catalog_binding"],
            "collector_binding": context["collector_binding"],
        },
    }
    return {**value, "control_digest": content_hash(value)}


def legitimate_semantics(result, baseline):
    semantics = (
        result.get("receiver_observation", {})
        .get("terminal", {})
        .get("decision", {})
        .get("semantics", {})
    )
    original = (
        baseline.get("receiver_observation", {})
        .get("terminal", {})
        .get("decision", {})
        .get("semantics", {})
    )
    count = semantics.get("record_count")
    return (
        type(count) is int
        and count > 0
        and count == original.get("record_count")
        and semantics.get("redacted_record_count") == count
        and semantics.get("retained_record_count") == 0
        and semantics.get("empty_record_count") == 0
    )
