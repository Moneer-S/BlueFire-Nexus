"""Resolve checkpoint defaults from the exact, previously approved contracts.

The proof carries the existing execution intent, not a new approval. Its digest
must reproduce the approval binding already sealed into the source run.
"""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import BehaviorDefinition, ContractError
from .registry import BehaviorRegistry
from .replay_checkpoint_values import (
    MAX_CHECKPOINT_JSON_BYTES,
    MAX_CHECKPOINT_JSON_NODES,
    CheckpointError,
    json_cost,
)
from .util import content_hash, json_clone

RESOLUTION_SCHEMA = "bluefire.checkpoint-parameter-resolution.v1"


def build_parameter_resolution(
    scenario: Mapping[str, Any],
    approval_binding: Mapping[str, Any],
    approved_intent: Mapping[str, Any],
) -> Mapping[str, Any]:
    template = json_clone(approved_intent)
    contracts = {}
    for step in template["resolved_alternate_envelope"]["steps"]:
        for option in step["options"]:
            for row in (option, *option["actions"]):
                contract = row["contract"]
                digest = content_hash(contract)
                _require(row["contract_digest"] == digest)
                contracts[digest] = contract
                row["contract"] = {"reviewed_contract_ref": digest}
    return {
        "schema_version": RESOLUTION_SCHEMA,
        "approval_binding": dict(approval_binding),
        "intent_template": template,
        "contracts": contracts,
        "authored_parameters": {
            step["id"]: dict(step.get("parameters", {})) for step in scenario["steps"]
        },
    }


def reviewed_intent(proof: Mapping[str, Any]) -> Mapping[str, Any]:
    """Reconstruct the original intent without adding authority or decoding text.

    Fixed contract slots reference ordinary JSON documents by content hash. This
    keeps the existing checkpoint structural limits and avoids repeated copies.
    """
    template_source = _mapping(proof.get("intent_template"))
    expanded_bytes, expanded_nodes = json_cost(template_source)
    template = json_clone(template_source)
    contracts = _mapping(proof.get("contracts"))
    costs = {}
    used = set()
    for step in template["resolved_alternate_envelope"]["steps"]:
        for option in step["options"]:
            for row in (option, *option["actions"]):
                reference = _mapping(row["contract"])
                _require(set(reference) == {"reviewed_contract_ref"})
                digest = reference["reviewed_contract_ref"]
                contract = _mapping(contracts[digest])
                if digest not in costs:
                    costs[digest] = json_cost(contract)
                    _require(digest == content_hash(contract))
                _require(row["contract_digest"] == digest)
                contract_bytes, contract_nodes = costs[digest]
                expanded_bytes += contract_bytes
                expanded_nodes += contract_nodes
                if expanded_bytes > MAX_CHECKPOINT_JSON_BYTES:
                    raise CheckpointError("checkpoint expanded approval exceeds its byte bound")
                if expanded_nodes > MAX_CHECKPOINT_JSON_NODES:
                    raise CheckpointError("checkpoint expanded approval exceeds its node bound")
                row["contract"] = dict(contract)
                used.add(digest)
    _require(used == set(contracts))
    return _mapping(template)


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CheckpointError("checkpoint parameter resolution requires an object")
    return value


def _require(condition: bool) -> None:
    if not condition:
        raise CheckpointError("checkpoint parameter resolution is not bound to its reviewed source")


def _resolved(behavior: BehaviorDefinition, authored: Mapping[str, Any]) -> dict[str, Any]:
    try:
        behavior.validate_parameters(authored)
        resolved = {
            spec.name: spec.default for spec in behavior.parameters if spec.default is not None
        }
        resolved.update(authored)
        behavior.validate_parameters(resolved)
        return resolved
    except (ContractError, TypeError, ValueError) as exc:
        raise CheckpointError(
            "checkpoint parameters violate the reviewed behavior contract"
        ) from exc


def _reviewed_behavior(contract: Mapping[str, Any]) -> BehaviorDefinition:
    # Canonical to_dict emits empty optional descriptions; authored-document
    # parsing expresses the same value by omission. Preserve the hashed record.
    document = json_clone(contract)
    for field in ("inputs", "outputs", "parameters"):
        for spec in document.get(field, []):
            if spec.get("description") == "":
                spec.pop("description")
    behavior = BehaviorDefinition.from_mapping(document)
    _require(content_hash(behavior.to_dict()) == content_hash(contract))
    return behavior


def resolution_hashes(
    value: Mapping[str, Any],
    *,
    scenario: Mapping[str, Any],
    plan_hash: str,
    source_run_id: str,
    source_binding_hash: str,
    authority: Mapping[str, Any],
) -> Mapping[str, str]:
    """Verify the original authority before accepting any resolved parameter hash."""
    try:
        proof = _mapping(value)
        _require(
            set(proof)
            == {
                "schema_version",
                "approval_binding",
                "intent_template",
                "contracts",
                "authored_parameters",
            }
        )
        _require(proof["schema_version"] == RESOLUTION_SCHEMA)
        binding = _mapping(proof["approval_binding"])
        _require(
            set(binding)
            == {"state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"}
        )
        intent = reviewed_intent(proof)
        _require(intent.get("schema_version") == "bluefire.execution-intent.v1")
        _require(binding["state_digest"] == content_hash(intent))
        _require(binding["plan_digest"] == plan_hash)
        _require(intent.get("scenario_digest") == scenario["scenario_hash"])
        _require(intent.get("mode") == "execute")
        _require(binding["profile_id"] == _mapping(intent.get("profile")).get("id"))
        _require(binding["target_scope_digest"] == content_hash(intent.get("target_scope")))
        _require(
            content_hash(intent.get("catalog_authority")) == authority["catalog"]["catalog_hash"]
        )
        _require(content_hash(intent.get("profile")) == authority["profile"]["profile_hash"])
        _require(
            content_hash(intent.get("target_scope")) == authority["target_scope"]["scope_hash"]
        )
        _require(
            content_hash(intent.get("runner_readiness")) == authority["runner"]["readiness_hash"]
        )
        _require(
            source_binding_hash
            == content_hash(
                {
                    "schema_version": "bluefire.checkpoint-source-binding.v1",
                    "run_id": source_run_id,
                    "scenario_digest": scenario["scenario_hash"],
                    "plan_digest": plan_hash,
                    "approval_binding_digest": content_hash(binding),
                }
            )
        )
        envelope = dict(_mapping(intent.get("resolved_alternate_envelope")))
        envelope_digest = envelope.pop("envelope_digest", None)
        _require(envelope_digest == content_hash(envelope))
        _require(envelope.get("schema_version") == "bluefire.approval-envelope.v1")
        _require(envelope.get("scenario_id") == scenario["scenario_id"])
        _require(envelope.get("catalog_authority") == intent.get("catalog_authority"))
        authored = _mapping(proof["authored_parameters"])
        summaries = scenario["steps"]
        rows = envelope.get("steps")
        if not isinstance(rows, list):
            raise CheckpointError("checkpoint parameter resolution steps are invalid")
        _require(len(rows) == len(summaries) <= 256)
        _require(set(authored) == {step["step_id"] for step in summaries})
        hashes: dict[str, str] = {}
        for summary, raw in zip(summaries, rows, strict=True):
            row = _mapping(raw)
            step_id = summary["step_id"]
            _require(row.get("step_id") == step_id)
            parameters = _mapping(authored[step_id])
            _require(content_hash(parameters) == summary["parameters_hash"])
            options = row.get("options")
            if not isinstance(options, list):
                raise CheckpointError("checkpoint parameter resolution options are invalid")
            _require(1 <= len(options) <= 257)
            primary = [option for option in options if _mapping(option).get("is_primary") is True]
            _require(len(primary) == 1)
            selected = primary[0]
            _require(selected.get("behavior_id") == summary["behavior_id"])
            contract = _mapping(selected.get("contract"))
            _require(selected.get("contract_digest") == content_hash(contract))
            behavior = _reviewed_behavior(contract)
            _require(behavior.id == summary["behavior_id"])
            resolved = _resolved(behavior, parameters)
            _require(content_hash(resolved) == content_hash(selected.get("resolved_parameters")))
            hashes[step_id] = content_hash(resolved)
        return hashes
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CheckpointError):
            raise
        raise CheckpointError("checkpoint parameter resolution is invalid") from exc


def current_parameter_hashes(
    registry: BehaviorRegistry,
    scenario: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> Mapping[str, str]:
    """Resolve a new target against the registry selected for its fresh review."""
    defined = scenario["steps"]
    planned = plan["steps"]
    _require(len(defined) == len(planned) <= 256)
    hashes = {}
    for step, compiled in zip(defined, planned, strict=True):
        _require(
            step["id"] == compiled["step_id"] and step["behavior_id"] == compiled["behavior_id"]
        )
        resolved = _resolved(registry.get_behavior(step["behavior_id"]), step.get("parameters", {}))
        _require(content_hash(resolved) == content_hash(compiled.get("parameters", {})))
        hashes[step["id"]] = content_hash(resolved)
    return hashes


def verify_current_contracts(proof: Mapping[str, Any], registry: BehaviorRegistry) -> None:
    """A node replay uses only the unchanged captured behavior and action contracts."""
    try:
        envelope = reviewed_intent(proof)["resolved_alternate_envelope"]
        for step in envelope["steps"]:
            for option in step["options"]:
                behavior = registry.get_behavior(option["behavior_id"])
                _require(content_hash(behavior.to_dict()) == option["contract_digest"])
                for reviewed_action in option["actions"]:
                    action = registry.get_action(reviewed_action["action_id"])
                    _require(content_hash(action.to_dict()) == reviewed_action["contract_digest"])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CheckpointError):
            raise
        raise CheckpointError("checkpoint parameter catalog is unavailable or changed") from exc
