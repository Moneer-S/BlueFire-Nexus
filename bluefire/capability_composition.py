"""Untrusted whole-graph sketches compiled to exact fresh-attempt review records."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Mapping, Sequence

from . import capability_file_access
from .capability_facts import validate_facts
from .capability_grant import digest, text, validate_grant
from .capability_packs import FILE_ACCESS_PACK, grant_pack
from .capability_resources import METHODS, CapabilityContractError, exact, reserve_resources
from .contracts import ScenarioDefinition, StepOutcome
from .registry import BehaviorRegistry, _dominators, _reachable_from, _topological_order
from .util import canonical_json_bytes, content_hash, json_clone

SCHEMA = "bluefire.composition-proposal.v1"
_STEP_ID = re.compile(r"^[a-z][a-z0-9_]{0,99}$")


def parse_proposal(value: Any) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise CapabilityContractError("proposal contains duplicate JSON keys")
            result[key] = item
        return result

    def constant(_value):
        raise CapabilityContractError("proposal contains non-finite JSON")

    try:
        if isinstance(value, bytes):
            if len(value) > 256 * 1024:
                raise CapabilityContractError("proposal exceeds its byte bound")
            value = json.loads(
                value.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
            )
        row = exact(
            value,
            {"schema_version", "title", "start", "steps", "edges", "evidence_refs", "rationale"},
            "graph proposal",
        )
        if len(canonical_json_bytes(row)) > 256 * 1024 or row["schema_version"] != SCHEMA:
            raise CapabilityContractError("proposal version or size is invalid")
        text(row["title"], "proposal title", 200)
        text(row["rationale"], "proposal rationale", 2000)
        if not isinstance(row["steps"], list) or not 1 <= len(row["steps"]) <= 64:
            raise CapabilityContractError("proposal node count is invalid")
        if not isinstance(row["edges"], list) or len(row["edges"]) > 256:
            raise CapabilityContractError("proposal edge count is invalid")
        references = row["evidence_refs"]
        if (
            not isinstance(references, list)
            or not 1 <= len(references) <= 64
            or any(not isinstance(item, str) for item in references)
            or len(set(references)) != len(references)
        ):
            raise CapabilityContractError("proposal evidence references are invalid")
        return dict(json_clone(row))
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, CapabilityContractError):
            raise
        raise CapabilityContractError("proposal is not strict bounded JSON") from exc


def _step_id(value: Any) -> str:
    if not isinstance(value, str) or _STEP_ID.fullmatch(value) is None:
        raise CapabilityContractError("graph step ID is invalid")
    return value


def _graph(
    proposal: Mapping[str, Any], grant: Mapping[str, Any], registry: BehaviorRegistry
) -> tuple[ScenarioDefinition, Mapping[str, Any], str]:
    methods = {row["behavior_id"]: row for row in grant["snapshot"]["methods"]}
    steps = {}
    for raw in proposal["steps"]:
        row = exact(raw, {"id", "behavior_id", "parameters"}, "graph step")
        identity = _step_id(row["id"])
        method = methods.get(row["behavior_id"]) if isinstance(row["behavior_id"], str) else None
        if identity in steps or method is None or not isinstance(row["parameters"], Mapping):
            raise CapabilityContractError("graph step is duplicate, unavailable or malformed")
        domains = method["parameter_domains"]
        if set(row["parameters"]) - set(domains):
            raise CapabilityContractError("graph parameters expand the capability domain")
        parameters = {}
        for spec in registry.get_behavior(row["behavior_id"]).parameters:
            domain = domains[spec.name]
            default = domain[0] if len(domain) == 1 else spec.default
            value = row["parameters"].get(spec.name, default)
            if not any(
                canonical_json_bytes(value) == canonical_json_bytes(item) for item in domain
            ):
                raise CapabilityContractError("graph parameter is outside the granted domain")
            parameters[spec.name] = value
        registry.get_behavior(row["behavior_id"]).validate_parameters(parameters)
        steps[identity] = {
            "id": identity,
            "behavior_id": row["behavior_id"],
            "parameters": parameters,
        }
    start = _step_id(proposal["start"])
    if start not in steps:
        raise CapabilityContractError("graph start is unavailable")
    if len(proposal["edges"]) > grant["limits"]["max_edges_per_attempt"]:
        raise CapabilityContractError("graph exceeds its edge allowance")
    successors: dict[str, set[str]] = defaultdict(set)
    predecessors: dict[str, set[str]] = defaultdict(set)
    routes = {}
    edges = []
    for raw in proposal["edges"]:
        edge = exact(raw, {"from_step", "outcome", "to_step"}, "graph edge")
        source, target = _step_id(edge["from_step"]), _step_id(edge["to_step"])
        outcome = edge["outcome"]
        if (
            source not in steps
            or target not in steps
            or not isinstance(outcome, str)
            or outcome not in {item.value for item in StepOutcome}
        ):
            raise CapabilityContractError("graph edge is outside the registered contract")
        if (source, outcome) in routes:
            raise CapabilityContractError("graph has ambiguous outcome routes")
        routes[source, outcome] = target
        successors[source].add(target)
        predecessors[target].add(source)
        edges.append(dict(edge))
    if predecessors[start] or _reachable_from(start, successors) != set(steps):
        raise CapabilityContractError("graph start/reachability is invalid")
    order = _topological_order(tuple(steps), successors, predecessors)
    dominators = _dominators(order, start, predecessors)
    for identity in order:
        row = steps[identity]
        inputs = {}
        for input_spec in registry.get_behavior(row["behavior_id"]).inputs:
            candidates = [
                {"from_step": source, "artifact": output.name}
                for source in order
                if source in dominators[identity] and source != identity
                for output in registry.get_behavior(steps[source]["behavior_id"]).outputs
                if (output.type, output.multiple) == (input_spec.type, input_spec.multiple)
            ]
            if len(candidates) > 1 or (input_spec.required and not candidates):
                raise CapabilityContractError(
                    "input lacks one unambiguous dominating semantic producer"
                )
            if candidates:
                inputs[input_spec.name] = candidates[0]
        row["inputs"] = inputs
    details = (
        capability_file_access.graph_details(steps, successors, routes, grant)
        if grant_pack(grant) == FILE_ACCESS_PACK
        else _receiver_details(steps, successors, predecessors, routes, grant)
    )
    reservation = reserve_resources(list(steps.values()), grant["limits"], pack=grant_pack(grant))
    indexes = {identity: index for index, identity in enumerate(order)}
    semantic = {
        "steps": [
            {
                "behavior_id": steps[identity]["behavior_id"],
                "parameters": steps[identity]["parameters"],
                "inputs": {
                    port: {"from_node": indexes[ref["from_step"]], "artifact": ref["artifact"]}
                    for port, ref in steps[identity]["inputs"].items()
                },
            }
            for identity in order
        ],
        "edges": sorted(
            (indexes[e["from_step"]], e["outcome"], indexes[e["to_step"]]) for e in edges
        ),
    }
    semantic_digest = content_hash(semantic)
    scenario = ScenarioDefinition.from_mapping(
        {
            "schema_version": "bluefire.scenario.v1",
            "id": "scenario.composed-" + semantic_digest[7:27] + ".v1",
            "title": proposal["title"],
            "purpose": grant["objective"]["question"],
            "start": start,
            "steps": [steps[identity] for identity in order],
            "edges": edges,
            "provenance": {
                "source": "BlueFire reviewed capability composition",
                "reference": grant["grant_id"],
                "license": "MIT",
                "derived": False,
                "notes": "Model graph normalized against a finite installed snapshot; not an execution approval.",
            },
        }
    )
    registry.validate_scenario(scenario)
    return scenario, {"reservation": reservation, **details}, semantic_digest


def _receiver_details(steps, successors, predecessors, routes, grant):
    handoffs = [key for key, step in steps.items() if step["behavior_id"] == METHODS[5]]
    cleanups = [key for key, step in steps.items() if step["behavior_id"] == METHODS[6]]
    if len(handoffs) != 1 or len(cleanups) != 1:
        raise CapabilityContractError("graph requires one receiver handoff and one cleanup")
    handoff, cleanup = handoffs[0], cleanups[0]
    if successors[cleanup] or any(
        routes.get((handoff, outcome.value)) != cleanup for outcome in StepOutcome
    ):
        raise CapabilityContractError("every receiver outcome must end in the reviewed cleanup")
    # Every business node must contribute to the one allowed receiver operation.
    ancestors = _reachable_from(handoff, predecessors)
    if set(steps) - {cleanup} != ancestors:
        raise CapabilityContractError("graph contains unrelated business operations")
    stage = steps[handoff]["inputs"]["bundle"]["from_step"]
    if steps[stage]["behavior_id"] != METHODS[4]:
        raise CapabilityContractError("receiver needs the reviewed JSONL staging producer")
    return {
        "handoff": {
            "step_id": handoff,
            "stage_step_id": stage,
            "port": grant["environment"]["port"],
            "host": "127.0.0.1",
            "artifact_type": "artifact.sandbox.bundle.v1",
            "format": "jsonl",
        },
    }


def compile_revision(
    proposal: Any,
    *,
    grant: Mapping[str, Any],
    expected_grant_digest: str,
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    current_environment: Mapping[str, Any],
    facts: Mapping[str, Any],
    expected_facts_digest: str,
    now_ms: int,
    previous_semantic_digests: Sequence[str] = (),
) -> dict[str, Any]:
    return _compile(
        proposal,
        grant=grant,
        expected_grant_digest=expected_grant_digest,
        registry=registry,
        implementation_digests=implementation_digests,
        current_environment=current_environment,
        facts=facts,
        expected_facts_digest=expected_facts_digest,
        now_ms=now_ms,
        previous_semantic_digests=previous_semantic_digests,
        revision=True,
    )


def compile_initial_graph(
    proposal: Any,
    *,
    grant: Mapping[str, Any],
    expected_grant_digest: str,
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    current_environment: Mapping[str, Any],
    facts: Mapping[str, Any],
    expected_facts_digest: str,
    now_ms: int,
) -> dict[str, Any]:
    return _compile(
        proposal,
        grant=grant,
        expected_grant_digest=expected_grant_digest,
        registry=registry,
        implementation_digests=implementation_digests,
        current_environment=current_environment,
        facts=facts,
        expected_facts_digest=expected_facts_digest,
        now_ms=now_ms,
        previous_semantic_digests=(),
        revision=False,
    )


def _compile(
    proposal: Any,
    *,
    grant: Mapping[str, Any],
    expected_grant_digest: str,
    registry: BehaviorRegistry,
    implementation_digests: Mapping[str, str],
    current_environment: Mapping[str, Any],
    facts: Mapping[str, Any],
    expected_facts_digest: str,
    now_ms: int,
    previous_semantic_digests: Sequence[str],
    revision: bool,
) -> dict[str, Any]:
    if (
        not isinstance(previous_semantic_digests, (tuple, list))
        or len(previous_semantic_digests) > 32
    ):
        raise CapabilityContractError("prior graph history is invalid")
    for value in previous_semantic_digests:
        digest(value, "prior graph digest")
    grant = validate_grant(
        grant,
        expected_digest=expected_grant_digest,
        registry=registry,
        implementation_digests=implementation_digests,
        current_environment=current_environment,
        now_ms=now_ms,
    )
    facts = validate_facts(
        facts,
        expected_digest=expected_facts_digest,
        grant=grant,
        now_ms=now_ms,
        require_prior_result=revision,
    )
    proposal = parse_proposal(proposal)
    by_id = {row["fact_id"]: row for row in facts["facts"]}
    references = set(proposal["evidence_refs"])
    if not references <= set(by_id) or any(
        by_id[key]["provenance"] != "observed" or now_ms >= by_id[key]["valid_until_ms"]
        for key in references
    ):
        raise CapabilityContractError("proposal references unknown, stale or unobserved evidence")
    required = (
        {"retained_file_control"}
        if grant_pack(grant) == FILE_ACCESS_PACK
        else {"receiver_result", "cleanup"} if revision else {"retained_policy"}
    )
    if not required <= {by_id[key]["kind"] for key in references}:
        raise CapabilityContractError("proposal omits its supporting evidence references")
    scenario, details, semantic_digest = _graph(proposal, grant, registry)
    if revision and semantic_digest in {facts["prior_graph_digest"], *previous_semantic_digests}:
        raise CapabilityContractError("equivalent attempted graph offers no new permitted route")
    body = {
        "schema_version": "bluefire.compiled-composition.v1",
        "revision_kind": "revision" if revision else "initial",
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "snapshot_digest": grant["snapshot"]["snapshot_digest"],
        "environment_digest": content_hash(grant["environment"]),
        "facts_digest": facts["facts_digest"],
        "prior_attempt_id": facts["prior_attempt_id"],
        "scenario": scenario.to_dict(),
        "action_implementations": {step.id: step.behavior_id for step in scenario.steps},
        "semantic_digest": semantic_digest,
        "evidence_refs": sorted(references),
        "rationale": proposal["rationale"],
        **details,
    }
    return {**body, "compiled_digest": content_hash(body)}
