"""No-effect compiler checks using the actual installed behavior/adapter contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.capability_composition import compile_initial_graph, compile_revision, parse_proposal
from bluefire.capability_facts import SCHEMA as FACT_SCHEMA
from bluefire.capability_facts import seal_facts, validate_facts
from bluefire.capability_grant import authority_id, create_grant, objective_result, validate_grant
from bluefire.capability_resources import (
    METHODS,
    RESERVATION_LIMITS,
    CapabilityContractError,
    accumulate_reservation,
    method_cost,
    reserve_resources,
)
from bluefire.contracts import SafetyTier, ScenarioDefinition
from bluefire.planner import PlanStep
from bluefire.receiver_policy import REDACTED_ONLY_POLICY, ReceiverContentPolicy
from bluefire.registry import load_builtin_registry
from bluefire.runner_adapter import RunnerActionAdapter
from bluefire.util import canonical_json_bytes, content_hash

GRANT_ID = "grant-" + "a" * 32
ATTEMPT_ID = "attempt-" + "b" * 32


@pytest.mark.parametrize(
    "kind,value",
    [
        ("grant", "grant-1"),
        ("attempt", "attempt-1"),
        ("grant", "grant-" + "A" * 32),
        ("attempt", "attempt-" + "b" * 31),
        ("grant", ATTEMPT_ID),
        ("attempt", GRANT_ID),
    ],
)
def test_authority_ids_match_native_provenance_contract(kind, value):
    with pytest.raises(CapabilityContractError):
        authority_id(value, kind)
    assert authority_id(GRANT_ID, "grant") == GRANT_ID
    assert authority_id(ATTEMPT_ID, "attempt") == ATTEMPT_ID


@pytest.fixture
def state():
    registry = load_builtin_registry()
    implementations = {method: content_hash({"test_implementation": method}) for method in METHODS}
    environment = {
        "environment_id": "owned-lab.v1",
        "environment_generation": "generation-1",
        "runner_id": "runner-1",
        "control_owner_id": "job-1",
        "policy_id": REDACTED_ONLY_POLICY,
        "policy_digest": ReceiverContentPolicy(REDACTED_ONLY_POLICY).digest,
        "port": 4317,
        **{
            key: content_hash(key)
            for key in (
                "enrollment_digest",
                "profile_digest",
                "target_scope_digest",
                "collector_digest",
                "control_digest",
            )
        },
    }
    limits = {
        "max_attempts": 3,
        "max_nodes_per_attempt": 16,
        "max_edges_per_attempt": 64,
        "max_business_steps": 24,
        "max_generated_bytes": 10 * 1024**2,
        "max_network_bytes": 3 * 1024**2,
        "max_peak_workspace_bytes": 4 * 1024**2,
        "max_workspace_files": 8,
        "max_retained_metadata_bytes": 8 * 1024**2,
        "max_reserved_attempt_ms": 270_000,
        "per_attempt_wall_ms": 90_000,
        "cleanup_reserve_ms": 10_000,
    }
    grant = create_grant(
        registry=registry,
        implementation_digests=implementations,
        objective={
            "question": "Preserve eight records through the retained defense.",
            "predicate": {
                "kind": "redacted_delivery_preserves_records",
                "record_count": 8,
                "data_class": "generated_public_jsonl",
            },
        },
        environment=environment,
        limits=limits,
        grant_id=GRANT_ID,
        approved_by="Test operator",
        created_at_ms=1000,
        expires_at_ms=901_000,
    )
    policy = fact(
        grant,
        "policy",
        "retained_policy",
        {
            "status": "retained",
            "policy_digest": environment["policy_digest"],
        },
    )
    facts = seal_facts(
        {
            "schema_version": FACT_SCHEMA,
            "environment_digest": content_hash(environment),
            "control_digest": environment["control_digest"],
            "prior_attempt_id": None,
            "prior_graph_digest": None,
            "facts": [policy],
        }
    )
    return {
        "grant": grant,
        "expected_grant_digest": grant["grant_digest"],
        "registry": registry,
        "implementation_digests": implementations,
        "current_environment": environment,
        "facts": facts,
        "expected_facts_digest": facts["facts_digest"],
        "now_ms": 2000,
    }


def fact(grant, identity, kind, value):
    return {
        "fact_id": identity,
        "kind": kind,
        "provenance": "observed",
        "source": {
            "kind": "control_record" if kind == "retained_policy" else "run_evidence",
            "id": "evidence-" + identity,
            "digest": content_hash(identity),
        },
        "observed_at_ms": 1000,
        "valid_until_ms": 900_000,
        "environment_digest": content_hash(grant["environment"]),
        "control_digest": grant["environment"]["control_digest"],
        "attempt_id": None if kind == "retained_policy" else ATTEMPT_ID,
        "value": value,
    }


def proposal(*, redact=False, discovery=METHODS[2]):
    identities = ["seed", "prepare", "inspect", "stage", "send", "clean"]
    methods = [METHODS[0], METHODS[1], discovery, METHODS[4], METHODS[5], METHODS[6]]
    return {
        "schema_version": "bluefire.composition-proposal.v1",
        "title": "Receiver trial",
        "start": "seed",
        "steps": [
            {
                "id": identity,
                "behavior_id": method,
                "parameters": {"redact_values": redact} if identity == "prepare" else {},
            }
            for identity, method in zip(identities, methods, strict=True)
        ],
        "edges": [
            {"from_step": left, "outcome": "success", "to_step": right}
            for left, right in zip(identities, identities[1:], strict=False)
        ]
        + [
            {"from_step": "send", "outcome": outcome, "to_step": "clean"}
            for outcome in ("blocked", "failed", "partial")
        ],
        "evidence_refs": ["policy"],
        "rationale": "Test the observed retained receiver policy.",
    }


def revision_state(state):
    result = deepcopy({key: value for key, value in state.items() if key != "registry"})
    result["registry"] = state["registry"]
    prior = compile_initial_graph(proposal(), **state)
    grant = result["grant"]
    body = {key: value for key, value in result["facts"].items() if key != "facts_digest"}
    body.update(prior_attempt_id=ATTEMPT_ID, prior_graph_digest=prior["semantic_digest"])
    body["facts"] += [
        fact(
            grant,
            "refusal",
            "receiver_result",
            {
                "decision": "policy_refused",
                "policy_digest": grant["environment"]["policy_digest"],
                "record_count": 8,
                "redacted_record_count": 0,
                "retained_record_count": 8,
                "empty_record_count": 0,
            },
        ),
        fact(grant, "cleanup", "cleanup", {"run": "complete", "receiver": "verified_closed"}),
    ]
    result["facts"] = seal_facts(body)
    result["expected_facts_digest"] = result["facts"]["facts_digest"]
    return result


def revision_proposal(**kwargs):
    value = proposal(redact=True, **kwargs)
    value["evidence_refs"] = ["refusal", "cleanup"]
    value["rationale"] = (
        "The receiver refused retained values; prepare the same count as redacted records."
    )
    return value


def reseal_facts(state):
    state["facts"] = seal_facts(
        {key: value for key, value in state["facts"].items() if key != "facts_digest"}
    )
    state["expected_facts_digest"] = state["facts"]["facts_digest"]


def test_initial_graph_does_not_require_a_prior_refusal_or_grant_authority(state):
    compiled = compile_initial_graph(proposal(), **state)
    scenario = ScenarioDefinition.from_mapping(compiled["scenario"])
    state["registry"].validate_scenario(scenario)
    assert scenario.step("seed").parameters == {"record_count": 8}
    assert scenario.step("send").inputs["bundle"].from_step == "stage"
    assert scenario.step("prepare").parameters == {"redact_values": False}
    assert compiled["revision_kind"] == "initial"
    assert "approval" not in compiled and "lease" not in compiled
    assert compiled["handoff"]["host"] == "127.0.0.1"
    assert "adaptive_execution" not in compiled["scenario"]


def test_evidence_driven_fresh_graph_has_exact_bindings_and_frozen_count(state):
    current = revision_state(state)
    compiled = compile_revision(revision_proposal(discovery=METHODS[3]), **current)
    assert compiled["prior_attempt_id"] == ATTEMPT_ID
    assert compiled["action_implementations"]["inspect"] == METHODS[3]
    assert compiled["scenario"]["steps"][1]["parameters"] == {"redact_values": True}
    assert compiled["reservation"]["generated_bytes"] == 3 * 1024**2
    assert compiled["reservation"]["network_bytes"] == 1024**2
    assert compiled["grant_digest"] == state["expected_grant_digest"]


@pytest.mark.parametrize(
    "field,value", [("record_count", 1), ("record_count", True), ("path", "/tmp/other")]
)
def test_parameters_cannot_shrink_objective_or_expand_target(state, field, value):
    graph = proposal()
    graph["steps"][0]["parameters"][field] = value
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(graph, **state)


@pytest.mark.parametrize(
    "change", ["parameter", "grant", "implementation", "environment", "expiry"]
)
def test_grant_verification_uses_independently_trusted_digest(state, change):
    if change == "parameter":
        state["grant"]["snapshot"]["methods"][0]["parameter_domains"]["record_count"] = [1]
        state["grant"]["grant_digest"] = content_hash(
            {key: value for key, value in state["grant"].items() if key != "grant_digest"}
        )
    elif change == "grant":
        state["grant"]["limits"]["max_attempts"] = 4
    elif change == "implementation":
        state["implementation_digests"][METHODS[1]] = content_hash("new binary")
    elif change == "environment":
        state["current_environment"]["environment_generation"] = "generation-2"
    else:
        state["now_ms"] = state["grant"]["expires_at_ms"]
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(proposal(), **state)


def test_snapshot_and_compiled_values_are_detached_from_callers(state):
    compiled = compile_initial_graph(proposal(), **state)
    compiled["scenario"]["steps"][0]["parameters"]["record_count"] = 1
    assert (
        compile_initial_graph(proposal(), **state)["scenario"]["steps"][0]["parameters"][
            "record_count"
        ]
        == 8
    )
    checked = validate_grant(
        state["grant"],
        expected_digest=state["expected_grant_digest"],
        **{
            key: state[key]
            for key in ("registry", "implementation_digests", "current_environment", "now_ms")
        },
    )
    checked["snapshot"]["methods"].clear()
    assert len(state["grant"]["snapshot"]["methods"]) == 7


@pytest.mark.parametrize(
    "change",
    [
        "hypothesis",
        "stale",
        "cleanup",
        "missing",
        "wrong_scope",
        "future",
        "tamper",
        "contradiction",
    ],
)
def test_revision_refuses_unproven_or_stale_inputs(state, change):
    state = revision_state(state)
    target = state["facts"]["facts"][1]
    if change == "hypothesis":
        target["provenance"] = "model_hypothesis"
    elif change == "stale":
        target["valid_until_ms"] = state["now_ms"]
    elif change == "cleanup":
        state["facts"]["facts"][2]["value"]["run"] = "incomplete"
    elif change == "missing":
        state["facts"]["facts"].pop()
    elif change == "wrong_scope":
        target["environment_digest"] = content_hash("another environment")
    elif change == "future":
        target["observed_at_ms"] = 3000
    elif change == "contradiction":
        other = deepcopy(target)
        other["fact_id"] = "conflicting"
        other["value"]["decision"] = "accepted"
        state["facts"]["facts"].append(other)
    else:
        target["value"]["retained_record_count"] = 7
    if change != "tamper":
        reseal_facts(state)
    with pytest.raises(CapabilityContractError):
        compile_revision(revision_proposal(), **state)


def test_initial_and_revision_fact_requirements_are_not_interchangeable(state):
    with pytest.raises(CapabilityContractError):
        compile_revision(revision_proposal(), **state)
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(proposal(), **revision_state(state))


def test_rehashed_facts_cannot_replace_the_trusted_record_digest(state):
    current = revision_state(state)
    trusted_digest = current["expected_facts_digest"]
    current["facts"]["facts"][1]["value"].update(redacted_record_count=8, retained_record_count=0)
    reseal_facts(current)
    assert current["facts"]["facts_digest"] != trusted_digest
    current["expected_facts_digest"] = trusted_digest
    with pytest.raises(CapabilityContractError, match="fact set changed"):
        compile_revision(revision_proposal(), **current)


@pytest.mark.parametrize("reference", ["missing", "policy"])
def test_revision_must_reference_its_actual_prior_result_and_cleanup(state, reference):
    graph = revision_proposal()
    graph["evidence_refs"] = [reference]
    with pytest.raises(CapabilityContractError):
        compile_revision(graph, **revision_state(state))


def test_renaming_nodes_does_not_create_a_new_attempted_route(state):
    current = revision_state(state)
    graph = proposal()
    graph["evidence_refs"] = ["refusal", "cleanup"]
    names = {step["id"]: "new_" + step["id"] for step in graph["steps"]}
    for step in graph["steps"]:
        step["id"] = names[step["id"]]
    for edge in graph["edges"]:
        edge["from_step"], edge["to_step"] = names[edge["from_step"]], names[edge["to_step"]]
    graph["start"] = names[graph["start"]]
    with pytest.raises(CapabilityContractError, match="equivalent"):
        compile_revision(graph, **current)


def test_compiler_rejects_ambiguous_real_semantic_producers(state):
    graph = proposal()
    graph["steps"].insert(3, {"id": "also_inspect", "behavior_id": METHODS[3], "parameters": {}})
    graph["edges"][2]["to_step"] = "also_inspect"
    graph["edges"].append({"from_step": "also_inspect", "outcome": "success", "to_step": "stage"})
    with pytest.raises(CapabilityContractError, match="unambiguous"):
        compile_initial_graph(graph, **state)


@pytest.mark.parametrize(
    "change",
    ["cleanup", "scope", "action", "cycle", "unknown", "edge", "edge_type", "input_binding"],
)
def test_full_graph_refuses_unreviewed_structure(state, change):
    graph = proposal()
    if change == "cleanup":
        graph["edges"].pop()
    elif change == "scope":
        graph["steps"][4]["parameters"]["port"] = 4321
    elif change == "action":
        graph["steps"][4]["action_id"] = METHODS[5]
    elif change == "cycle":
        graph["edges"].append({"from_step": "clean", "outcome": "success", "to_step": "seed"})
    elif change == "unknown":
        graph["steps"][2]["behavior_id"] = "endpoint.discovery.system.v1"
    elif change == "edge":
        graph["edges"][0]["outcome"] = "invented"
    elif change == "edge_type":
        graph["edges"][0]["outcome"] = []
    else:
        graph["steps"][1]["inputs"] = {
            "workspace": {"from_step": "old_attempt", "artifact": "workspace"}
        }
    with pytest.raises(ValueError):
        compile_initial_graph(graph, **state)


def test_strict_wire_parser_refuses_duplicate_keys_and_nonfinite_numbers():
    with pytest.raises(CapabilityContractError):
        parse_proposal(b'{"title":"first","title":"second"}')
    with pytest.raises(CapabilityContractError):
        parse_proposal(b'{"value":NaN}')


def test_resource_reservations_count_every_material_write_and_never_refund(state):
    graph = compile_initial_graph(proposal(), **state)
    reservation = graph["reservation"]
    assert reservation["generated_bytes"] == reservation["peak_workspace_bytes"] == 3 * 1024**2
    assert reservation["workspace_files"] == 3
    assert reservation["business_steps"] == 5
    assert reservation["retained_metadata_bytes"] > 0
    totals = dict.fromkeys(RESERVATION_LIMITS, 0)
    for _ in range(3):
        totals = accumulate_reservation(totals, reservation, state["grant"]["limits"])
    assert totals["reserved_attempt_ms"] == 270_000
    assert totals["generated_bytes"] == 9 * 1024**2
    with pytest.raises(CapabilityContractError):
        accumulate_reservation(totals, reservation, state["grant"]["limits"])


def test_cost_contracts_reject_unknown_bounds_and_fixed_slot_overwrites(state):
    with pytest.raises(CapabilityContractError):
        method_cost("endpoint.discovery.system.v1")
    steps = proposal()["steps"]
    steps.append({"id": "second_seed", "behavior_id": METHODS[0], "parameters": {}})
    with pytest.raises(CapabilityContractError, match="conflicting"):
        reserve_resources(steps, state["grant"]["limits"])


@pytest.mark.parametrize(
    "limit,value",
    [
        ("max_generated_bytes", 3 * 1024**2 - 1),
        ("max_network_bytes", 1024**2 - 1),
        ("max_peak_workspace_bytes", 3 * 1024**2 - 1),
        ("max_workspace_files", 2),
        ("max_retained_metadata_bytes", 6 * 128 * 1024 - 1),
        ("max_business_steps", 4),
    ],
)
def test_each_resource_dimension_is_checked_before_admission(state, limit, value):
    limits = dict(state["grant"]["limits"])
    limits[limit] = value
    with pytest.raises(CapabilityContractError):
        reserve_resources(proposal()["steps"], limits)


@pytest.mark.parametrize(
    "field",
    ["record_count", "redacted_record_count", "receiver_verified", "policy_digest", "run_cleanup"],
)
def test_success_predicate_cannot_be_satisfied_by_model_prose(state, field):
    result = {
        "receiver_verified": True,
        "policy_digest": state["grant"]["environment"]["policy_digest"],
        "data_class": "generated_public_jsonl",
        "record_count": 8,
        "redacted_record_count": 8,
        "retained_record_count": 0,
        "empty_record_count": 0,
        "decision": "accepted",
        "run_cleanup": "complete",
        "receiver_cleanup": "verified_closed",
    }
    assert objective_result(state["grant"], result)["established"]
    result[field] = {
        "record_count": 1,
        "redacted_record_count": 7,
        "receiver_verified": False,
        "policy_digest": content_hash("other"),
        "run_cleanup": "incomplete",
    }[field]
    assert not objective_result(state["grant"], result)["established"]


def test_parser_and_registry_use_actual_artifact_types_not_shape_coincidence(state):
    compiled = compile_initial_graph(canonical_json_bytes(proposal()), **state)
    stage = next(step for step in compiled["scenario"]["steps"] if step["id"] == "stage")
    assert stage["inputs"] == {"records": {"from_step": "inspect", "artifact": "records"}}
    observed_type = state["registry"].get_behavior(METHODS[2]).outputs[0].type
    assert observed_type == state["registry"].get_behavior(METHODS[4]).inputs[0].type
    validate_facts(
        state["facts"],
        expected_digest=state["expected_facts_digest"],
        grant=state["grant"],
        now_ms=state["now_ms"],
        require_prior_result=False,
    )


def test_installed_semantic_drift_invalidates_reviewed_cost_contract(state, monkeypatch):
    registry = state["registry"]
    original = registry.get_behavior
    changed = original(METHODS[4])
    changed = replace(changed, inputs=(replace(changed.inputs[0], name="different_port"),))
    monkeypatch.setattr(
        registry, "get_behavior", lambda key: changed if key == METHODS[4] else original(key)
    )
    with pytest.raises(CapabilityContractError, match="semantic contract"):
        compile_initial_graph(proposal(), **state)


@pytest.mark.parametrize("history", ["not_a_sequence", ["not_a_digest"], [{}]])
def test_revision_history_is_a_bounded_digest_contract(state, history):
    with pytest.raises(CapabilityContractError):
        compile_revision(
            revision_proposal(), previous_semantic_digests=history, **revision_state(state)
        )


@pytest.mark.parametrize("discovery", [METHODS[2], METHODS[3]])
def test_compiled_bindings_feed_real_adapter_outputs_without_effects(state, discovery):
    compiled = compile_initial_graph(proposal(redact=True, discovery=discovery), **state)
    adapter = RunnerActionAdapter()
    steps = {
        row["id"]: PlanStep(
            step_id=row["id"],
            behavior_id=row["behavior_id"],
            action_id=row["behavior_id"],
            simulation_id=None,
            parameters=row["parameters"],
            inputs=row["inputs"],
            expected_outputs=(),
            required_capabilities=(),
            safety_tier=SafetyTier.CONTROLLED,
            alternates=(),
        )
        for row in compiled["scenario"]["steps"]
    }
    receipts = ("a" * 64,)
    workspace = adapter.logical_outputs(
        steps["seed"],
        bound_inputs={},
        receipt_ids=receipts,
        runner_output={
            "artifact": "fixtures/input.jsonl",
            "sha256": "b" * 64,
            "size": 800,
            "template": "telemetry-seed",
            "record_count": 8,
            "format": "jsonl",
        },
    )
    fixture = adapter.logical_outputs(
        steps["prepare"],
        bound_inputs=workspace,
        receipt_ids=receipts,
        runner_output={
            "artifact": "fixtures/transformed.jsonl",
            "sha256": "c" * 64,
            "size": 800,
            "record_count": 8,
            "redact_values": True,
            "redacted_value_count": 8,
            "format": "jsonl",
            "implementation": "in_process_reviewed_jsonl_transform",
        },
    )
    discovery_output = {
        "path": "fixtures/transformed.jsonl",
        "returned_entries": 1,
        "target_cardinality": "one",
        "entries": [
            {
                "path": "fixtures/transformed.jsonl",
                "name": "transformed.jsonl",
                "kind": "file",
                "size": 800,
                **({"readonly": False} if discovery == METHODS[3] else {}),
            }
        ],
    }
    records = adapter.logical_outputs(
        steps["inspect"],
        bound_inputs=fixture,
        receipt_ids=receipts,
        runner_output=discovery_output,
    )
    bundle = adapter.logical_outputs(
        steps["stage"],
        bound_inputs=records,
        receipt_ids=receipts,
        runner_output={
            "artifact": "staged/bundle.jsonl",
            "format": "jsonl",
            "input_count": 1,
            "accepted_input_count": 1,
            "rejected_input_count": 0,
            "record_count": 8,
            "sha256": "d" * 64,
            "size": 800,
            "complete": True,
        },
    )
    outputs = {"seed": workspace, "prepare": fixture, "inspect": records, "stage": bundle}
    bound = {
        identity: {
            port: outputs[ref["from_step"]][ref["artifact"]]
            for port, ref in steps[identity].inputs.items()
        }
        for identity in steps
    }
    for identity in bound:
        request = adapter.adapt(steps[identity], bound_inputs=bound[identity], receipt_ids=receipts)
        reviewed = method_cost(steps[identity].action_id)
        assert set(request.filesystem_scope) <= set(
            reviewed["reads"] + reviewed["writes"] + reviewed["material_directories"]
        )
    assert adapter.adapt(
        steps["stage"], bound_inputs=records, receipt_ids=receipts
    ).observable_paths == ("staged/bundle.jsonl",)
    assert adapter.adapt(
        steps["send"], bound_inputs=bound["send"], receipt_ids=receipts
    ).network_destinations == ({"host": "127.0.0.1", "port": 4317},)
    assert adapter.adapt(
        steps["clean"], bound_inputs=bound["clean"], receipt_ids=receipts
    ).params == {"receipt_ids": list(receipts)}
    assert (
        records["records"][0]["record_count"]
        == state["grant"]["objective"]["predicate"]["record_count"]
    )
