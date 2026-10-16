"""Pure contract checks for the fixed Darwin retained-file composition pack."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bluefire.capability_composition import compile_initial_graph
from bluefire.capability_facts import validate_facts
from bluefire.capability_grant import create_grant, objective_result
from bluefire.capability_macos_file_access import initial_proposal, seal_facts
from bluefire.capability_packs import (
    FILE_ACCESS_METHODS,
    FILE_ACCESS_PACK,
    MACOS_FILE_ACCESS_METHODS,
    MACOS_FILE_ACCESS_PACK,
)
from bluefire.capability_resources import CapabilityContractError, method_cost, reserve_resources
from bluefire.contracts import StepOutcome
from bluefire.registry import load_builtin_registry
from bluefire.util import content_hash

GRANT_ID = "grant-" + "c" * 32
NOW_MS = 2_000


@pytest.fixture
def state():
    registry = load_builtin_registry()
    implementations = {
        method: content_hash({"implementation": method}) for method in MACOS_FILE_ACCESS_METHODS
    }
    environment = {
        "environment_id": "owned-macos-workspace.v1",
        "environment_generation": "generation-a",
        "runner_id": "runner-macos-a",
        "enrollment_digest": content_hash("runner-enrollment"),
        "profile_digest": content_hash("runner-profile"),
        "target_scope_digest": content_hash("target-scope"),
        "collector_digest": content_hash("collector"),
        "control_owner_id": "owner-control-a",
        "control_digest": content_hash("control-record"),
        "resource_id": "file-resource-a",
        "resource_generation": "resource-generation-a",
        "resource_digest": content_hash("resource-content"),
        "probe_enrollment_digest": content_hash("original-probe-enrollment"),
        "baseline_digest": content_hash("original-baseline"),
        "control_revision": 7,
        "mode": "0600",
        "workspace_custody_digest": content_hash("original-workspace-custody"),
        "binding_digest": content_hash("original-file-binding"),
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
    objective = {
        "question": "Verify the retained macOS file defense without changing it.",
        "predicate": {
            "kind": "non_owner_denied_owner_preserves_records",
            "record_count": 8,
            "data_class": "generated_public_jsonl",
            "sha256": content_hash("original-eight-records"),
        },
    }
    grant = create_grant(
        registry=registry,
        implementation_digests=implementations,
        objective=objective,
        environment=environment,
        limits=limits,
        grant_id=GRANT_ID,
        approved_by="Contract test operator",
        created_at_ms=1_000,
        expires_at_ms=901_000,
        pack=MACOS_FILE_ACCESS_PACK,
    )
    return {
        "registry": registry,
        "implementations": implementations,
        "grant": grant,
        "environment": environment,
        "limits": limits,
        "now_ms": NOW_MS,
    }


def compiled(state, proposal=None):
    grant = state["grant"]
    facts_document = seal_facts(grant)
    facts = validate_facts(
        facts_document,
        expected_digest=facts_document["facts_digest"],
        grant=grant,
        now_ms=state["now_ms"],
        require_prior_result=False,
    )
    return compile_initial_graph(
        initial_proposal() if proposal is None else proposal,
        grant=grant,
        expected_grant_digest=grant["grant_digest"],
        registry=state["registry"],
        implementation_digests=state["implementations"],
        current_environment=state["environment"],
        facts=facts,
        expected_facts_digest=facts["facts_digest"],
        now_ms=state["now_ms"],
    )


def test_real_catalog_pack_is_isolated_from_linux_methods_and_costs(state):
    grant = state["grant"]
    methods = grant["snapshot"]["methods"]
    assert grant["pack"] == MACOS_FILE_ACCESS_PACK
    assert grant["snapshot"]["platform"] == "macos"
    assert tuple(row["behavior_id"] for row in methods) == MACOS_FILE_ACCESS_METHODS
    assert not set(FILE_ACCESS_METHODS) & {row["behavior_id"] for row in methods}
    with pytest.raises(CapabilityContractError):
        method_cost(MACOS_FILE_ACCESS_METHODS[0], pack=FILE_ACCESS_PACK)
    with pytest.raises(CapabilityContractError):
        method_cost(FILE_ACCESS_METHODS[0], pack=MACOS_FILE_ACCESS_PACK)


def test_graph_is_exactly_three_methods_and_eight_outcome_edges(state):
    result = compiled(state)
    steps = result["scenario"]["steps"]
    edges = result["scenario"]["edges"]
    assert len(steps) == 3
    assert {step["behavior_id"] for step in steps} == set(MACOS_FILE_ACCESS_METHODS)
    assert len(edges) == 2 * len(StepOutcome) == 8
    by_behavior = {step["behavior_id"]: step for step in steps}
    probe, owner, close = (by_behavior[method] for method in MACOS_FILE_ACCESS_METHODS)
    assert {edge["from_step"] for edge in edges} == {probe["id"], owner["id"]}
    assert {edge["from_step"] for edge in edges if edge["to_step"] == owner["id"]} == {probe["id"]}
    assert {edge["from_step"] for edge in edges if edge["to_step"] == close["id"]} == {owner["id"]}
    assert all(
        {edge["outcome"] for edge in edges if edge["from_step"] == step_id}
        == {outcome.value for outcome in StepOutcome}
        for step_id in (probe["id"], owner["id"])
    )
    assert result["macos_file_access"]["probe_step_id"] == probe["id"]
    assert result["macos_file_access"]["owner_step_id"] == owner["id"]
    assert result["macos_file_access"]["cleanup_step_id"] == close["id"]


@pytest.mark.parametrize("change", ["missing_edge", "extra_method"])
def test_graph_rejects_noncanonical_macos_routes(state, change):
    proposal = initial_proposal()
    if change == "missing_edge":
        proposal["edges"].pop()
    else:
        proposal["steps"].append(
            {"id": "extra", "behavior_id": "sandbox.cleanup.v1", "parameters": {}}
        )
        proposal["edges"].extend(
            {
                "from_step": "close_attempt",
                "outcome": outcome.value,
                "to_step": "extra",
            }
            for outcome in StepOutcome
        )
    with pytest.raises(CapabilityContractError):
        compiled(state, proposal)


def test_reservation_charges_two_native_calls_and_no_filesystem_or_network(state):
    methods = MACOS_FILE_ACCESS_METHODS
    costs = [method_cost(method, pack=MACOS_FILE_ACCESS_PACK) for method in methods]
    reservation = reserve_resources(
        [{"behavior_id": method} for method in methods],
        state["limits"],
        pack=MACOS_FILE_ACCESS_PACK,
    )
    assert sum(cost["native_primitive_requests"] for cost in costs) == 2
    assert all(not cost["writes"] and not cost["material_directories"] for cost in costs)
    assert all(cost["removes"] is None for cost in costs)
    assert all(cost["generated_bytes"] == cost["network_bytes"] == 0 for cost in costs)
    assert reservation["native_primitive_requests"] == 2
    assert reservation["business_steps"] == 2
    assert reservation["generated_bytes"] == reservation["network_bytes"] == 0
    assert reservation["workspace_files"] == 0
    assert reservation["material_write_slots"] == []


def test_binding_and_original_probe_enrollment_are_separate_provenance(state):
    environment = state["environment"]
    assert environment["binding_digest"] != environment["probe_enrollment_digest"]
    dependency = compiled(state)["macos_file_access"]
    assert dependency["binding_digest"] == environment["binding_digest"]
    assert dependency["probe_enrollment_digest"] == environment["probe_enrollment_digest"]
    assert dependency["workspace_custody_digest"] == environment["workspace_custody_digest"]


def test_wrong_facts_expired_facts_and_revision_route_are_refused(state):
    grant = state["grant"]
    facts = seal_facts(grant)
    altered = deepcopy(facts)
    altered["facts"][0]["value"]["binding_digest"] = content_hash("other-binding")
    altered["facts_digest"] = content_hash(
        {key: value for key, value in altered.items() if key != "facts_digest"}
    )
    with pytest.raises(CapabilityContractError):
        validate_facts(
            altered,
            expected_digest=altered["facts_digest"],
            grant=grant,
            now_ms=state["now_ms"],
            require_prior_result=False,
        )
    with pytest.raises(CapabilityContractError):
        validate_facts(
            facts,
            expected_digest=facts["facts_digest"],
            grant=grant,
            now_ms=grant["expires_at_ms"],
            require_prior_result=False,
        )
    with pytest.raises(CapabilityContractError):
        validate_facts(
            facts,
            expected_digest=facts["facts_digest"],
            grant=grant,
            now_ms=state["now_ms"],
            require_prior_result=True,
        )


def test_objective_distinguishes_established_truth_from_unknown(state):
    environment = state["environment"]
    predicate = state["grant"]["objective"]["predicate"]
    result = {
        "probe_verified": True,
        "non_owner_decision": "denied",
        "owner_verified": True,
        "owner_decision": "allowed",
        "resource_digest": environment["resource_digest"],
        "resource_generation": environment["resource_generation"],
        "control_revision": environment["control_revision"],
        "binding_digest": environment["binding_digest"],
        "sha256": predicate["sha256"],
        "record_count": predicate["record_count"],
        "request_closure": "verified_closed",
        "attempt_artifacts": "not_created",
        "workers_retained": True,
        "whole_enrollment_cleanup": False,
    }
    established = objective_result(state["grant"], result)
    assert established["established"] is True
    assert all(established["checks"].values())

    uncertain = {
        **result,
        "probe_verified": False,
        "non_owner_decision": "unknown",
        "owner_verified": False,
        "owner_decision": "unknown",
        "request_closure": "unknown",
        "attempt_artifacts": "unknown",
        "workers_retained": False,
    }
    unresolved = objective_result(state["grant"], uncertain)
    assert unresolved["established"] is False
    assert unresolved["checks"]["probe_authenticated"] is False
    assert unresolved["checks"]["requests_closed"] is False
    assert unresolved["checks"]["enrollment_retained"] is False

    rolled_back = objective_result(state["grant"], {**result, "whole_enrollment_cleanup": True})
    assert rolled_back["established"] is False
    assert rolled_back["checks"]["enrollment_retained"] is False
