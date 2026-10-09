"""Authored no-effect contracts, not evidence of a real principal access test."""

from copy import deepcopy

import pytest

from bluefire import capability_file_access as pack
from bluefire.capability_composition import compile_initial_graph, compile_revision
from bluefire.capability_grant import create_grant, objective_result
from bluefire.capability_packs import FILE_ACCESS_METHODS, FILE_ACCESS_PACK, grant_pack, review_pack
from bluefire.capability_resources import CapabilityContractError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_capability_composition import state as state


@pytest.fixture
def file_state(state):
    environment = {
        key: value
        for key, value in state["current_environment"].items()
        if key not in {"policy_id", "policy_digest", "port"}
    }
    environment.update(
        resource_id="file-resource-" + "c" * 32,
        resource_generation="file-generation-" + "d" * 32,
        resource_digest=content_hash("retained generated resource"),
        probe_enrollment_digest=content_hash("separate enrolled reader"),
        baseline_digest=content_hash("actual allowed baseline"),
        control_revision=3,
        mode="0600",
    )
    implementations = {
        method: content_hash({"authored_implementation": method}) for method in FILE_ACCESS_METHODS
    }
    grant = create_grant(
        registry=state["registry"],
        implementation_digests=implementations,
        objective={
            "question": "Deny the enrolled non-owner while preserving the owner read.",
            "predicate": {
                "kind": pack.PREDICATE,
                "record_count": 8,
                "data_class": "generated_public_jsonl",
                "sha256": content_hash("eight exact original records"),
            },
        },
        environment=environment,
        limits=state["grant"]["limits"],
        grant_id=state["grant"]["grant_id"],
        approved_by="Authored test operator",
        created_at_ms=1000,
        expires_at_ms=901000,
        pack=FILE_ACCESS_PACK,
    )
    facts = pack.seal_facts(grant)
    return {
        "grant": grant,
        "expected_grant_digest": grant["grant_digest"],
        "registry": state["registry"],
        "implementation_digests": implementations,
        "current_environment": environment,
        "facts": facts,
        "expected_facts_digest": facts["facts_digest"],
        "now_ms": 2000,
    }


def test_both_packs_share_compiler_without_changing_receiver_bytes(state, file_state):
    before = canonical_json_bytes(state["grant"])
    compiled = compile_initial_graph(pack.initial_proposal(), **file_state)
    assert canonical_json_bytes(state["grant"]) == before
    assert grant_pack(file_state["grant"]) == FILE_ACCESS_PACK
    assert compiled["reservation"]["network_bytes"] == 0
    assert compiled["reservation"]["generated_bytes"] == 2 * 16384
    assert compiled["reservation"]["workspace_files"] == 2
    assert "handoff" not in compiled and "port" not in file_state["grant"]["environment"]
    assert compiled["scenario"]["steps"][1]["inputs"] == {
        "probe": {"from_step": "probe", "artifact": "probe"}
    }
    assert compiled["scenario"]["steps"][2]["inputs"] == {
        "workspace": {"from_step": "probe", "artifact": "workspace"}
    }


@pytest.mark.parametrize(
    "change",
    [
        "path",
        "identity",
        "mode",
        "harden",
        "skip_owner",
        "skip_cleanup",
        "duplicate_probe",
        "foreign_fact",
    ],
)
def test_model_cannot_expand_endpoint_graph(file_state, change):
    proposal = pack.initial_proposal()
    if change in ("path", "identity", "mode"):
        proposal["steps"][0]["parameters"][change] = "/unreviewed" if change == "path" else "root"
    elif change == "harden":
        proposal["steps"][0]["behavior_id"] = "sandbox.permission.relax.v1"
    elif change == "skip_owner":
        proposal["edges"][0]["to_step"] = "cleanup"
    elif change == "skip_cleanup":
        proposal["edges"].pop()
    elif change == "duplicate_probe":
        proposal["steps"].append(
            {"id": "other", "behavior_id": FILE_ACCESS_METHODS[0], "parameters": {}}
        )
    else:
        proposal["evidence_refs"] = ["policy"]
    with pytest.raises(ValueError):
        compile_initial_graph(proposal, **file_state)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.capability-grant.v1"),
        ("pack", "unknown.v1"),
        ("pack", "bluefire.receiver-composition-pack.v1"),
    ],
)
def test_unknown_or_cross_pack_grants_refuse(file_state, field, value):
    file_state["grant"][field] = value
    with pytest.raises(ValueError):
        compile_initial_graph(pack.initial_proposal(), **file_state)


@pytest.mark.parametrize(
    "field",
    [
        "probe_enrollment_digest",
        "resource_digest",
        "resource_generation",
        "control_revision",
        "mode",
    ],
)
def test_changed_actual_resource_or_principal_revokes_admission(file_state, field):
    file_state["current_environment"] = deepcopy(file_state["current_environment"])
    file_state["current_environment"][field] = (
        4 if field == "control_revision" else "0640" if field == "mode" else content_hash("changed")
    )
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(pack.initial_proposal(), **file_state)


def test_finite_pack_honestly_reports_no_different_route(file_state):
    with pytest.raises(CapabilityContractError, match="no different permitted route"):
        compile_revision(pack.initial_proposal(), **file_state)


def test_rehashed_client_facts_do_not_replace_trusted_fact_binding(file_state):
    file_state["facts"]["facts"][0]["value"]["control_revision"] = 99
    file_state["facts"]["facts_digest"] = content_hash(
        {key: value for key, value in file_state["facts"].items() if key != "facts_digest"}
    )
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(pack.initial_proposal(), **file_state)


def result(file_state):
    grant = file_state["grant"]
    return {
        "probe_verified": True,
        "non_owner_decision": "permission_denied",
        "owner_verified": True,
        "owner_decision": "allowed",
        **{
            key: grant["environment"][key]
            for key in (
                "resource_digest",
                "resource_generation",
                "control_revision",
                "probe_enrollment_digest",
                "mode",
            )
        },
        "sha256": grant["objective"]["predicate"]["sha256"],
        "record_count": 8,
        "identity_unchanged": True,
        "parents_unchanged": True,
        "acl_unchanged": True,
        "run_cleanup": "complete",
        "request_cleanup": "verified_closed",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("non_owner_decision", "unknown"),
        ("non_owner_decision", "allowed"),
        ("owner_decision", "unknown"),
        ("record_count", 7),
        ("sha256", content_hash("different")),
        ("identity_unchanged", False),
        ("parents_unchanged", False),
        ("acl_unchanged", False),
        ("request_cleanup", "unknown"),
        ("run_cleanup", "incomplete"),
    ],
)
def test_permission_bits_or_unknown_transport_do_not_establish_effective_access(
    file_state, field, value
):
    observed = result(file_state)
    assert objective_result(file_state["grant"], observed)["established"]
    observed[field] = value
    assert not objective_result(file_state["grant"], observed)["established"]


def test_review_discriminator_never_infers_endpoint_from_extra_fields():
    request = {"control_owner_id": "job-" + "a" * 32, "question": "Question", "limits": {}}
    assert review_pack(request) == "bluefire.receiver-composition-pack.v1"
    with pytest.raises(ValueError):
        review_pack({**request, "pack": FILE_ACCESS_PACK})
    assert (
        review_pack(
            {
                **request,
                "schema_version": "bluefire.composition-review-request.v2",
                "pack": FILE_ACCESS_PACK,
            }
        )
        == FILE_ACCESS_PACK
    )
