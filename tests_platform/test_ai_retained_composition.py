"""Metadata-only retained-result proposals; authored replies, no model/native calls."""

import json
import threading
import uuid
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import composition_context
from bluefire.ai_broker_contract import BrokerEnrollment, schema_identity
from bluefire.ai_composition_contract import (
    EVIDENCE_PURPOSE,
    PURPOSE,
    RETAINED_OUTPUT_SCHEMA,
    RETAINED_OUTPUT_VERSION,
    RETAINED_PURPOSE,
)
from bluefire.ai_composition_evidence_data import validate_retained_model_context
from bluefire.ai_live_authorization import create_authorization, now_ms, request_reservation
from bluefire.ai_runtime_composition import format_request, propose, validate_candidate
from bluefire.ai_wire import AIProviderTransportError
from bluefire.capability_grant import build_snapshot, create_grant
from bluefire.capability_packs import RECEIVER_RETAINED_PACK
from bluefire.capability_resources import METHODS, CapabilityContractError
from bluefire.product_store_errors import ProductStoreError
from bluefire.retained_artifacts import METHOD, POLICY
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_receiver_inspection import Access
from tests_platform.test_ai_runtime_composition import candidate, context, request, wait
from tests_platform.test_ai_runtime_composition import harness as harness
from tests_platform.test_ai_runtime_composition import provider as provider
from tests_platform.test_ai_runtime_composition import saved as saved
from tests_platform.test_capability_composition import state as state
from tests_platform.test_composition_evidence_context import envelope
from tests_platform.test_composition_evidence_context import history as history


def source():
    row = {
        "run_id": "run-20261028T010203Z-" + "a" * 16,
        "attempt_id": "attempt-" + "b" * 32,
        "lineage_id": "lineage-1",
        "step_id": "stage",
        "artifact": "bundle",
        "artifact_type": "artifact.sandbox.bundle.v1",
        "sha256": "c" * 64,
        "size_bytes": 100,
    }
    return {**row, "source_ref": content_hash(row)}


def retained_context(state, supplied=None, sources=None):
    supplied = deepcopy(context(state) if supplied is None else supplied)
    supplied["schema_version"] = composition_context.RETAINED_CONTEXT_SCHEMA
    supplied["snapshot"] = build_snapshot(
        state["registry"],
        {**state["implementation_digests"], METHOD: content_hash(METHOD)},
        supplied["objective"],
        state["current_environment"],
        pack=RECEIVER_RETAINED_PACK,
    )
    sources = [] if sources is None else sources
    supplied["retained_artifacts"] = {
        "policy": deepcopy(POLICY),
        "available_sources": sources,
        "availability": "available" if sources else "none_available",
    }
    return supplied


def test_initial_proposal_without_sources_uses_new_exact_purpose(provider, state):
    current = retained_context(state)
    body, model = format_request(provider, current)
    assert schema_identity(body, provider.kind) == (
        RETAINED_PURPOSE,
        content_hash(RETAINED_OUTPUT_SCHEMA),
    )
    assert "verified prior failure or refusal" in body.decode()
    assert "actual observed refusal" not in body.decode()
    assert model["historical_context"] is None
    assert model["retained_artifacts"]["available_sources"] == []
    validate_retained_model_context(model)
    result = propose(
        config=provider,
        access=Access(
            value={
                "schema_version": RETAINED_OUTPUT_VERSION,
                "candidate": candidate(state),
                "reconsideration": None,
            }
        ),
        context=current,
        cancel=threading.Event(),
    )
    assert result["reconsideration"] is None


def test_available_custody_and_failed_route_are_separate_from_actual_use(provider, history):
    current = retained_context(history.harness.state, history.context, [source()])
    value = envelope(history)
    value["schema_version"] = RETAINED_OUTPUT_VERSION
    # The new producer feeds the normal handoff and cleanup route.
    graph = value["candidate"]
    graph["start"] = "reuse"
    graph["steps"] = [
        {
            "id": "reuse",
            "behavior_id": METHOD,
            "parameters": {"source_ref": source()["source_ref"]},
        },
        *[row for row in graph["steps"] if row["id"] in {"send", "clean"}],
    ]
    graph["edges"] = [
        {"from_step": "reuse", "outcome": "success", "to_step": "send"},
        *[row for row in graph["edges"] if row["from_step"] == "send"],
    ]
    body, model = format_request(history.harness.provider, current)
    validate_retained_model_context(model)
    assert model["historical_context"]["attempts"][0]["findings"]
    assert "never send this payload" not in body.decode()
    result = propose(
        config=history.harness.provider,
        access=Access(value=value),
        context=current,
        cancel=threading.Event(),
    )
    assert result["candidate"]["steps"][0]["parameters"] == {"source_ref": source()["source_ref"]}
    value["candidate"]["steps"][0]["parameters"]["source_ref"] = content_hash("invented")
    with pytest.raises(CapabilityContractError, match="unavailable retained source"):
        validate_candidate(value["candidate"], current)


@pytest.mark.parametrize(
    "defect", ["payload", "digest", "policy", "availability", "initial_path", "foreign_method"]
)
def test_model_data_boundary_refuses_raw_or_expanded_context(provider, state, defect):
    _, model = format_request(provider, retained_context(state, sources=[source()]))
    if defect == "payload":
        model["retained_artifacts"]["available_sources"][0]["payload_hex"] = "abcd"
    elif defect == "digest":
        model["retained_artifacts"]["available_sources"][0]["size_bytes"] += 1
    elif defect == "policy":
        model["retained_artifacts"]["policy"]["max_artifacts_per_attempt"] = 2
    elif defect == "availability":
        model["retained_artifacts"]["availability"] = "none_available"
    elif defect == "initial_path":
        model["initial_proposal"]["steps"][0]["parameters"]["path"] = "/private/path"
    else:
        model["methods"][-1]["behavior_id"] = "arbitrary.exec.v1"
    with pytest.raises(CapabilityContractError):
        validate_retained_model_context(model)


@pytest.mark.parametrize("old_purpose", [PURPOSE, EVIDENCE_PURPOSE])
def test_existing_authorizations_do_not_enable_retained_purpose(provider, state, old_purpose):
    body, model = format_request(provider, retained_context(state))
    enrollment = BrokerEnrollment.create(
        provider,
        session_id="a" * 64,
        expires_at_ms=now_ms() + 300000,
        schemas=((RETAINED_PURPOSE, content_hash(RETAINED_OUTPUT_SCHEMA)),),
        destination_policy="explicit_endpoint",
    )
    authority = {
        "kind": "direct",
        "binding_digest": enrollment.digest,
        "provider": provider.to_dict(),
        "expires_at_ms": enrollment.expires_at_ms,
    }

    def authorize(purpose):
        return create_authorization(
            authorization_request(provider, purposes=[purpose], local_endpoint_authorized=True),
            authority,
        )

    with pytest.raises(AIProviderTransportError):
        request_reservation(provider, body, authorize(old_purpose))
    authorization = authorize(RETAINED_PURPOSE)
    request_reservation(provider, body, authorization)
    model["retained_artifacts"]["payload_hex"] = "abcd"
    wire = json.loads(body)
    if provider.kind.value == "openai_responses":
        wire["input"] = json.dumps(model)
    else:
        wire["messages"][1]["content"] = json.dumps(model)
    with pytest.raises(AIProviderTransportError):
        request_reservation(provider, canonical_json_bytes(wire), authorization)


def test_review_exposes_retention_and_native_availability_only_for_new_pack(state, monkeypatch):
    resolved = {
        **state,
        "record_count": 8,
        "implementation_digests": {**state["implementation_digests"], METHOD: content_hash(METHOD)},
        "baseline": {"source_binding": {"kind": "unit_source"}},
    }
    monkeypatch.setattr(composition_context, "resolve", lambda *args, **kwargs: resolved)
    reviewed = composition_context.review(
        None, "job-control", question="Preserve records", pack=RECEIVER_RETAINED_PACK
    )
    assert reviewed["schema_version"] == "bluefire.composition-review.v2"
    assert reviewed["retention"] == POLICY
    assert reviewed["native_materialization"]["readiness"] == "ready"
    assert reviewed["review_digest"] == content_hash(
        {key: value for key, value in reviewed.items() if key != "review_digest"}
    )


def test_source_context_projects_validated_metadata_and_preserves_legacy(monkeypatch):
    from bluefire import retained_artifacts

    jobs = SimpleNamespace()
    calls = []

    def available(*args, **kwargs):
        calls.append(kwargs)
        return [source()]

    monkeypatch.setattr(retained_artifacts, "available_sources", available)
    body = {"schema_version": "bluefire.composition-proposal-context.v1"}
    assert (
        composition_context.retained_proposal_context(jobs, {}, body, owner_id="job-objective")
        == body
    )
    result = composition_context.retained_proposal_context(
        jobs, {"pack": RECEIVER_RETAINED_PACK}, body, owner_id="job-objective"
    )
    assert result["retained_artifacts"]["available_sources"] == [source()]
    assert result["retained_artifacts"]["availability"] == "available"
    assert calls == [{"owner_id": "job-objective"}]


def test_later_failed_materialization_keeps_original_source_identity(provider, history):
    current = retained_context(history.harness.state, history.context, [source()])
    failed_run = "run-20261029T010203Z-" + "d" * 16
    fact = next(row for row in current["facts"]["facts"] if row["kind"] == "receiver_result")
    fact["kind"] = "retained_artifact_result"
    fact["value"] = {
        "source": source(),
        "prior_run_id": failed_run,
        "later_failure": {"step_id": "send", "outcome": "failed"},
        "receiver_decision": "unknown",
    }
    _, model = format_request(history.harness.provider, current)
    projected = next(row for row in model["facts"] if row["kind"] == "retained_artifact_result")
    assert projected["value"]["source"]["run_id"] != projected["value"]["prior_run_id"]
    validate_retained_model_context(model)
    projected["value"]["receiver_decision"] = "accepted"
    with pytest.raises(CapabilityContractError):
        validate_retained_model_context(model)


def test_durable_initial_result_preserves_captured_context_when_readiness_changes(harness):
    h = harness
    state = h.state
    old = state["grant"]
    state["implementation_digests"][METHOD] = content_hash(METHOD)
    state["grant"] = create_grant(
        registry=state["registry"],
        implementation_digests=state["implementation_digests"],
        environment=state["current_environment"],
        pack=RECEIVER_RETAINED_PACK,
        grant_id="grant-" + "e" * 32,
        **{
            key: old[key]
            for key in ("objective", "limits", "approved_by", "created_at_ms", "expires_at_ms")
        },
    )
    state["expected_grant_digest"] = state["grant"]["grant_digest"]
    store = h.service.product_store
    store.save_capability_grant(
        state["grant"],
        lineage_id="lineage-1",
        **{
            key: state[key]
            for key in ("registry", "implementation_digests", "current_environment", "now_ms")
        },
    )
    owner_request = {
        "schema_version": "bluefire.composition-objective-request.v1",
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
    }
    owner, _ = store.create_idempotent_job(
        "composition.objective",
        owner_request,
        submission_id=str(uuid.uuid4()),
        intent_digest=content_hash(owner_request),
    )
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state='completed',progress_json=? WHERE job_id=?",
            (json.dumps({"admission": {"accepted": True, "problem": None}}), owner["job_id"]),
        )
    h.owner = owner["job_id"]
    state["parent_job_id"] = h.owner
    supplied = retained_context(state)
    h.context.clear()
    h.context.update(supplied)
    h.access.value = {
        "schema_version": RETAINED_OUTPUT_VERSION,
        "candidate": candidate(state),
        "reconsideration": None,
    }
    submitted = h.jobs.submit(h.owner, request(h))
    result = wait(h.jobs, submitted["job"]["job_id"])
    assert result["candidate_ready"]
    assert result["proposal"]["schema_version"] == "bluefire.composition-ai-result.v3"
    captured = deepcopy(result["job"]["request"]["context"])
    h.context["retained_artifacts"]["available_sources"] = [source()]
    h.context["retained_artifacts"]["availability"] = "available"
    reopened = h.jobs.read(result["job"]["job_id"])
    assert reopened["job"]["request"]["context"] == captured
    assert not reopened["candidate_ready"]
    assert len(h.access.calls) == 1


def test_retained_review_refuses_profile_without_explicit_native_method():
    current = {"workflow": "retained_redaction", "run_intent": {"runner_profile_id": "profile"}}
    owner = {"progress": {"receiver_completed": True}}
    transport = {
        "schema_version": "bluefire.runner-transport-identity.v1",
        "transport": "mutual-tls-loopback",
        "tls": "TLSv1.3",
        "enrollment_generation": "generation",
    }
    runner = SimpleNamespace(
        execute_task=lambda: pytest.fail("No native execution"),
        transport_identity=lambda: transport,
    )
    readiness = {
        "platform": "linux",
        "enabled_actions": [{"action_id": method, "readiness": "ready"} for method in METHODS],
    }
    service = SimpleNamespace(
        receiver_defense=SimpleNamespace(
            _job=lambda _: owner, _fresh=lambda _: current, baseline=lambda _: {}
        ),
        _profile=lambda *_: object(),
        _execute_readiness_boundary=lambda *_, **kwargs: (runner, None, readiness),
        _catalog_snapshot=SimpleNamespace(action_bindings={}, to_dict=lambda: {}),
    )
    with pytest.raises(ProductStoreError, match="ready retained-result materialization"):
        composition_context.resolve(service, "job-owner", pack=RECEIVER_RETAINED_PACK)
