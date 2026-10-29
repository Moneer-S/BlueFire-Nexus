"""Sealed historical context and authored provider jobs; no native or model calls."""

import json
import threading
import uuid
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.ai_broker_contract import BrokerEnrollment, schema_identity
from bluefire.ai_broker_live_authorization import BrokerLiveAuthorizations
from bluefire.ai_composition_contract import (
    EVIDENCE_OUTPUT_SCHEMA,
    EVIDENCE_OUTPUT_VERSION,
    EVIDENCE_PURPOSE,
    FILE_ACCESS_OUTPUT_SCHEMA,
    MACOS_FILE_ACCESS_OUTPUT_SCHEMA,
    OUTPUT_SCHEMA,
    PURPOSE,
    REFRESH_PREREQUISITES,
)
from bluefire.ai_composition_evidence_data import validate_model_context
from bluefire.ai_live_authorization import create_authorization, now_ms, request_reservation
from bluefire.ai_runtime_composition import (
    CompositionAIJobs,
    format_request,
    propose,
)
from bluefire.ai_wire import AIProviderError, AIProviderTransportError
from bluefire.capability_facts import seal_facts
from bluefire.capability_packs import FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK
from bluefire.capability_resources import METHODS, CapabilityContractError
from bluefire.composition_evidence_context import (
    CONTEXT_SCHEMA,
    QUERY_SCHEMA,
    REQUEST_SCHEMA,
    RESULT_SCHEMA,
    selection,
    validate_reconsideration,
)
from bluefire.composition_knowledge import QUERY_SCHEMA as KNOWLEDGE_QUERY_SCHEMA
from bluefire.composition_knowledge import build_knowledge
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore
from bluefire.runner_contracts import _verified_grant_attempt
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_runtime_composition import (
    candidate,
    compiler_args,
    context,
    file_access_context,
    wait,
)
from tests_platform.test_ai_runtime_composition import (
    harness as harness,
)
from tests_platform.test_ai_runtime_composition import (
    provider as provider,
)
from tests_platform.test_ai_runtime_composition import (
    saved as saved,
)
from tests_platform.test_ai_runtime_composition import (
    state as state,
)
from tests_platform.test_capability_composition import revision_state
from tests_platform.test_product_store_capability_grants import claim, unused


def retained_source(harness, runs, *, now=3000):
    store = harness.service.product_store
    plan = {"schema_version": "bluefire.plan.v1", "autonomy": "off", "steps": []}
    compiled = harness.saved[2]
    token = uuid.uuid4().hex
    run_id = runs._new_run_id()
    marker = {
        "parent_job_id": harness.owner,
        "grant_id": harness.state["grant"]["grant_id"],
        "grant_digest": harness.state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + token,
        "compiled_digest": compiled["compiled_digest"],
        "run_id": run_id,
    }
    child_request = {"composition_attempt": marker}
    store.create_idempotent_job(
        "composition.attempt",
        child_request,
        submission_id=str(uuid.UUID(hex=token)),
        intent_digest=content_hash(child_request),
    )
    args = {
        "expected_compiled_digest": compiled["compiled_digest"],
        "attempt_id": marker["attempt_id"],
        "job_id": "job-" + token,
        "run_id": run_id,
        "plan_digest": content_hash(plan),
        "native_envelope_digest": content_hash("authored envelope"),
        "current_environment": harness.state["current_environment"],
        "now_ms": now,
    }
    lease = store.reserve_capability_attempt(harness.state["grant"]["grant_id"], compiled, **args)
    claim(harness.saved, lease, now_ms=now + 1)
    retained_claim = store.get_capability_attempt(lease["attempt_id"])["claim"]
    run = runs.create_run(
        scenario=compiled["scenario"],
        plan=plan,
        policy={
            "grant_attempt": _verified_grant_attempt(
                retained_claim["document"],
                expected_document_digest=retained_claim["document_digest"],
            ).to_dict()
        },
        profile=None,
        _reserved_run_id=lease["run_id"],
    )
    record = EvidenceRecord.create(
        run_id=lease["run_id"],
        step_id="prepare",
        behavior_id=METHODS[1],
        action_id=METHODS[1],
        provenance=EvidenceProvenance.OBSERVED,
        producer="collector.collection-semantics.sandbox.v1",
        content={
            "artifact_type": "collector_observation",
            "observation_kind": "collection_semantics",
            "observed_fields": {
                "record_count": 8,
                "retained_record_count": 8,
                "redacted_record_count": 0,
                "container": "jsonl",
                "raw_log": "never send this payload",
            },
        },
        timestamp="1970-01-01T00:00:04Z",
        target_scope_ref="generated-fixture",
    )
    runs.finalize(
        run.run_id,
        result={"schema_version": "bluefire.run-result.v1", "status": "failed", "mode": "execute"},
        evidence=[record.to_dict()],
        detections=[],
    )
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    with store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='failed' WHERE job_id=?", (lease["job_id"],))
    return lease


def make_query(harness, *ids, prior=None):
    knowledge = build_knowledge(
        harness.jobs,
        harness.owner,
        {"schema_version": KNOWLEDGE_QUERY_SCHEMA, "attempt_ids": list(ids)},
    )
    return {
        "schema_version": QUERY_SCHEMA,
        "prior_attempt_id": prior or ids[-1],
        "attempt_ids": list(ids),
        "knowledge_digest": knowledge["knowledge_digest"],
    }


@pytest.fixture
def history(harness, tmp_path):
    runs = RunStore(tmp_path / "history-runs")
    harness.service.detection_lab = SimpleNamespace(run_store=runs)
    lease = retained_source(harness, runs)
    revised = revision_state(compiler_args(harness.state))
    body = {key: value for key, value in revised["facts"].items() if key != "facts_digest"}
    body["prior_attempt_id"] = lease["attempt_id"]
    for row in body["facts"]:
        if row["kind"] != "retained_policy":
            row["attempt_id"] = lease["attempt_id"]
    revised["facts"] = seal_facts(body)
    revised["expected_facts_digest"] = revised["facts"]["facts_digest"]
    harness.state.update(revised)
    harness.context.update(context(revised, initial=False))
    harness.context["initial_scenario"] = None
    query = make_query(harness, lease["attempt_id"])
    current = harness.jobs.requested_context(harness.owner, query)
    return SimpleNamespace(harness=harness, runs=runs, lease=lease, query=query, context=current)


def envelope(history):
    current = history.context
    finding = current["historical_context"]["attempts"][0]["findings"][0]
    choice = next(
        row for row in current["historical_context"]["choices"] if row["step_id"] == "prepare"
    )
    value = candidate(history.harness.state, redact=True)
    value["evidence_refs"] = ["refusal", "cleanup"]
    return {
        "schema_version": EVIDENCE_OUTPUT_VERSION,
        "candidate": value,
        "reconsideration": {
            "reconsidered_choices": [
                {
                    "attempt_id": choice["attempt_id"],
                    "compiled_digest": choice["compiled_digest"],
                    "step_id": choice["step_id"],
                    "finding_refs": [
                        {
                            "finding_id": finding["finding_id"],
                            "record_ref": deepcopy(finding["record_ref"]),
                        }
                    ],
                    "reason": "Later collection evidence shows retained values; reconsider the earlier transform.",
                }
            ],
            "refresh_requirements": [
                {
                    "prerequisite": name,
                    "explanation": "Require fresh server verification before relying on current state.",
                }
                for name in REFRESH_PREREQUISITES
            ],
        },
    }


def submit_request(history):
    return {
        **history.query,
        "schema_version": REQUEST_SCHEMA,
        "submission_id": str(uuid.uuid4()),
        "provider_id": history.harness.provider.id,
        "context_digest": history.context["context_digest"],
    }


def test_selected_source_choices_and_findings_are_separate_from_current_facts(history):
    current = history.context
    assert current["schema_version"] == CONTEXT_SCHEMA
    choice = next(
        row for row in current["historical_context"]["choices"] if row["step_id"] == "prepare"
    )
    assert choice["parameters"] == {"redact_values": False}
    body, model = format_request(history.harness.provider, current)
    assert schema_identity(body, history.harness.provider.kind) == (
        EVIDENCE_PURPOSE,
        content_hash(EVIDENCE_OUTPUT_SCHEMA),
    )
    validate_model_context(model)
    assert "never send this payload" not in body.decode()
    assert len(model["facts"]) == 3
    assert all(
        row["applicability"]["status"] == "historical_only"
        for attempt in model["historical_context"]["attempts"]
        for row in attempt["findings"]
    )


@pytest.mark.parametrize(
    "defect", ["extra", "duplicate", "null_prior", "bad_version", "bad_digest"]
)
def test_context_query_is_exact_and_bounded(history, defect):
    value = deepcopy(history.query)
    if defect == "extra":
        value["facts"] = []
    elif defect == "duplicate":
        value["attempt_ids"] *= 2
    elif defect == "null_prior":
        value["prior_attempt_id"] = None
    elif defect == "bad_version":
        value["schema_version"] = "unknown"
    else:
        value["knowledge_digest"] = "invalid"
    with pytest.raises((CapabilityContractError, ProductStoreError)):
        selection(value)


def test_old_selection_can_reconsider_older_choice_but_frontier_must_be_latest(history):
    h = history.harness
    later = retained_source(h, history.runs, now=4500)
    with pytest.raises(ProductStoreError, match="latest settled"):
        h.jobs.requested_context(h.owner, history.query)
    query = make_query(h, history.lease["attempt_id"], prior=later["attempt_id"])
    current = h.jobs.requested_context(h.owner, query)
    assert current["historical_context"]["attempt_ids"] == [history.lease["attempt_id"]]
    with h.service.product_store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='running' WHERE job_id=?", (later["job_id"],))
    with pytest.raises(ProductStoreError, match="Settle every"):
        h.jobs.requested_context(h.owner, query)


@pytest.mark.parametrize(
    "defect",
    [
        "attempt",
        "step",
        "compiled",
        "record_hash",
        "record_owner",
        "finding",
        "missing_refresh",
        "duplicate_refresh",
        "promote",
    ],
)
def test_model_cannot_invent_choices_citations_refresh_or_execution_facts(history, defect):
    value = envelope(history)
    choice = value["reconsideration"]["reconsidered_choices"][0]
    if defect == "attempt":
        choice["attempt_id"] = "attempt-" + "f" * 32
    elif defect == "step":
        choice["step_id"] = "invented"
    elif defect == "compiled":
        choice["compiled_digest"] = content_hash("foreign")
    elif defect == "record_hash":
        choice["finding_refs"][0]["record_ref"]["record_hash"] = content_hash("tamper")
    elif defect == "record_owner":
        choice["finding_refs"][0]["record_ref"]["owner_id"] = "job-" + "f" * 32
    elif defect == "finding":
        choice["finding_refs"][0]["finding_id"] = "finding-invented"
    elif defect == "missing_refresh":
        value["reconsideration"]["refresh_requirements"].pop()
    elif defect == "duplicate_refresh":
        value["reconsideration"]["refresh_requirements"][1] = value["reconsideration"][
            "refresh_requirements"
        ][0]
    else:
        value["candidate"]["evidence_refs"].append(choice["finding_refs"][0]["finding_id"])
    history.harness.access.value = value
    with pytest.raises(AIProviderError, match="strict validation"):
        propose(
            config=history.harness.provider,
            access=history.harness.access,
            context=history.context,
            cancel=threading.Event(),
        )


def test_durable_reconsideration_reopen_cancel_and_exact_submission_do_not_execute(history):
    h = history.harness
    h.access.value = envelope(history)
    request = submit_request(history)
    result = wait(h.jobs, h.jobs.submit(h.owner, request)["job"]["job_id"])
    assert result["candidate_ready"] and result["proposal"]["schema_version"] == RESULT_SCHEMA
    assert result["proposal"]["reconsideration"] == h.access.value["reconsideration"]
    assert result["job"]["request"]["context"] == history.context
    assert h.jobs.submit(h.owner, request)["proposal"] == result["proposal"]
    assert (
        CompositionAIJobs(h.service).read(result["job"]["job_id"])["proposal"] == result["proposal"]
    )
    assert len(h.access.calls) == 1
    with h.service.product_store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_attempts").fetchone()[0] == 1
    assert not h.jobs.cancel(result["job"]["job_id"])["candidate_ready"]


@pytest.mark.parametrize(
    "change", ["digest", "source", "frontier", "provider", "context", "cancel"]
)
def test_freshness_and_cancellation_prevent_publication(history, change):
    h = history.harness
    h.access.value = envelope(history)
    request = submit_request(history)
    if change == "digest":
        request["knowledge_digest"] = content_hash("different selection")
    elif change == "source":
        h.access.after = lambda: (
            history.runs.root / history.lease["run_id"] / "evidence.json"
        ).write_text("[]")
    elif change == "frontier":
        h.access.after = lambda: retained_source(h, history.runs, now=4500)
    elif change == "context":
        h.access.after = lambda: h.context["facts"]["facts"][0]["value"].update(status="unknown")
    elif change == "provider":
        h.access.after = lambda: setattr(
            h.service,
            "_runtime_ai",
            lambda: SimpleNamespace(
                provider=lambda _: SimpleNamespace(
                    kind=h.provider.kind, to_dict=lambda: {"changed": True}
                )
            ),
        )
    else:
        h.access.after = lambda: h.access.calls[-1][-1].set()
    result = wait(h.jobs, h.jobs.submit(h.owner, request)["job"]["job_id"])
    assert not result["candidate_ready"] and result["proposal"] is None
    assert len(h.access.calls) == (0 if change == "digest" else 1)


@pytest.mark.parametrize("transport", ["direct", "broker"])
def test_new_purpose_requires_explicit_authorization_and_exact_history_input(history, transport):
    h = history.harness
    body, model = format_request(h.provider, history.context)
    enrollment = BrokerEnrollment.create(
        h.provider,
        session_id="a" * 64,
        expires_at_ms=now_ms() + 300_000,
        schemas=(
            (PURPOSE, content_hash(OUTPUT_SCHEMA)),
            (EVIDENCE_PURPOSE, content_hash(EVIDENCE_OUTPUT_SCHEMA)),
        ),
        destination_policy="explicit_endpoint",
    )
    authority = {
        "kind": transport,
        "binding_digest": enrollment.digest,
        "provider": h.provider.to_dict(),
        "expires_at_ms": enrollment.expires_at_ms,
    }
    old = create_authorization(
        authorization_request(h.provider, purposes=[PURPOSE], local_endpoint_authorized=True),
        authority,
    )
    new = create_authorization(
        authorization_request(
            h.provider, purposes=[EVIDENCE_PURPOSE], local_endpoint_authorized=True
        ),
        authority,
    )
    broker = BrokerLiveAuthorizations(enrollment)

    def reserve(auth, payload):
        if transport == "broker":
            broker.authorize(auth)
            return broker.reserve(payload)
        return request_reservation(h.provider, payload, auth)

    with pytest.raises(AIProviderTransportError):
        reserve(old, body)
    reserve(new, body)
    wire = json.loads(body)
    model["historical_context"]["attempts"][0]["findings"][0]["summary"][
        "arbitrary_text"
    ] = "not allowed"
    if h.provider.kind.value == "openai_responses":
        wire["input"] = json.dumps(model)
    else:
        wire["messages"][1]["content"] = json.dumps(model)
    with pytest.raises(AIProviderTransportError):
        reserve(new, canonical_json_bytes(wire))


def test_service_context_version_dispatch_preserves_legacy_exact_shape(history):
    h = history.harness
    service = SimpleNamespace(composition_ai=h.jobs)
    assert (
        BlueFireService.composition_proposal_context(service, h.owner, history.query)
        == history.context
    )
    assert (
        BlueFireService.composition_proposal_context(
            service, h.owner, {"prior_attempt_id": history.lease["attempt_id"]}
        )["schema_version"]
        != CONTEXT_SCHEMA
    )
    with pytest.raises(ProductStoreError):
        BlueFireService.composition_proposal_context(
            service, h.owner, {"prior_attempt_id": None, "attempt_ids": []}
        )


@pytest.mark.parametrize("provenance", ["synthetic", "counterfactual"])
def test_historical_metadata_preserves_supported_provenance_and_nullable_action(
    history, provenance
):
    _body, model = format_request(history.harness.provider, history.context)
    finding = model["historical_context"]["attempts"][0]["findings"][0]
    finding.update(
        provenance=provenance, action_id=None, semantic_kind="record_metadata", summary={}
    )
    validate_model_context(model)


@pytest.mark.parametrize("field", ["attempt_id", "compiled_digest", "step_id"])
def test_malformed_reconsidered_identity_fails_with_controlled_contract_error(history, field):
    value = envelope(history)["reconsideration"]
    value["reconsidered_choices"][0][field] = {"malformed": []}
    with pytest.raises(CapabilityContractError):
        validate_reconsideration(value, history.context)


def test_unhashable_fact_value_is_a_controlled_data_refusal(history):
    _body, model = format_request(history.harness.provider, history.context)
    model["facts"][0]["value"]["status"] = {}
    with pytest.raises(CapabilityContractError):
        validate_model_context(model)


def test_equally_ordered_frontier_is_refused(history, monkeypatch):
    h = history.harness
    original = h.service.product_store.list_jobs

    def ambiguous():
        rows = original()
        child = next(row for row in rows if row["job_id"] == history.lease["job_id"])
        return [*rows, deepcopy(child)]

    monkeypatch.setattr(h.service.product_store, "list_jobs", ambiguous)
    with pytest.raises(ProductStoreError, match="ordering is ambiguous"):
        h.jobs.requested_context(h.owner, history.query)


def test_invalid_existing_attempt_is_not_treated_as_an_unused_admission(history, monkeypatch):
    h = history.harness
    original = h.service.product_store.get_capability_attempt
    selected = selection(history.query)

    def corrupt(identifier):
        if identifier == history.lease["attempt_id"]:
            raise ProductStoreError("Stored attempt integrity failed")
        return original(identifier)

    monkeypatch.setattr(h.service.product_store, "get_capability_attempt", corrupt)
    from bluefire.composition_evidence_context import historical_context

    with pytest.raises(ProductStoreError, match="integrity failed"):
        historical_context(h.jobs, h.owner, selected, history.context)


@pytest.mark.parametrize("pack", [FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK])
def test_new_history_purpose_cannot_be_used_with_other_packs(provider, pack):
    current = file_access_context(pack)
    current["schema_version"] = CONTEXT_SCHEMA
    with pytest.raises(CapabilityContractError, match="only the receiver"):
        format_request(provider, current)


def test_original_purpose_schema_hashes_remain_exact():
    assert (
        content_hash(OUTPUT_SCHEMA)
        == "sha256:d9f2cb4afa62b56338c3b2ea7d9c7ed9fe9118edd0cfce860349d229376167e2"
    )
    assert (
        content_hash(FILE_ACCESS_OUTPUT_SCHEMA)
        == "sha256:13ecbbf8c4ed0934ed25468ac6efbb0e673ac5e856953dd2e7dd0ca41c7eabcb"
    )
    assert (
        content_hash(MACOS_FILE_ACCESS_OUTPUT_SCHEMA)
        == "sha256:a8d81e026ac21f252e227e7691b9c37d3e06824150962131d3f3c97693881d32"
    )
