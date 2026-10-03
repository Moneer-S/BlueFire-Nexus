"""Authored provider replies and durable jobs; no model, runner, receiver or network effects."""

import json
import threading
import time
import uuid
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.ai_authorized_access import AuthorizedAIProviderAccess
from bluefire.ai_broker_contract import BrokerEnrollment, schema_identity
from bluefire.ai_broker_live_authorization import BrokerLiveAuthorizations
from bluefire.ai_live_authorization import PURPOSES, _schemas, create_authorization, now_ms
from bluefire.ai_runtime_composition import (
    KIND,
    OUTPUT_SCHEMA,
    PURPOSE,
    CompositionAIJobs,
    context_digest,
    format_request,
    propose,
)
from bluefire.ai_wire import AIProviderCancelled, AIProviderError, AIProviderTransportError
from bluefire.capability_composition import compile_initial_graph, compile_revision
from bluefire.capability_facts import seal_facts
from bluefire.job_runtime import RunJobController
from bluefire.prepared_lab_enrollment import enroll
from bluefire.product_store import ProductStore
from bluefire.util import content_hash
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_receiver_inspection import Access
from tests_platform.test_ai_receiver_inspection import provider as provider
from tests_platform.test_capability_composition import proposal, revision_state
from tests_platform.test_capability_composition import state as state
from tests_platform.test_product_store_capability_grants import reserve, unused
from tests_platform.test_product_store_capability_grants import saved as saved


def candidate(state, *, redact=False):
    result = proposal(redact=redact)
    domains = {
        row["behavior_id"]: row["parameter_domains"]
        for row in state["grant"]["snapshot"]["methods"]
    }
    for step in result["steps"]:
        step["parameters"] = {
            **{name: values[0] for name, values in domains[step["behavior_id"]].items()},
            **step["parameters"],
        }
    return result


def context(state, *, initial=True):
    return {
        "schema_version": "bluefire.composition-proposal-context.v1",
        "grant_id": state["grant"]["grant_id"],
        "objective": state["grant"]["objective"],
        "snapshot": state["grant"]["snapshot"],
        "facts": state["facts"],
        "initial_proposal": candidate(state) if initial else None,
    }


def compiler_args(state):
    return {
        key: state[key]
        for key in (
            "grant",
            "expected_grant_digest",
            "registry",
            "implementation_digests",
            "current_environment",
            "facts",
            "expected_facts_digest",
            "now_ms",
        )
    }


def wait(jobs, job_id):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = jobs.read(job_id)
        if result["job"]["state"] in {"completed", "failed", "cancelled", "interrupted"}:
            return result
        time.sleep(0.01)
    pytest.fail("Authored composition job did not settle")


@pytest.fixture
def harness(saved, provider):
    store, state, _, _ = saved
    state["now_ms"] = 5000
    controller = RunJobController(store, lambda *_: pytest.fail("No effects are permitted"))
    supplied = context(state)

    def validate(owner, value, *, prior_attempt_id=None):
        if prior_attempt_id is None:
            return compile_initial_graph(value, **compiler_args(state))
        return compile_revision(value, **compiler_args(state), previous_semantic_digests=[])

    composition = SimpleNamespace(
        clock=lambda: state["now_ms"],
        proposal_context=lambda *_args, **_kwargs: deepcopy(supplied),
        validate_proposal=validate,
    )
    access = Access(value=candidate(state))
    service = SimpleNamespace(
        product_store=store,
        job_controller=controller,
        composition=composition,
        _provider_access=access,
        _runtime_configuration_lock=threading.RLock(),
        _runtime_ai=lambda: SimpleNamespace(provider=lambda _id: provider),
    )
    jobs = CompositionAIJobs(service)
    yield SimpleNamespace(
        jobs=jobs,
        service=service,
        state=state,
        saved=saved,
        context=supplied,
        access=access,
        owner=state["parent_job_id"],
        provider=provider,
    )
    controller.shutdown()


def request(harness, *, prior=None):
    return {
        "submission_id": str(uuid.uuid4()),
        "provider_id": harness.provider.id,
        "prior_attempt_id": prior,
        "context_digest": harness.jobs.context(harness.owner, prior_attempt_id=prior)[
            "context_digest"
        ],
    }


def test_exact_dialects_registered_schema_and_sanitized_model_context(provider, state):
    supplied = context(state)
    supplied["private_token"] = "do-not-send"
    supplied["snapshot"]["methods"][0]["implementation_path"] = "C:/private/runner"
    body, projected = format_request(provider, supplied)
    assert schema_identity(body, provider.kind) == (PURPOSE, content_hash(OUTPUT_SCHEMA))
    assert PURPOSE in PURPOSES and _schemas()[PURPOSE] == content_hash(OUTPUT_SCHEMA)
    assert (PURPOSE, content_hash(OUTPUT_SCHEMA)) in enroll(provider, "explicit_endpoint").schemas
    assert b"do-not-send" not in body and b"C:/private" not in body
    assert "grant_id" not in projected and "implementation_digest" not in json.dumps(projected)
    assert "source" not in projected["facts"][0] and "attempt_id" not in projected["facts"][0]
    access = Access(value=candidate(state))
    result = propose(config=provider, access=access, context=supplied, cancel=threading.Event())
    assert result["candidate"] == candidate(state)
    assert len(access.calls) == 1 and result["provider"]["used_fallback"] is False
    assert not {"compiled", "lease", "approval", "native_envelope"}.intersection(result)


@pytest.mark.parametrize(
    "defect",
    ["extra_authority", "method", "parameter_path", "port", "missing_parameter", "invented_fact"],
)
def test_untrusted_proposal_cannot_add_authority_methods_paths_or_evidence(provider, state, defect):
    value = candidate(state)
    if defect == "extra_authority":
        value["approval"] = True
    elif defect == "method":
        value["steps"][0]["behavior_id"] = "arbitrary.exec.v1"
    elif defect == "parameter_path":
        value["steps"][0]["parameters"]["path"] = "/private/data"
    elif defect == "missing_parameter":
        value["steps"][0]["parameters"] = {}
    elif defect == "port":
        value["steps"][4]["parameters"]["port"] = 65534
    else:
        value["evidence_refs"] = ["invented-proof"]
    with pytest.raises(AIProviderError):
        propose(
            config=provider,
            access=Access(value=value),
            context=context(state),
            cancel=threading.Event(),
        )


def test_context_identity_binds_fact_observation_time_and_value(state):
    supplied = context(state)
    changed = deepcopy(supplied)
    changed["facts"]["facts"][0]["observed_at_ms"] += 1
    changed["facts"]["facts_digest"] = content_hash("refreshed")
    assert context_digest(changed) != context_digest(supplied)
    changed = deepcopy(supplied)
    changed["facts"]["facts"][0]["value"]["status"] = "rolled_back"
    assert context_digest(changed) != context_digest(supplied)


def test_durable_initial_candidate_has_one_provider_call_no_execution_and_exact_retry(harness):
    value = request(harness)
    submitted = harness.jobs.submit(harness.owner, value)
    result = wait(harness.jobs, submitted["job"]["job_id"])
    assert result["job"]["kind"] == KIND and result["job"]["state"] == "completed"
    assert result["candidate_ready"] and result["provider_outcome"] == "candidate"
    assert result["proposal"]["candidate"] == candidate(harness.state)
    assert harness.jobs.submit(harness.owner, value)["proposal"] == result["proposal"]
    assert len(harness.access.calls) == 1
    with harness.service.product_store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_attempts").fetchone()[0] == 0
    reopened = CompositionAIJobs(harness.service).read(result["job"]["job_id"])
    assert reopened["proposal"] == result["proposal"]
    harness.jobs.cancel(result["job"]["job_id"])
    assert not harness.jobs.read(result["job"]["job_id"])["candidate_ready"]


def test_revision_is_provider_authored_from_actual_refusal_not_an_authored_itinerary(harness):
    lease = reserve(harness.saved)
    harness.service.product_store.settle_capability_attempt(lease["attempt_id"], unused(lease))
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
    value = candidate(revised, redact=True)
    value["evidence_refs"] = ["policy", "refusal", "cleanup"]
    harness.access.value = value
    started = harness.jobs.submit(harness.owner, request(harness, prior=lease["attempt_id"]))
    result = wait(harness.jobs, started["job"]["job_id"])
    assert result["candidate_ready"] and result["proposal"]["candidate"] == value
    wire = json.loads(harness.access.calls[0][1])
    model = json.loads(wire.get("input") or wire["messages"][1]["content"])
    assert model["revision"] is True and model["initial_proposal"] is None
    assert {row["evidence_ref"] for row in model["facts"]} == {"policy", "refusal", "cleanup"}


@pytest.mark.parametrize("change", ["context", "grant", "provider", "candidate"])
def test_inflight_change_or_invalid_graph_prevents_publication(harness, change):
    value = request(harness)
    if change == "candidate":
        harness.access.value["edges"] = []
    elif change == "context":
        harness.access.after = lambda: harness.context["facts"]["facts"][0]["value"].update(
            status="unknown"
        )
    elif change == "grant":
        harness.access.after = lambda: harness.service.product_store.change_capability_grant_state(
            harness.state["grant"]["grant_id"], status="revoked", now_ms=6000
        )
    else:
        harness.access.after = lambda: setattr(
            harness.service,
            "_runtime_ai",
            lambda: SimpleNamespace(
                provider=lambda _id: SimpleNamespace(
                    kind=harness.provider.kind, to_dict=lambda: {"changed": True}
                )
            ),
        )
    started = harness.jobs.submit(harness.owner, value)
    result = wait(harness.jobs, started["job"]["job_id"])
    assert result["job"]["state"] == "failed" and result["proposal"] is None
    assert result["provider_outcome"] == "context_refused"


@pytest.mark.parametrize("outcome", ["cancelled", "unknown", "refused", "invalid", "unavailable"])
def test_provider_outcomes_are_distinct_and_never_fallback_or_silently_retry(harness, outcome):
    if outcome == "cancelled":
        harness.access.after = lambda: harness.access.calls[-1][-1].set()
    elif outcome == "unknown":

        def fail():
            raise AIProviderTransportError(
                "Authored timeout", retryable=True, code="request_timeout"
            )

        harness.access.after = fail
    elif outcome == "refused":
        harness.access.raw = json.dumps(
            {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "refusal", "refusal": "fixture"}],
                    }
                ],
            }
            if harness.provider.kind.value == "openai_responses"
            else {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "refusal": "fixture", "content": None},
                    }
                ],
            }
        ).encode()
    elif outcome == "invalid":
        harness.access.raw = b"not-json"
    else:
        harness.access.ready = False
    value = request(harness)
    started = harness.jobs.submit(harness.owner, value)
    result = wait(harness.jobs, started["job"]["job_id"])
    assert result["provider_outcome"] == outcome and result["proposal"] is None
    harness.jobs.submit(harness.owner, value)
    assert len(harness.access.calls) == (0 if outcome == "unavailable" else 1)


def test_stopped_objective_refuses_before_any_provider_request(harness):
    value = request(harness)
    harness.service.product_store.change_capability_grant_state(
        harness.state["grant"]["grant_id"], status="paused", now_ms=6000
    )
    started = harness.jobs.submit(harness.owner, value)
    result = wait(harness.jobs, started["job"]["job_id"])
    assert result["provider_outcome"] == "context_refused"
    assert result["proposal"] is None and harness.access.calls == []


def test_cancellation_before_transport_never_calls_provider(provider, state):
    access, cancel = Access(value=candidate(state)), threading.Event()
    cancel.set()
    with pytest.raises(AIProviderCancelled):
        propose(config=provider, access=access, context=context(state), cancel=cancel)
    assert access.calls == []


@pytest.mark.parametrize("transport", ["direct", "broker"])
def test_composition_purpose_requires_explicit_exact_schema_authorization_and_budget(
    provider, state, tmp_path, transport
):
    body, _ = format_request(provider, context(state))
    limits = {
        "max_requests": 1,
        "max_request_bytes": len(body),
        "max_reserved_output_tokens": provider.max_output_tokens,
    }
    request = authorization_request(
        provider,
        purposes=[PURPOSE],
        limits=limits,
        local_endpoint_authorized=True,
    )
    if transport == "direct":
        underlying = Access(value=candidate(state))
        access = AuthorizedAIProviderAccess(underlying, ProductStore(tmp_path / "provider.db"))

        def authorize(value):
            return access.authorize(value)

        def post(value):
            return access.post(provider, body=value, timeout_seconds=1)

    else:
        enrollment = BrokerEnrollment.create(
            provider,
            session_id="a" * 64,
            expires_at_ms=now_ms() + 300_000,
            schemas=((PURPOSE, content_hash(OUTPUT_SCHEMA)),),
            destination_policy="explicit_endpoint",
        )
        access = BrokerLiveAuthorizations(enrollment)
        authority_context = {
            "kind": "broker",
            "binding_digest": enrollment.digest,
            "provider": provider.to_dict(),
            "expires_at_ms": enrollment.expires_at_ms,
        }

        def authorize(value):
            return access.authorize(create_authorization(value, authority_context))

        post = access.reserve
    with pytest.raises(AIProviderTransportError):
        post(body)
    if transport == "direct":
        authorize({**request, "purposes": ["bluefire_connection_check"]})
        with pytest.raises(AIProviderTransportError):
            post(body)
        assert underlying.calls == []
    authorize(request)
    mutated = body.replace(b'"additionalProperties": false', b'"additionalProperties": true')
    assert mutated != body
    with pytest.raises(AIProviderTransportError):
        post(mutated)
    post(body)
    with pytest.raises(AIProviderTransportError) as error:
        post(body)
    assert error.value.code == "live_usage_exhausted"
    if transport == "direct":
        assert len(underlying.calls) == 1


def test_stale_context_is_durably_refused_without_provider_dispatch(harness):
    value = request(harness)
    harness.context["facts"]["facts"][0]["observed_at_ms"] += 1
    submitted = harness.jobs.submit(harness.owner, value)
    result = wait(harness.jobs, submitted["job"]["job_id"])
    assert result["provider_outcome"] == "context_refused" and result["proposal"] is None
    assert harness.access.calls == []
    assert harness.jobs.submit(harness.owner, value)["job"]["job_id"] == result["job"]["job_id"]


def test_inflight_cancel_retains_one_attempt_and_never_publishes_candidate(harness):
    entered = threading.Event()

    def hold():
        entered.set()
        assert harness.access.calls[-1][-1].wait(5)

    harness.access.after = hold
    submitted = harness.jobs.submit(harness.owner, request(harness))
    assert entered.wait(5)
    harness.jobs.cancel(submitted["job"]["job_id"])
    result = wait(harness.jobs, submitted["job"]["job_id"])
    assert result["job"]["state"] == "cancelled"
    assert result["provider_outcome"] == "cancelled" and result["proposal"] is None
    assert len(harness.access.calls) == 1


def test_owner_stop_cancels_provider_children_and_keeps_saved_candidates_stopped(harness):
    completed = harness.jobs.submit(harness.owner, request(harness))
    completed = wait(harness.jobs, completed["job"]["job_id"])
    entered = threading.Event()

    def hold():
        entered.set()
        assert harness.access.calls[-1][-1].wait(5)

    harness.access.after = hold
    running = harness.jobs.submit(harness.owner, request(harness))
    assert entered.wait(5)
    harness.jobs.stop_owner(harness.owner)
    result = wait(harness.jobs, running["job"]["job_id"])
    assert result["job"]["state"] == "cancelled" and result["proposal"] is None
    retained = harness.jobs.read(completed["job"]["job_id"])
    assert retained["proposal"] == completed["proposal"] and not retained["candidate_ready"]


def test_known_purpose_authorization_refusal_is_not_unknown_transport(harness):
    access = AuthorizedAIProviderAccess(harness.access, harness.service.product_store)
    access.authorize(
        authorization_request(
            harness.provider,
            purposes=["bluefire_connection_check"],
            local_endpoint_authorized=True,
        )
    )
    harness.service._provider_access = access
    started = harness.jobs.submit(harness.owner, request(harness))
    result = wait(harness.jobs, started["job"]["job_id"])
    assert result["provider_outcome"] == "refused" and result["proposal"] is None
    assert result["job"]["progress"]["retryable"] is False
    assert "No model request was sent" in result["job"]["progress"]["operation_error"]
    assert harness.access.calls == []
    assert access.list()["authorizations"][0]["usage"]["requests"] == 0
