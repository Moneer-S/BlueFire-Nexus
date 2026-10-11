"""Pure original-request and safe-result guards; no runner or domain observations."""

from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire import ad_smb_results as results
from bluefire.ad_smb_contract import AdSmbError
from bluefire.runner_contracts import seal_manifest, seal_profile
from bluefire.util import content_hash
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_jobs import FakeExecutor


def original():
    executor = FakeExecutor()
    owner = {
        "job_id": "job-" + "a" * 32,
        "request": {"environment": executor.selected, "readiness": executor.ready},
        "progress": {
            "revision": 0,
            "operations": [],
            "reserved": {},
            "pending_operation": None,
            "policy_state": "baseline",
            "stopped": False,
        },
    }
    review = results.review_document(owner, "inspect")
    request = results.request_for(
        owner,
        "inspect",
        "job-" + "b" * 32,
        0,
        NOW.isoformat(),
        (NOW + timedelta(seconds=60)).isoformat(),
        review,
        "fixture-reviewer",
    )
    return executor, owner, review, request


def test_exact_original_context_roundtrip_is_detached_but_not_authentication():
    executor, _owner, _review, request = original()
    value = executor.original(request)
    checked = results.original_context(request, value)
    assert checked == value
    value["manifest"]["action_id"] = "mutated"
    assert checked["manifest"]["action_id"] == results.ACTION


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", "execute-" + "0" * 64),
        ("transport_request_hash", pin("0")),
        ("request_digest", pin("0")),
        ("schema_version", "unknown"),
    ],
)
def test_original_context_foreign_identity_refused(field, value):
    executor, _owner, _review, request = original()
    context = executor.original(request)
    context[field] = value
    with pytest.raises(AdSmbError):
        results.original_context(request, context)


@pytest.mark.parametrize(
    "field",
    ["channel_digest", "host_id", "native_generation", "profile_digest", "runner_profile_id"],
)
def test_original_transport_cannot_be_rebound(field):
    executor, _owner, _review, request = original()
    context = deepcopy(executor.original(request))
    context["transport_identity"][field] = "foreign" if field == "runner_profile_id" else pin("0")
    with pytest.raises(AdSmbError):
        results.original_context(request, context)


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_scope", {"filesystem": ["*"], "network": []}),
        ("allowed_actions", [results.ACTION, "other"]),
        ("capabilities", ["ad_smb_access", "native_execution"]),
        ("sandbox_root", "C:\\foreign"),
        ("approval_required_at_or_above", None),
    ],
)
def test_resealed_changed_profile_is_not_the_saved_native_policy(field, value):
    executor, _owner, _review, request = original()
    context = deepcopy(executor.original(request))
    context["profile"][field] = value
    context["profile"] = seal_profile(context["profile"])
    with pytest.raises(AdSmbError):
        results.original_context(request, context)


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_id", "other"),
        ("behavior_id", "other"),
        ("cleanup_action_id", "other"),
        ("required_capabilities", []),
        ("target_scope", {"filesystem": [], "network": [{"host": "foreign"}]}),
        ("limits", {"timeout_ms": 900000}),
    ],
)
def test_resealed_changed_manifest_cannot_replace_original(field, value):
    executor, _owner, _review, request = original()
    context = deepcopy(executor.original(request))
    context["manifest"][field] = value
    context["manifest"] = seal_manifest(context["manifest"])
    with pytest.raises(AdSmbError):
        results.original_context(request, context)


@pytest.mark.parametrize(
    "field,value",
    [
        ("index", True),
        ("index", -1),
        ("index", 1),
        ("reviewed_by", "https://not-a-reviewer"),
        ("workflow_job_id", "job-" + "0" * 32),
        ("scope_digest", pin("0")),
        ("extra", False),
        ("requested_at", (NOW - timedelta(seconds=1)).isoformat()),
        ("deadline", NOW.isoformat()),
        ("deadline", (NOW + timedelta(seconds=61)).isoformat()),
    ],
)
def test_changed_original_step_refused(field, value):
    _executor, owner, review, request = original()
    request[field] = value
    with pytest.raises(AdSmbError):
        results.validate_request(owner, request, review)


@pytest.mark.parametrize("delta", [-1, 61])
def test_member_observation_outside_original_request_window_is_not_fresh(delta):
    executor, _owner, _review, request = original()
    request["requested_at"] = (NOW + timedelta(seconds=10)).isoformat()
    request["deadline"] = (NOW + timedelta(seconds=70)).isoformat()
    execution = deepcopy(executor.terminal(request))
    execution["observation"]["snapshot"]["observed_at"] = (
        NOW + timedelta(seconds=10 + delta)
    ).isoformat()
    with pytest.raises(AdSmbError, match="original request window"):
        results.validate_execution(request, execution)


def test_known_partial_observation_does_not_invent_full_stage_or_unknown_effect():
    execution = {"dispatch": "not_started", "cleanup": "verified", "observation": None}
    value = results.outcome("baseline", [execution])
    assert value["state"] == "not_started" and value["read_expectation"] == "incomplete"
    assert value["effective_access_claim"] is False


def test_available_readiness_cannot_omit_one_native_prerequisite():
    executor, _owner, _review, _request = original()
    for field in ("member_observation", "client_read_admission", "secret_channel_available"):
        value = {**executor.ready, field: False}
        with pytest.raises(AdSmbError):
            results.readiness(value)


def test_request_digest_is_an_identity_not_an_authentication_claim():
    executor, _owner, _review, request = original()
    execution = executor.terminal(request)
    assert execution["request_digest"] == content_hash(request)
    outcome = results.outcome("inspect", [results.validate_execution(request, execution)])
    assert outcome["state"] == "complete"
    assert outcome["authenticated_remote_reader"] is False
    assert outcome["independent_observation"] is False
    assert outcome["effective_access_claim"] is False
