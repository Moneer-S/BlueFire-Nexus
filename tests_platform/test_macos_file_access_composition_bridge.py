"""Fixed attempt-channel fakes only; no process, socket or native worker starts."""

import threading
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_bridge as bridge
from bluefire import macos_file_access_method as method
from bluefire.execution_contracts import execution_task_identity
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.util import content_hash
from tests_platform import test_macos_file_access_bridge as bridge_cases

creator_fake = bridge_cases.creator_fake
original = bridge_cases.original


@pytest.fixture
def attempt(original):
    producer, value, state = original.producer, original.value, original.state
    producer._namespace.mode = "0600"
    producer._state = "hardened"
    producer._revision = 3
    producer._last_binding = producer._binding()
    base = {
        "schema_version": "bluefire.macos-file-access-attempt-dispatch.v1",
        "attempt_id": "attempt-" + "1" * 32,
        "grant_id": "grant-" + "2" * 32,
        "grant_digest": content_hash("grant"),
        "lease_digest": content_hash("lease"),
        "compiled_digest": content_hash("compiled"),
        "job_id": "job-" + "3" * 32,
        "run_id": "run-1",
        "control_owner_id": "file-control-" + "4" * 64,
        "workspace_binding_digest": content_hash("workspace"),
        "dependency_digest": content_hash("dependency"),
        "probe_step_id": "probe",
        "owner_step_id": "owner",
        "cleanup_step_id": "close",
        "issued_at_ms": state["wall"],
        "business_expires_at_ms": state["wall"] + 4000,
        "cleanup_expires_at_ms": state["wall"] + 8000,
        "issued_monotonic_ns": state["clock"],
        "business_deadline_ns": state["clock"] + 4_000_000_000,
        "cleanup_deadline_ns": state["clock"] + 8_000_000_000,
        "primitive_budget": {"probe": 1, "verify_owner": 1, "total": 2},
        "probe_task_id": None,
        "probe_receipt_digest": None,
        "task_closures": [],
        "cleanup_claim": None,
        "cleanup_claim_digest": None,
    }
    frames, receipts = {}, {}

    def frame(operation="probe"):
        context = producer.review_context(operation)
        current = deepcopy(base)
        cleanup = operation == "close_attempt"
        if operation != "probe" and "probe" in receipts:
            current.update(
                probe_task_id=receipts["probe"]["task_id"],
                probe_receipt_digest=content_hash(receipts["probe"]),
            )
        manifest = {
            "schema_version": "bluefire.runner-manifest.v1",
            "request_id": operation,
            "run_id": base["run_id"],
            "step_id": {"probe": "probe", "verify_owner": "owner", "close_attempt": "close"}[
                operation
            ],
            "behavior_id": method.METHODS[
                ("probe", "verify_owner", "close_attempt").index(operation)
            ],
            "action_id": method.METHODS[
                ("probe", "verify_owner", "close_attempt").index(operation)
            ],
            "runner_id": "local-runner",
            "runner_profile_id": "original-profile",
            "params": {},
            "request_hash": "",
            "platform": "macos",
        }
        profile = {
            "schema_version": "bluefire.runner-profile.v1",
            "runner_id": "local-runner",
            "profile_id": "original-profile",
            "platform": "macos",
            "sandbox_root": "/private/var/empty/fake-attempt",
            "macos_file_access_binding": context["binding"],
            "policy_digest": "",
        }
        profile["policy_digest"] = content_hash(profile)
        manifest["policy_digest"] = profile["policy_digest"]
        if cleanup:
            authority = {
                "schema_version": "bluefire.macos-file-access-artifact-closure-claim.v1",
                **{
                    key: base[key]
                    for key in (
                        "attempt_id",
                        "lease_digest",
                        "compiled_digest",
                        "run_id",
                        "cleanup_step_id",
                    )
                },
                "issued_at_ms": state["wall"],
                "expires_at_ms": base["cleanup_expires_at_ms"],
                "issued_monotonic_ns": state["clock"],
                "deadline_ns": base["cleanup_deadline_ns"],
                "scope": "attempt_artifact_closure_only",
            }
            manifest["macos_file_access_cleanup"] = authority
            current.update(
                cleanup_claim=authority,
                cleanup_claim_digest=content_hash(authority),
                task_closures=[
                    {
                        "task_id": receipt["task_id"],
                        "transport_request_hash": receipt["transport_request_hash"],
                        "request_hash": frames[key]["claim"]["request_hash"],
                        "state": "complete",
                        "native_receipt_digest": content_hash(receipt),
                    }
                    for key, receipt in receipts.items()
                ],
            )
        else:
            manifest["grant_attempt"] = {
                key: base[key]
                for key in (
                    "attempt_id",
                    "grant_id",
                    "grant_digest",
                    "lease_digest",
                    "compiled_digest",
                    "run_id",
                )
            }
        manifest["request_hash"] = content_hash(manifest)
        task_id, transport = execution_task_identity(manifest, profile)
        if operation == "probe":
            current["probe_task_id"] = task_id
        expires = base["cleanup_expires_at_ms" if cleanup else "business_expires_at_ms"]
        deadline = base["cleanup_deadline_ns" if cleanup else "business_deadline_ns"]
        intent = {
            "schema_version": "bluefire.macos-file-access-reviewed-task.v1",
            "operation": operation,
            "task_id": task_id,
            "transport_request_hash": transport,
            "context_digest": context["context_digest"],
            "binding_digest": content_hash(context["binding"]),
            "control_revision": producer._revision,
            "issued_at_ms": state["wall"],
            "expires_at_ms": min(state["wall"] + 5000, expires),
            "issued_monotonic_ns": state["clock"],
            "deadline_ns": min(state["clock"] + 5_000_000_000, deadline),
        }
        result = {
            "schema_version": "bluefire.macos-file-access-committed-task.v1",
            "intent": intent,
            "claim": {
                "job_id": base["job_id"],
                "task_id": task_id,
                "step_id": manifest["step_id"],
                "request_hash": manifest["request_hash"],
                "transport_request_hash": transport,
                "manifest": manifest,
                "runner_profile": profile,
            },
            "preparation_digest": content_hash("reservation"),
            "job_id": base["job_id"],
            "attempt": current,
            "cancelled": False,
        }
        result["dispatch_digest"] = content_hash(result)
        frames[operation] = result
        return result

    def dispatch(frame):
        request = {
            "schema_version": "bluefire.macos-workspace-request.v1",
            "sequence": value._sequence + 1,
            "operation": "dispatch_committed",
            "payload": frame,
        }
        value._received_request = request
        try:
            result = value._received(request)["payload"]
            if frame["intent"]["operation"] != "close_attempt":
                receipts[frame["intent"]["operation"]] = result
            return result
        finally:
            value._received_request = None

    return SimpleNamespace(
        original=original,
        producer=producer,
        state=state,
        value=value,
        base=base,
        frame=frame,
        dispatch=dispatch,
        receipts=receipts,
        frames=frames,
    )


def rehash(frame):
    frame["dispatch_digest"] = content_hash(
        {key: value for key, value in frame.items() if key != "dispatch_digest"}
    )


def test_pair_is_reserved_before_probe_and_owner_consumes_same_reserved_slot(attempt):
    probe = attempt.dispatch(attempt.frame())
    assert attempt.producer._used_budget == 2 and len(attempt.state["calls"]) == 1
    owner = attempt.dispatch(attempt.frame("verify_owner"))
    assert attempt.producer._used_budget == 2 and len(attempt.state["calls"]) == 2
    assert (
        probe["terminals"][0]["outcome"] == "denied"
        and owner["terminals"][0]["outcome"] == "allowed"
    )
    closure = attempt.dispatch(attempt.frame("close_attempt"))
    assert method.validate_closure(closure) == closure
    assert (
        closure["attempt_artifacts"] == "not_created" and closure["original_workers"] == "retained"
    )
    assert not closure["whole_enrollment_cleanup"] and len(attempt.state["calls"]) == 2
    assert not attempt.state["settles"]


@pytest.mark.parametrize("change", ["budget", "attempt", "probe", "receipt", "binding", "lease"])
def test_owner_refuses_changed_same_attempt_dependency_without_second_primitive(attempt, change):
    attempt.dispatch(attempt.frame())
    frame = attempt.frame("verify_owner")
    if change == "budget":
        frame["attempt"]["primitive_budget"]["total"] = 1
    elif change == "attempt":
        frame["attempt"]["attempt_id"] = "attempt-" + "9" * 32
    elif change == "probe":
        frame["attempt"]["probe_task_id"] = "execute-" + "9" * 64
    elif change == "receipt":
        frame["attempt"]["probe_receipt_digest"] = content_hash("other")
    elif change == "binding":
        frame["intent"]["binding_digest"] = content_hash("other")
    else:
        frame["attempt"]["lease_digest"] = content_hash("other")
    rehash(frame)
    with pytest.raises(MacOSFileAccessContractError):
        attempt.dispatch(frame)
    assert len(attempt.state["calls"]) == 1 and attempt.producer._used_budget == 2


@pytest.mark.parametrize("operation", ["probe", "verify_owner", "close_attempt"])
def test_original_task_or_closure_cannot_be_replayed(attempt, operation):
    frame = attempt.frame()
    attempt.dispatch(frame)
    if operation != "probe":
        frame = attempt.frame("verify_owner")
        attempt.dispatch(frame)
    if operation == "close_attempt":
        frame = attempt.frame("close_attempt")
        attempt.dispatch(frame)
    before = len(attempt.state["calls"])
    with pytest.raises(MacOSFileAccessContractError):
        attempt.dispatch(frame)
    assert len(attempt.state["calls"]) == before and attempt.producer._used_budget == 2


def test_budget_shortage_refuses_whole_pair_before_first_probe(attempt):
    attempt.producer._used_budget = 63
    with pytest.raises(MacOSFileAccessContractError):
        attempt.dispatch(attempt.frame())
    assert not attempt.state["calls"] and attempt.producer._used_budget == 63


def test_unknown_probe_never_closes_from_empty_artifact_claim(attempt):
    attempt.state["fail_role"] = "reader"
    result = attempt.dispatch(attempt.frame())
    assert result["state"] == "unknown" and attempt.producer._used_budget == 2
    with pytest.raises(MacOSFileAccessContractError):
        attempt.frame("close_attempt")
    assert len(attempt.state["calls"]) == 1


def test_business_deadline_does_not_renew_but_reserved_cleanup_time_remains(attempt):
    attempt.dispatch(attempt.frame())
    attempt.dispatch(attempt.frame("verify_owner"))
    attempt.state["wall"] = attempt.base["business_expires_at_ms"]
    attempt.state["clock"] = attempt.base["business_deadline_ns"]
    closure = attempt.dispatch(attempt.frame("close_attempt"))
    assert closure["state"] == "closed" and len(attempt.state["calls"]) == 2


@pytest.mark.parametrize("started", [False, True])
def test_cleanup_can_close_only_original_completed_or_unsent_usage_without_new_reads(
    attempt, started
):
    if started:
        attempt.dispatch(attempt.frame())
    owner_frame = attempt.frame("verify_owner") if started else None
    frame = attempt.frame("close_attempt")
    if owner_frame is not None:
        claim = owner_frame["claim"]
        frame["attempt"]["task_closures"].append(
            {
                "task_id": claim["task_id"],
                "transport_request_hash": claim["transport_request_hash"],
                "request_hash": claim["request_hash"],
                "state": "not_sent",
                "native_receipt_digest": None,
            }
        )
        rehash(frame)
    closure = attempt.dispatch(frame)
    assert closure["state"] == "closed" and closure["producer_request_usage"] == "settled"
    assert len(attempt.state["calls"]) == int(started)
    assert attempt.producer._used_budget == (2 if started else 0)
    if owner_frame is not None:
        with pytest.raises(MacOSFileAccessContractError):
            attempt.dispatch(owner_frame)
        assert len(attempt.state["calls"]) == 1 and attempt.producer._used_budget == 2


@pytest.mark.parametrize("clock", ["wall", "clock"])
def test_cleanup_deadline_equality_cannot_mint_closure(attempt, clock):
    attempt.dispatch(attempt.frame())
    attempt.dispatch(attempt.frame("verify_owner"))
    attempt.state["wall"] = attempt.base["business_expires_at_ms"]
    attempt.state["clock"] = attempt.base["business_deadline_ns"]
    frame = attempt.frame("close_attempt")
    attempt.state[clock] = attempt.base[
        "cleanup_expires_at_ms" if clock == "wall" else "cleanup_deadline_ns"
    ]
    with pytest.raises(MacOSFileAccessContractError):
        attempt.dispatch(frame)
    assert len(attempt.state["calls"]) == 2


@pytest.mark.parametrize("change", ["missing", "receipt", "request", "not_sent"])
def test_closure_cannot_omit_or_replace_original_request_usage(attempt, change):
    attempt.dispatch(attempt.frame())
    attempt.dispatch(attempt.frame("verify_owner"))
    frame = attempt.frame("close_attempt")
    if change == "missing":
        frame["attempt"]["task_closures"].pop()
    elif change == "receipt":
        frame["attempt"]["task_closures"][0]["native_receipt_digest"] = content_hash("other")
    elif change == "request":
        frame["attempt"]["task_closures"][0]["request_hash"] = content_hash("other")
    else:
        frame["attempt"]["task_closures"][0].update(state="not_sent", native_receipt_digest=None)
    rehash(frame)
    with pytest.raises(MacOSFileAccessContractError):
        attempt.dispatch(frame)
    assert (
        len(attempt.state["calls"]) == 2
        and not attempt.value._attempts[attempt.base["attempt_id"]]["closed"]
    )


def test_composition_transport_commits_exact_standard_payload_before_exchange(attempt):
    frame = attempt.frame()
    events = []

    class Store:
        def begin_macos_capability_dispatch(self, task, transport, **context):
            assert (
                task == frame["claim"]["task_id"]
                and transport == frame["claim"]["transport_request_hash"]
            )
            assert context["creator_context"]["operation"] == "probe"
            events.append("committed")
            return frame

    class Endpoint:
        def assert_current(self):
            pass

        def review_context(self, operation):
            events.append("context")
            return attempt.producer.review_context(operation)

        def dispatch_committed(self, current, *, cancel_event):
            assert events == ["context", "committed"] and not cancel_event.is_set()
            events.append("exchange")
            return attempt.dispatch(current)

    transport = bridge.MacOSWorkspaceTaskTransport(Endpoint(), Store())
    result = transport.execute_task(
        frame["claim"]["manifest"],
        frame["claim"]["runner_profile"],
        task_id=frame["claim"]["task_id"],
        cancel_event=threading.Event(),
    )
    assert events == ["context", "committed", "exchange"] and result["status"] == "success"
    assert result["receipt_ids"] == [] and "cleanup" not in result
    assert result["output"]["macos_receipt"] == attempt.receipts["probe"]
    assert result["output"]["observation"]["native_receipt_digest"] == content_hash(
        attempt.receipts["probe"]
    )


@pytest.mark.parametrize("failure", ["cancelled", "commit_failed", "channel_lost"])
def test_composition_transport_never_replays_cancelled_or_uncommitted_work(attempt, failure):
    frame = attempt.frame()
    cancelled = threading.Event()
    calls = []

    class Store:
        def begin_macos_capability_dispatch(self, *_args, **_options):
            calls.append("commit")
            if failure == "commit_failed":
                raise RuntimeError("fake dispatch commit rollback")
            if failure == "cancelled":
                cancelled.set()
            return frame

    class Endpoint:
        def assert_current(self):
            pass

        def review_context(self, operation):
            return attempt.producer.review_context(operation)

        def dispatch_committed(self, *_args, **_options):
            calls.append("exchange")
            raise OSError("fake original channel lost")

    transport = bridge.MacOSWorkspaceTaskTransport(Endpoint(), Store())
    error = (
        RuntimeError
        if failure == "commit_failed"
        else MacOSFileAccessContractError if failure == "cancelled" else OSError
    )
    with pytest.raises(error):
        transport.execute_task(
            frame["claim"]["manifest"],
            frame["claim"]["runner_profile"],
            task_id=frame["claim"]["task_id"],
            cancel_event=cancelled,
        )
    assert calls == (["commit", "exchange"] if failure == "channel_lost" else ["commit"])
    assert not attempt.state["calls"] and attempt.producer._used_budget == 0
