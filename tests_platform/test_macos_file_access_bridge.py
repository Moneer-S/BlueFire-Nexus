"""Fake original-channel integration only; no threads, sockets or workers start."""

import threading
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_bridge as bridge
from bluefire import macos_file_access_creator as creator
from bluefire import macos_file_access_workspace as workspace
from bluefire.execution_contracts import execution_task_identity
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.macos_file_access_peer import MacOSChildConsistency
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_macos_file_access_creator as creator_cases

creator_fake = creator_cases.fake


def test_workspace_composition_entry_supplies_only_the_exact_original_attach_factory(monkeypatch):
    owner = object.__new__(workspace.MacOSWorkspaceOwner)
    factories = []
    monkeypatch.setattr(owner, "start", lambda *, bridge_factory: factories.append(bridge_factory))
    bridge.start_workspace(owner)
    assert len(factories) == 1
    assert factories[0].__self__ is bridge.OriginalMacOSWorkspaceBridge
    assert factories[0].__func__ is bridge.OriginalMacOSWorkspaceBridge.attach.__func__


@pytest.mark.parametrize("entry", ["start", "attach"])
@pytest.mark.parametrize("kind", ["document", "subclass"])
def test_original_workspace_entry_and_attach_still_reject_recreated_owner(entry, kind):
    class Recreated(workspace.MacOSWorkspaceOwner):
        pass

    owner = {} if kind == "document" else object.__new__(Recreated)
    operation = (
        bridge.start_workspace if entry == "start" else bridge.OriginalMacOSWorkspaceBridge.attach
    )
    with pytest.raises(MacOSFileAccessContractError):
        operation(owner)


@pytest.fixture
def original(creator_fake, monkeypatch):
    create, _lease, _reserve, state = creator_fake
    producer = create()
    owner = object.__new__(workspace.MacOSWorkspaceOwner)
    owner._creator = producer
    owner._stream = creator.socket.socket()
    owner._process = object()
    owner._consistency = MacOSChildConsistency(103, 101, (100, 1), (501,) * 6)
    owner._channel_lock = threading.RLock()
    owner._state = "active"
    state.update(replies=[], received=[], controller_closes=0, host_checks=0, no_fork_checks=0)

    def current():
        state["host_checks"] += 1
        if owner._state != "active":
            raise MacOSFileAccessContractError("fake original HOST lost")

    def close():
        state["controller_closes"] += 1

    def forbidden(_process):
        state["no_fork_checks"] += 1
        raise AssertionError("normal HOST must permit fixed descendants")

    class Thread:
        def __init__(self, **options):
            self.target = options["target"]

        def start(self):
            raise AssertionError("this fake must not start a real or simulated background loop")

        def join(self, **_options):
            pass

        def is_alive(self):
            return False

    monkeypatch.setattr(owner, "assert_current", current)

    def guard(deadline=None):
        if deadline is not None and state["clock"] >= deadline:
            raise MacOSFileAccessContractError("fake fixed original frame deadline")
        return 1.0 if deadline is None else min(1.0, (deadline - state["clock"]) / 1e9)

    monkeypatch.setattr(owner, "_guard", guard)
    monkeypatch.setattr(owner, "_close_endpoint", close)
    monkeypatch.setattr(producer._runtime, "_refresh_darwin_no_fork_proof", forbidden)
    monkeypatch.setattr(bridge, "threading", SimpleNamespace(Thread=Thread))
    monkeypatch.setattr(bridge, "time", SimpleNamespace(time_ns=lambda: state["wall"] * 1_000_000))
    monkeypatch.setattr(bridge, "darwin_clock_ns", lambda: state["clock"])
    value = bridge.OriginalMacOSWorkspaceBridge.attach(owner)
    monkeypatch.setattr(
        bridge,
        "select",
        SimpleNamespace(
            select=lambda *_args: ([], [], []) if value._in_task else ([owner._stream], [], [])
        ),
    )

    def frame(operation="baseline"):
        context = producer.review_context(operation)
        manifest = {
            "schema_version": "bluefire.macos-file-access-task.v1",
            "run_id": "run-1",
            "step_id": operation,
            "action_id": "macos.file_access." + operation + ".v1",
            "request_hash": content_hash({"operation": operation}),
            "params": {},
            "approval": {"review_digest": content_hash("review")},
        }
        profile = {
            "schema_version": "bluefire.macos-file-access-task-profile.v1",
            "macos_file_access_binding": context["binding"],
        }
        profile["policy_digest"] = content_hash(profile)
        task, transport = execution_task_identity(manifest, profile)
        intent = {
            "schema_version": "bluefire.macos-file-access-reviewed-task.v1",
            "operation": operation,
            "task_id": task,
            "transport_request_hash": transport,
            "context_digest": context["context_digest"],
            "binding_digest": content_hash(context["binding"]),
            "control_revision": context["binding"]["control_revision"],
            "issued_at_ms": state["wall"],
            "expires_at_ms": state["wall"] + 5000,
            "issued_monotonic_ns": state["clock"],
            "deadline_ns": state["clock"] + 5_000_000_000,
        }
        result = {
            "schema_version": "bluefire.macos-file-access-committed-task.v1",
            "intent": intent,
            "claim": {
                "job_id": "job-1",
                "task_id": task,
                "step_id": operation,
                "request_hash": manifest["request_hash"],
                "transport_request_hash": transport,
                "manifest": manifest,
                "runner_profile": profile,
            },
            "preparation_digest": content_hash("prepared"),
            "job_id": "job-1",
            "attempt": None,
            "cancelled": False,
        }
        result["dispatch_digest"] = content_hash(result)
        return result

    def run(frame, operation="dispatch_committed", sequence=1):
        request = {
            "schema_version": "bluefire.macos-workspace-request.v1",
            "sequence": sequence,
            "operation": operation,
            "payload": frame,
        }

        def receive(stream, guard):
            assert stream is owner._stream and not state["received"]
            guard()
            state["received"].append(request)
            return request

        def send(stream, response, guard):
            assert stream is owner._stream
            guard()
            state["replies"].append(response)
            value.close()

        monkeypatch.setattr(workspace, "_receive", receive)
        monkeypatch.setattr(workspace, "_send", send)
        value._run()

    return SimpleNamespace(
        producer=producer, owner=owner, value=value, frame=frame, run=run, state=state
    )


def test_committed_frame_on_original_host_channel_mints_once_and_reserves_pair(original):
    frame = original.frame()
    original.run(frame)
    receipt = original.state["replies"][0]["payload"]
    assert receipt["state"] == "complete" and receipt["operation"] == "baseline"
    assert receipt["task_id"] == frame["intent"]["task_id"]
    assert original.producer._used_budget == 2 and len(original.state["calls"]) == 2
    assert original.state["host_checks"] > 0 and original.state["no_fork_checks"] == 0
    assert (
        receipt["settlement_scope"] == "producer_local_only"
        and not receipt["whole_enrollment_cleanup"]
    )
    with pytest.raises(MacOSFileAccessContractError):
        original.value._reserve_received(frame)


@pytest.mark.parametrize(
    "change", ["task", "transport", "manifest", "profile", "dispatch", "cancelled", "attempt"]
)
def test_changed_committed_provenance_never_reserves_or_dispatches(original, change):
    frame = original.frame()
    if change == "task":
        frame["claim"]["task_id"] = "execute-" + "0" * 64
    elif change == "transport":
        frame["claim"]["transport_request_hash"] = content_hash("other")
    elif change == "manifest":
        frame["claim"]["manifest"]["params"] = {"command": "unavailable"}
    elif change == "profile":
        frame["claim"]["runner_profile"]["extra"] = True
    elif change == "dispatch":
        frame["dispatch_digest"] = content_hash("other")
    elif change == "cancelled":
        frame["cancelled"] = True
    else:
        frame["attempt"] = {"attempt_id": "unwired"}
    if change != "dispatch":
        frame["dispatch_digest"] = content_hash(
            {k: v for k, v in frame.items() if k != "dispatch_digest"}
        )
    original.run(frame)
    assert not original.state["calls"] and not original.state["replies"]
    assert original.producer._used_budget == 0
    assert original.value._lease._poisoned and original.state["controller_closes"] == 1


@pytest.mark.parametrize(
    "failure", ["budget", "expired", "channel_lost", "between_primitives", "primitive_unknown"]
)
def test_original_guard_and_nonrefundable_primitive_reservation(original, monkeypatch, failure):
    frame = original.frame()
    if failure == "budget":
        original.producer._used_budget = creator.MAX_REQUESTS - 1
    elif failure == "expired":
        original.state["clock"] = frame["intent"]["deadline_ns"]
    elif failure == "channel_lost":
        monkeypatch.setattr(
            bridge,
            "select",
            SimpleNamespace(select=lambda *_args: ([original.owner._stream], [], [])),
        )
    elif failure == "between_primitives":
        monkeypatch.setattr(
            bridge,
            "select",
            SimpleNamespace(
                select=lambda *_args: (
                    ([original.owner._stream], [], [])
                    if original.state["calls"] or not original.value._in_task
                    else ([], [], [])
                )
            ),
        )
    else:
        original.state["fail_role"] = "reader"
    original.run(frame)
    if failure in ("primitive_unknown", "between_primitives"):
        assert len(original.state["calls"]) == 1 and original.producer._used_budget == 2
        if failure == "primitive_unknown":
            assert original.state["replies"][0]["payload"]["state"] == "unknown"
        else:
            assert not original.state["replies"] and original.value._lease._poisoned
    else:
        assert not original.state["calls"] and not original.state["replies"]
        assert original.producer._used_budget == (
            creator.MAX_REQUESTS - 1 if failure == "budget" else 0
        )


def test_transport_commits_dispatch_before_endpoint_exchange(original):
    frame = original.frame()
    calls = []

    class Store:
        def begin_macos_file_access_dispatch(self, task, transport, *, now_ms):
            assert (
                task == frame["claim"]["task_id"]
                and transport == frame["claim"]["transport_request_hash"]
            )
            assert now_ms > 0
            calls.append("committed")
            return deepcopy(frame)

    class Endpoint:
        def assert_current(self):
            calls.append("current")

        def dispatch_committed(self, actual, *, cancel_event):
            assert actual == frame and calls[-1] == "committed" and not cancel_event.is_set()
            calls.append("exchange")
            return {"state": "complete", "settlement_scope": "producer_local_only"}

    transport = bridge.MacOSWorkspaceTaskTransport(Endpoint(), Store())
    result = transport.execute_task(
        frame["claim"]["manifest"],
        frame["claim"]["runner_profile"],
        task_id=frame["claim"]["task_id"],
        cancel_event=threading.Event(),
    )
    assert calls == ["current", "committed", "exchange"]
    assert (
        result["status"] == "success" and result["output"]["macos_receipt"]["state"] == "complete"
    )


def test_transport_failed_commit_cannot_reach_endpoint(original):
    frame = original.frame()

    class Store:
        def begin_macos_file_access_dispatch(self, *_args, **_options):
            raise RuntimeError("fake rollback before dispatch commit")

    class Endpoint:
        def assert_current(self):
            pass

        def dispatch_committed(self, *_args, **_options):
            raise AssertionError("uncommitted provenance reached original channel")

    transport = bridge.MacOSWorkspaceTaskTransport(Endpoint(), Store())
    with pytest.raises(RuntimeError, match="rollback"):
        transport.execute_task(
            frame["claim"]["manifest"],
            frame["claim"]["runner_profile"],
            task_id=frame["claim"]["task_id"],
            cancel_event=threading.Event(),
        )


def test_review_document_and_direct_frame_cannot_mint(original):
    frame = original.frame()
    assert bridge._committed(frame) == frame and original.producer._used_budget == 0
    request = {
        "schema_version": "bluefire.macos-workspace-request.v1",
        "sequence": 1,
        "operation": "dispatch_committed",
        "payload": frame,
    }
    with pytest.raises(MacOSFileAccessContractError):
        original.value._received(request)
    original.run({"operation": "baseline"}, operation="review_context")
    assert original.state["replies"][0]["payload"]["operation"] == "baseline"
    assert not original.state["calls"] and original.producer._used_budget == 0


def test_unexpected_original_channel_sequence_cannot_dispatch(original):
    original.run(original.frame(), sequence=2)
    assert not original.state["calls"] and not original.state["replies"]
    assert original.value._lease._poisoned and original.producer._used_budget == 0


def test_cancellation_after_committed_attempt_boundary_cannot_dispatch(original):
    frame = original.frame()
    cancelled = threading.Event()

    class Store:
        def begin_macos_file_access_dispatch(self, *_args, **_options):
            cancelled.set()
            return frame

    class Endpoint:
        def assert_current(self):
            pass

        def dispatch_committed(self, *_args, **_options):
            raise AssertionError("cancelled original task reached the channel")

    transport = bridge.MacOSWorkspaceTaskTransport(Endpoint(), Store())
    with pytest.raises(MacOSFileAccessContractError):
        transport.execute_task(
            frame["claim"]["manifest"],
            frame["claim"]["runner_profile"],
            task_id=frame["claim"]["task_id"],
            cancel_event=cancelled,
        )


@pytest.mark.parametrize("truncated", [False, True])
def test_parent_frame_preserves_slow_chunks_under_original_five_second_bound(
    original, monkeypatch, truncated
):
    frame = original.frame()
    request = {
        "schema_version": "bluefire.macos-workspace-request.v1",
        "sequence": 1,
        "operation": "dispatch_committed",
        "payload": frame,
    }
    encoded = canonical_json_bytes(request)
    raw = bytearray(len(encoded).to_bytes(4, "little") + encoded)
    if truncated:
        raw[:] = raw[:2]
    state = dict(reads=0)
    original_clock = original.state["clock"]

    def receive(size, _ancillary):
        state["reads"] += 1
        original.state["clock"] += 25_000_000
        if state["reads"] <= 4 or not raw:
            raise TimeoutError("fake short socket wait")
        count = min(size, 512, len(raw))
        result = bytes(raw[:count])
        del raw[:count]
        return result, [], 0, ""

    def timeout(seconds):
        assert 0 < seconds <= 0.025

    def send(_stream, response, guard):
        guard()
        original.state["replies"].append(response)
        original.value.close()

    monkeypatch.setattr(original.owner._stream, "recvmsg", receive, raising=False)
    monkeypatch.setattr(original.owner._stream, "settimeout", timeout, raising=False)
    monkeypatch.setattr(workspace, "_send", send)
    original.value._run()
    if truncated:
        assert original.state["clock"] == original_clock + 5_000_000_000
        assert not original.state["calls"] and not original.state["replies"]
        assert original.value._lease._poisoned and original.state["controller_closes"] == 1
    else:
        assert state["reads"] > 4 and original.state["clock"] - original_clock > 25_000_000
        assert original.state["replies"][0]["payload"]["state"] == "complete"
        assert original.producer._used_budget == 2
