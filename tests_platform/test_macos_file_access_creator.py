"""Original creator state with fake namespace/workers/lease, not installed proof."""

import threading
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_creator as creator
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.macos_file_access_peer import MacOSChildConsistency
from bluefire.util import content_hash
from tests_platform.test_macos_file_access_contract import binding, credentials, observation


@pytest.fixture
def fake(monkeypatch):
    state = dict(
        clock=1000,
        wall=1000,
        nonce=0,
        calls=[],
        starts=[],
        settles=[],
        fail_start=None,
        fail_role=None,
        late_role=None,
        releases={},
        namespace_closes=0,
        socket_closes=[],
        fail_socket_close=False,
    )

    class Runtime:
        runner_binary_digest = "sha256:" + "1" * 64
        _watchdog_interpreter_digest = "sha256:" + "2" * 64
        parent_death_script_digest = "sha256:" + "3" * 64

        def _darwin_process_is_indeterminate(self, _process):
            return False

        def _refresh_darwin_no_fork_proof(self, _process):
            return True

    class Socket:
        family = 1

        def fileno(self):
            return 50

        def getsockopt(self, *_args):
            return 1

        def getpeername(self):
            return ""

        def set_inheritable(self, _value):
            pass

        def close(self):
            state["socket_closes"].append(self)
            if state["fail_socket_close"]:
                raise OSError("fake close invalidated its handle then failed")

    class Namespace:
        latest = None

        @classmethod
        def create(cls, *, owner, reader, retained):
            value = cls()
            value.source = binding()
            value.source.update(owner=owner, reader=reader)
            value.mode = "0640"
            value.active = False
            value.unknown = False
            cls.latest = value
            retained.append(value)
            return value

        def assert_current(self):
            if self.unknown or state["clock"] >= self.source["original_deadline_ns"]:
                raise MacOSFileAccessContractError("fake namespace unavailable")

        def binding(self, *, custody_digest, revision):
            self.assert_current()
            result = deepcopy(self.source)
            result.update(custody_digest=custody_digest, control_revision=revision, mode=self.mode)
            return result

        @contextmanager
        def operation(self):
            self.assert_current()
            assert not self.active
            self.active = True
            try:
                yield
            except BaseException:
                self.unknown = True
                raise
            finally:
                self.active = False

        def descriptor(self, role):
            return 13 if role == "control" else 11

        def close_handles(self):
            state["namespace_closes"] += 1
            return True

    class Worker:
        def __init__(self, _runtime, _binding, *, role, **_options):
            self.role = role

        def start(self):
            state["starts"].append(self.role)
            if state["fail_start"] == self.role:
                raise OSError("fake partial worker")

        def exchange(self, original):
            assert Namespace.latest.active
            state["calls"].append((self.role, original))
            if state["fail_role"] == self.role:
                raise OSError("fake uncertain exchange")
            result = observation(original)
            if self.role != "reader":
                result["principal"] = original["binding"]["owner"]
            result["fresh_read"]["mode"] = original["binding"]["mode"]
            if self.role == "reader" and original["binding"]["mode"] == "0600":
                result.update(
                    outcome="denied", fresh_read=None, request_handle_cleanup="not_opened"
                )
            if self.role == "control":
                target = "0600" if original["operation"] == "harden" else "0640"
                Namespace.latest.mode = target
                resource = original["binding"]["resource"]
                result.update(
                    outcome="mode_changed",
                    fresh_read=None,
                    request_handle_cleanup="not_opened",
                    held_control={
                        **{
                            key: resource[key]
                            for key in ("device", "inode", "size_bytes", "record_count", "sha256")
                        },
                        "before_mode": original["binding"]["mode"],
                        "after_mode": target,
                    },
                )
            if state["late_role"] == self.role:
                state["clock"] = original["deadline_ns"]
            return result

        def settle(self):
            state["settles"].append(self.role)
            return state["releases"].get(self.role, True)

    def token(_size):
        state["nonce"] += 1
        return f"{state['nonce']:064x}"

    active = {}
    monkeypatch.setattr(
        creator,
        "runner",
        SimpleNamespace(
            SubprocessRustRunner=Runtime,
            _DARWIN_INDETERMINATE_LOCK=threading.RLock(),
            _DARWIN_ACTIVE_PROCESSES=active,
        ),
    )
    monkeypatch.setattr(
        creator,
        "socket",
        SimpleNamespace(
            socket=Socket,
            AF_UNIX=1,
            SOCK_STREAM=1,
            SOL_SOCKET=1,
            SO_TYPE=1,
            socketpair=lambda *_args: (Socket(), Socket()),
        ),
    )
    monkeypatch.setattr(creator, "os", SimpleNamespace(getpid=lambda: 101))
    monkeypatch.setattr(creator, "time", SimpleNamespace(time_ns=lambda: state["wall"] * 1000000))
    monkeypatch.setattr(creator, "secrets", SimpleNamespace(token_hex=token))
    monkeypatch.setattr(creator, "darwin_clock_ns", lambda: state["clock"])
    monkeypatch.setattr(creator, "SealedMacOSNamespace", Namespace)
    monkeypatch.setattr(creator, "MacOSFileAccessWorker", Worker)
    monkeypatch.setattr(
        creator,
        "observe_owned_child",
        lambda *_args, **_kwargs: MacOSChildConsistency(
            103, 101, (100, 1), (501, 501, 501, 501, 501, 501)
        ),
    )
    runtime = Runtime()

    def create():
        retained = []
        value = creator.MacOSFileAccessCreator.create(
            runtime, owner=credentials(501), reader=credentials(502), retained=retained
        )
        assert retained == [value]
        return value

    def lease(value):
        # Deliberate fake producer construction, never a production minter.
        result = object.__new__(creator.OriginalMacOSControllerLease)
        process = object()
        active[process] = runtime
        result._creator, result._runtime, result._channel = value, runtime, Socket()
        result._workspace_process = process
        result._workspace_consistency = MacOSChildConsistency(
            103, 101, (100, 1), (501, 501, 501, 501, 501, 501)
        )
        result._closed = result._poisoned = False
        value._lease = result
        return result

    def reserve(value, operation):
        context = value.review_context(operation)
        state["nonce"] += 1
        digest = "sha256:" + f"{state['nonce']:064x}"
        original = creator.ReviewedMacOSTaskIntent.from_document(
            dict(
                schema_version="bluefire.macos-file-access-reviewed-task.v1",
                operation=operation,
                task_id="execute-" + digest[7:],
                transport_request_hash=digest,
                context_digest=context["context_digest"],
                binding_digest=content_hash(context["binding"]),
                control_revision=context["binding"]["control_revision"],
                issued_at_ms=state["wall"],
                expires_at_ms=state["wall"] + 5000,
                issued_monotonic_ns=state["clock"],
                deadline_ns=state["clock"] + 5000000000,
            )
        )
        result = object.__new__(creator.OriginalMacOSTaskReservation)
        result._creator, result._lease, result._intent = value, value._lease, original
        result._used = False
        return result

    return create, lease, reserve, state


def test_explicit_setup_retains_three_workers_but_has_no_public_effect_minter(fake):
    create, _lease, _reserve, state = fake
    value = create()
    assert state["starts"] == ["reader", "owner", "control"]
    assert not state["calls"] and value._lease is None
    for cls in (
        creator.MacOSFileAccessCreator,
        creator.OriginalMacOSControllerLease,
        creator.OriginalMacOSTaskReservation,
        creator.OwnedMacOSTaskReceipt,
    ):
        with pytest.raises(TypeError):
            cls({"self_asserted": True})


def test_complete_lifecycle_has_fresh_paired_reads_same_generation_and_retained_workers(fake):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    receipts = []
    for operation in ("baseline", "harden", "probe", "verify_owner", "rollback"):
        reservation = reserve(value, operation)
        receipt = getattr(value, "_" + operation)(reservation)
        assert type(receipt) is creator.OwnedMacOSTaskReceipt
        assert receipt.document()["state"] == "complete" and reservation._used
        assert receipt.document()["whole_enrollment_cleanup"] is False
        assert receipt.document()["settlement_scope"] == "producer_local_only"
        assert "task_usage" not in receipt.document()
        receipts.append(receipt.document())
    assert value._state == "rolled_back" and value._revision == 4
    assert value._used_budget == 8 and not state["settles"]
    assert [role for role, _request in state["calls"]] == [
        "reader",
        "owner",
        "control",
        "reader",
        "owner",
        "control",
        "reader",
        "owner",
    ]
    assert {row["binding"]["generation"] for _role, row in state["calls"]} == {
        binding()["generation"]
    }
    assert receipts[2]["terminals"][0]["outcome"] == "denied"
    assert receipts[3]["terminals"][0]["fresh_read"] is not None
    assert receipts[3]["terminals"][0]["held_control"] is None
    assert all(
        row["binding"]["original_deadline_ns"] == binding()["original_deadline_ns"]
        for _role, row in state["calls"]
    )


def test_inactive_intent_and_unattached_lease_never_authorize_bytes(fake):
    create, _lease, reserve, state = fake
    value = create()
    original = reserve(value, "baseline")
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original._intent)
    assert not state["calls"] and not original._used


@pytest.mark.parametrize("operation,remaining", [("baseline", 1), ("rollback", 2)])
def test_whole_primitive_count_reserved_before_first_bytes(fake, operation, remaining):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    if operation == "rollback":
        value._baseline(reserve(value, "baseline"))
        value._harden(reserve(value, "harden"))
    before = len(state["calls"])
    value._used_budget = 64 - remaining
    original = reserve(value, operation)
    with pytest.raises(MacOSFileAccessContractError):
        getattr(value, "_" + operation)(original)
    assert len(state["calls"]) == before and not original._used
    assert not value._namespace.unknown


def test_replay_same_opaque_reservation_or_same_task_identity_never_starts_again(fake):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    value._baseline(original)
    before = len(state["calls"])
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    assert len(state["calls"]) == before
    assert value.retained_task_receipt(original._intent.document()["task_id"]) is not None


@pytest.mark.parametrize("field", ["context_digest", "binding_digest", "control_revision"])
def test_stale_review_refuses_without_poisoning_namespace_or_dispatch(fake, field):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    original._intent._document[field] = 2 if field == "control_revision" else "sha256:" + "0" * 64
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    assert not state["calls"] and not original._used and not value._namespace.unknown


@pytest.mark.parametrize("failure", ["exchange", "late"])
def test_post_dispatch_ambiguity_spends_pair_budget_and_retains_unknown_without_retry(
    fake, failure
):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    state["fail_role" if failure == "exchange" else "late_role"] = "reader"
    receipt = value._baseline(original)
    assert (
        receipt.document()["state"] == "unknown"
        and receipt.document()["producer_request_usage"] == "unknown"
    )
    assert value._used_budget == 2 and len(state["calls"]) == 1 and original._used
    assert value._state == "unknown"
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    assert len(state["calls"]) == 1


def test_original_expiry_equality_never_renews_or_consumes(fake):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    state["clock"] = original._intent.document()["deadline_ns"]
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    assert not state["calls"] and not original._used


def test_late_receipt_serialization_replaces_complete_with_retained_unknown(fake, monkeypatch):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    receipt = value._receipt

    def delayed(*args):
        result = receipt(*args)
        if result.document()["state"] == "complete":
            state["clock"] = original._intent.document()["deadline_ns"]
        return result

    monkeypatch.setattr(value, "_receipt", delayed)
    result = value._baseline(original)
    assert result.document()["state"] == "unknown"
    assert result.document()["producer_request_usage"] == "unknown"
    assert value.retained_task_receipt(original._intent.document()["task_id"]) is result
    assert value._state == "unknown" and len(state["calls"]) == 2


@pytest.mark.parametrize("failure", ["raises", "oversizes"])
def test_late_final_guard_and_failed_unknown_serialization_never_retain_success(
    fake, monkeypatch, failure
):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    canonical = creator.canonical_json_bytes
    serialized_states = []

    def serialization(document):
        if document.get("schema_version") != "bluefire.macos-file-access-task-receipt.v1":
            return canonical(document)
        serialized_states.append(document["state"])
        if document["state"] == "complete":
            result = canonical(document)
            state["clock"] = original._intent.document()["deadline_ns"]
            return result
        if failure == "raises":
            raise RuntimeError("fake unknown receipt serialization failed")
        return b" " * (creator.MAX_MESSAGE + 1)

    monkeypatch.setattr(creator, "canonical_json_bytes", serialization)
    expected = RuntimeError if failure == "raises" else MacOSFileAccessContractError
    with pytest.raises(expected):
        value._baseline(original)
    task_id = original._intent.document()["task_id"]
    assert serialized_states == ["complete", "unknown"]
    assert value.retained_task_receipt(task_id) is None
    assert task_id in value._tasks and value._state == "unknown"
    assert original._used and value._used_budget == 2 and len(state["calls"]) == 2
    with pytest.raises(MacOSFileAccessContractError):
        value._baseline(original)
    assert len(state["calls"]) == 2 and value.retained_task_receipt(task_id) is None


def test_owner_verification_requires_original_completed_probe_dependency(fake):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    value._baseline(reserve(value, "baseline"))
    value._harden(reserve(value, "harden"))
    before = len(state["calls"])
    original = reserve(value, "verify_owner")
    with pytest.raises(MacOSFileAccessContractError):
        value._verify_owner(original)
    assert len(state["calls"]) == before and not original._used


def test_retirement_attempts_all_workers_and_never_asserts_fixture_removal_or_reset(fake):
    create, lease, _reserve, state = fake
    value = create()
    lease(value)
    state["releases"]["reader"] = False
    report = value.close()
    assert state["settles"] == ["reader", "owner", "control"]
    assert not report["workers_closed"] and state["namespace_closes"] == 0
    state["releases"]["reader"] = True
    report = value.close()
    assert report["workers_closed"] and report["namespace_handles_closed"]
    assert (
        report["settled"] is False
        and report["fixture_removed"] is False
        and report["live_ready"] is False
    )
    assert not state["calls"]
    with pytest.raises(MacOSFileAccessContractError):
        value.reset()


def test_partial_setup_retains_owner_before_worker_creation_failure(fake):
    _create, _lease, _reserve, state = fake
    runtime = creator.runner.SubprocessRustRunner()
    retained = []
    state["fail_start"] = "owner"
    with pytest.raises(OSError):
        creator.MacOSFileAccessCreator.create(
            runtime, owner=credentials(501), reader=credentials(502), retained=retained
        )
    assert len(retained) == 1 and retained[0]._state == "unknown"
    assert list(retained[0]._workers) == ["reader", "owner"]
    assert retained[0]._namespaces
    assert state["starts"] == ["reader", "owner"]
    with pytest.raises(MacOSFileAccessContractError):
        creator.MacOSFileAccessCreator.create(
            runtime, owner=credentials(501), reader=credentials(502), retained=retained
        )


def test_operation_lock_cannot_queue_or_mutate_namespace(fake):
    create, lease, reserve, state = fake
    value = create()
    lease(value)
    original = reserve(value, "baseline")
    value._lock.acquire()
    try:
        with pytest.raises(MacOSFileAccessContractError):
            value._baseline(original)
    finally:
        value._lock.release()
    assert not state["calls"] and not original._used


def test_reentrant_retirement_after_retained_append_cannot_close_or_revive_setup(fake, monkeypatch):
    _create, _lease, _reserve, state = fake
    retained = []
    namespace_create = creator.SealedMacOSNamespace.create
    seen = []

    def create_namespace(**options):
        assert len(retained) == 1 and retained[0]._state == "creating"
        with pytest.raises(MacOSFileAccessContractError):
            retained[0].close()
        seen.append(retained[0])
        assert retained[0]._state == "creating" and not state["settles"]
        return namespace_create(**options)

    monkeypatch.setattr(creator.SealedMacOSNamespace, "create", create_namespace)
    value = creator.MacOSFileAccessCreator.create(
        creator.runner.SubprocessRustRunner(),
        owner=credentials(501),
        reader=credentials(502),
        retained=retained,
    )
    assert seen == [value] and value._state == "created"
    assert state["starts"] == ["reader", "owner", "control"]
    assert not state["socket_closes"] and state["namespace_closes"] == 0


@pytest.mark.parametrize("close_fails", [False, True])
def test_orphan_socket_close_is_attempted_once_even_when_handle_invalidates_then_raises(
    fake, monkeypatch, close_fails
):
    _create, _lease, _reserve, state = fake
    retained = []

    def fail_worker(*_args, **_options):
        raise OSError("fake constructor before worker owns sockets")

    monkeypatch.setattr(creator, "MacOSFileAccessWorker", fail_worker)
    with pytest.raises(OSError):
        creator.MacOSFileAccessCreator.create(
            creator.runner.SubprocessRustRunner(),
            owner=credentials(501),
            reader=credentials(502),
            retained=retained,
        )
    value = retained[0]
    assert not value._workers and len(value._sockets) == 1
    state["fail_socket_close"] = close_fails
    first = value.close()
    assert len(state["socket_closes"]) == 2
    state["fail_socket_close"] = False
    second = value.close()
    assert len(state["socket_closes"]) == 2
    assert first["namespace_handles_closed"] is (not close_fails)
    assert second["namespace_handles_closed"] is (not close_fails)
    assert first["settled"] is second["settled"] is False
