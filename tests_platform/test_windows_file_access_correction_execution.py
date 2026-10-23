"""Private runtime with real SQLite authority and exact fake native producers.

Synthetic closure/postimage producers replace OS boundaries only. Reservation,
baseline joins, dispatch, Ready consumption, wire checks and publication are real.
"""

from __future__ import annotations

import io
import shutil
import threading
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_correction_execution as module
from bluefire import windows_file_access_correction_observation as observation
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_correction_wire as wire_fake
from tests_platform import test_windows_file_access_process as process_fake
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_control_process import terminal
from tests_platform.test_windows_file_access_correction_reservation import reserve
from tests_platform.test_windows_file_access_correction_reservation import reviewed as reviewed
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def _fake_control_receipt(binding, result):
    """A fake supervisor producer, never reconstruction from persisted JSON."""
    row = {
        "schema_version": module.control_process.RECEIPT_SCHEMA,
        "binding_digest": content_hash(binding),
        "dispatch": "attempted" if result is not None else "unknown",
        "process_cleanup": "verified",
        "terminal": {
            "schema_version": module.control_process.entry.RESULT_SCHEMA,
            "binding_digest": content_hash(binding),
            "result": result,
        },
        "settled": False,
    }
    module.control_process.validate_retained_control_receipt(row, binding)
    receipt = object.__new__(module.control_process.OwnedCorrectionControlReceipt)
    object.__setattr__(receipt, "_raw", canonical_json_bytes(row))
    object.__setattr__(receipt, "_binding", canonical_json_bytes(binding))
    return receipt


@pytest.fixture
def execution(reviewed, paired, monkeypatch):
    value = reviewed
    store = value.store
    job, created = reserve(value)
    assert created
    job_id = job["job_id"]
    checked_setup = paired[1]
    state = SimpleNamespace(
        wall=ISSUED + 2501,
        mono=100.0,
        fault=None,
        preimages=[],
        controls=[],
        postimages=[],
        producers=[],
        launches=[],
        buffers=[],
        control_owner=None,
        retest_owner=None,
        checked_postimage=None,
        remote_client=None,
        phases=[],
    )
    control = SimpleNamespace(
        store=store, service=SimpleNamespace(product_store=store), clock=lambda: state.wall
    )
    runtime = module.WindowsCorrectionRuntime(control)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: state.mono))
    monkeypatch.setattr(module.context, "time", SimpleNamespace(monotonic=lambda: state.mono))
    monkeypatch.setattr(runtime, "_clock", lambda: at_ms(state.wall))
    monkeypatch.setattr(process_fake.module, "_utc", lambda: at_ms(state.wall))
    monkeypatch.setattr(process_fake.module, "_monotonic", lambda: state.mono)

    def read_setup(*, now_ms):
        assert now_ms == state.wall
        return checked_setup

    def preimage(checked, **kwargs):
        assert checked is checked_setup and kwargs["now_ms"] == state.wall
        state.preimages.append(kwargs)
        if state.fault == "preimage":
            raise observation.WindowsCorrectionObservationError("synthetic preimage refusal")
        return value.original["review_context"]["previous_descriptor_sha256"]

    class ControlOwner:
        def __init__(self, receipt):
            self.cleanup_receipt = receipt
            self.calls = 0

        def retry_cleanup(self):
            self.calls += 1
            if state.fault == "control_cleanup_raises":
                raise RuntimeError("synthetic control cleanup refusal")
            return state.fault != "control_cleanup"

    def run_control(checked, binding_bytes, **kwargs):
        assert checked is checked_setup
        binding = module.admission.validate_correction_binding(binding_bytes, checked)
        state.controls.append(kwargs)
        assert module.journal.has_dispatch(store, job_id)
        assert store.file_access_operation_records(job_id)["tasks"] == []
        if state.fault == "after_dispatch":
            raise ProductStoreError("synthetic failure before child release")
        kwargs["before_dispatch"]()
        result = None if state.fault == "negative_control" else terminal(binding)["result"]
        owner = ControlOwner(_fake_control_receipt(binding, result))
        state.control_owner = owner
        kwargs["retain_cleanup_owner"](owner)
        state.wall += 500
        state.mono += 0.5
        return SimpleNamespace(
            process_cleanup="unknown" if state.fault == "control_cleanup" else "verified"
        )

    def postimage(value_input, **kwargs):
        state.postimages.append(kwargs)
        assert value_input.checked_setup is checked_setup
        records = store.file_access_operation_records(job_id)
        assert value_input.binding_bytes == canonical_json_bytes(records["preparation"]["binding"])
        assert set(module.journal.control_evidence(store, job_id)) == {"dispatch", "closure"}
        if state.fault == "postimage":
            raise observation.WindowsCorrectionObservationError("synthetic postimage refusal")
        checked = object.__new__(observation.VerifiedWindowsCorrectionPostimage)
        fields = {
            "_setup": checked_setup,
            "_raw": checked_setup._raw,
            "_receipt": checked_setup._receipt,
            "_binding": value_input.binding_bytes,
            "_descriptor_sha256": (
                "sha256:" + "9" * 64
                if state.fault == "postimage_descriptor"
                else value_input.target_descriptor_sha256
            ),
        }
        for key, item in fields.items():
            object.__setattr__(checked, key, item)
        observation.checked_provenance(checked)
        state.checked_postimage = checked
        return checked

    class Begin:
        """Fake secret boundary still requires the actual committed Ready allowance."""

        credential_cleanup = "verified"

        def __init__(self, checked, original, packet, **kwargs):
            observation.checked_provenance(checked)
            self.original, self.packet, self.callbacks = original, packet, kwargs
            self.consumed = False
            state.producers.append(self)

        def __call__(self, prefix):
            assert not self.consumed
            self.consumed = True
            assert prefix == module.wire.correction_begin_prefix(
                self.packet, clock=at_ms(state.wall), monotonic_now=state.mono
            )
            self.callbacks["revalidate_original"]()
            self.callbacks["require_ready_allowance"]()
            original = module.wire._reservation(self.original, module.wire._CORRECTION)
            trail = module.native.query(
                store,
                original["task_id"],
                original["transport_request_hash"],
                module.wire._document(self.original._expected),
                at_ms(state.wall),
                _protocol=module.native._Protocol.CORRECTION_V3,
            )
            assert trail.ready_bytes is not None and trail.terminal_bytes is None
            private = bytearray(process_fake.framed(prefix + b"\x01\0A\0"))
            state.buffers.append(private)
            return private

    class RetestOwner(module.CorrectionLaunchOwner):
        def __init__(self, original):
            self.original, self.inner, self.result = original, None, None
            self.calls = 0

        def retry_cleanup(self):
            self.calls += 1
            assert self.inner is not None
            return self.inner.retry_cleanup()

        def outcome(self, clean):
            assert clean and self.inner.verified and self.result is not None
            result = replace(
                self.result,
                cleanup="verified",
                cleanup_owner=None,
                cleanup_receipt=self.inner.cleanup_receipt,
            )
            return SimpleNamespace(process=result)

    def launch(checked, original, packet, producer, **kwargs):
        observation.checked_provenance(checked)
        state.launches.append(packet)
        retained = module.wire.validate_correction_retained_packet(original, packet._raw)
        ready, proof = wire_fake.envelopes(
            retained, reader="allowed" if state.fault == "allowed_reader" else "data_access_denied"
        )
        resource = module.wire._reservation(original, module.wire._CORRECTION)["manifest"][
            "params"
        ]["windows_file_read_request"]["resource"]
        for phase in ("reader", "owner"):
            if proof["result"][phase]["outcome"] == "allowed":
                proof["result"][phase].update(
                    bytes_read=resource["size_bytes"], observed_sha256=resource["sha256"]
                )
        proof["observed_at"] = (
            at_ms(state.wall + 1000).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
        process = process_fake.Process(canonical_json_bytes(ready), canonical_json_bytes(proof))
        containment = process_fake.Containment()
        containment.finish_failure = state.fault == "retest_cleanup"
        owner = RetestOwner(original)
        owner.process, owner.containment = process, containment
        state.retest_owner = owner
        kwargs["retain_launch_owner"](owner)

        state.wall += 1000
        state.mono += 1.0

        result = process_fake.module.supervise_correction_suspended(
            process,
            owned_job=5001,
            containment=containment,
            prepared_packet=packet,
            original_reservation=original,
            revalidate_original=kwargs["revalidate_original"],
            begin_producer=producer,
            cancellation_event=kwargs["cancellation_event"],
            evidence_sink=kwargs["evidence_sink"],
            retain_cleanup_owner=lambda inner: setattr(owner, "inner", inner),
        )
        owner.result = result
        return SimpleNamespace(cleanup=result.cleanup)

    monkeypatch.setattr(module.context, "read_windows_file_setup_status", read_setup)
    monkeypatch.setattr(observation, "observe_correction_preimage", preimage)
    monkeypatch.setattr(module.control_process, "run_correction_control_process", run_control)
    monkeypatch.setattr(observation, "observe_correction_postimage", postimage)
    monkeypatch.setattr(
        module.managed_session,
        "time",
        SimpleNamespace(
            monotonic=lambda: state.mono,
            time_ns=lambda: state.wall * 1_000_000,
        ),
    )

    class ManagedClient:
        def __init__(self):
            self.descriptor = None
            self.ready = None
            self.terminal = None
            self.returncode = None
            self.consume_receipt = None
            self.result = None

        def transport_identity(self):
            return module.wire._document(checked_setup._receipt)["source"]["transport"]

        def _close_result(self):
            owner = state.retest_owner
            if owner is None or not owner.retry_cleanup():
                return None
            process = owner.outcome(True).process
            if (
                process is None
                or process.cleanup_receipt is None
                or self.ready is None
                or self.terminal is None
                or self.returncode is None
                or self.consume_receipt is None
                or self.descriptor is None
            ):
                return None
            managed = module.managed_result.build_managed_result(
                self.descriptor,
                ready=self.ready,
                terminal=self.terminal,
                actual_returncode=self.returncode,
                persisted_consume_receipt=self.consume_receipt,
                cleanup_receipt=process.cleanup_receipt._raw,
            )
            self.result = module.managed_result.build_runner_result(
                self.descriptor,
                managed,
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
            )
            return self.result

        def execute_windows_correction_session(
            self, manifest, profile, descriptor_value, *, cancel_event, ready_consumer
        ):
            self.descriptor = module.managed_session.validate_descriptor(
                descriptor_value, manifest, profile
            )
            _observation_input, original, packet = module.managed_session.correction_inputs(
                self.descriptor
            )
            acknowledged = False

            def require_ready():
                assert acknowledged

            def evidence(stage, raw, returncode, _clock):
                nonlocal acknowledged
                if stage == "packet":
                    assert raw == self.descriptor.packet and returncode is None
                elif stage == "ready":
                    ack_nonce = "a" * 64
                    identity = {
                        "task_id": self.descriptor.value["task_id"],
                        "transport_request_hash": self.descriptor.value[
                            "transport_request_hash"
                        ],
                        "session_nonce": self.descriptor.value["session_nonce"],
                        "packet_digest": self.descriptor.packet_digest,
                        "ready_digest": content_hash(module.wire._document(raw)),
                        "ack_nonce": ack_nonce,
                    }
                    persisted = ready_consumer(self.descriptor.packet, raw, identity)
                    consume_receipt = module.managed_session.callback_consume_receipt(
                        persisted,
                        self.descriptor,
                        ready_digest=identity["ready_digest"],
                        ack_nonce=ack_nonce,
                    )
                    self.consume_receipt = consume_receipt
                    self.ready = raw
                    if state.fault == "after_ready":
                        raise ProductStoreError(
                            "synthetic failure after durable Ready consumption"
                        )
                    acknowledged = True
                elif stage == "terminal":
                    assert acknowledged
                    self.terminal, self.returncode = raw, returncode
                else:
                    raise AssertionError("unexpected correction evidence stage")

            checked = state.checked_postimage
            assert checked is not None
            producer = Begin(
                checked,
                original,
                packet,
                revalidate_original=lambda: module.managed_session.validate_descriptor(
                    self.descriptor.value, manifest, profile
                ),
                require_ready_allowance=require_ready,
                cancellation_event=cancel_event,
            )
            launched = launch(
                checked,
                original,
                packet,
                producer,
                revalidate_original=lambda: module.managed_session.validate_descriptor(
                    self.descriptor.value, manifest, profile
                ),
                evidence_sink=evidence,
                cancellation_event=cancel_event,
                retain_launch_owner=lambda _owner: None,
            )
            if launched.cleanup != "verified" or self._close_result() is None:
                raise ProductStoreError("synthetic managed correction remains active")
            return self.result

        def recover(self, task_id, request_hash):
            if (
                self.descriptor is None
                or task_id != self.descriptor.value["task_id"]
                or request_hash != self.descriptor.value["transport_request_hash"]
            ):
                return {"state": "not_found", "result": None}
            result = self.result or self._close_result()
            return {
                "state": "completed" if result is not None else "indeterminate",
                "result": result,
            }

    client = ManagedClient()
    state.remote_client = client
    source = module.wire._document(checked_setup._receipt)["source"]
    control.service.runner_lifecycle = SimpleNamespace(
        client_for_profile=lambda profile_id: (
            client,
            None,
        )
        if profile_id == source["source_profile_id"]
        else pytest.fail("unexpected correction profile")
    )
    ctx = SimpleNamespace(
        job_id=job_id, cancellation_event=threading.Event(), checkpoint=state.phases.append
    )
    request = {**value.original["submitted_request"], "review": value.original["review"]}
    return SimpleNamespace(
        value=value,
        store=store,
        job=job_id,
        control=control,
        runtime=runtime,
        state=state,
        ctx=ctx,
        request=request,
        monkeypatch=monkeypatch,
    )


def _records(value):
    return value.store.file_access_operation_records(value.job)


def _revision_count(value):
    with value.store._connection() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM file_access_revisions WHERE job_id=?", (value.job,)
        ).fetchone()[0]


def _abort(value, name):
    statements = {
        "control": "CREATE TRIGGER synthetic_control_failure BEFORE INSERT ON file_access_windows_control_evidence WHEN NEW.stage='closure' BEGIN SELECT RAISE(ABORT, 'synthetic control persistence'); END",
        "dispatch": "CREATE TRIGGER synthetic_dispatch_failure BEFORE INSERT ON file_access_windows_control_evidence WHEN NEW.stage='dispatch' BEGIN SELECT RAISE(ABORT, 'synthetic dispatch persistence'); END",
        "retest": "CREATE TRIGGER synthetic_retest_failure BEFORE INSERT ON file_access_owned_process_closures BEGIN SELECT RAISE(ABORT, 'synthetic retest persistence'); END",
        "publication": "CREATE TRIGGER synthetic_publication_failure BEFORE INSERT ON file_access_outcomes WHEN json_extract(NEW.document_json,'$.state')='complete' BEGIN SELECT RAISE(ABORT, 'synthetic publication persistence'); END",
    }
    with value.store._connection(write=True) as connection:
        connection.execute(statements[name])


def _forbid_new_work(value):
    def forbidden(*args, **kwargs):
        pytest.fail("Recovery must not observe, decrypt, prepare or launch new work")

    value.monkeypatch.setattr(module.context, "read_windows_file_setup_status", forbidden)
    value.monkeypatch.setattr(observation, "observe_correction_preimage", forbidden)
    value.monkeypatch.setattr(observation, "observe_correction_postimage", forbidden)
    value.monkeypatch.setattr(module.control_process, "run_correction_control_process", forbidden)
    value.monkeypatch.setattr(module.wire, "prepare_correction_packet", forbidden)


def test_private_runtime_publishes_one_hardened_revision_from_both_closed_phases(execution):
    v = execution
    v.runtime.execute(v.ctx, v.request)
    rows = _records(v)
    assert rows["outcome"]["state"] == "complete" and len(rows["tasks"]) == 1
    assert _revision_count(v) == 1
    control = v.store.get_file_access_control(rows["control_owner_id"])["document"]
    assert control["status"] == "hardened" and control["revision"] == 3
    assert control["baseline"] == v.value.prior["baseline"]
    assert control["resource"]["state"] == "metadata_only"
    assert control["correction"]["owned_control_cleanup"] == "verified"
    assert (
        control["retest"]["non_owner"] == "data_access_denied"
        and control["retest"]["owner"] == "allowed"
    )
    assert (
        control["retest"]["native_cleanup"] == control["retest"]["owned_job_cleanup"] == "verified"
    )
    assert not control["retest"]["independent_observation"]
    assert set(module.journal.control_evidence(v.store, v.job)) == {"dispatch", "closure"}
    assert (
        len(v.state.controls)
        == len(v.state.postimages)
        == len(v.state.producers)
        == len(v.state.launches)
        == 1
    )
    assert v.state.buffers and all(not any(buffer) for buffer in v.state.buffers)
    assert v.job not in v.runtime._control_owners and v.job not in v.runtime._retest_owners
    assert v.state.retest_owner.process._handle.closed
    assert all(
        getattr(v.state.retest_owner.process, name).closed for name in ("stdin", "stdout", "stderr")
    )


@pytest.mark.parametrize("failure", ["preimage", "dispatch"])
def test_failure_before_dispatch_lock_has_no_effect_or_native_task(execution, failure):
    v = execution
    if failure == "preimage":
        v.state.fault = "preimage"
    else:
        _abort(v, "dispatch")
    with pytest.raises((ProductStoreError, observation.WindowsCorrectionObservationError)):
        v.runtime.execute(v.ctx, v.request)
    assert not module.journal.has_dispatch(v.store, v.job)
    assert _records(v)["outcome"]["state"] == "refused_no_effect"
    assert _records(v)["tasks"] == [] and _revision_count(v) == 0
    assert v.state.controls == v.state.postimages == v.state.producers == v.state.launches == []


def test_failure_after_durable_dispatch_stays_unknown_with_zero_tasks_and_cannot_replay(execution):
    v = execution
    v.state.fault = "after_dispatch"
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)
    before = _records(v)
    assert before["outcome"]["state"] == "unknown" and before["tasks"] == []
    assert set(module.journal.control_evidence(v.store, v.job)) == {"dispatch"}
    assert _revision_count(v) == 0
    reopened = ProductStore(v.store.path)
    v.runtime.store = reopened
    v.state.fault = None
    with pytest.raises(ProductStoreError, match="only be reconciled"):
        v.runtime.execute(v.ctx, v.request)
    assert reopened.file_access_operation_records(v.job) == before
    assert len(v.state.controls) == 1 and v.state.launches == []


@pytest.mark.parametrize("fault", ["negative_control", "postimage", "postimage_descriptor"])
def test_nonpositive_effect_or_postimage_never_authorizes_a_retest(execution, fault):
    v = execution
    v.state.fault = fault
    with pytest.raises(
        (
            ProductStoreError,
            observation.WindowsCorrectionObservationError,
            module.wire.NativeWireError,
        )
    ):
        v.runtime.execute(v.ctx, v.request)
    assert _records(v)["outcome"]["state"] == "unknown" and _records(v)["tasks"] == []
    assert _revision_count(v) == 0
    assert v.state.producers == v.state.launches == []
    assert set(module.journal.control_evidence(v.store, v.job)) == {"dispatch", "closure"}


def test_original_expiry_and_bounded_local_deadline_pass_without_renewal(execution):
    v = execution
    v.runtime.execute(v.ctx, v.request)
    prepared = _records(v)["preparation"]
    deadline = 100.0 + (prepared["expires_at_ms"] - prepared["issued_at_ms"]) / 1000
    assert v.state.controls[0]["original_monotonic_deadline"] == pytest.approx(deadline)
    assert v.state.postimages[0]["deadline"] == pytest.approx(deadline)
    launch = v.state.launches[0]
    assert 100.0 < launch._deadline == launch._original_deadline <= deadline
    descriptor = v.state.remote_client.descriptor
    assert descriptor is not None
    assert "packet_deadline" not in descriptor.value
    assert "original_monotonic_deadline" not in descriptor.value
    packet = module.wire._document(descriptor.packet)
    assert launch._deadline == pytest.approx(descriptor.packet_deadline)
    assert deadline - 0.01 <= launch._deadline <= deadline
    assert 0 < packet["remaining_ms"] <= 5_000
    manifest = _records(v)["tasks"][0]["task"]["manifest"]
    assert module.wire._time(manifest["expires_at"]) <= at_ms(prepared["expires_at_ms"])
    assert prepared["expires_at_ms"] == v.value.original["review"]["expires_at_ms"]
    assert prepared["expires_at_ms"] <= v.value.saved["imported"]["enrollment"]["expires_at_ms"]


def test_ready_consume_is_one_durable_row_and_cannot_be_rebound(execution):
    v = execution
    v.state.fault = "after_ready"
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)

    descriptor = v.state.remote_client.descriptor
    ready = v.state.remote_client.ready
    receipt = v.state.remote_client.consume_receipt
    assert descriptor is not None and ready is not None and receipt is not None
    with v.store._connection() as connection:
        rows = connection.execute(
            "SELECT stage,document_json FROM file_access_task_evidence WHERE task_id=? "
            "ORDER BY stage",
            (descriptor.value["task_id"],),
        ).fetchall()
    assert [row["stage"] for row in rows] == ["managed_ready_consume", "packet", "ready"]

    identity = {
        "store": v.store,
        "task_id": descriptor.value["task_id"],
        "transport_hash": descriptor.value["transport_request_hash"],
        "expected_binding": descriptor.value["expected_binding"],
        "session_nonce": descriptor.value["session_nonce"],
        "ack_nonce": receipt["ack_nonce"],
        "packet": descriptor.packet,
        "ready": ready,
        "clock": v.runtime._clock(),
    }
    repeated = module.managed_ready_store.persisted_managed_correction_ready(**identity)
    assert repeated.document() == receipt
    checked = module.managed_ready_store.validate_persisted_managed_correction_ready(
        v.store,
        identity["task_id"],
        identity["transport_hash"],
        identity["expected_binding"],
        receipt,
        packet=identity["packet"],
        ready=identity["ready"],
        clock=identity["clock"],
    )
    assert checked.document() == receipt
    loaded = module.managed_ready_store.load_persisted_managed_correction_ready(
        v.store,
        identity["task_id"],
        identity["transport_hash"],
        identity["expected_binding"],
        packet=identity["packet"],
        ready=identity["ready"],
        clock=identity["clock"],
    )
    assert loaded.document() == receipt

    for mutation in (
        {"session_nonce": "b" * 64},
        {"ack_nonce": "c" * 64},
    ):
        with pytest.raises(ProductStoreError):
            module.managed_ready_store.persisted_managed_correction_ready(
                **{**identity, **mutation}
            )
    with v.store._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM file_access_task_evidence "
            "WHERE task_id=? AND stage='managed_ready_consume'",
            (identity["task_id"],),
        ).fetchone()[0] == 1

    missing_path = v.store.path.with_name("missing-managed-ready-consume.sqlite3")
    shutil.copy2(v.store.path, missing_path)
    missing = ProductStore(missing_path)
    with missing._connection(write=True) as connection:
        connection.execute("DROP TRIGGER file_access_task_evidence_no_delete")
        connection.execute(
            "DELETE FROM file_access_task_evidence "
            "WHERE task_id=? AND stage='managed_ready_consume'",
            (identity["task_id"],),
        )
    with pytest.raises(ProductStoreError):
        module.managed_ready_store.validate_persisted_managed_correction_ready(
            missing,
            identity["task_id"],
            identity["transport_hash"],
            identity["expected_binding"],
            receipt,
            packet=identity["packet"],
            ready=identity["ready"],
            clock=identity["clock"],
        )
    with pytest.raises(ProductStoreError):
        module.managed_ready_store.load_persisted_managed_correction_ready(
            missing,
            identity["task_id"],
            identity["transport_hash"],
            identity["expected_binding"],
            packet=identity["packet"],
            ready=identity["ready"],
            clock=identity["clock"],
        )
    with missing._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM file_access_task_evidence "
            "WHERE task_id=? AND stage='managed_ready_consume'",
            (identity["task_id"],),
        ).fetchone()[0] == 0


def test_recovery_rejects_foreign_session_before_result_persistence(execution):
    v = execution
    v.state.fault = "retest_persistence"
    _abort(v, "retest")
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)
    with v.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER synthetic_retest_failure")

    client = v.state.remote_client
    descriptor = client.descriptor
    assert client.result is not None and descriptor is not None
    foreign_nonce = "f" * 64
    managed = dict(client.result["output"]["windows_correction"])
    consume = {**managed["persisted_consume_receipt"], "session_nonce": foreign_nonce}
    managed.update(
        session_nonce=foreign_nonce,
        persisted_consume_receipt=consume,
        persisted_consume_digest=module.managed_session.persisted_consume_digest(consume),
    )
    client.result = {**client.result, "output": {"windows_correction": managed}}
    packet = module.wire._document(descriptor.packet)
    module.managed_result.validate_runner_result(
        client.result,
        packet["manifest"],
        packet["profile"],
        expected_packet=descriptor.packet,
    )
    v.monkeypatch.setattr(
        v.runtime,
        "_persist_managed_result",
        lambda *args, **kwargs: pytest.fail(
            "A foreign managed session must be rejected before result persistence"
        ),
    )

    with pytest.raises(ProductStoreError, match="original managed correction outcome"):
        v.runtime._recover_managed_result(v.job)


def test_noop_ready_consumer_cannot_ack_or_release_begin(execution):
    v = execution
    v.monkeypatch.setattr(
        module.managed_ready_store,
        "persisted_managed_correction_ready",
        lambda *args, **kwargs: SimpleNamespace(
            document=lambda: {"schema_version": "synthetic-no-op"}
        ),
    )

    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)

    assert len(v.state.producers) == 1
    assert not v.state.producers[0].consumed
    assert v.state.remote_client.consume_receipt is None
    descriptor = v.state.remote_client.descriptor
    assert descriptor is not None
    with v.store._connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM file_access_task_evidence "
            "WHERE task_id=? AND stage='managed_ready_consume'",
            (descriptor.value["task_id"],),
        ).fetchone()[0] == 0


def test_failed_after_ready_status_and_duplicate_handoffs_are_refused(execution):
    v = execution
    v.runtime.execute(v.ctx, v.request)
    descriptor = v.state.remote_client.descriptor
    ready = v.state.remote_client.ready
    receipt = v.state.remote_client.consume_receipt
    assert descriptor is not None and ready is not None and receipt is not None

    failed = module.managed_session.ManagedCorrectionControl(
        descriptor, enrollment_binding={"binding": "one"}
    )
    fixed_deadline = failed.deadline
    failed.publish_ready(ready, receipt["ack_nonce"])
    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        failed.publish_ready(ready, receipt["ack_nonce"])
    failed.fail("watchdog_handoff_failed")
    failed_status = module.managed_session.validate_status(failed.status(), descriptor)
    assert failed_status["state"] == "failed"
    assert not {"ready_b64", "ready_digest", "ack_nonce"} & set(failed_status)
    assert failed.deadline == fixed_deadline

    control = module.managed_session.ManagedCorrectionControl(
        descriptor, enrollment_binding={"binding": "two"}
    )
    control.publish_ready(ready, receipt["ack_nonce"])
    ready_payload = module.managed_session.watchdog_ready_payload(
        descriptor, ready, receipt["ack_nonce"]
    )
    acknowledgement = {
        "schema_version": module.managed_session.ACK_SCHEMA,
        "original_task_id": descriptor.value["task_id"],
        "original_request_hash": descriptor.value["transport_request_hash"],
        "session_nonce": descriptor.value["session_nonce"],
        "packet_digest": descriptor.packet_digest,
        "ready_digest": ready_payload["ready_digest"],
        "ack_nonce": receipt["ack_nonce"],
        "persisted_consume_receipt": receipt,
        "persisted_consume_digest": module.managed_session.persisted_consume_digest(
            receipt
        ),
    }
    assert control.register_ack(acknowledgement) == acknowledgement
    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        control.register_ack(acknowledgement)
    assert control.deadline == descriptor.packet_deadline


def test_watchdog_frames_reject_mutation_and_wrong_authentication_key():
    key = bytearray(range(32))
    frame = module.managed_session.encode_frame("ready", {"sequence": 1}, key)
    assert module.managed_session.read_frame(
        io.BytesIO(frame), expected_kind="ready", key=key
    ) == {"sequence": 1}

    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        module.managed_session.read_frame(
            io.BytesIO(frame), expected_kind="ready", key=bytearray(reversed(key))
        )
    changed = bytearray(frame)
    changed[-1] ^= 1
    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        module.managed_session.read_frame(
            io.BytesIO(changed), expected_kind="ready", key=key
        )


def test_descriptor_uses_endpoint_local_epoch_without_renewing_live_session(execution):
    v = execution
    v.runtime.execute(v.ctx, v.request)
    descriptor = v.state.remote_client.descriptor
    assert descriptor is not None
    issued = descriptor.value["packet_issued_at_ms"]
    packet = module.wire._document(descriptor.packet)
    manifest = _records(v)["tasks"][0]["task"]["manifest"]
    profile = _records(v)["tasks"][0]["task"]["runner_profile"]

    v.state.wall = issued + 100
    v.state.mono = 10.0
    epoch_one = module.managed_session.validate_descriptor(
        descriptor.value, manifest, profile
    )
    first_remaining = epoch_one.packet_deadline - v.state.mono
    v.state.mono = 1_000_000.0
    epoch_two = module.managed_session.validate_descriptor(
        descriptor.value, manifest, profile
    )
    assert epoch_two.packet_deadline - v.state.mono == pytest.approx(first_remaining)

    original_deadline = epoch_two.packet_deadline
    v.state.wall += 200
    v.state.mono += 0.2
    repeated = module.managed_session.validate_descriptor(
        descriptor.value, manifest, profile
    )
    assert repeated.packet_deadline == pytest.approx(original_deadline)
    assert epoch_two.packet_deadline == original_deadline

    v.state.wall = issued - 1
    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        module.managed_session.validate_descriptor(descriptor.value, manifest, profile)
    expires = module.managed_session._milliseconds(module.wire._time(manifest["expires_at"]))
    v.state.wall = expires
    with pytest.raises(module.managed_session.ManagedCorrectionSessionError):
        module.managed_session.validate_descriptor(descriptor.value, manifest, profile)
    assert 0 < packet["remaining_ms"] <= 5_000


@pytest.mark.parametrize(
    "fault", ["control_cleanup", "control_cleanup_raises", "control_persistence"]
)
def test_control_owner_is_retained_until_cleanup_and_persistence_both_succeed(execution, fault):
    v = execution
    v.state.fault = fault
    if fault == "control_persistence":
        _abort(v, "control")
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)
    assert v.runtime._control_owners[v.job] is v.state.control_owner
    assert _records(v)["outcome"]["state"] == "unknown" and _records(v)["tasks"] == []
    assert set(module.journal.control_evidence(v.store, v.job)) == {"dispatch"}
    digest = _records(v)["outcome_digest"]
    if fault == "control_persistence":
        with v.store._connection(write=True) as connection:
            connection.execute("DROP TRIGGER synthetic_control_failure")
    v.state.fault = None
    _forbid_new_work(v)
    with pytest.raises(ProductStoreError):
        v.runtime.recover(v.job, expected_outcome_digest=digest)
    assert v.job not in v.runtime._control_owners
    assert set(module.journal.control_evidence(v.store, v.job)) == {"dispatch", "closure"}
    assert _records(v)["outcome_digest"] == digest and _records(v)["tasks"] == []
    assert _revision_count(v) == 0


@pytest.mark.parametrize(
    "fault", ["retest_cleanup", "retest_persistence", "publication_persistence"]
)
def test_recovery_only_closes_retained_owner_and_publishes_existing_evidence(execution, fault):
    v = execution
    v.state.fault = fault
    if fault == "retest_persistence":
        _abort(v, "retest")
    elif fault == "publication_persistence":
        _abort(v, "publication")
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)
    before = _records(v)
    assert before["outcome"]["state"] == "unknown" and len(before["tasks"]) == 1
    assert _revision_count(v) == 0
    assert v.job not in v.runtime._retest_owners
    if fault != "publication_persistence":
        assert v.state.remote_client.descriptor is not None
    if fault == "retest_persistence":
        with v.store._connection(write=True) as connection:
            connection.execute("DROP TRIGGER synthetic_retest_failure")
    elif fault == "publication_persistence":
        with v.store._connection(write=True) as connection:
            connection.execute("DROP TRIGGER synthetic_publication_failure")
    v.state.retest_owner.containment.finish_failure = False
    v.state.fault = None
    v.state.wall = before["preparation"]["expires_at_ms"] + 86400000
    v.state.mono = 90000.0
    _forbid_new_work(v)
    v.runtime.recover(v.job, expected_outcome_digest=before["outcome_digest"])
    assert _records(v)["outcome"]["state"] == "complete" and _revision_count(v) == 1
    assert _records(v)["tasks"] == before["tasks"]
    assert v.job not in v.runtime._retest_owners
    assert (
        len(v.state.controls)
        == len(v.state.postimages)
        == len(v.state.producers)
        == len(v.state.launches)
        == 1
    )
    assert all(not any(buffer) for buffer in v.state.buffers)


def test_one_owner_cleanup_failure_does_not_skip_second_owner_persistence(execution):
    v = execution
    v.runtime.execute(v.ctx, v.request)
    v.runtime._retain_control(v.job, v.state.control_owner)
    v.runtime._retain_retest(v.job, v.state.retest_owner)
    v.state.fault = "control_cleanup_raises"
    before_reader = v.state.retest_owner.calls
    assert not v.runtime.cleanup(v.job)
    assert v.state.retest_owner.calls == before_reader + 1
    assert v.runtime._control_owners[v.job] is v.state.control_owner
    assert v.job not in v.runtime._retest_owners
    assert _records(v)["outcome"]["state"] == "complete" and _revision_count(v) == 1
    v.state.fault = None
    assert v.runtime.cleanup(v.job) and v.job not in v.runtime._control_owners


def test_allowed_reader_retains_actual_evidence_but_never_publishes_hardened_control(execution):
    v = execution
    v.state.fault = "allowed_reader"
    with pytest.raises(ProductStoreError):
        v.runtime.execute(v.ctx, v.request)
    assert _records(v)["outcome"]["state"] == "unknown" and len(_records(v)["tasks"]) == 1
    assert _revision_count(v) == 0
    digest = _records(v)["outcome_digest"]
    _forbid_new_work(v)
    with pytest.raises(ProductStoreError):
        v.runtime.recover(v.job, expected_outcome_digest=digest)
    assert _records(v)["outcome_digest"] == digest and _revision_count(v) == 0
