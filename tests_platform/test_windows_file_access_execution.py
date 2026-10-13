"""Connected paired execution with real SQLite/jobs and fake OS boundaries only."""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import file_access_context
from bluefire import windows_file_access_context as windows_context
from bluefire import windows_file_access_enrollment as enrollment
from bluefire import windows_file_access_execution as runtime
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_pair_admission as admission
from bluefire import windows_file_access_pair_credential as credential
from bluefire import windows_file_access_pair_launch as launch
from bluefire import windows_file_access_process as supervisor
from bluefire.file_access_control import FileAccessControl
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_pair_launch as launch_fake
from tests_platform import test_windows_file_access_pair_process as process_pair
from tests_platform import test_windows_file_access_pair_wire as pair_wire
from tests_platform import test_windows_file_access_process as process_fake
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed


@pytest.fixture
def connected(pair_observed, tmp_path, monkeypatch):
    observe, clocks, backend, row = pair_observed
    path = tmp_path / "connected.db"
    store = ProductStore(path)
    # This test does not exercise unrelated service initialization facilities.
    # Its actual property/API/shutdown methods use one long-lived controller.
    service = object.__new__(BlueFireService)
    service.product_store = store
    service.job_controller = RunJobController(store, recover_on_start=False, max_workers=1)
    service._file_access = FileAccessControl(service, clock=lambda: clocks["wall"])
    control = service.file_access
    state = SimpleNamespace(
        fault=None,
        provider_calls=[],
        buffers=[],
        producers=[],
        write_packets=[],
        release=threading.Event(),
        entered=threading.Event(),
        aware=None,
    )
    state.aware = datetime.fromtimestamp(clocks["wall"] / 1000, timezone.utc) + timedelta(
        microseconds=321
    )

    # The established launcher harness also uses permissive protocol stubs in
    # its unit tests. Restore every one: this integration keeps actual joins,
    # provenance parsing, receipt loading and original reservation validation.
    saved = [
        (admission, "checked_provenance"),
        (admission, "_purpose"),
        (enrollment, "read_windows_file_pair_enrollment"),
        (credential.setup, "_load_pair_receipt"),
        (credential.native_setup, "_NativeSetup"),
        (credential.session, "current_process_principal"),
    ]
    saved = [(module, name, getattr(module, name)) for module, name in saved]
    actual_os = {name: getattr(os, name) for name in ("read", "pipe", "fdopen", "close")}
    harness = launch_fake.harness.__wrapped__(monkeypatch)
    routed_os = {name: getattr(os, name) for name in actual_os}
    for name, function in actual_os.items():
        monkeypatch.setattr(os, name, function)
    monkeypatch.setattr(launch, "os", SimpleNamespace(fspath=os.fspath, **routed_os))
    for module, name, function in saved:
        monkeypatch.setattr(module, name, function)
    state.harness = harness

    receipt = json.loads(backend.files[credential.setup._RECEIPT_PATH])
    image_path = next(path for path in backend.files if path.endswith("bluefire-runner.exe"))
    image = backend.files[image_path]
    root = observe._managed_root()
    monkeypatch.setattr(launch_fake, "_ROOT", root)
    monkeypatch.setattr(launch_fake, "_IMAGE_PATH", Path(image_path))
    monkeypatch.setattr(launch_fake, "_IMAGE", image)
    monkeypatch.setattr(launch_fake, "_FILE_ID", row["native_image"]["identity"]["file_id"])
    harness.bootstrap_digest[0] = row["native_image"]["sha256"]
    harness.client_transport[0] = receipt["source"]["transport"]
    monkeypatch.setattr(
        launch,
        "load_runner_manifest",
        lambda **_: SimpleNamespace(
            sha256=row["native_image"]["sha256"][7:], size=len(image), runner_version="0.1.0"
        ),
    )

    # Reopening the fake image starts a fresh byte stream, as a real handle does.
    image_offset = [0]
    original_observe = backend.observe

    def observe_file(path, **kwargs):
        if path == image_path:
            image_offset[0] = 0
        return original_observe(path, **kwargs)

    def read_image(descriptor, maximum):
        assert descriptor == 550
        offset = image_offset[0]
        value = image[offset : offset + maximum]
        image_offset[0] += len(value)
        return value

    backend.observe = observe_file
    monkeypatch.setattr(observe, "os", SimpleNamespace(fspath=str, read=read_image))
    monkeypatch.setattr(
        observe,
        "time",
        SimpleNamespace(time_ns=lambda: clocks["wall"] * 1000000, monotonic=lambda: 10.0),
    )
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: 10.0))
    monkeypatch.setattr(launch, "time", SimpleNamespace(monotonic=lambda: 10.0))
    monkeypatch.setattr(credential, "time", SimpleNamespace(monotonic=lambda: 10.0))
    monkeypatch.setattr(credential.native, "time", SimpleNamespace(monotonic=lambda: 10.0))
    monkeypatch.setattr(launch, "_utc", lambda: state.aware)
    monkeypatch.setattr(credential, "_utc", lambda: state.aware)
    monkeypatch.setattr(supervisor, "_utc", lambda: state.aware)
    monkeypatch.setattr(supervisor, "_monotonic", lambda: 10.0)
    monkeypatch.setattr(control.windows, "_clock", lambda: state.aware)
    monkeypatch.setattr(windows_context, "_clock", lambda: state.aware)
    monkeypatch.setattr(file_access_context, "is_windows_host", lambda: True)

    wipe = credential._wipe

    def capture_wipe(value):
        wipe(value)
        if value is not None:
            state.buffers.append(value)

    monkeypatch.setattr(credential, "_wipe", capture_wipe)

    class Provider:
        provider_id = "windows-dpapi-current-user.v1"

        def unprotect(self, purpose, opaque):
            assert purpose == backend.purpose
            assert opaque == backend.files[credential.setup._CREDENTIAL_PATH]
            packet = state.write_packets[-1]
            prepared = store.file_access_preparation(packet["manifest"]["run_id"])["document"]
            trail = store.file_access_native_pair_evidence(
                packet["task_id"],
                transport_request_hash=packet["request_hash"],
                expected_binding=prepared["expected_binding"],
                clock=state.aware,
            )
            assert trail.ready_bytes is not None and trail.terminal_bytes is None
            state.provider_calls.append(purpose)
            if state.fault == "blocked_provider":
                state.entered.set()
                state.release.wait()
            return b"A\0b\0"

    monkeypatch.setattr(credential, "WindowsDPAPISecretProvider", Provider)

    containment_factory = launch.WindowsJobContainment

    def containment(**kwargs):
        result = containment_factory(**kwargs)
        result.finish_failure = state.fault == "cleanup"
        return result

    monkeypatch.setattr(launch, "WindowsJobContainment", containment)

    original_fdopen = launch.os.fdopen

    def fdopen(descriptor, mode, *, buffering):
        stream = original_fdopen(descriptor, mode, buffering=buffering)
        if mode != "wb":
            return stream
        original_write = stream.write

        def write(data):
            if not stream.writes:
                packet = json.loads(bytes(data)[4:])
                state.write_packets.append(packet)
                prepared = store.file_access_preparation(packet["manifest"]["run_id"])["document"]
                original = wire.validate_pair_original_reservation(
                    prepared["original"], expected_binding=prepared["expected_binding"]
                )
                retained = wire.validate_pair_retained_packet(original, bytes(data)[4:])
                ready, terminal = pair_wire.envelopes(retained)
                if state.fault == "partial":
                    ready, terminal = process_pair.partial(retained)
                    harness.process_holder[0].code = 4
                elif state.fault == "denied":
                    ready, terminal = pair_wire.envelopes(retained, "data_access_denied")
                resource = prepared["expected_binding"]["resource"]
                for phase in ("reader", "owner"):
                    proof = terminal["result"][phase]
                    if proof["outcome"] == "allowed":
                        proof.update(
                            bytes_read=resource["size_bytes"], observed_sha256=resource["sha256"]
                        )
                terminal["observed_at"] = state.aware.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                )
                stdout = next(value for value in harness.streams if value.label == "stdout")
                stdout.data = process_fake.framed(
                    canonical_json_bytes(ready)
                ) + process_fake.framed(canonical_json_bytes(terminal))
            return original_write(data)

        stream.write = write
        return stream

    monkeypatch.setattr(launch.os, "fdopen", fdopen)
    state.store, state.service, state.control, state.clocks = store, service, control, clocks
    state.row, state.path = row, path
    state.selection = {
        "enrollment_id": row["enrollment_id"],
        "enrollment_digest": content_hash(row),
    }
    closed = []
    service._provider_access = SimpleNamespace(close=lambda: closed.append("provider"))
    service._provider_check_transport = SimpleNamespace(close=lambda: closed.append("transport"))
    service.receiver_defense = SimpleNamespace(owners=SimpleNamespace(close_all=lambda: True))
    service.composition = SimpleNamespace(owners=SimpleNamespace(close_all=lambda: True))
    state.closed = closed
    try:
        yield state
    finally:
        state.release.set()
        service.job_controller.shutdown()
        assert control.windows.close_all()


def request_for(state):
    imported = state.service.import_file_access_setup(state.selection)
    assert imported["schema_version"] == "bluefire.windows-file-access-control.v2"
    assert imported["revision"] == 1 and imported["status"] == "setup_verified"
    assert imported["allowed_operations"] == ["baseline"]
    status = state.service.file_access_status()
    assert status["available"] is True and status["problem"] is None
    assert status["allowed_operations"] == []
    reviewed = state.service.file_access_review(
        {"operation": "baseline", "control_owner_id": imported["control_owner_id"]}
    )
    assert reviewed["effect"] == (
        "Read the generated resource once as the non-owner and once as the owner, "
        "compare byte counts and content digests, and verify native and owned-job closure. "
        "Account and resource cleanup remains required."
    )
    return dict(
        submission_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        review={"operation": "baseline", "control_owner_id": imported["control_owner_id"]},
        review_digest=reviewed["review_digest"],
        reviewed_by="synthetic-operator",
    )


def submit(state, request=None):
    request = request or request_for(state)
    response = state.service.submit_file_access_operation(request)
    job_id = response["job"]["job_id"]
    job = state.service.job_controller.wait(job_id, timeout=15)
    return request, job_id, job


@contextmanager
def occupied_controller(state):
    """Hold the one actual worker while a real file-access job stays queued."""
    entered, release = threading.Event(), threading.Event()

    def hold(ctx, _request):
        ctx.checkpoint({"phase": "synthetic_worker_held"})
        entered.set()
        release.wait()

    blocker = state.service.job_controller.submit("synthetic.test.hold", {}, callback=hold)
    try:
        assert entered.wait(timeout=10)
        yield
    finally:
        release.set()
        state.service.job_controller.wait(blocker["job_id"], timeout=15)


def assert_no_private_attempt(state):
    assert state.provider_calls == state.harness.popen_calls == state.write_packets == []
    with state.store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM file_access_task_claims").fetchone()[0] == 0
        assert (
            connection.execute("SELECT count(*) FROM file_access_task_evidence").fetchone()[0] == 0
        )
    assert state.control.windows._owners == {}


def test_queued_original_has_unresolved_control_but_zero_ready_allowance(connected):
    state = connected
    with occupied_controller(state):
        request = request_for(state)
        response = state.service.submit_file_access_operation(request)
        job_id = response["job"]["job_id"]
        assert response["job"]["state"] == "queued"
        saved = state.store.file_access_operation_records(job_id)
        assert saved["outcome"] is saved["preparation"] is None and saved["tasks"] == []
        public = response["control"]
        assert public["schema_version"] == "bluefire.windows-file-access-control.v2"
        assert public["revision"] == 1 and public["status"] == "uncertain"
        assert public["task_usage_state"] == "unresolved" and public["allowed_operations"] == []
        assert_no_private_attempt(state)
        assert state.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
        with pytest.raises(ProductStoreError):
            state.service.file_access_review(request["review"])
        assert state.service.job_controller.cancel(job_id)["state"] == "cancelled"
        state.service.file_access_operation(job_id)


def test_cancelled_preclaim_original_remains_no_effect_without_review_or_replay(connected):
    state = connected
    with occupied_controller(state):
        request = request_for(state)
        response = state.service.submit_file_access_operation(request)
        job_id = response["job"]["job_id"]
        original = state.store.file_access_operation_records(job_id)["document"]
        assert state.service.job_controller.cancel(job_id)["state"] == "cancelled"
        response = state.service.file_access_operation(job_id)
        saved = state.store.file_access_operation_records(job_id)
        assert saved["document"] == original
        assert saved["preparation"] is None and saved["tasks"] == []
        assert saved["outcome"] == {
            "state": "refused_no_effect",
            "evidence_digest": content_hash([]),
            "control_digest": None,
        }
        public = response["control"]
        assert public["schema_version"] == "bluefire.windows-file-access-control.v2"
        assert public["revision"] == 1 and public["status"] == "setup_verified"
        assert public["task_usage_state"] == "none" and public["allowed_operations"] == []
        assert_no_private_attempt(state)
        replay = state.service.submit_file_access_operation(request)
        assert replay["job"]["job_id"] == job_id and replay["control"] == public
        with pytest.raises(ProductStoreError):
            state.service.file_access_review(request["review"])
        stale = dict(request, submission_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        with pytest.raises(ProductStoreError):
            state.store.create_file_access_operation(
                stale,
                review_document=original["review"],
                review_context=original["review_context"],
                enrollment_id=state.row["enrollment_id"],
                now_ms=state.clocks["wall"],
            )
        same, created = state.store.create_file_access_operation(
            request,
            review_document=original["review"],
            review_context=original["review_context"],
            enrollment_id=state.row["enrollment_id"],
            now_ms=state.clocks["wall"],
        )
        assert same["job_id"] == job_id and created is False
        assert_no_private_attempt(state)


def test_full_fake_vertical_path_publishes_two_actual_phases_and_closure(connected):
    state = connected
    _, job_id, job = submit(state)
    assert job["state"] == "completed", job.get("error")
    saved = state.store.file_access_operation_records(job_id)
    assert (
        len(saved["tasks"]) == 1 and saved["tasks"][0]["task"]["step_id"] == "read_generated_pair"
    )
    assert saved["outcome"]["state"] == "complete"
    public = state.service.file_access_operation(job_id)["control"]
    assert public["schema_version"] == "bluefire.windows-file-access-control.v2"
    assert public["status"] == "baseline_verified" and public["revision"] == 2
    assert public["baseline"]["non_owner"] == public["baseline"]["owner"] == "allowed"
    assert not public["baseline"]["independent_observation"] and public["allowed_operations"] == []
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1
    assert state.buffers and all(not any(value) for value in state.buffers)
    assert all(stream.closed for stream in state.harness.streams)
    assert state.harness.process_holder[0]._handle.closed
    assert not state.control.windows._owners
    assert not any(
        value in str(public)
        for value in ("S-1-", "secret-ref", "C:\\", "record_count", "worker_uid")
    )


def test_full_precision_same_millisecond_receipt_is_persisted_not_future(connected):
    state = connected
    _, job_id, job = submit(state)
    assert job["state"] == "completed", job.get("error")
    assert state.aware.microsecond % 1000 == 321
    with state.store._connection() as connection:
        document = json.loads(
            connection.execute(
                "SELECT document_json FROM file_access_owned_process_closures"
            ).fetchone()[0]
        )
    receipt = json.loads(document["receipt_utf8"])
    assert receipt["observed_at"] == state.aware.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    assert state.store.file_access_operation_records(job_id)["outcome"]["state"] == "complete"


def test_repeated_import_and_operation_submission_never_relaunch_or_decrypt(connected):
    state = connected
    request, job_id, job = submit(state)
    assert job["state"] == "completed", job.get("error")
    assert state.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
    assert state.service.import_file_access_setup(state.selection)["revision"] == 2
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1
    with pytest.raises(ProductStoreError):
        state.service.file_access_review(request["review"])


def test_unknown_original_recovers_after_expiry_without_observation_or_relaunch(
    connected, monkeypatch
):
    state = connected
    with state.store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER synthetic_publish_failure BEFORE INSERT ON file_access_revisions BEGIN SELECT RAISE(ABORT,'synthetic'); END"
        )
    _, job_id, job = submit(state)
    assert job["state"] == "failed"
    original = state.store.file_access_operation_records(job_id)
    assert original["outcome"]["state"] == "unknown"
    uncertain = state.service.file_access_operation(job_id)["control"]
    assert uncertain["schema_version"] == "bluefire.windows-file-access-control.v2"
    assert uncertain["revision"] == 1 and uncertain["status"] == "uncertain"
    assert uncertain["task_usage_state"] == "unresolved" and uncertain["allowed_operations"] == []
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1
    with state.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER synthetic_publish_failure")
    state.aware += timedelta(days=1)
    state.clocks["wall"] = int(state.aware.timestamp() * 1000)

    def forbidden(*_, **__):
        raise AssertionError("historical reconciliation must never observe, decrypt or launch")

    monkeypatch.setattr(runtime.context, "baseline_context", forbidden)
    monkeypatch.setattr(credential.enrollment, "read_windows_file_pair_enrollment", forbidden)
    monkeypatch.setattr(runtime, "launch_pair_baseline", forbidden)
    request = dict(
        submission_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        expected_outcome_digest=original["outcome_digest"],
        reviewed_by="synthetic operator",
    )
    recovered = state.service.reconcile_file_access_operation(job_id, request)
    assert recovered["reconciliation"]["state"] == "complete"
    assert recovered["control"]["status"] == "baseline_verified"
    assert recovered["control"]["schema_version"] == "bluefire.windows-file-access-control.v2"
    assert (
        recovered["control"]["revision"] == 2 and recovered["control"]["allowed_operations"] == []
    )
    assert state.service.reconcile_file_access_operation(job_id, request) == recovered
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1


@pytest.mark.parametrize("fault", ["denied", "partial"])
def test_actual_denied_or_partial_pair_remains_unknown_without_baseline(connected, fault):
    state = connected
    state.fault = fault
    _, job_id, job = submit(state)
    assert job["state"] == "failed"
    saved = state.store.file_access_operation_records(job_id)
    assert saved["outcome"]["state"] == "unknown"
    public = state.service.file_access_operation(job_id)["control"]
    assert public["schema_version"] == "bluefire.windows-file-access-control.v2"
    assert public["revision"] == 1 and public["status"] == "uncertain"
    assert public["task_usage_state"] == "unresolved" and public["allowed_operations"] == []
    context = saved["preparation"]
    evidence = state.store.file_access_native_pair_cleanup_evidence(
        context["original"]["task_id"],
        transport_request_hash=context["original"]["transport_request_hash"],
        expected_binding=context["expected_binding"],
        clock=state.aware,
    )
    assert evidence.owned_job_cleanup == "verified"
    projection = evidence.native_evidence.projection
    assert projection.reader_outcome == ("data_access_denied" if fault == "denied" else "allowed")
    assert projection.owner_outcome == ("allowed" if fault == "denied" else "unknown")
    assert evidence.native_evidence.actual_returncode == (0 if fault == "denied" else 4)
    assert not projection.settled and projection.owned_job_cleanup == "unverified"


def test_stop_during_fake_dpapi_prevents_late_begin_and_replay(connected):
    state = connected
    state.fault = "blocked_provider"
    request = request_for(state)
    response = state.service.submit_file_access_operation(request)
    job_id = response["job"]["job_id"]
    try:
        assert state.entered.wait(timeout=10)
        stopped = state.service.job_controller.cancel(job_id)
        assert stopped["state"] == "cancelling"
    finally:
        state.release.set()
    job = state.service.job_controller.wait(job_id, timeout=15)
    # A boundary exception after possible effects is conservatively failed,
    # not JobCancelled; cancellation still prevents every later Begin write.
    assert job["state"] == "failed"
    assert state.store.file_access_operation_records(job_id)["outcome"]["state"] == "unknown"
    stdin = next(value for value in state.harness.streams if value.label == "stdin")
    assert len(stdin.writes) == 1
    assert state.buffers and all(not any(value) for value in state.buffers)
    assert state.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1


def test_long_lived_service_controller_closes_exact_registry_at_shutdown(connected):
    state = connected
    assert state.service.file_access is state.service.file_access is state.control
    _, _, job = submit(state)
    assert job["state"] == "completed", job.get("error")
    state.service.close()
    assert state.closed == ["provider", "transport"]
    assert state.control.windows._closing and not state.control.windows._owners
    assert len(state.harness.popen_calls) == 1


def test_unknown_closure_retains_exact_owner_until_service_shutdown_retry(connected):
    state = connected
    state.fault = "cleanup"
    _, job_id, job = submit(state)
    assert job["state"] == "failed"
    assert state.store.file_access_operation_records(job_id)["outcome"]["state"] == "unknown"
    assert len(state.control.windows._owners) == 1
    owner = state.control.windows._owners[job_id]
    assert state.service.file_access.windows._owners[job_id] is owner
    assert state.harness.process_holder[0]._handle.closed is False
    state.harness.containments[0].finish_failure = False
    state.service.close()
    assert owner.resources_closed and state.harness.process_holder[0]._handle.closed
    assert state.control.windows._owners == {} and state.control.windows._closing
    assert len(state.provider_calls) == len(state.harness.popen_calls) == 1
    saved = state.store.file_access_operation_records(job_id)
    prepared = saved["preparation"]
    closed = state.store.file_access_native_pair_cleanup_evidence(
        prepared["original"]["task_id"],
        transport_request_hash=prepared["original"]["transport_request_hash"],
        expected_binding=prepared["expected_binding"],
        clock=state.aware,
    )
    assert closed.owned_job_cleanup == "verified" and saved["outcome"]["state"] == "unknown"
    assert not closed.settled
