"""Service lifetime and exact in-memory Windows ownership, with no native effects."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bluefire import file_access_control, service
from bluefire import windows_file_access_execution as execution
from bluefire import windows_file_access_pair_launch as launch
from bluefire.product_store_errors import ProductStoreError
from tests_platform import test_windows_file_access_pair_wire as pair


def forbidden(*_, **__):
    pytest.fail("Shutdown must not launch, decrypt, or reconstruct a native owner")


class ClosingBoundary:
    def __init__(self, events, name, failure=None):
        self.events, self.name, self.failure = events, name, failure

    def close(self):
        self.events.append(self.name)
        if isinstance(self.failure, Exception):
            raise self.failure
        return self.failure is not False

    shutdown = close
    close_all = close


def bare_service(*, failures=None, windows=None, correction=None):
    failures = failures or {}
    events = []
    instance = service.BlueFireService.__new__(service.BlueFireService)
    instance._provider_access = ClosingBoundary(events, "provider", failures.get("provider"))
    instance._provider_check_transport = ClosingBoundary(
        events, "transport", failures.get("transport")
    )
    instance.job_controller = ClosingBoundary(events, "jobs", failures.get("jobs"))
    instance.receiver_defense = SimpleNamespace(
        owners=ClosingBoundary(events, "receiver", failures.get("receiver"))
    )
    instance.composition = SimpleNamespace(
        owners=ClosingBoundary(events, "composition", failures.get("composition"))
    )
    instance._file_access = SimpleNamespace(
        windows=windows or ClosingBoundary(events, "windows", failures.get("windows")),
        windows_correction=correction
        or ClosingBoundary(events, "correction", failures.get("correction")),
    )
    return instance, events


def test_real_service_initialization_keeps_one_file_access_controller(monkeypatch, tmp_path):
    registry = object()
    store = SimpleNamespace(
        recover_interrupted_jobs=lambda: [], interrupt_active_capability_grants=lambda **_: None
    )

    def quiet(*_, **__):
        return SimpleNamespace(application_committed=lambda *_: None)

    monkeypatch.setattr(
        service,
        "RunStore",
        lambda root: SimpleNamespace(root=root, recover_interrupted_runs=lambda: []),
    )
    monkeypatch.setattr(service, "ProductStore", lambda _: store)
    monkeypatch.setattr(service, "ManagedAIJSONTransport", quiet)
    monkeypatch.setattr(service, "AuthorizedAIProviderAccess", lambda access, _: access)
    for name in (
        "DetectionLabService",
        "RunJobController",
        "DetectionAIJobs",
        "MethodComparisonJobs",
        "DetectionCreateJobs",
        "GraphAIJobs",
        "AssistanceRunJobs",
        "ReceiverDefenseJobs",
        "AdSmbJobs",
        "S3AccessJobs",
        "ExperimentAssistance",
        "ReceiverAssistance",
    ):
        monkeypatch.setattr(service, name, quiet)
    monkeypatch.setattr("bluefire.composition_jobs.CompositionJobs", quiet)
    monkeypatch.setattr(service, "seed_product_metadata", quiet)
    monkeypatch.setattr(
        service.BlueFireService,
        "_load_action_catalog_snapshot",
        lambda _: SimpleNamespace(registry=registry),
    )
    monkeypatch.setattr(service.BlueFireService, "_load_scenarios", lambda _: {})
    for name in (
        "_recover_interrupted_cleanup",
        "_refresh_runtime_configuration",
        "_synchronize_run_index",
    ):
        monkeypatch.setattr(service.BlueFireService, name, lambda _: None)
    controls = []
    actual = file_access_control.FileAccessControl

    def create_control(instance):
        control = actual(instance)
        controls.append(control)
        return control

    monkeypatch.setattr(file_access_control, "FileAccessControl", create_control)
    instance = service.BlueFireService(
        project_root=tmp_path,
        runs_dir=tmp_path / "unused-runs",
        product_db_path=tmp_path / "unused.db",
        registry=registry,
        config=SimpleNamespace(runner_profiles=(), ai=object()),
        runner_lifecycle=object(),
        ai_provider_access=object(),
        s3_access_executor=object(),
    )
    assert controls == [instance.file_access]
    assert instance.file_access is instance.file_access is controls[0]
    assert instance.file_access.windows.control is controls[0]
    assert instance.file_access.windows.store is store
    assert instance.file_access.windows_correction.control is controls[0]
    assert instance.file_access.windows_correction.store is store
    assert instance.file_access.windows_correction._control_owners == {}
    assert instance.file_access.windows_correction._retest_owners == {}
    owner = object()
    instance.file_access.windows._retain("synthetic-job", owner)
    assert instance.file_access.windows._owners == {"synthetic-job": owner}
    assert not (tmp_path / "unused.db").exists()
    assert not (tmp_path / "unused-runs").exists()


def test_shutdown_closes_windows_after_job_controller_and_other_registries():
    instance, events = bare_service()
    instance.close()
    assert events == [
        "provider",
        "transport",
        "jobs",
        "receiver",
        "composition",
        "windows",
        "correction",
    ]


@pytest.mark.parametrize("boundary", ["provider", "transport", "jobs"])
def test_earlier_shutdown_exception_still_closes_all_owner_registries(boundary):
    failure = RuntimeError("synthetic close failure")
    instance, events = bare_service(failures={boundary: failure})
    with pytest.raises(RuntimeError) as caught:
        instance.close()
    assert caught.value is failure
    assert events == [
        "provider",
        "transport",
        "jobs",
        "receiver",
        "composition",
        "windows",
        "correction",
    ]


@pytest.mark.parametrize("boundary", ["receiver", "composition", "windows", "correction"])
@pytest.mark.parametrize("failure", [False, RuntimeError("synthetic registry failure")])
def test_failed_registry_is_visible_without_skipping_later_registries(boundary, failure):
    instance, events = bare_service(failures={boundary: failure})
    with pytest.raises(ProductStoreError, match="lack verified cleanup"):
        instance.close()
    assert events == [
        "provider",
        "transport",
        "jobs",
        "receiver",
        "composition",
        "windows",
        "correction",
    ]


@pytest.mark.parametrize("boundary", ["provider", "transport", "jobs"])
@pytest.mark.parametrize("runtime", ["windows", "correction"])
def test_windows_cleanup_failure_remains_visible_after_earlier_shutdown_failure(boundary, runtime):
    instance, events = bare_service(
        failures={boundary: RuntimeError("synthetic earlier failure"), runtime: False}
    )
    with pytest.raises(ProductStoreError, match="lack verified cleanup"):
        instance.close()
    assert events == [
        "provider",
        "transport",
        "jobs",
        "receiver",
        "composition",
        "windows",
        "correction",
    ]


class RetainedOwner:
    def __init__(self, failure=False, *, process=None, original=None):
        self.failure, self.process, self.original = failure, process, original
        self.cleanup_calls = 0
        self.outcome_calls = 0

    def retry_cleanup(self):
        self.cleanup_calls += 1
        if isinstance(self.failure, Exception):
            raise self.failure
        return self.failure is not False

    def outcome(self, clean):
        assert clean is True
        self.outcome_calls += 1
        return SimpleNamespace(process=self.process)


def runtime(store=None):
    return execution.WindowsBaselineRuntime(SimpleNamespace(store=store or SimpleNamespace()))


def test_duplicate_job_cannot_replace_the_actual_retained_owner():
    windows = runtime()
    original, replacement = RetainedOwner(), RetainedOwner()
    windows._retain("original-job", original)
    with pytest.raises(ProductStoreError, match="no longer available"):
        windows._retain("original-job", replacement)
    assert windows._owners == {"original-job": original}
    assert original.cleanup_calls == replacement.cleanup_calls == 0


@pytest.mark.parametrize("failure", [False, OSError("synthetic retained close failure")])
def test_service_failure_keeps_exact_owner_for_cleanup_only_retry(failure):
    windows = runtime()
    failed, closed = RetainedOwner(failure), RetainedOwner(True)
    windows._retain("failed", failed)
    windows._retain("closed", closed)
    instance, _ = bare_service(windows=windows)
    with pytest.raises(ProductStoreError, match="lack verified cleanup"):
        instance.close()
    assert windows._closing is True
    assert windows._owners == {"failed": failed}
    assert failed.cleanup_calls == closed.cleanup_calls == 1
    assert failed.outcome_calls == 0 and closed.outcome_calls == 1
    failed.failure = True
    instance.close()
    assert windows._owners == {}
    assert failed.cleanup_calls == 2 and failed.outcome_calls == 1
    assert closed.cleanup_calls == 1


def test_receipt_persistence_failure_retains_physically_closed_owner_for_exact_retry():
    original, _, _ = pair.prepared()
    receipt, calls = object(), []
    fail = [True]

    def record(task_id, **kwargs):
        calls.append((task_id, kwargs))
        if fail[0]:
            raise ProductStoreError("synthetic persistence refusal")

    windows = runtime(SimpleNamespace(record_file_access_native_pair_cleanup=record))
    owner = RetainedOwner(True, process=SimpleNamespace(cleanup_receipt=receipt), original=original)
    windows._retain("original-job", owner)
    assert windows.close_all() is False
    assert windows._owners == {"original-job": owner}
    fail[0] = False
    assert windows.close_all() is True
    assert windows._owners == {} and len(calls) == 2
    first_task, first = calls[0]
    second_task, second = calls[1]
    assert (
        first_task
        == second_task
        == execution.wire._reservation(original, execution.wire._PAIR)["task_id"]
    )
    assert first["receipt"] is second["receipt"] is receipt
    assert first["transport_request_hash"] == second["transport_request_hash"]
    assert first["expected_binding"] == second["expected_binding"]


def test_closing_registry_rejects_owner_before_launch_thread_or_native_work(monkeypatch):
    windows, created = runtime(), []
    assert windows.close_all() is True

    def owner(*args):
        value = object()
        created.append(value)
        return value

    monkeypatch.setattr(launch, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(launch, "PairLaunchOwner", owner)
    monkeypatch.setattr(launch, "threading", SimpleNamespace(Thread=forbidden))
    with pytest.raises(ProductStoreError, match="no longer available"):
        launch.launch_pair_baseline(
            object(),
            object(),
            object(),
            object(),
            revalidate_original=forbidden,
            evidence_sink=forbidden,
            cancellation_event=object(),
            retain_launch_owner=lambda value: windows._retain("late-job", value),
        )
    assert len(created) == 1 and windows._owners == {}


def test_historical_recovery_never_reconstructs_owner_or_replays_work(monkeypatch):
    calls = []

    class HistoricalStore:
        def recover_windows_file_access_baseline(self, job_id, **kwargs):
            calls.append((job_id, kwargs))

        def __getattr__(self, name):
            pytest.fail(f"Historical recovery must not consult mutable launch state: {name}")

    windows = runtime(HistoricalStore())
    monkeypatch.setattr(execution, "PairLaunchOwner", forbidden)
    monkeypatch.setattr(execution, "PairBeginProducer", forbidden)
    monkeypatch.setattr(execution, "launch_pair_baseline", forbidden)
    monkeypatch.setattr(execution.wire, "prepare_pair_packet", forbidden)
    assert windows.close_all() is True
    windows.recover("original-job", expected_outcome_digest="sha256:" + "1" * 64)
    assert windows._owners == {}
    assert len(calls) == 1 and calls[0][0] == "original-job"
    assert calls[0][1]["expected_outcome_digest"] == "sha256:" + "1" * 64
