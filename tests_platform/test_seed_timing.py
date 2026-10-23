import threading
from types import SimpleNamespace

import pytest

from tests_platform import seed_timing
from tests_platform.seed_timing import SeedTiming, observe_service_seed


def test_reports_progress_and_current_operation_age_without_private_values():
    now = [10.0]
    timing = SeedTiming(clock=lambda: now[0])
    messages = []
    with timing.phase("seed-metadata"):
        with timing.operation("resource-save"):
            now[0] = 70.0
            timing.report_due((60.0, 120.0), write=messages.append)
            timing.report_due((60.0, 120.0), write=messages.append)
    now[0] = 130.0
    timing.report_due((60.0, 120.0), write=messages.append)

    assert len(messages) == 2
    assert messages[0] == (
        "bluefire_seed_timing elapsed=60.0s phase=seed-metadata "
        "scenario_saves=0/0 resource_saves=0/1 "
        "current=resource-save operation_age=60.0s\n"
    )
    assert "elapsed=120.0s" in messages[1]
    assert all("SECRET" not in message for message in messages)


def test_timing_labels_are_static_allowlisted_values():
    timing = SeedTiming()
    with pytest.raises(ValueError, match="not allowlisted"):
        with timing.phase("SECRET phase"):
            pass
    with pytest.raises(ValueError, match="not allowlisted"):
        with timing.operation("SECRET operation"):
            pass


def test_stderr_close_does_not_escape_monitor(monkeypatch):
    class ClosedStream:
        def write(self, _message):
            raise ValueError("closed stream")

        def flush(self):
            return None

    monkeypatch.setattr(seed_timing.sys, "stderr", ClosedStream())
    seed_timing._write_stderr("bluefire_seed_timing elapsed=60.0s\n")


@pytest.mark.parametrize("fail", [False, True])
def test_wrappers_restore_after_service_seed_success_or_failure(fail):
    calls = []
    now = [0.0]
    timing_ref = []

    class Store:
        def save_scenario(self, value):
            calls.append("scenario")

        def save_resource(self, kind, resource_id):
            calls.append("resource")

    def seed(store):
        store.save_scenario("SECRET scenario id")
        store.save_resource("SECRET kind", "SECRET resource id")
        now[0] = 60.0
        timing_ref[0].report_due((60.0,), write=messages.append)
        if fail:
            raise RuntimeError("fixture failure")

    service_module = SimpleNamespace(seed_product_metadata=seed)
    original_seed = service_module.seed_product_metadata
    original_scenario = Store.save_scenario
    original_resource = Store.save_resource
    messages = []

    context = observe_service_seed(
        service_module,
        Store,
        thresholds=(60.0,),
        monitor=False,
        clock=lambda: now[0],
        write=messages.append,
    )
    if fail:
        with pytest.raises(RuntimeError, match="fixture failure"):
            with context as timing:
                timing_ref.append(timing)
                service_module.seed_product_metadata(Store())
    else:
        with context as timing:
            timing_ref.append(timing)
            service_module.seed_product_metadata(Store())

    assert calls == ["scenario", "resource"]
    assert service_module.seed_product_metadata is original_seed
    assert Store.save_scenario is original_scenario
    assert Store.save_resource is original_resource
    assert len(messages) == 1
    assert "SECRET" not in messages[0]


def test_monitor_emits_at_threshold_and_joins_without_leaking_worker():
    messages = []
    reported = threading.Event()

    def write(message):
        messages.append(message)
        reported.set()

    service_module = SimpleNamespace(seed_product_metadata=lambda: None)

    class Store:
        def save_scenario(self):
            return None

        def save_resource(self):
            return None

    with observe_service_seed(
        service_module,
        Store,
        thresholds=(0.01,),
        interval=0.002,
        write=write,
    ) as timing:
        worker = timing.monitor_thread
        assert reported.wait(1)

    assert messages and "elapsed=" in messages[0]
    assert worker is not None and not worker.is_alive()


def test_monitor_start_failure_is_preserved_and_wrappers_are_restored():
    calls = []

    class Store:
        def save_scenario(self):
            return None

        def save_resource(self):
            return None

    def seed():
        return None

    class FailedStartThread:
        ident = 1

        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("original monitor start failure")

        def join(self, *, timeout):
            calls.append(timeout)
            raise RuntimeError("cleanup must not replace start failure")

        def is_alive(self):
            return True

    service_module = SimpleNamespace(seed_product_metadata=seed)
    original_seed = service_module.seed_product_metadata
    original_scenario = Store.save_scenario
    original_resource = Store.save_resource

    with pytest.raises(RuntimeError, match="original monitor start failure"):
        with observe_service_seed(
            service_module,
            Store,
            thresholds=(0.01,),
            interval=0.002,
            thread_factory=FailedStartThread,
        ):
            pass

    assert calls == [2.0]
    assert service_module.seed_product_metadata is original_seed
    assert Store.save_scenario is original_scenario
    assert Store.save_resource is original_resource


def test_bounded_join_failure_is_reported_after_wrappers_restore():
    calls = []

    class Store:
        def save_scenario(self):
            return None

        def save_resource(self):
            return None

    class StuckMonitor:
        ident = 1

        def __init__(self, **_kwargs):
            pass

        def start(self):
            return None

        def join(self, *, timeout):
            calls.append(timeout)
            raise RuntimeError("join unavailable")

        def is_alive(self):
            return True

    service_module = SimpleNamespace(seed_product_metadata=lambda: None)
    original_seed = service_module.seed_product_metadata
    original_scenario = Store.save_scenario
    original_resource = Store.save_resource

    with pytest.raises(RuntimeError, match="did not stop within its bound"):
        with observe_service_seed(
            service_module,
            Store,
            thresholds=(0.01,),
            interval=0.002,
            join_timeout=0.05,
            thread_factory=StuckMonitor,
        ):
            pass

    assert calls == [0.05]
    assert service_module.seed_product_metadata is original_seed
    assert Store.save_scenario is original_scenario
    assert Store.save_resource is original_resource
