from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, TextIO

import pytest

from bluefire.ai import DeterministicOfflineProvider, build_ai_provider
from bluefire.ai_transport import ManagedAIJSONTransport, UrllibAIJSONTransport
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError
from bluefire.config import AIProviderKind, AutonomyLevel, load_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes
from tests_platform.test_ai import FakeTransport, _proposal, _request
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_transport_deadline import endpoint as endpoint
from tests_platform.test_ai_transport_deadline import workers as workers
from tests_platform.test_ai_wire_runtime import _ai_config, _envelope, _provider_config

ROOT = Path(__file__).resolve().parents[1]
KINDS = (AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS)
_DIAGNOSTIC_LIMIT_BYTES = 4096
_DIAGNOSTIC_STAGES = {
    "before_endpoint",
    "request_active",
    "shutdown_wait",
    "job_cancellation",
    "job_settlement",
    "postconditions",
    "unknown",
}
_DIAGNOSTIC_JOB_STATES = {
    "queued",
    "planning",
    "running",
    "awaiting_approval",
    "cancelling",
    "cancelled",
    "completed",
    "failed",
    "paused",
}


def _safe_stack(rows: list[tuple[str, int]]) -> list[dict[str, Any]]:
    return [
        {"function": name[:80], "line": line}
        for name, line in rows[:16]
        if isinstance(name, str)
        and type(line) is int
        and all(char.isalnum() or char in "._<>" for char in name[:80])
    ]


def _format_cancellation_diagnostic(
    *,
    stage: str,
    timings_ms: dict[str, float],
    job_state: str,
    endpoint_entered: bool,
    endpoint_path_count: int,
    slow_body_seen: bool,
    http_workers: list[tuple[int | None, int | None, bool]],
    close_alive: bool,
    close_stack: list[tuple[str, int]],
    callback_thread_id: int | None,
    callback_thread_name: str | None,
    callback_alive: bool,
    callback_stack: list[tuple[str, int]],
) -> str:
    safe = {
        "stage": stage if stage in _DIAGNOSTIC_STAGES else "unknown",
        "timings_ms": {
            key: min(300_000, max(0, round(value)))
            for key, value in timings_ms.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        },
        "job_state": (
            job_state
            if isinstance(job_state, str) and job_state in _DIAGNOSTIC_JOB_STATES
            else "unknown"
        ),
        "endpoint": {
            "entered": endpoint_entered,
            "path_count": min(100, max(0, endpoint_path_count)),
            "slow_body_seen": slow_body_seen,
        },
        "http_workers": [
            {"pid": pid, "returncode": code, "alive": alive}
            for pid, code, alive in http_workers[:2]
        ],
        "close_thread": {"alive": close_alive, "stack": _safe_stack(close_stack)},
        "callback": {
            "thread_id": callback_thread_id,
            "thread_name": (
                callback_thread_name[:80]
                if isinstance(callback_thread_name, str)
                and all(char.isalnum() or char in "._-" for char in callback_thread_name)
                else None
            ),
            "alive": callback_alive,
            "stack": _safe_stack(callback_stack),
        },
    }
    encoded = json.dumps(safe, separators=(",", ":"), sort_keys=True)
    return (
        encoded if len(encoded.encode("utf-8")) <= _DIAGNOSTIC_LIMIT_BYTES else '{"truncated":true}'
    )


@contextmanager
def _diagnose_cancellation_assertions(render: Callable[[], str], stream: TextIO) -> Iterator[None]:
    """Print safe diagnostics only on failure and re-raise unchanged."""

    try:
        yield
    except Exception:
        try:
            payload = render()
        except BaseException:
            payload = '{"stage":"unknown","capture":"failed"}'
        try:
            stream.write(f"provider-cancellation-diagnostic={payload}\n")
            stream.flush()
        except BaseException:
            pass
        raise


def test_cancellation_diagnostic_is_bounded_and_omits_unapproved_values() -> None:
    unapproved_value = "provider response must never appear in diagnostics"
    payload = _format_cancellation_diagnostic(
        stage="shutdown_wait",
        timings_ms={"endpoint_wait_ms": 4000},
        job_state=unapproved_value,
        endpoint_entered=True,
        endpoint_path_count=1,
        slow_body_seen=True,
        http_workers=[(123, None, True)] * 100,
        close_alive=True,
        close_stack=[("close", 25)] * 100,
        callback_thread_id=456,
        callback_thread_name="ThreadPoolExecutor-0_0",
        callback_alive=True,
        callback_stack=[("_execute_job", 30)] * 100,
    )

    assert len(payload.encode("utf-8")) <= _DIAGNOSTIC_LIMIT_BYTES
    assert unapproved_value not in payload
    assert '"job_state":"unknown"' in payload
    assert payload.count('"pid"') == 2
    assert payload.count('"function"') <= 32
    assert '"stage":"shutdown_wait"' in payload
    assert '"thread_name":"ThreadPoolExecutor-0_0"' in payload
    assert _safe_stack([(unapproved_value, 1)]) == []


def test_postcondition_diagnostic_preserves_the_original_assertion() -> None:
    stream = io.StringIO()
    original = AssertionError("original assertion")
    with pytest.raises(AssertionError) as raised:
        with _diagnose_cancellation_assertions(
            lambda: _format_cancellation_diagnostic(
                stage="postconditions",
                timings_ms={},
                job_state="queued",
                endpoint_entered=False,
                endpoint_path_count=0,
                slow_body_seen=False,
                http_workers=[],
                close_alive=False,
                close_stack=[],
                callback_thread_id=None,
                callback_thread_name=None,
                callback_alive=False,
                callback_stack=[],
            ),
            stream,
        ):
            raise original

    assert raised.value is original
    assert stream.getvalue().startswith("provider-cancellation-diagnostic=")
    assert '"stage":"postconditions"' in stream.getvalue()


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("autonomy", ["assist", "auto"])
@pytest.mark.parametrize("signal", ["cancel", "close"])
def test_in_flight_job_proposal_is_cancelled_and_reaped_without_fallback(
    tmp_path: Path,
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
    kind: AIProviderKind,
    autonomy: str,
    signal: str,
) -> None:
    url, entered, paths = endpoint
    provider = replace(
        _provider_config(kind), endpoint=f"{url}/slow-body", timeout_seconds=300, max_retries=5
    )
    config = replace(load_config(ROOT / "config/bluefire.example.yaml"), ai=_ai_config(provider))
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        config=config,
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
    )
    # Missing consent cannot start a worker, even for this authored local endpoint.
    denied = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
    assert denied["code"] == "live_authorization_required"
    assert not entered.is_set() and not paths and not workers
    grant = service.authorize_ai(
        authorization_request(
            provider,
            purposes=["bluefire_ai_proposal"],
            local_endpoint_authorized=True,
            limits={
                "max_requests": 1,
                "max_request_bytes": 500_000,
                "max_reserved_output_tokens": provider.max_output_tokens,
            },
        )
    )["authorization"]
    # The shipped composition is under test: no injected provider or HTTP transport.
    diagnostic_started = time.monotonic()
    callback_observation: dict[str, Any] = {
        "thread_id": None,
        "thread_name": None,
        "started_at": None,
        "finished_at": None,
        "job_state": None,
    }
    callback_observation_lock = threading.Lock()
    original_callback = service.job_controller._default_callback
    assert original_callback is not None

    def observed_callback(*args: Any, **kwargs: Any) -> Any:
        started_at = time.monotonic()
        current_thread = threading.current_thread()
        with callback_observation_lock:
            callback_observation.update(
                thread_id=current_thread.ident,
                thread_name=current_thread.name,
                started_at=started_at,
                job_state="running",
            )
        try:
            return original_callback(*args, **kwargs)
        finally:
            with callback_observation_lock:
                callback_observation["finished_at"] = time.monotonic()

    monkeypatch.setattr(service.job_controller, "_default_callback", observed_callback)
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": autonomy,
            "ai_provider_id": provider.id,
        }
    )
    job_id = submission["job"]["job_id"]
    initial_job_state = submission["job"].get("state")
    original_cancel = service.job_controller.cancel

    def observed_cancel(target_job_id: str) -> Mapping[str, Any]:
        snapshot = original_cancel(target_job_id)
        if target_job_id == job_id:
            state = snapshot.get("state")
            if isinstance(state, str):
                with callback_observation_lock:
                    callback_observation["job_state"] = state
        return snapshot

    monkeypatch.setattr(service.job_controller, "cancel", observed_cancel)
    errors: list[BaseException] = []
    stage = {"name": "before_endpoint"}
    marks: dict[str, float] = {}

    def mark(name: str) -> None:
        marks[name] = time.monotonic()

    def diagnostic_payload() -> str:
        if callback_observation_lock.acquire(timeout=0.005):
            try:
                observed = dict(callback_observation)
            finally:
                callback_observation_lock.release()
        else:
            observed = {}
        http_workers: list[tuple[int | None, int | None, bool]] = []
        for process in workers[:2]:
            try:
                returncode = process.poll()
                http_workers.append((process.pid, returncode, returncode is None))
            except BaseException:
                http_workers.append((None, None, False))

        def thread_stack(thread_id: int | None) -> list[tuple[str, int]]:
            rows = []
            frame = sys._current_frames().get(thread_id) if thread_id is not None else None
            while frame is not None and len(rows) < 16:
                rows.append((frame.f_code.co_name, frame.f_lineno))
                frame = frame.f_back
            return rows

        callback_thread_id = observed.get("thread_id")
        callback_thread_id = callback_thread_id if type(callback_thread_id) is int else None
        timings_ms = {}
        if "endpoint_wait_started" in marks and "endpoint_wait_finished" in marks:
            timings_ms["endpoint_wait_ms"] = (
                marks["endpoint_wait_finished"] - marks["endpoint_wait_started"]
            ) * 1000
        if "endpoint_entered" in marks:
            timings_ms["submit_to_endpoint_ms"] = (
                marks["endpoint_entered"] - diagnostic_started
            ) * 1000
        callback_started_at = observed.get("started_at")
        if isinstance(callback_started_at, (int, float)):
            timings_ms["submit_to_callback_ms"] = (callback_started_at - diagnostic_started) * 1000
            callback_finished_at = observed.get("finished_at")
            if isinstance(callback_finished_at, (int, float)):
                timings_ms["callback_runtime_ms"] = (
                    callback_finished_at - callback_started_at
                ) * 1000
        request_end = marks.get("shutdown_join_started", marks.get("job_cancel_requested"))
        if request_end is not None and "endpoint_entered" in marks:
            timings_ms["request_active_ms"] = (request_end - marks["endpoint_entered"]) * 1000
        if "shutdown_join_started" in marks and "shutdown_join_finished" in marks:
            timings_ms["shutdown_join_ms"] = (
                marks["shutdown_join_finished"] - marks["shutdown_join_started"]
            ) * 1000
        if "job_wait_started" in marks and "job_wait_finished" in marks:
            timings_ms["job_wait_ms"] = (
                marks["job_wait_finished"] - marks["job_wait_started"]
            ) * 1000
        elif "job_wait_started" in marks:
            timings_ms["job_wait_ms"] = (time.monotonic() - marks["job_wait_started"]) * 1000
        thread_name = observed.get("thread_name")
        thread_name = thread_name if isinstance(thread_name, str) else None
        return _format_cancellation_diagnostic(
            stage=stage["name"],
            timings_ms=timings_ms,
            job_state=(
                observed.get("job_state")
                if isinstance(observed.get("job_state"), str)
                else initial_job_state if isinstance(initial_job_state, str) else "unknown"
            ),
            endpoint_entered=entered.is_set(),
            endpoint_path_count=len(paths),
            slow_body_seen="/slow-body" in paths,
            http_workers=http_workers,
            close_alive=closer.is_alive(),
            close_stack=thread_stack(closer.ident),
            callback_thread_id=callback_thread_id,
            callback_thread_name=thread_name,
            callback_alive=callback_started_at is not None and observed.get("finished_at") is None,
            callback_stack=thread_stack(callback_thread_id),
        )

    def close() -> None:
        try:
            service.close()
        except BaseException as exc:
            errors.append(exc)

    closer = threading.Thread(target=close, daemon=True)
    try:
        mark("endpoint_wait_started")
        endpoint_reached = entered.wait(4)
        mark("endpoint_wait_finished")
        with _diagnose_cancellation_assertions(diagnostic_payload, sys.stderr):
            assert endpoint_reached, "proposal never reached the local endpoint"
        stage["name"] = "request_active"
        mark("endpoint_entered")
        started = time.monotonic()
        if signal == "close":
            stage["name"] = "shutdown_wait"
            mark("shutdown_join_started")
            closer.start()
            closer.join(timeout=3)
            mark("shutdown_join_finished")
            with _diagnose_cancellation_assertions(diagnostic_payload, sys.stderr):
                assert not closer.is_alive(), "service shutdown waited for the provider timeout"
        else:
            stage["name"] = "job_cancellation"
            service.cancel_job(job_id)
            mark("job_cancel_requested")
        stage["name"] = "job_settlement"
        mark("job_wait_started")
        with _diagnose_cancellation_assertions(diagnostic_payload, sys.stderr):
            result = service.job_controller.wait(job_id, timeout=3)
        mark("job_wait_finished")
        with _diagnose_cancellation_assertions(diagnostic_payload, sys.stderr):
            assert time.monotonic() - started < 3
        stage["name"] = "postconditions"
        with _diagnose_cancellation_assertions(diagnostic_payload, sys.stderr):
            assert result["state"] == "cancelled"
            assert not errors
            assert len(workers) == 1 and workers[0].poll() is not None
            assert paths == ["/slow-body"]
            retained = service.ai_authorizations()["authorizations"][0]
            assert retained["authorization_id"] == grant["authorization_id"]
            assert retained["usage"]["requests"] == 1
            run = service.store.get_run(result["progress"]["run_id"])
            assert result["result_ref"] == run["run_id"]
            assert result["progress"]["run_status"] == "cancelled"
            assert run["status"] == "cancelled"
            assert run["finalized_at"] and run["manifest"]
            assert service.store.validate_bundle(run["run_id"])["valid"]
            assert run["steps"] and run["evidence"]["records"]
            assert result["progress"]["completed_steps"] == len(run["steps"])
            assert "objective_reached" not in run
            assert run["objective_evaluation"]["status"] == "not_evaluated"
            assert any(row["run_id"] == run["run_id"] for row in service.product_store.list_runs())
            assert not any(event["event_type"] == "ai.proposal" for event in run["events"])
            if signal == "cancel":
                # A job signal must not poison the service's other provider operations.
                success_provider = replace(
                    _provider_config(AIProviderKind.OPENAI_RESPONSES), endpoint=f"{url}/success"
                )
                service.authorize_ai(
                    authorization_request(success_provider, local_endpoint_authorized=True)
                )
                checked = service.check_ai_provider(
                    {
                        "provider": success_provider.to_dict(),
                        "connect": True,
                    }
                )
                assert checked["code"] == "probe_passed"
    finally:
        # Even a regression must not leave a configured 300-second child behind.
        def refuse(*args: Any, **kwargs: Any) -> bytes:
            raise AIProviderCancelled()

        monkeypatch.setattr(UrllibAIJSONTransport, "post", refuse)
        for process in workers:
            if process.poll() is None:
                process.kill()
        service.close()
        if closer.ident is not None:
            closer.join(timeout=3)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("signal", ["cancel", "close"])
def test_retry_delay_is_interruptible_and_never_becomes_a_fallback(
    kind: AIProviderKind, signal: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = ManagedAIJSONTransport()
    cancelled = threading.Event()
    transport = owner.bind(cancelled)
    waiting = threading.Event()
    original_wait = transport.cancellation.wait

    def wait(delay: float) -> bool:
        if delay == 2.0:
            waiting.set()
        return original_wait(delay)

    monkeypatch.setattr(transport.cancellation, "wait", wait)
    fake = FakeTransport(*(AIProviderTransportError("retry", retryable=True) for _ in range(4)))
    provider = build_ai_provider(
        _ai_config(_provider_config(kind)),
        transport=fake,
        cancel_event=transport.cancellation,
    )
    monkeypatch.setattr(
        DeterministicOfflineProvider,
        "propose",
        lambda *args: pytest.fail("cancelled proposal invoked deterministic fallback"),
    )
    errors: list[BaseException] = []

    def propose() -> None:
        try:
            provider.propose(_request(AutonomyLevel.AUTO))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=propose, daemon=True)
    try:
        thread.start()
        assert waiting.wait(4)
        started = time.monotonic()
        owner.close() if signal == "close" else cancelled.set()
        thread.join(timeout=0.75)
        assert not thread.is_alive()
        assert time.monotonic() - started < 0.75
        assert len(fake.calls) == 4
        assert len(errors) == 1 and isinstance(errors[0], AIProviderCancelled)
    finally:
        owner.close()
        thread.join(timeout=2)


@pytest.mark.parametrize("kind", KINDS)
def test_response_racing_cancellation_cannot_return_a_proposal(kind: AIProviderKind) -> None:
    cancelled = threading.Event()

    class Transport:
        def post(self, *args: Any, **kwargs: Any) -> bytes:
            cancelled.set()
            return canonical_json_bytes(_envelope(kind, _proposal()))

    provider = build_ai_provider(
        _ai_config(_provider_config(kind)), transport=Transport(), cancel_event=cancelled
    )
    with pytest.raises(AIProviderCancelled):
        provider.propose(_request(AutonomyLevel.AUTO))


@pytest.mark.parametrize("kind", KINDS)
def test_cancelled_credential_readiness_does_not_fall_back(kind: AIProviderKind) -> None:
    cancelled = threading.Event()
    cancelled.set()
    provider = build_ai_provider(
        _ai_config(_provider_config(kind, authenticated=True)),
        environ={},
        cancel_event=cancelled,
    )
    with pytest.raises(AIProviderCancelled):
        provider.propose(_request(AutonomyLevel.ASSIST))
