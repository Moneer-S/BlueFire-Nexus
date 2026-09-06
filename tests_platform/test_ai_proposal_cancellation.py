from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire.ai import DeterministicOfflineProvider, build_ai_provider
from bluefire.ai_transport import ManagedAIJSONTransport, UrllibAIJSONTransport
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError
from bluefire.config import AIProviderKind, AutonomyLevel, load_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes
from tests_platform.test_ai import FakeTransport, _proposal, _request
from tests_platform.test_ai_transport_deadline import endpoint as endpoint
from tests_platform.test_ai_transport_deadline import workers as workers
from tests_platform.test_ai_wire_runtime import _ai_config, _envelope, _provider_config

ROOT = Path(__file__).resolve().parents[1]
KINDS = (AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS)


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
    # The shipped composition is under test: no injected provider or HTTP transport.
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": autonomy,
            "ai_provider_id": provider.id,
        }
    )
    job_id = submission["job"]["job_id"]
    errors: list[BaseException] = []

    def close() -> None:
        try:
            service.close()
        except BaseException as exc:
            errors.append(exc)

    closer = threading.Thread(target=close, daemon=True)
    try:
        assert entered.wait(4), "proposal never reached the local endpoint"
        started = time.monotonic()
        if signal == "close":
            closer.start()
            closer.join(timeout=3)
            assert not closer.is_alive(), "service shutdown waited for the provider timeout"
        else:
            service.cancel_job(job_id)
        result = service.job_controller.wait(job_id, timeout=3)
        assert time.monotonic() - started < 3
        assert result["state"] == "cancelled"
        assert not errors
        assert len(workers) == 1 and workers[0].poll() is not None
        assert paths == ["/slow-body"]
        run = service.store.get_run(result["progress"]["run_id"])
        assert not any(event["event_type"] == "ai.proposal" for event in run["events"])
        if signal == "cancel":
            # A job signal must not poison the service's other provider operations.
            checked = service.check_ai_provider(
                {
                    "provider": replace(
                        _provider_config(AIProviderKind.OPENAI_RESPONSES),
                        endpoint=f"{url}/success",
                    ).to_dict(),
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
