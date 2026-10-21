"""Pure bounds and receipt checks for the installed Assistant cancellation proof."""

from __future__ import annotations

import hashlib
import os
import signal
from copy import deepcopy
from pathlib import Path

import pytest

from tools.verify_installed_cancellation import (
    _report_passed,
    cleanup_confirmed,
    digest,
    safe_driver_report,
    stop_group,
    valid_fixture_request,
)


def test_browser_driver_allows_only_bounded_optional_graph_step_context() -> None:
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "tests"
        / "installed"
        / "installed-cancellation.mjs"
    ).read_text(encoding="utf-8")
    assert 'exactKeys(body, ["kind", "base_scenario", "edit_step"])' in driver
    assert 'exactKeys(editStep, ["scenario", "step_id", "dirty"])' in driver
    assert "bodySize <= 1_048_576" in driver
    assert "postedGraphSelection = structuredClone(body)" in driver
    assert (
        'assert.deepEqual(expectedContext.selected, { kind: "graph", base_scenario: null })'
        in driver
    )


def fixture_request() -> dict[str, object]:
    return {
        "model": "bluefire-local-cancel-fixture-v1",
        "instructions": "bounded fixture instructions",
        "input": "owned local request",
        "max_output_tokens": 64,
        "store": False,
        "parallel_tool_calls": False,
        "tools": [],
        "tool_choice": "none",
        "text": {
            "format": {
                "type": "json_schema",
                "name": "bluefire_experiment_assistance",
                "schema": {"type": "object"},
                "strict": True,
            }
        },
    }


def test_fixture_accepts_only_bounded_credential_free_request() -> None:
    assert valid_fixture_request(fixture_request(), body_bytes=256, authorization=None)
    assert not valid_fixture_request(fixture_request(), body_bytes=0, authorization=None)
    assert not valid_fixture_request(
        fixture_request(), body_bytes=256, authorization="Bearer secret"
    )
    assert not valid_fixture_request(fixture_request(), body_bytes=1_048_577, authorization=None)
    extra = fixture_request()
    extra["extra"] = "not allowed"
    assert not valid_fixture_request(extra, body_bytes=256, authorization=None)


def test_digest_uses_streaming_sha256_compatible_with_python_310(tmp_path, monkeypatch) -> None:
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"installed cancellation fixture")
    monkeypatch.setattr(
        hashlib,
        "file_digest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("newer API used")),
        raising=False,
    )
    assert digest(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def driver_report() -> dict[str, object]:
    operation = {
        "job_id": "job-" + "a" * 32,
        "job_state": "cancelled",
        "turn_status": "cancelled",
        "result_count": 0,
    }
    return {
        "schema_version": "bluefire.installed-assistant-cancellation.v1",
        "status": "passed",
        "installed_service": True,
        "local_fixture_only": True,
        "live_model_inference": False,
        "native_execution": False,
        "checks": [
            "ephemeral_browser_session_connected",
            "provider_activation_and_one_request_usage_authorized_in_ui",
            "assistant_job_started_from_current_graph_context",
            "authorized_local_fixture_request_held_before_response",
            "normal_assistant_stop_reached_durable_cancelled_terminal",
            "page_reload_recovered_same_saved_cancelled_operation_from_server",
        ],
        "blocked_requests": [],
        "cancelled_operation": operation,
        "reloaded_operation": deepcopy(operation),
        "counts": {
            "session": 1,
            "provider_save": 1,
            "activation": 1,
            "authorization": 1,
            "graph_context": 1,
            "graph_context_get": 1,
            "assistance_submit": 1,
            "cancel": 1,
        },
        "browser_context_closed": True,
        "browser_closed": True,
        "cleanup_passed": True,
    }


def test_pass_receipt_requires_durable_same_operation_and_full_cleanup() -> None:
    report = driver_report()
    assert _report_passed(report)
    reloaded = deepcopy(report["reloaded_operation"])
    assert isinstance(reloaded, dict)
    reloaded["job_id"] = "job-" + "b" * 32
    report["reloaded_operation"] = reloaded
    assert not _report_passed(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("browser_closed", False),
        ("browser_context_closed", False),
        ("cleanup_passed", False),
        ("blocked_requests", [{"method": "POST", "path": "/unexpected", "reason": "unexpected"}]),
        ("native_execution", True),
    ],
)
def test_pass_receipt_rejects_incomplete_or_out_of_scope_journeys(
    field: str, value: object
) -> None:
    report = driver_report()
    report[field] = value
    assert not _report_passed(report)


def test_safe_driver_projection_rejects_bearer_fields_and_host_diagnostics() -> None:
    report = driver_report()
    assert safe_driver_report(report) is not None
    report["capability"] = "sensitive"
    assert safe_driver_report(report) is None


def test_cleanup_requires_every_owned_process_and_runtime_to_be_gone() -> None:
    cleanup = {
        "browser_process_group": "stopped",
        "fixture_thread": "stopped",
        "service_http_server": "closed",
        "service_thread": "stopped",
        "service": "closed",
        "temporary_state_removed": True,
    }
    assert cleanup_confirmed(cleanup)
    for key in cleanup:
        incomplete = deepcopy(cleanup)
        incomplete[key] = False if key == "temporary_state_removed" else "stop_failed"
        assert not cleanup_confirmed(incomplete)
    not_started = deepcopy(cleanup)
    not_started["browser_process_group"] = "not_started"
    assert cleanup_confirmed(not_started)
    assert not_started["browser_process_group"] != "stopped"


def test_preflight_cleanup_does_not_claim_unstarted_resources_stopped() -> None:
    cleanup = {
        "browser_process_group": "not_started",
        "fixture_thread": "not_started",
        "service_http_server": "not_started",
        "service_thread": "not_started",
        "service": "not_started",
        "temporary_state_removed": True,
    }
    assert cleanup_confirmed(cleanup)
    assert cleanup["browser_process_group"] == "not_started"


class ExitedProcess:
    pid = 12345

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float) -> int:
        return 0


@pytest.mark.skipif(os.name != "posix", reason="owned process groups are POSIX-only")
def test_stop_group_reaps_descendants_after_leader_exits() -> None:
    alive = True
    signals: list[int] = []

    def fake_killpg(_pgid: int, sig: int) -> None:
        nonlocal alive
        if sig == 0:
            if not alive:
                raise ProcessLookupError
            return
        signals.append(sig)
        if sig == signal.SIGTERM:
            alive = False

    assert stop_group(ExitedProcess(), killpg=fake_killpg)  # type: ignore[arg-type]
    assert signals == [signal.SIGINT, signal.SIGTERM]


@pytest.mark.skipif(os.name != "posix", reason="owned process groups are POSIX-only")
def test_stop_group_reports_descendants_that_survive_kill() -> None:
    def fake_killpg(_pgid: int, sig: int) -> None:
        if sig == 0:
            return

    assert not stop_group(ExitedProcess(), killpg=fake_killpg)  # type: ignore[arg-type]
