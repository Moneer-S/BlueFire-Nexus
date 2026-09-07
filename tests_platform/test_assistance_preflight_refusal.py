"""Durable native preparation diagnostics without authority or extra work."""

import threading
import time
from http import HTTPStatus

import pytest

from bluefire.ai_assistance import OUTPUT_SCHEMA, PURPOSE
from bluefire.ai_broker_contract import BrokerEnrollment
from bluefire.application_errors import APIError
from bluefire.prepared_lab_enrollment import product_config
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_assistance_saved_runs import run_context
from tests_platform.test_graph_ai_jobs import ROOT
from tests_platform.test_graph_ai_jobs import setup as setup


def settled(service, request):
    parent = service.submit_assistance_turn(request)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=20)
    child_id = parent["progress"]["children"]["step-1"]["job_id"]
    return parent, service.job_controller.wait(child_id, timeout=20)


def test_refused_report_survives_reopen_without_preparation_or_run(setup, tmp_path, monkeypatch):
    service, access, body = setup
    request = run_context(service, access, body)
    original = service.preflight
    report = None

    def refused(value):
        nonlocal report
        report = dict(original(value))
        report["problems"] = [
            "Runner inventory is unavailable; verify the selected runner and retry."
        ]
        report["findings"] = list(report["problems"])
        return report

    monkeypatch.setattr(service, "preflight", refused)
    parent, child = settled(service, request)
    assert child["state"] == "failed"
    envelope = service.assistance_run_job(child["job_id"])
    refusal = child["progress"]["preflight_refusal"]
    assert refusal["code"] == "run_preflight_refused" and refusal["preflight"] == report
    assert refusal["context_digest"] == request["context_digest"]
    assert refusal["run_request_digest"].startswith("sha256:")
    assert not envelope["review_ready"]
    assert all(
        envelope[key] is None for key in ("preparation", "decision", "run_job", "inspection_job")
    )
    assert not service.list()["runs"]
    calls = list(access.calls)
    service.close()
    reopened = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
    )
    try:
        retained = reopened.assistance_run_job(child["job_id"])
        assert retained["job"]["progress"]["preflight_refusal"] == refusal
        assert not retained["review_ready"] and retained["run_job"] is None
        assert not reopened.list()["runs"] and access.calls == calls
    finally:
        reopened.close()


@pytest.mark.parametrize("boundary", ["fresh", "preflight"])
def test_safe_api_error_before_report_is_retained_without_nested_details(
    setup, monkeypatch, boundary
):
    service, access, body = setup
    request = run_context(service, access, body)

    def unavailable(*_args):
        raise APIError(
            HTTPStatus.CONFLICT,
            "runner_inventory_unavailable",
            "Runner inventory is unavailable. Start the selected runner.",
            details={"private": "must not persist provider payload or personal paths"},
        )

    if boundary == "fresh":
        monkeypatch.setattr(service.assistance_runs, "_fresh", unavailable)
    else:
        monkeypatch.setattr(service, "preflight", unavailable)
    _, child = settled(service, request)
    assert child["state"] == "failed"
    refusal = child["progress"]["preflight_refusal"]
    assert refusal["code"] == "runner_inventory_unavailable"
    assert refusal["message"] == "Runner inventory is unavailable. Start the selected runner."
    assert refusal["preflight"] is None and refusal["run_request_digest"] is None
    assert "private" not in str(refusal) and "details" not in refusal
    assert not service.list()["runs"]


def test_stop_during_preflight_cannot_publish_refusal_or_preparation(setup, monkeypatch):
    service, access, body = setup
    request = run_context(service, access, body)
    entered, release = threading.Event(), threading.Event()

    def held(_value):
        entered.set()
        assert release.wait(10)
        return {"problems": ["Runner inventory is unavailable."], "findings": []}

    monkeypatch.setattr(service, "preflight", held)
    parent = service.submit_assistance_turn(request)["job"]
    assert entered.wait(10)
    parent = service.job_controller.wait(parent["job_id"], timeout=10)
    child_id = parent["progress"]["children"]["step-1"]["job_id"]
    try:
        service.cancel_job(parent["job_id"])
    finally:
        release.set()
    child = service.job_controller.wait(child_id, timeout=20)
    assert child["state"] == "cancelled"
    assert "preflight_refusal" not in child["progress"] and "preparation" not in child["progress"]
    assert not service.list()["runs"]


@pytest.mark.parametrize(
    "runtime_provider", [None, "deterministic-offline.v1", "missing-provider.v1"]
)
def test_actual_enrolled_off_configuration_retains_dangling_refusal_without_model_substitution(
    setup, runtime_provider
):
    service, access, body = setup
    provider = service._runtime_ai().provider(body["provider_id"])
    enrollment = BrokerEnrollment.create(
        provider,
        session_id="a" * 64,
        expires_at_ms=time.time_ns() // 1_000_000 + 60_000,
        schemas=((PURPOSE, content_hash(OUTPUT_SCHEMA)),),
        destination_policy="explicit_endpoint",
    )
    actual = product_config(enrollment)
    service._runtime_ai_config = actual.ai
    assert actual.ai.provider("deterministic-offline.v1").kind.value == "deterministic"
    request = run_context(service, access, body)
    request["selection"]["run_intent"]["ai_provider_id"] = runtime_provider
    request["context_digest"] = service.assistance_run_context({"selection": request["selection"]})[
        "context_digest"
    ]
    _, child = settled(service, request)
    envelope = service.assistance_run_job(child["job_id"])
    if runtime_provider == "missing-provider.v1":
        assert child["state"] == "failed" and envelope["preparation"] is None
        refusal = child["progress"]["preflight_refusal"]
        assert refusal["code"] == "ai_provider_not_found" and refusal["preflight"] is None
    else:
        assert child["state"] == "completed" and envelope["review_ready"]
        assert envelope["preparation"]["run_request"]["ai_provider_id"] == runtime_provider
    assert envelope["run_job"] is None and not service.list()["runs"]
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft", PURPOSE]
