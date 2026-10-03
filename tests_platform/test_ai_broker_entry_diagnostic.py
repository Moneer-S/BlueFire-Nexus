"""Finite cached broker-entry evidence without changing the original wait or cleanup."""

import inspect
import json
import threading
from concurrent.futures import Future
from types import SimpleNamespace

import pytest

from bluefire.ai_broker import BrokeredAIProviderAccess
from bluefire.ai_broker_contract import BrokerEnrollment
from bluefire.job_runtime import RunJobController, _JobControl
from tests_platform import test_ai_broker_service as broker


def specimen():
    controller = object.__new__(RunJobController)
    controller._closed = False
    control = _JobControl("private-job-id", {}, lambda *_args: None, False)
    control.future = Future()
    controller._controls = {control.job_id: control}
    enrollment = object.__new__(BrokerEnrollment)
    object.__setattr__(enrollment, "expires_at_ms", 10**15)
    channel = broker.DeterministicBroker(enrollment)
    access = object.__new__(BrokeredAIProviderAccess)
    access._cancel = threading.Event()
    return SimpleNamespace(job_controller=controller), access, channel, control, control.job_id


@pytest.mark.parametrize(
    "state", ["PENDING", "RUNNING", "CANCELLED", "CANCELLED_AND_NOTIFIED", "FINISHED"]
)
def test_future_labels_never_claim_persisted_job_outcome(monkeypatch, state):
    args = specimen()
    args[3].future._state = state
    args[3].slot_released = True
    args[0].job_controller._controls.clear()
    monkeypatch.setattr(broker.sys, "_current_frames", lambda: {})
    observed = broker._broker_entry_evidence(*args)
    assert observed["future_state_cached"] == state
    assert observed["control_available"] is True and observed["control_registered"] is False
    assert observed["slot_released"] is True
    assert observed["job_outcome"] == "not_observed"
    assert observed["selected_worker_observed"] is False


def test_missing_already_released_control_stays_unknown(monkeypatch):
    service, access, channel, control, job_id = specimen()
    control.future._state = "FINISHED"
    service.job_controller._controls.clear()
    monkeypatch.setattr(broker.sys, "_current_frames", lambda: {})
    observed = broker._broker_entry_evidence(service, access, channel, None, job_id)
    assert observed["control_available"] is False
    assert observed["control_registered"] is None
    assert observed["future_state_cached"] == "unknown"
    assert observed["slot_released"] is None
    assert observed["job_outcome"] == "not_observed"


@pytest.mark.parametrize(
    "relationship", ["selected", "different_control", "different_controller", "same_name"]
)
def test_worker_evidence_requires_exact_code_and_both_object_identities(monkeypatch, relationship):
    args = specimen()
    controller, control = args[0].job_controller, args[3]
    records = []

    class StopCapture(BaseException):
        pass

    class CaptureCondition:
        def __enter__(self):
            frame = inspect.currentframe().f_back
            monkeypatch.setattr(broker.sys, "_current_frames", lambda: {7: frame})
            records.append(broker._broker_entry_evidence(*args))
            raise StopCapture

        def __exit__(self, *_args):
            pytest.fail("capture stops before entering the condition")

    target = controller
    if relationship == "different_controller":
        target = object.__new__(RunJobController)
    target._condition = CaptureCondition()
    target_control = control
    if relationship == "different_control":
        target_control = _JobControl(control.job_id, {}, lambda *_args: None, False)

    def _run_job(self, control):
        with self._condition:
            pytest.fail("capture should not execute a job body")

    call = _run_job if relationship == "same_name" else RunJobController._run_job
    with pytest.raises(StopCapture):
        call(target, target_control)
    observed = records[0]
    assert observed["selected_worker_observed"] is (relationship == "selected")
    assert bool(observed["selected_worker_functions"]) is (relationship == "selected")
    if relationship == "selected":
        assert observed["selected_worker_functions"][0] == "_run_job"


@pytest.mark.parametrize("report_section", [False, True])
def test_scan_and_request_bounds_omit_private_values(monkeypatch, capsys, report_section):
    args = specimen()
    private_value = "synthetic-private-value:/operator/provider-request"
    args[3].future._state = private_value
    args[3].cancel_requested = private_value
    args[3].cancel_event._flag = 1
    args[2].requests = [{"kind": "post", "body": private_value}] * 31 + [
        {"kind": private_value}
    ] * 9
    args[2].closed = private_value
    frame = None
    for _ in range(25):
        frame = SimpleNamespace(f_code=SimpleNamespace(co_name=private_value), f_back=frame)
    monkeypatch.setattr(broker.sys, "_current_frames", lambda: {i: frame for i in range(9)})
    sections = []
    sink = (lambda *row: sections.append(row)) if report_section else None
    broker._report_broker_entry(*args, add_report_section=sink)
    captured = capsys.readouterr()
    assert captured.err == ""
    if report_section:
        assert captured.out == "" and len(sections) == 1
        when, title, output = sections[0]
        assert (when, title) == ("call", "Broker entry diagnostic")
    else:
        assert sections == []
        output = captured.out.removeprefix("Broker entry diagnostic: ")
    assert len(output) <= 4096
    assert private_value not in output and args[4] not in output
    observed = json.loads(output)
    assert observed["future_state_cached"] == "unknown"
    assert observed["cancel_requested"] is None and observed["control_cancel_flag"] is None
    assert observed["channel_closed"] is None
    assert observed["request_counts"] == {
        "post": 31,
        "unknown": 1,
        "readiness": 0,
        "authorize": 0,
        "revoke": 0,
    }
    assert observed["requests_truncated"] is True
    assert observed["thread_scan_truncated"] is True and observed["frame_scan_truncated"] is True
    assert observed["selected_worker_functions"] == []


@pytest.mark.parametrize("expired", [False, True])
def test_expiry_is_only_a_current_boolean_and_unsupported_lists_are_unknown(monkeypatch, expired):
    args = specimen()
    args[2].requests = object()
    monkeypatch.setattr(
        broker, "time", SimpleNamespace(time_ns=lambda: (10**15 - (not expired)) * 1_000_000)
    )
    monkeypatch.setattr(broker.sys, "_current_frames", lambda: {})
    observed = broker._broker_entry_evidence(*args)
    assert observed["enrollment_expired"] is expired
    assert observed["request_list_available"] is False and observed["requests_truncated"] is None
    assert sum(observed["request_counts"].values()) == 0
    assert observed["job_outcome"] == "not_observed"


@pytest.mark.parametrize("report_failure", ["none", "inspection", "output"])
@pytest.mark.parametrize("wait_failure", ["false", "original_assertion"])
def test_original_entry_assertion_and_cleanup_survive_reporter_failure(
    monkeypatch, tmp_path, report_failure, wait_failure, capsys
):
    service, access, channel, control, job_id = specimen()
    original = AssertionError("original authored assertion")
    closed = []
    reported = []
    real_report = broker._report_broker_entry
    sections = []

    def add_report_section(*args):
        if report_failure == "output":
            raise OSError("synthetic diagnostic output failure")
        sections.append(args)

    request = SimpleNamespace(node=SimpleNamespace(add_report_section=add_report_section))

    def wait(seconds):
        assert seconds == 3
        if wait_failure == "original_assertion":
            raise original
        return False

    def report(*args, **kwargs):
        assert args == (service, access, channel, control, job_id)
        assert kwargs == {"add_report_section": add_report_section}
        reported.append(True)
        real_report(*args, **kwargs)

    def broken_inspection(*_args):
        raise KeyboardInterrupt("synthetic diagnostic failure")

    channel.entered = SimpleNamespace(wait=wait)
    service.submit_run = lambda _request: {"job": {"job_id": job_id}}
    service.close = lambda: closed.append(True)
    monkeypatch.setattr(
        broker,
        "setup",
        lambda _path: (SimpleNamespace(id="authored-provider"), service, access, channel),
    )
    monkeypatch.setattr(broker, "_report_broker_entry", report)
    if report_failure == "inspection":
        monkeypatch.setattr(broker, "_broker_entry_evidence", broken_inspection)
    with pytest.raises(AssertionError) as refused:
        broker.test_normal_job_cancellation_drains_broker_without_publishing_a_late_proposal(
            tmp_path, "close", request, monkeypatch
        )
    if wait_failure == "original_assertion":
        assert refused.value is original
    else:
        # Pytest adds assertion introspection after the unchanged authored message.
        assert (
            str(refused.value).splitlines()[0] == "normal job did not reach broker proposal request"
        )
    assert closed == [True] and reported == [True]
    assert capsys.readouterr() == ("", "")
    assert [row[1] for row in sections] == {
        "none": ["Broker entry diagnostic", "Broker job startup"],
        "inspection": ["Broker job startup"],
        "output": [],
    }[report_failure]


@pytest.mark.parametrize("signal", ["cancel", "close"])
def test_successful_original_caller_keeps_assertions_without_reporting(
    monkeypatch, tmp_path, signal, capsys
):
    service, access, channel, control, job_id = specimen()
    closed, cancelled, waits = [], [], []
    channel.entered = SimpleNamespace(wait=lambda seconds: seconds == 3)
    channel.requests = [{"kind": "post"}]
    service.submit_run = lambda _request: {"job": {"job_id": job_id}}
    service.close = lambda: closed.append(True)
    service.cancel_job = lambda selected: cancelled.append(selected)
    service.store = SimpleNamespace(get_run=lambda _run_id: {"events": []})
    service.check_ai_provider = lambda _request: {"code": "probe_passed"}

    def terminal_wait(selected, timeout):
        waits.append((selected, timeout))
        return {"state": "cancelled", "progress": {"run_id": "authored-run"}}

    service.job_controller.wait = terminal_wait
    monkeypatch.setattr(
        broker,
        "setup",
        lambda _path: (
            SimpleNamespace(id="authored-provider", to_dict=lambda: {}),
            service,
            access,
            channel,
        ),
    )
    monkeypatch.setattr(
        broker,
        "_report_broker_entry",
        lambda *_args: pytest.fail("successful entry must not report"),
    )
    sections = []
    request = SimpleNamespace(
        node=SimpleNamespace(add_report_section=lambda *args: sections.append(args))
    )
    broker.test_normal_job_cancellation_drains_broker_without_publishing_a_late_proposal(
        tmp_path, signal, request, monkeypatch
    )
    assert sections == [] and capsys.readouterr() == ("", "")
    assert waits == [(job_id, 3)]
    assert cancelled == ([job_id] if signal == "cancel" else [])
    assert closed == ([True] if signal == "cancel" else [True, True])
