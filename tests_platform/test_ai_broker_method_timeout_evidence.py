"""Real timeout traceback, authored snapshots and no service or worker effects."""

import json
import threading
from types import SimpleNamespace

import pytest

from bluefire.config import AIProviderKind
from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController
from tests_platform import test_ai_broker_graph_assistance as evidence
from tests_platform import test_ai_broker_method_comparison as target

SENSITIVE = "private-credential-request-environment-job-id"


def actual_timeout(snapshot):
    controller = RunJobController.__new__(RunJobController)
    controller._condition = threading.Condition()
    controller._store = SimpleNamespace(get_job=lambda _job_id: snapshot)
    try:
        controller.wait_for_state(SENSITIVE, {JobState.COMPLETED}, timeout=0)
    except JobWaitTimeout as error:
        error.args = (SENSITIVE,)
        return error
    pytest.fail("the authored running job must time out")


def test_timeout_snapshot_and_worker_functions_emit_only_fixed_labels(monkeypatch, capsys):
    timeout = actual_timeout(
        {
            "state": "running",
            "job_id": SENSITIVE,
            "result_ref": SENSITIVE,
            "request": {"credential": SENSITIVE},
            "progress": {
                "phase": SENSITIVE,
                "operation_phase": "comparing_detections",
                "comparison": SENSITIVE,
            },
        }
    )
    frame = SimpleNamespace(
        f_code=SimpleNamespace(co_filename="/private/credential/source.py", co_name="_connection"),
        f_lineno=7,
        f_locals={"credential": SENSITIVE},
        f_back=SimpleNamespace(
            f_code=SimpleNamespace(co_filename=SENSITIVE, co_name=SENSITIVE),
            f_locals={"data": SENSITIVE},
            f_back=None,
        ),
    )
    monkeypatch.setattr(evidence.sys, "_current_frames", lambda: {SENSITIVE: frame})
    custom_error = type(SENSITIVE, (RuntimeError,), {})(SENSITIVE)
    evidence._timeout_evidence(
        "before_cleanup",
        SimpleNamespace(calls=[target.PURPOSE, SENSITIVE]),
        SimpleNamespace(is_alive=lambda: True),
        [custom_error],
        timeout=timeout,
        wait_stage="replay_wait",
    )
    output = capsys.readouterr().out
    assert SENSITIVE not in output and "/private" not in output and "source.py" not in output
    assert "credential" not in output and len(output.encode()) < 2048
    assert json.loads(output.removeprefix("Broker timeout evidence: ")) == {
        "phase": "before_cleanup",
        "wait_stage": "replay_wait",
        "last_wait_job": {
            "available": True,
            "state": "running",
            "phase": "unknown",
            "operation_phase": "comparing_detections",
            "has_result_ref": True,
            "has_comparison": True,
        },
        "thread_functions": [["_connection", "other"]],
        "purposes": [target.PURPOSE, "unknown"],
        "broker_worker_alive": True,
        "broker_error_types": ["other"],
    }


@pytest.mark.parametrize("diagnostic_fails", [False, True])
def test_replay_timeout_preserves_wait_exception_and_cleanup(
    monkeypatch, tmp_path, capsys, diagnostic_fails
):
    timeout = actual_timeout({"state": "running", "progress": {"phase": "planning"}})
    order = []
    worker = SimpleNamespace(alive=True)
    worker.is_alive = lambda: worker.alive

    def join(seconds):
        assert seconds == 3
        order.append("join")
        worker.alive = False

    worker.join = join
    transport = SimpleNamespace(post=None, requests=[SENSITIVE])

    def wait(job_id, *, timeout):
        assert timeout == 15
        order.append(job_id)
        if job_id == "proposal":
            return {"job_id": job_id, "state": "completed", "progress": {}}
        raise original_timeout

    original_timeout = timeout
    service = SimpleNamespace(
        method_comparison_context=lambda _run: {"source_binding_digest": SENSITIVE},
        detection_candidate=lambda _candidate: {"candidate": {"digest": SENSITIVE}},
        submit_method_comparison=lambda *_args: {"job": {"job_id": "proposal"}},
        decide_method_comparison=lambda *_args: {"replay_job": {"job_id": "replay"}},
        job_controller=SimpleNamespace(wait=wait),
        close=lambda: order.append("close"),
    )
    monkeypatch.setattr(target, "BlueFireService", lambda **_kwargs: service)
    monkeypatch.setattr(target, "authorize_service", lambda *_args: None)
    monkeypatch.setattr(target, "product_config", lambda _enrollment: None)
    monkeypatch.setattr(target, "ManagedRunnerLifecycle", lambda _path: None)
    monkeypatch.setattr(target, "source_run", lambda *_args: SENSITIVE)
    monkeypatch.setattr(target, "query_candidate", lambda *_args: SENSITIVE)
    monkeypatch.setattr(target, "decision", lambda _job: {})
    monkeypatch.setattr(
        target.support,
        "start",
        lambda *_args: (
            SimpleNamespace(id=SENSITIVE),
            None,
            None,
            transport,
            worker,
            [RuntimeError(SENSITIVE)],
        ),
    )
    monkeypatch.setattr(evidence.sys, "_current_frames", lambda: {})
    original_evidence = evidence._timeout_evidence

    def record(phase, *args, **kwargs):
        order.append(phase)
        original_evidence(phase, *args, **kwargs)

    monkeypatch.setattr(target, "_timeout_evidence", record)
    if diagnostic_fails:

        def refused_output(*_args, **_kwargs):
            raise RuntimeError(SENSITIVE)

        monkeypatch.setattr(evidence, "print", refused_output, raising=False)
    with pytest.raises(JobWaitTimeout) as caught:
        target.test_method_job_uses_fixed_enrolled_schema(
            tmp_path, None, AIProviderKind.CHAT_COMPLETIONS, monkeypatch
        )
    assert caught.value is original_timeout
    assert order == ["proposal", "replay", "before_cleanup", "close", "join", "cleanup_exit"]
    output = capsys.readouterr().out
    assert SENSITIVE not in output and str(tmp_path) not in output
    if diagnostic_fails:
        assert output == ""
    else:
        before, after = [
            json.loads(line.removeprefix("Broker timeout evidence: "))
            for line in output.splitlines()
        ]
        assert (
            before["wait_stage"] == "replay_wait" and before["last_wait_job"]["phase"] == "planning"
        )
        assert before["broker_worker_alive"] is True
        assert after["cleanup_completed"] is True and after["broker_worker_alive"] is False
