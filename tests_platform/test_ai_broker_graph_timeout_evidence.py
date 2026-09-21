"""Timeout metadata preserves the failure and existing cleanup without exposing content."""

import json
from types import SimpleNamespace

import pytest

from bluefire.config import AIProviderKind
from bluefire.job_runtime import JobWaitTimeout
from tests_platform import test_ai_broker_graph_assistance as target


@pytest.mark.parametrize("diagnostic_fails", [False, True])
def test_timeout_retains_original_failure_and_sanitized_cleanup_evidence(
    tmp_path, monkeypatch, capsys, diagnostic_fails
):
    order = []
    sensitive = "never-print-provider-request-or-error-message"
    timeout = JobWaitTimeout(sensitive)
    worker = SimpleNamespace(alive=True)
    worker.is_alive = lambda: worker.alive

    def join(seconds):
        assert seconds == 3
        order.append("join")
        worker.alive = False

    worker.join = join
    fixture = SimpleNamespace(calls=[target.PURPOSE, sensitive])
    transport = SimpleNamespace(post=None)
    service = SimpleNamespace(
        assistance_graph_context=lambda: {"selected": {}, "context_digest": "synthetic"},
        close=lambda: order.append("close"),
    )
    monkeypatch.setattr(target, "BlueFireService", lambda **_kwargs: service)
    monkeypatch.setattr(target, "authorize_service", lambda *_args: None)
    monkeypatch.setattr(target, "product_config", lambda _enrollment: None)
    monkeypatch.setattr(target, "ManagedRunnerLifecycle", lambda _path: None)
    monkeypatch.setattr(target, "Access", lambda: fixture)
    monkeypatch.setattr(
        target.support,
        "start",
        lambda *_args: (
            SimpleNamespace(id="synthetic"),
            None,
            None,
            transport,
            worker,
            [RuntimeError(sensitive)],
        ),
    )

    def fail_proposal(*_args):
        raise timeout

    monkeypatch.setattr(target, "proposed", fail_proposal)
    frame = SimpleNamespace(
        f_code=SimpleNamespace(co_filename="/private/source/test_fixture.py", co_name="fixture"),
        f_lineno=7,
        f_back=None,
        f_locals={"credential": sensitive},
    )
    monkeypatch.setattr(target.sys, "_current_frames", lambda: {123: frame})
    original_evidence = target._timeout_evidence

    def record_evidence(phase, *args, **kwargs):
        order.append(phase)
        original_evidence(phase, *args, **kwargs)

    monkeypatch.setattr(target, "_timeout_evidence", record_evidence)
    if diagnostic_fails:

        def unavailable_output(*_args, **_kwargs):
            raise RuntimeError(sensitive)

        monkeypatch.setattr(target, "print", unavailable_output, raising=False)
    with pytest.raises(JobWaitTimeout) as caught:
        target.test_enrolled_graph_turn_and_proposal_retain_native_review_boundary(
            tmp_path, None, AIProviderKind.OPENAI_RESPONSES, monkeypatch, "new"
        )
    assert caught.value is timeout
    assert order == ["before_cleanup", "close", "join", "cleanup_exit"]
    output = capsys.readouterr().out
    assert sensitive not in output and "/private/source" not in output
    assert "credential" not in output
    if diagnostic_fails:
        assert output == ""
        return
    before, after = [
        json.loads(line.removeprefix("Broker timeout evidence: ")) for line in output.splitlines()
    ]
    assert before == {
        "phase": "before_cleanup",
        "thread_stacks": [[{"file": "test_fixture.py", "function": "fixture", "line": 7}]],
        "purposes": [target.PURPOSE, "unknown"],
        "broker_worker_alive": True,
        "broker_error_types": ["RuntimeError"],
    }
    assert after == {
        "phase": "cleanup_exit",
        "purposes": [target.PURPOSE, "unknown"],
        "broker_worker_alive": False,
        "broker_error_types": ["RuntimeError"],
        "cleanup_completed": True,
    }
