"""Authored child tokens and timeout objects; no subprocess or service starts."""

import json
import subprocess

import pytest

from tests_platform import assistance_run_recovery_diagnostics as diagnostic
from tests_platform import test_assistance_run_recovery as fixture

PRIVATE = "PRIVATE_PATH_PROVIDER_REQUEST_JOB_ID_MUST_NOT_APPEAR"


def emit_timeout(capsys, stderr):
    timeout = subprocess.TimeoutExpired([PRIVATE], 45, stderr=stderr)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        with diagnostic.process_loss_timeout_diagnostics():
            raise timeout
    assert caught.value is timeout
    output = capsys.readouterr().out
    assert PRIVATE not in output and len(output.encode()) < 2048
    return json.loads(output.removeprefix("Process-loss diagnostic: "))


def test_child_events_are_unbuffered_fixed_tokens_and_preserve_error(monkeypatch):
    writes = []
    monkeypatch.setattr(diagnostic.os, "write", lambda fd, data: writes.append((fd, data)))
    original = ValueError(PRIVATE)
    with pytest.raises(ValueError) as caught:
        with diagnostic.record_child_failure():
            diagnostic.record_phase("review")
            raise original
    assert caught.value is original
    assert writes == [
        (2, b"BF_PROCESS_LOSS:phase:review\n"),
        (2, b"BF_PROCESS_LOSS:error:ValueError\n"),
    ]


def test_unknown_exception_never_renders_its_message(monkeypatch):
    class PrivateError(Exception):
        def __str__(self):
            pytest.fail("Exception text was accessed")

    writes = []
    monkeypatch.setattr(diagnostic.os, "write", lambda _fd, data: writes.append(data))
    original = PrivateError(PRIVATE)
    with pytest.raises(PrivateError) as caught:
        with diagnostic.record_child_failure():
            raise original
    assert caught.value is original
    assert writes == [b"BF_PROCESS_LOSS:error:unknown\n"]


@pytest.mark.parametrize("failure_site", ["write", "emitter"])
def test_child_diagnostic_failure_preserves_normal_flow_and_original_error(
    monkeypatch, failure_site
):
    def unavailable(*_args):
        raise KeyboardInterrupt(PRIVATE)

    if failure_site == "write":
        monkeypatch.setattr(diagnostic.os, "write", unavailable)
    else:
        monkeypatch.setattr(diagnostic, "_emit", unavailable)
    diagnostic.record_phase("service_init")
    original = RuntimeError(PRIVATE)
    with pytest.raises(RuntimeError) as caught:
        with diagnostic.record_child_failure():
            raise original
    assert caught.value is original


def test_parent_accepts_only_complete_allowlisted_tokens(capsys):
    stderr = (
        b"BF_PROCESS_LOSS:phase:imports\nBF_PROCESS_LOSS:phase:graph_prepare\n"
        b"BF_PROCESS_LOSS:error:JobWaitTimeout\nBF_PROCESS_LOSS:phase:graph_prepare\n"
        + PRIVATE.encode()
        + b"\nBF_PROCESS_LOSS:phase:"
        + PRIVATE.encode()
        + b"\n"
        + b"BF_PROCESS_LOSS:phase:review:extra\nBF_PROCESS_LOSS:phase:\xff\n"
    )
    report = emit_timeout(capsys, stderr)
    assert report["phases_seen"] == ["imports", "graph_prepare"]
    assert report["exception_categories"] == ["JobWaitTimeout"]
    assert report["captured_stderr_available"] is True
    assert report["capture_truncated"] is False
    assert report["capture_incomplete"] is False
    assert report["rejected_event"] is True


@pytest.mark.parametrize("stderr", [None, PRIVATE, {"content": PRIVATE}])
def test_absent_or_nonbyte_capture_remains_unknown(capsys, stderr):
    report = emit_timeout(capsys, stderr)
    assert report["phases_seen"] == report["exception_categories"] == []
    assert report["captured_stderr_available"] is False


@pytest.mark.parametrize("stderr", [b"x" * 4096, b"ignored\n" * 32])
def test_capture_limits_cannot_admit_late_events(capsys, stderr):
    report = emit_timeout(capsys, stderr + b"\nBF_PROCESS_LOSS:phase:marker_written\n")
    assert report["phases_seen"] == []
    assert report["capture_truncated"] is True


@pytest.mark.parametrize("truncated", [False, True])
def test_unterminated_token_never_becomes_a_valid_phase(capsys, truncated):
    token = b"BF_PROCESS_LOSS:phase:marker_written"
    if truncated:
        stderr = b"x" * (4096 - len(token) - 1) + b"\n" + token + PRIVATE.encode() + b"\n"
    else:
        stderr = token
    report = emit_timeout(capsys, stderr)
    assert report["phases_seen"] == []
    assert report["capture_incomplete"] is True
    assert report["capture_truncated"] is truncated
    assert report["rejected_event"] is True


@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
@pytest.mark.parametrize("boundary", ["run_link", "inspection_published"])
@pytest.mark.parametrize("reporter_fails", [False, True])
def test_actual_fixture_keeps_outer_timeout_options_and_exception(
    tmp_path, monkeypatch, capsys, kind, boundary, reporter_fails
):
    original = subprocess.TimeoutExpired([PRIVATE], 45, stderr=b"BF_PROCESS_LOSS:phase:run_wait\n")
    calls = []

    def timeout(args, **kwargs):
        calls.append(args)
        assert args[0] == fixture.sys.executable and args[1] == "-c"
        assert args[3:] == [
            str(tmp_path / "crash.sqlite3"),
            str(tmp_path / "marker.json"),
            kind,
            boundary,
        ]
        assert kwargs == {
            "cwd": fixture.ROOT,
            "capture_output": True,
            "timeout": 45,
            "check": False,
        }
        raise original

    monkeypatch.setattr(fixture.subprocess, "run", timeout)
    if reporter_fails:

        def unavailable(*_args):
            raise OSError(PRIVATE)

        monkeypatch.setattr(diagnostic, "_report", unavailable)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        fixture.test_process_loss_after_run_link_or_inspection_publication_resumes_only_retained_run(
            tmp_path, kind, boundary, monkeypatch
        )
    assert caught.value is original and len(calls) == 1
    assert not (tmp_path / "marker.json").exists()
    output = capsys.readouterr().out
    assert PRIVATE not in output
    if reporter_fails:
        assert output == ""
    else:
        assert json.loads(output.removeprefix("Process-loss diagnostic: "))["phases_seen"] == [
            "run_wait"
        ]


def test_success_and_unrelated_exception_do_not_report(monkeypatch):
    def unexpected(*_args):
        pytest.fail("Unexpected diagnostic")

    monkeypatch.setattr(diagnostic, "_report", unexpected)
    with diagnostic.process_loss_timeout_diagnostics():
        result = "unchanged"
    assert result == "unchanged"
    original = ValueError(PRIVATE)
    with pytest.raises(ValueError) as caught:
        with diagnostic.process_loss_timeout_diagnostics():
            raise original
    assert caught.value is original
