from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from bluefire.cross_platform_wheel import _write_member
from tools import verify_packaged_runner as verifier
from tools.verify_packaged_runner import _disposable_workspace_proof, _native_runner_members


def test_failure_diagnostic_is_bounded_and_never_emits_unapproved_values():
    sensitive = "private path credential environment subprocess output"
    unapproved_type = type(sensitive, (RuntimeError,), {})
    error = unapproved_type(sensitive * 10_000)
    error.__cause__ = RuntimeError(sensitive)
    error.__cause__.__context__ = ValueError(sensitive)
    error.__cause__.__context__.__cause__ = error
    payload = verifier._failure_diagnostic(sensitive, error, {"state": sensitive})

    assert sensitive not in payload
    assert len(payload.encode("utf-8")) < 1024
    assert json.loads(payload) == {
        "schema_version": "bluefire.packaged-runner-failure.v1",
        "phase": "unknown",
        "reason": "verification_failed",
        "exception_types": ["other", "RuntimeError", "ValueError"],
    }


@pytest.mark.parametrize("failure", ["exception", "status"])
def test_smoke_bootstrap_failure_reports_safe_phase_without_starting_runner(
    monkeypatch, tmp_path, capsys, failure
):
    import bluefire.runner_bootstrap as bootstrap
    import bluefire.runner_client as client

    sensitive = "private credential or local path"

    def refused_bootstrap(**_kwargs):
        if failure == "exception":
            try:
                raise client.RunnerTransportError(sensitive)
            except client.RunnerTransportError as exc:
                raise bootstrap.RunnerBootstrapError(sensitive) from exc
        return SimpleNamespace(
            public_status=lambda: {
                "state": sensitive,
                "source": "environment_override",
                "code": sensitive,
                "path": sensitive,
            }
        )

    monkeypatch.setattr(bootstrap, "bootstrap_runner", refused_bootstrap)
    monkeypatch.setattr(
        client, "SubprocessRustRunner", lambda *_a, **_k: pytest.fail("runner must not start")
    )
    monkeypatch.delenv("BLUEFIRE_RUNNER_BINARY", raising=False)
    monkeypatch.delenv("BLUEFIRE_SANDBOX_ROOT", raising=False)
    checkout = tmp_path / "unused-checkout"
    checkout.mkdir()
    code = verifier._cli(
        ["smoke", "--work-root", str(tmp_path / "work"), "--forbid-root", str(checkout)]
    )

    captured = capsys.readouterr()
    assert code == 2 and not captured.out
    assert sensitive not in captured.err and str(tmp_path) not in captured.err
    lines = captured.err.splitlines()
    assert lines[0] == "packaged runner verification failed"
    diagnostic = json.loads(lines[1])
    assert diagnostic["phase"] == "bootstrap"
    if failure == "exception":
        assert diagnostic["reason"] == "bootstrap_failed"
        assert diagnostic["exception_types"] == ["RunnerBootstrapError", "RunnerTransportError"]
        assert "bootstrap" not in diagnostic
    else:
        assert diagnostic["reason"] == "packaged_readiness_invalid"
        assert diagnostic["bootstrap"] == {
            "state": "unknown",
            "source": "environment_override",
        }


def test_diagnostic_capture_failure_preserves_cli_refusal(monkeypatch, capsys):
    def refused(_argv):
        raise ValueError("private original failure")

    def broken_diagnostic(*_args):
        raise RuntimeError("private diagnostic failure")

    monkeypatch.setattr(verifier, "main", refused)
    monkeypatch.setattr(verifier, "_failure_diagnostic", broken_diagnostic)
    assert verifier._cli([]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "private" not in captured.err
    assert json.loads(captured.err.splitlines()[1])["capture"] == "failed"


def test_successful_cli_keeps_the_original_report_and_exit_status(monkeypatch, capsys):
    def successful(_argv):
        verifier._write_report(None, {"verified": True})
        return 0

    monkeypatch.setattr(verifier, "main", successful)
    assert verifier._cli([]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"verified": True}
    assert not captured.err


def test_packaged_wheel_refuses_foreign_native_runner_sibling() -> None:
    root = "bluefire_nexus-3.0.0.data/purelib/bluefire/native"
    with pytest.raises(RuntimeError, match="exactly one target-native runner"):
        _native_runner_members(
            [f"{root}/bluefire-runner.exe", f"{root}/bluefire-runner"],
            "bluefire-runner.exe",
        )


def test_wheel_member_extraction_preserves_binary_bytes(tmp_path) -> None:
    payload = b"MZ\n\x1a\n\x00binary\r\npayload\n"
    destination = tmp_path / "bluefire-runner.exe"

    _write_member(destination, payload)

    assert destination.read_bytes() == payload


def test_disposable_workspace_proof_is_sanitized_and_machine_checkable(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = tmp_path / "runner-temp" / "bluefire-wheel-smoke-state"
    sandbox = work_root / "sandbox"
    checkout.mkdir()
    sandbox.mkdir(parents=True)

    proof = _disposable_workspace_proof(
        work_root=work_root,
        checkout=checkout,
        sandbox=sandbox,
        remaining_files=[],
        signed_alias={"remaining_file_count": 0},
    )

    assert proof == {
        "schema_version": "bluefire.disposable-workspace-proof.v1",
        "work_root": {
            "role": "ci-temp-disposable",
            "outside_checkout": True,
            "path": "omitted",
        },
        "source": {
            "wheel_imported_outside_checkout": True,
            "source_overrides_absent": True,
        },
        "sandboxes": [
            {
                "name": "fixture-smoke",
                "relative_scope": "sandbox",
                "inside_work_root": True,
                "remaining_file_count": 0,
            },
            {
                "name": "signed-alias-smoke",
                "relative_scope": "alias-sandbox",
                "inside_work_root": True,
                "remaining_file_count": 0,
            },
        ],
    }
    serialized = repr(proof)
    assert str(tmp_path) not in serialized
    assert str(checkout) not in serialized
    assert str(work_root) not in serialized


def test_disposable_workspace_proof_refuses_checkout_work_root(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = checkout / "wheel-smoke-state"
    sandbox = work_root / "sandbox"
    sandbox.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="outside the checkout"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=sandbox,
            remaining_files=[],
            signed_alias={"remaining_file_count": 0},
        )


def test_disposable_workspace_proof_refuses_escaped_or_dirty_sandbox(tmp_path):
    checkout = tmp_path / "checkout"
    work_root = tmp_path / "runner-temp" / "bluefire-wheel-smoke-state"
    escaped_sandbox = tmp_path / "other" / "sandbox"
    retained = work_root / "sandbox" / "leak.txt"
    checkout.mkdir()
    work_root.mkdir(parents=True)
    escaped_sandbox.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="inside the disposable root"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=escaped_sandbox,
            remaining_files=[],
            signed_alias={"remaining_file_count": 0},
        )

    with pytest.raises(RuntimeError, match="retained files"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=work_root / "sandbox",
            remaining_files=[retained],
            signed_alias={"remaining_file_count": 0},
        )

    with pytest.raises(RuntimeError, match="retained file count"):
        _disposable_workspace_proof(
            work_root=work_root,
            checkout=checkout,
            sandbox=work_root / "sandbox",
            remaining_files=[],
            signed_alias={},
        )
