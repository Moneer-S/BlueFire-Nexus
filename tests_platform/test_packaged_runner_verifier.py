from __future__ import annotations

import hashlib
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


@pytest.mark.parametrize("category", ["private-category", ["timeout"], {"timeout": True}])
def test_failure_diagnostic_ignores_unknown_or_unhashable_pair_category(category):
    error = RuntimeError("private detail")
    error.diagnostic_category = category

    payload = verifier._failure_diagnostic("windows_pair_capability", error)

    assert "failure_category" not in json.loads(payload)
    assert "private-category" not in payload
    assert "timeout" not in payload
    assert "private detail" not in payload


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


def test_cli_sanitizes_actual_api_error_from_signed_alias_stage(monkeypatch, tmp_path, capsys):
    from bluefire.application_errors import APIError

    sensitive = "private credential and subprocess output"
    private_path = str(tmp_path / "private-store")

    def refused_smoke(_args):
        verifier._stage("alias_execute")
        raise APIError(
            403,
            sensitive,
            sensitive + private_path,
            details={"path": private_path, "output": sensitive * 10_000},
        ) from ValueError(private_path)

    monkeypatch.setattr(verifier, "smoke_installed_runner", refused_smoke)
    code = verifier._cli(
        ["smoke", "--work-root", str(tmp_path / "work"), "--forbid-root", private_path]
    )

    captured = capsys.readouterr()
    assert code == 2 and not captured.out
    assert sensitive not in captured.err and str(tmp_path) not in captured.err
    assert "Traceback" not in captured.err and len(captured.err.encode("utf-8")) < 1024
    lines = captured.err.splitlines()
    assert len(lines) == 2 and lines[0] == "packaged runner verification failed"
    assert json.loads(lines[1]) == {
        "schema_version": "bluefire.packaged-runner-failure.v1",
        "phase": "signed_alias",
        "reason": "alias_execution_failed",
        "exception_types": ["APIError", "ValueError"],
    }


@pytest.mark.parametrize("boundary", ["main", "diagnostic"])
@pytest.mark.parametrize("control", [KeyboardInterrupt(), SystemExit(7)])
def test_cli_preserves_process_control_exceptions(monkeypatch, capsys, boundary, control):
    def interrupted(*_args):
        raise control

    def refused(_argv):
        raise ValueError("private original failure")

    monkeypatch.setattr(verifier, "main", interrupted if boundary == "main" else refused)
    monkeypatch.setattr(verifier, "_failure_diagnostic", interrupted)
    with pytest.raises(type(control)) as raised:
        verifier._cli([])
    assert raised.value is control
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == ("" if boundary == "main" else "packaged runner verification failed\n")


def test_cli_preserves_argument_parser_exit(monkeypatch, capsys):
    monkeypatch.setattr(
        verifier, "smoke_installed_runner", lambda _args: pytest.fail("handler must not run")
    )
    with pytest.raises(SystemExit) as raised:
        verifier._cli(["smoke"])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert not captured.out and "usage:" in captured.err
    assert "packaged runner verification failed" not in captured.err


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


@pytest.fixture
def installed_smoke_boundary(monkeypatch, tmp_path):
    """Synthetic OS/process boundary; real verifier and capability parser only."""
    import bluefire
    from bluefire import runner_bootstrap, runner_client
    from bluefire import windows_file_access_enrollment_setup as setup
    from tests_platform.test_windows_file_access_setup_lifecycle import synthetic_query_capability

    package = tmp_path / "installed" / "bluefire"
    package.mkdir(parents=True)
    init = package / "__init__.py"
    init.write_text("# synthetic installed package\n", encoding="ascii")
    binary = package / "bluefire-runner.exe"
    binary.write_bytes(b"synthetic image, never executed")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    args = SimpleNamespace(work_root=tmp_path / "work", forbid_root=checkout, report=None)
    state = {"platform": "windows", "architecture": "x86_64", "fault": None}
    query_calls, execute_calls, reports = [], [], []
    monkeypatch.setattr(bluefire, "__file__", str(init))
    monkeypatch.delenv("BLUEFIRE_RUNNER_BINARY", raising=False)
    monkeypatch.delenv("BLUEFIRE_SANDBOX_ROOT", raising=False)
    monkeypatch.setattr(runner_bootstrap, "current_platform", lambda: state["platform"])

    def bootstrap(**kwargs):
        assert kwargs["environ"] == {}
        return SimpleNamespace(
            binary_path=binary,
            manifest=SimpleNamespace(
                platform=state["platform"],
                architecture=state["architecture"],
                runner_version="0.1.0",
            ),
            public_status=lambda: {"state": "ready", "source": "packaged"},
        )

    class FakeRunner:
        def __init__(self, actual_binary, *_a, **_k):
            assert actual_binary == binary

        def inventory(self):
            return {
                "runner_id": "bluefire-rust-runner.v1",
                "runner_version": "0.1.0",
                "platform": state["platform"],
                "actions": [],
            }

        def execute(self, manifest, _profile):
            execute_calls.append(manifest["action_id"])
            fixture = args.work_root / "sandbox" / "fixtures" / "smoke.jsonl"
            if len(execute_calls) == 1:
                fixture.parent.mkdir()
                raw = (
                    json.dumps(
                        {
                            "record_id": "synthetic-001",
                            "synthetic": True,
                            "template": "telemetry-seed",
                            "value": "telemetry-value-001",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    + b"\n"
                )
                fixture.write_bytes(raw)
                return {
                    "status": "success",
                    "receipt_ids": ["synthetic-receipt"],
                    "output": {
                        "artifact": "fixtures/smoke.jsonl",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                        "template": "telemetry-seed",
                        "record_count": 1,
                        "format": "jsonl",
                    },
                }
            fixture.unlink()
            cleanup = {
                "requested_receipts": 1,
                "verified_receipts": 1,
                "verification_performed": True,
                "errors": [],
                "retained_paths": [],
            }
            return {"status": "success", "cleanup": cleanup, "output": cleanup}

    def query(command, **kwargs):
        query_calls.append(command)
        assert command == [str(binary), "windows-file-baseline-worker-capability"]
        assert kwargs["stdin"] == setup.subprocess.DEVNULL and kwargs["shell"] is False
        assert kwargs["timeout"] == 5.0
        fault = state["fault"]
        if fault == "timeout":
            raise setup.subprocess.TimeoutExpired(command, 5.0)
        if fault == "launch":
            raise OSError("private executable path")
        row = synthetic_query_capability(setup.enrollment._PAIR_SETUP)
        if fault == "old":
            row = synthetic_query_capability(setup.enrollment._READER_SETUP)
        if fault == "unsupported":
            row["supported"] = False
        raw = json.dumps(row).encode()
        if fault == "malformed":
            raw = b"private malformed"
        elif fault == "oversize":
            raw = b"x" * 1025
        kwargs["stdout"].write(raw)
        if fault == "stderr":
            kwargs["stderr"].write(b"private capability stderr")
        if fault == "after_deadline":
            setup.time.monotonic = lambda: 106.0
        return SimpleNamespace(returncode=4 if fault == "exit" else 0)

    monkeypatch.setattr(runner_bootstrap, "bootstrap_runner", bootstrap)
    monkeypatch.setattr(runner_client, "SubprocessRustRunner", FakeRunner)
    monkeypatch.setattr(setup.subprocess, "run", query)
    monkeypatch.setattr(setup.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(
        verifier, "_smoke_signed_package_alias", lambda *_a: {"remaining_file_count": 0}
    )
    monkeypatch.setattr(verifier, "_write_report", lambda _path, report: reports.append(report))
    return args, state, query_calls, execute_calls, reports, binary


@pytest.mark.parametrize(
    "platform,architecture",
    [("windows", "x86_64"), ("linux", "x86_64"), ("macos", "x86_64"), ("windows", "aarch64")],
)
def test_installed_smoke_queries_only_windows_x86_pair_support_and_preserves_old_flow(
    installed_smoke_boundary, platform, architecture
):
    args, state, calls, executions, reports, binary = installed_smoke_boundary
    state.update(platform=platform, architecture=architecture)
    assert verifier.smoke_installed_runner(args) == 0
    assert executions == ["sandbox.fixture.create.v1", "sandbox.cleanup.v1"]
    assert len(reports) == 1 and reports[0]["verified"] is True
    if platform == "windows" and architecture == "x86_64":
        assert calls == [[str(binary), "windows-file-baseline-worker-capability"]]
        capability = reports[0]["windows_pair_worker"]
        assert capability["scope"] == "protocol_support_only" and len(capability) == 16
        assert "readiness" not in capability and "enrollment" not in capability
    else:
        assert calls == [] and "windows_pair_worker" not in reports[0]


@pytest.mark.parametrize(
    ("fault", "category"),
    [
        ("old", "contract_mismatch"),
        ("unsupported", "contract_mismatch"),
        ("exit", "nonzero_exit"),
        ("stderr", "stderr_nonempty"),
        ("malformed", "output_malformed"),
        ("oversize", "output_oversize"),
        ("timeout", "timeout"),
        ("launch", "launch_failure"),
        ("after_deadline", "deadline_expired"),
    ],
)
def test_installed_pair_capability_failure_precedes_fixture_and_has_sanitized_diagnostic(
    installed_smoke_boundary, fault, category, capsys
):
    args, state, calls, executions, reports, _binary = installed_smoke_boundary
    state["fault"] = fault
    assert (
        verifier._cli(
            ["smoke", "--work-root", str(args.work_root), "--forbid-root", str(args.forbid_root)]
        )
        == 2
    )
    assert len(calls) == 1 and executions == [] and reports == []
    captured = capsys.readouterr()
    assert (
        not captured.out
        and "private" not in captured.err
        and str(args.work_root) not in captured.err
    )
    diagnostic = json.loads(captured.err.splitlines()[1])
    assert diagnostic["phase"] == "protocol_support"
    assert diagnostic["reason"] == "windows_pair_capability_invalid"
    assert diagnostic["failure_category"] == category


def test_pair_capability_invalid_deadline_is_classified_without_launch(
    installed_smoke_boundary,
):
    from bluefire import windows_file_access_enrollment_setup as setup

    _args, _state, calls, _executions, _reports, binary = installed_smoke_boundary
    with pytest.raises(setup.contract.NativeWireError) as invalid:
        setup._query_capability_for(binary, "0.1.0", None, setup.enrollment._PAIR_SETUP)
    assert invalid.value.diagnostic_category == "invalid_deadline"
    with pytest.raises(setup.contract.NativeWireError) as expired:
        setup._query_capability_for(binary, "0.1.0", 100.0, setup.enrollment._PAIR_SETUP)
    assert expired.value.diagnostic_category == "deadline_expired"
    with pytest.raises(setup.contract.NativeWireError) as unbounded:
        setup._query_capability_for(binary, "0.1.0", 106.0, setup.enrollment._PAIR_SETUP)
    assert unbounded.value.diagnostic_category == "invalid_deadline"
    assert calls == []
