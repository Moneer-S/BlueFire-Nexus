from __future__ import annotations

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import verify_installed_windows_result_publication as verifier


def _junit(path: Path, *, status: str | None = None, count: int = 4) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        tests=str(count),
        failures=str(int(status == "failure")),
        errors=str(int(status == "error")),
        skipped=str(int(status == "skipped")),
    )
    for index, node in enumerate(verifier.TEST_IDS[:count]):
        file, name = node.split("::")
        case = ET.SubElement(
            suite, "testcase", classname=file[:-3].replace("/", "."), name=name, time="0.1"
        )
        if index == 0 and status:
            ET.SubElement(case, status, message="private fixture credential").text = "private trace"
        ET.SubElement(case, "system-out").text = "private captured output"
    ET.ElementTree(root).write(path, encoding="utf-8")


@pytest.mark.parametrize("status", [None, "failure", "error", "skipped"])
def test_junit_preserves_counts_but_not_sensitive_output(tmp_path, status):
    raw, public = tmp_path / "raw.xml", tmp_path / "safe.xml"
    _junit(raw, status=status)
    report = verifier._junit(raw, public)
    assert report["passed"] is (status is None)
    assert report["exact_test_ids"] and report["declared_counts_match"]
    assert report["tests"] == 4
    assert "private" not in public.read_text()
    assert "system-out" not in public.read_text()
    assert report["raw_junit_sha256"] == verifier._digest(raw)


@pytest.mark.parametrize("change", ["missing", "duplicate", "unknown", "counts"])
def test_junit_rejects_incomplete_duplicate_unknown_or_miscounted_cases(tmp_path, change):
    raw, public = tmp_path / "raw.xml", tmp_path / "safe.xml"
    _junit(raw)
    tree = ET.parse(raw)
    suite = tree.getroot()[0]
    if change == "missing":
        suite.remove(suite[-1])
    elif change == "duplicate":
        suite[-1].attrib.update(suite[0].attrib)
    elif change == "unknown":
        suite[-1].set("name", "private_unknown_test")
    else:
        suite.set("tests", "9")
    tree.write(raw)
    assert verifier._junit(raw, public)["passed"] is False
    assert "private" not in public.read_text()


@pytest.mark.parametrize(
    "raw", [b"<!DOCTYPE testsuite><testsuite/>", b"<!ENTITY x 'secret'>", b"<broken>"]
)
def test_junit_rejects_untrusted_or_malformed_xml(tmp_path, raw):
    path = tmp_path / "raw.xml"
    path.write_bytes(raw)
    with pytest.raises((ValueError, ET.ParseError)):
        verifier._junit(path, tmp_path / "safe.xml")


def test_geometry_uses_utf16_and_rejects_long_basetemp():
    report = verifier._geometry(Path("D:/t/bfn-12345678"))
    assert report["deep_pending_units"] == 323
    assert report["managed_pending_units_upper_bound"] < 240
    with pytest.raises(ValueError, match="geometry"):
        verifier._geometry(Path("D:/" + "x" * 60))


def test_environment_has_no_inherited_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "never forwarded")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "never forwarded")
    env = verifier._environment(tmp_path, "C:/Windows", "AMD64")
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert env["HOME"] == str(tmp_path / "home")
    assert env["PROCESSOR_ARCHITECTURE"] == "AMD64"
    with pytest.raises(ValueError):
        verifier._environment(tmp_path, "C:/Windows", "ARM64")


def test_failure_diagnostics_keep_normalized_numeric_context_not_messages(tmp_path):
    try:
        try:
            error = PermissionError(13, "private credential and path")
            error.winerror = 5
            error.ntstatus = 0xC0000022
            raise error
        except PermissionError:
            raise RuntimeError("private normalized message") from None
    except RuntimeError as normalized:
        plugin = verifier._FailureDiagnostics(tmp_path)
        plugin.pytest_runtest_makereport(
            SimpleNamespace(nodeid=verifier.TEST_IDS[0]),
            SimpleNamespace(when="call", excinfo=SimpleNamespace(value=normalized)),
        )
    value = json.loads((tmp_path / "failure-00.json").read_text())
    assert value["test_id"] == verifier.TEST_IDS[0]
    assert value["phase"] == "call"
    assert value["exceptions"] == [
        {"error_type": "RuntimeError"},
        {"error_type": "PermissionError", "errno": 13, "winerror": 5, "ntstatus": 0xC0000022},
    ]
    assert "private" not in json.dumps(value)


def test_failure_diagnostics_bound_cycles_types_codes_and_names(tmp_path):
    error = type("private_token", (Exception,), {})("private message")
    error.__context__ = error
    error.errno = True
    error.winerror = 2**40
    error.ntstatus = "private"
    plugin = verifier._FailureDiagnostics(tmp_path)
    for _ in range(20):
        plugin.pytest_runtest_makereport(
            SimpleNamespace(nodeid="private/path.py::private_test"),
            SimpleNamespace(when="private", excinfo=SimpleNamespace(value=error)),
        )
    assert len(list(tmp_path.glob("failure-*.json"))) == 12
    value = json.loads((tmp_path / "failure-00.json").read_text())
    assert value == {
        "test_id": "unrecognized_test",
        "phase": "unknown",
        "exceptions": [{"error_type": "Exception"}],
    }
    assert "private" not in json.dumps(value)


def _source(tmp_path):
    source = tmp_path / "archive"
    for name in ("tests_platform", "tools", "bluefire"):
        (source / name).mkdir(parents=True)
    for name in (
        "pyproject.toml",
        "bluefire/_source_revision.txt",
        "tools/" + verifier._HELPER,
        "tools/" + verifier._VERIFIER,
        "tests_platform/helper.py",
    ):
        (source / name).write_text("fixture", encoding="ascii")
    return source


def test_snapshot_binds_archived_helpers_and_configuration(tmp_path):
    source = _source(tmp_path)
    before = verifier._snapshot(source)
    assert len(before) == 5
    (source / "tests_platform/helper.py").write_text("changed")
    after = verifier._snapshot(source)
    assert verifier._snapshot_digest(before) != verifier._snapshot_digest(after)
    assert set(before) == set(after)


def test_snapshot_propagates_directory_read_failure(tmp_path, monkeypatch):
    source = _source(tmp_path)

    def failed_walk(*args, onerror, **kwargs):
        onerror(PermissionError("fixture"))

    monkeypatch.setattr(verifier.os, "walk", failed_walk)
    with pytest.raises(PermissionError):
        verifier._snapshot(source)


def test_product_module_origin_must_remain_installed(tmp_path, monkeypatch):
    package = tmp_path / "installed"
    package.mkdir()
    installed = package / "__init__.py"
    installed.write_text("fixture")
    source = tmp_path / "checkout.py"
    source.write_text("fixture")
    modules = {"bluefire": SimpleNamespace(__file__=str(installed))}
    monkeypatch.setattr(verifier, "sys", SimpleNamespace(modules=modules))
    assert set(verifier._module_origins(package)) == {"bluefire"}
    modules["bluefire.other"] = SimpleNamespace(__file__=str(source))
    with pytest.raises(ValueError, match="outside"):
        verifier._module_origins(package)


@pytest.mark.parametrize("origin", [None, "missing"])
def test_product_module_without_valid_file_fails(tmp_path, monkeypatch, origin):
    monkeypatch.setattr(
        verifier, "sys", SimpleNamespace(modules={"bluefire": SimpleNamespace(__file__=origin)})
    )
    with pytest.raises((ValueError, OSError)):
        verifier._module_origins(tmp_path)


@pytest.fixture
def identity(tmp_path, monkeypatch):
    source = _source(tmp_path)
    package = tmp_path / "installed/bluefire"
    package.mkdir(parents=True)
    revision = "a" * 40
    (source / "bluefire/_source_revision.txt").write_text(revision)
    (source / "bluefire/__init__.py").write_text("fixture")
    (package / "__init__.py").write_text("fixture")
    (package / "_build_info.json").write_text(
        json.dumps({"source_revision": revision, "source_provenance": "git_archive"})
    )
    (source / "tools" / verifier._VERIFIER).write_bytes(Path(verifier.__file__).read_bytes())
    helper = source / "tools" / verifier._HELPER
    wheel = tmp_path / "candidate.whl"
    wheel.write_bytes(b"test fixture, not a wheel")
    monkeypatch.setattr(
        verifier,
        "_load_helper",
        lambda *args: SimpleNamespace(_installed_package_matches_wheel=lambda *args: True),
    )
    monkeypatch.setattr(
        verifier.importlib.metadata,
        "distribution",
        lambda name: SimpleNamespace(version="3.0.0rc2", read_text=lambda name: None),
    )
    monkeypatch.setattr(
        verifier.sysconfig,
        "get_paths",
        lambda: {"purelib": str(package.parent), "platlib": str(package.parent)},
    )
    monkeypatch.setattr(verifier.importlib, "import_module", lambda name: None)
    monkeypatch.setattr(verifier, "_module_origins", lambda package: {"bluefire": "fixture"})
    args = argparse.Namespace(
        source=source,
        forbid_root=source.parent / "checkout",
        source_revision=revision,
        helper=helper,
        wheel=wheel,
    )
    # The archived source lives inside the forbidden checkout; the installed tree does not.
    args.forbid_root = source
    return args, package


def test_identity_binds_archive_revision_and_product_python(identity):
    args, package = identity
    found, report = verifier._installed_identity(args)
    assert found == package
    assert report["source_revision"] == "a" * 40
    assert report["wheel_sha256"] == verifier._digest(args.wheel)


@pytest.mark.parametrize(
    "mismatch",
    ["archive_revision", "build_revision", "provenance", "product", "git", "verifier", "wheel"],
)
def test_identity_refuses_mismatch(identity, monkeypatch, mismatch):
    args, package = identity
    if mismatch == "archive_revision":
        (args.source / "bluefire/_source_revision.txt").write_text("b" * 40)
    elif mismatch in {"build_revision", "provenance"}:
        info = json.loads((package / "_build_info.json").read_text())
        info["source_revision" if mismatch == "build_revision" else "source_provenance"] = "wrong"
        (package / "_build_info.json").write_text(json.dumps(info))
    elif mismatch == "product":
        (package / "__init__.py").write_text("different")
    elif mismatch == "git":
        (args.source / ".git").write_text("gitdir: nowhere")
    elif mismatch == "verifier":
        (args.source / "tools" / verifier._VERIFIER).write_text("different")
    else:
        monkeypatch.setattr(
            verifier,
            "_load_helper",
            lambda *args: SimpleNamespace(_installed_package_matches_wheel=lambda *args: False),
        )
    with pytest.raises(ValueError):
        verifier._installed_identity(args)


class _Process:
    def __init__(self, timeout=False):
        self.returncode = None
        self.timeout = timeout
        self.waits = []
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.timeout and self.returncode is None:
            raise subprocess.TimeoutExpired("fixture", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -1


class _Containment:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def create_job(self):
        self.calls.append("create")
        return 1

    def assign(self, job, process):
        self.calls.append("assign")
        if self.failure == "assign":
            raise OSError("fixture")

    def resume_suspended(self, process):
        self.calls.append("resume")
        if self.failure == "resume":
            raise OSError("fixture")

    def terminate(self, process):
        self.calls.append("terminate")
        process.kill()
        return self.failure != "finish"

    def finish(self, process):
        self.calls.append("finish")
        return self.failure != "finish"

    def close_handle(self, job):
        self.calls.append("close")
        return True


@pytest.mark.parametrize("mode", ["success", "timeout", "assign", "resume", "finish", "spawn"])
def test_supervisor_owns_suspended_child_and_bounds_cleanup(tmp_path, monkeypatch, mode):
    process = _Process(timeout=mode == "timeout")
    containment = _Containment(mode)

    def spawn(command, **options):
        assert options["creationflags"] == 0x08000004
        assert options["env"] == {"fixture": "only"}
        assert options["cwd"] == tmp_path
        if mode == "spawn":
            raise OSError("fixture")
        return process

    monkeypatch.setattr(verifier.subprocess, "Popen", spawn)
    result = verifier._supervise(
        ["fixture"], runtime=tmp_path, env={"fixture": "only"}, containment=containment
    )
    assert result["process_exited"]
    assert result["job_empty"] is (mode != "finish")
    assert result["timed_out"] is (mode == "timeout")
    assert all(timeout <= verifier._MAX_SECONDS for timeout in process.waits)
    if mode == "assign":
        assert "resume" not in containment.calls and process.killed
    if mode in {"timeout", "resume"}:
        assert "terminate" in containment.calls
    if mode == "success":
        assert containment.calls == ["create", "assign", "resume", "finish"]


def test_cleanup_refuses_nonowned_path(tmp_path):
    bad = tmp_path / "not-owned"
    bad.mkdir()
    with pytest.raises(ValueError, match="ownership"):
        verifier._cleanup(bad, tmp_path)
    assert bad.is_dir()
    owned = tmp_path / "bfn-12345678"
    owned.mkdir()
    (owned / "owned.txt").write_text("fixture")
    verifier._cleanup(owned, tmp_path)
    assert not owned.exists()


def _main_args(tmp_path):
    return [
        "--source",
        str(tmp_path),
        "--wheel",
        str(tmp_path / "candidate.whl"),
        "--helper",
        str(tmp_path / "helper.py"),
        "--forbid-root",
        str(tmp_path),
        "--output",
        str(tmp_path / "evidence"),
        "--runner-temp",
        str(tmp_path),
        "--source-revision",
        "a" * 40,
    ]


def test_failed_preflight_saves_sanitized_receipt_without_claiming_native_pass(
    tmp_path, monkeypatch
):
    def refuse():
        raise ValueError("private diagnostic must not be published")

    monkeypatch.setattr(verifier, "_require_host", refuse)
    assert verifier.main(_main_args(tmp_path)) == 1
    receipt = json.loads((tmp_path / "evidence/result-publication.json").read_text())
    assert receipt["status"] == "failed_or_incomplete"
    assert receipt["error_type"] == "ValueError"
    assert "private diagnostic" not in json.dumps(receipt)
    assert receipt["runtime_retained"] is False


def test_existing_output_is_never_overwritten(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "keep.txt").write_text("original")
    assert verifier.main(_main_args(tmp_path)) == 1
    assert list(evidence.iterdir()) == [evidence / "keep.txt"]


@pytest.mark.parametrize("changed", [False, True])
def test_worker_selects_only_four_archived_cases_and_checks_inputs_afterward(
    tmp_path, monkeypatch, changed
):
    runtime = tmp_path / "bfn-12345678"
    runtime.mkdir()
    source = _source(tmp_path)
    helper = source / "tests_platform/helper.py"
    snapshot = {"tests_platform/helper.py": verifier._digest(helper)}
    args = argparse.Namespace(runtime=runtime, runner_temp=tmp_path, source=source)
    monkeypatch.setattr(verifier, "_require_host", lambda: None)
    monkeypatch.setattr(verifier, "_geometry", lambda root: {})
    monkeypatch.setattr(
        verifier, "_installed_identity", lambda args: (tmp_path, {"exact": "fixture"})
    )
    monkeypatch.setattr(verifier, "_module_origins", lambda package: {"bluefire": "fixture"})
    monkeypatch.setattr(verifier, "_snapshot", lambda source: dict(snapshot))
    fake_sys = SimpleNamespace(
        path=[], modules={"tests_platform.helper": SimpleNamespace(__file__=str(helper))}
    )
    monkeypatch.setattr(verifier, "sys", fake_sys)

    def run(arguments, *, plugins):
        assert "--noconftest" in arguments and "--import-mode=importlib" in arguments
        assert "--timeout=60" in arguments and "--timeout-method=thread" in arguments
        assert arguments[-4:] == [
            str(source / node.split("::")[0]) + "::" + node.split("::")[1]
            for node in verifier.TEST_IDS
        ]
        assert fake_sys.path == [str(source)]
        assert len(plugins) == 1 and isinstance(plugins[0], verifier._FailureDiagnostics)
        if changed:
            snapshot["tests_platform/helper.py"] = "changed"
        return 0

    monkeypatch.setattr(pytest, "main", run)
    assert verifier._worker(args) == int(changed)
    report = json.loads((runtime / "worker.json").read_text())
    assert report["status"] == ("failed_or_incomplete" if changed else "passed")
    if not changed:
        assert report["loaded_archived_inputs"] == snapshot
        assert report["source_inputs_unchanged"] and report["installed_product_unchanged"]


@pytest.mark.parametrize("outcome", ["passed", "skipped", "timeout", "cleanup_failure"])
def test_main_requires_exact_tests_stopped_job_and_cleanup(tmp_path, monkeypatch, outcome):
    monkeypatch.setattr(verifier, "_require_host", lambda: None)
    monkeypatch.setattr(verifier, "_geometry", lambda root: {})
    monkeypatch.setattr(verifier, "_environment", lambda *args: {"SYSTEMROOT": str(tmp_path)})
    monkeypatch.setattr(verifier.os, "environ", {"SYSTEMROOT": str(tmp_path)})
    monkeypatch.setattr(
        verifier, "_installed_identity", lambda args: (tmp_path, {"exact": "fixture"})
    )
    monkeypatch.setattr(verifier, "_snapshot", lambda source: {"input": "fixture"})
    monkeypatch.setitem(
        verifier.sys.modules,
        "bluefire.runner_windows_containment",
        SimpleNamespace(WindowsJobContainment=lambda **kwargs: None),
    )

    def supervise(command, *, runtime, env, containment):
        assert "-I" in command and "-B" in command and "--worker" in command
        if outcome == "timeout":
            verifier._write_json(
                runtime / "failure-00.json",
                {
                    "test_id": verifier.TEST_IDS[0],
                    "phase": "call",
                    "exceptions": [{"error_type": "PermissionError", "winerror": 5}],
                },
            )
            return {"process_exited": True, "job_empty": True, "timed_out": True, "returncode": -1}
        _junit(runtime / "raw-junit.xml", status="skipped" if outcome == "skipped" else None)
        verifier._write_json(runtime / "worker.json", {"status": "passed"})
        return {"process_exited": True, "job_empty": True, "timed_out": False, "returncode": 0}

    monkeypatch.setattr(verifier, "_supervise", supervise)
    if outcome == "cleanup_failure":

        def refuse_cleanup(*args):
            raise PermissionError("private")

        monkeypatch.setattr(verifier, "_cleanup", refuse_cleanup)
    assert verifier.main(_main_args(tmp_path)) == (0 if outcome == "passed" else 1)
    report = json.loads((tmp_path / "evidence/result-publication.json").read_text())
    assert report["status"] == ("passed" if outcome == "passed" else "failed_or_incomplete")
    assert report["runtime_removed"] is (outcome == "passed")
    assert report["runtime_retained"] is (outcome != "passed")
    if outcome == "timeout":
        assert report["failure_diagnostics"][0]["exceptions"][0]["winerror"] == 5
    if outcome in {"passed", "cleanup_failure"}:
        assert (tmp_path / "evidence/result-publication-observations.json").is_file()


def test_workflow_uses_existing_wheel_and_sanitized_artifact_lane():
    workflow = (Path(__file__).parents[1] / ".github/workflows/tests.yml").read_text()
    start = workflow.index("      - name: Verify installed Windows native result publication")
    end = workflow.index(
        "      - name: Verify installed Windows native cancellation and cleanup", start
    )
    step = workflow[start:end]
    assert workflow.index("      - name: Set up Node.js for installed verification") < start
    assert (
        "if: always() && matrix.platform == 'windows' && steps.installed-wheel.outcome == 'success'"
        in step
    )
    assert "pytest>=9.0.3,<10" in step and "pytest-timeout>=2.4,<3" in step
    assert "bluefire-wheel-smoke/Scripts/python.exe" in step
    assert "--source-revision $env:GITHUB_SHA" in step
    assert "-I -B $verifier" in step and "'wheel-source'" in step
    assert "git " not in step and "pip install" in step
    assert "bluefire-installed-windows-result-publication-evidence/*.json" in workflow
    assert "bluefire-installed-windows-result-publication-evidence/*.xml" in workflow
