from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bluefire import install_gate_browser_runtime as runtime
from bluefire import product_acceptance_process as acceptance_process
from tools import install_gate_journey_support as support


def _report() -> dict[str, Any]:
    return {
        "engine": "edge-headless",
        "browser_sandbox": "disabled-for-ephemeral-probe",
        "network_scope": "loopback-only",
        **{
            name: True
            for name in (
                "javascript_executed",
                "authenticated_root_rendered",
                "catalog_data_rendered",
                "runs_navigation_present",
                "runs_route_rendered",
                "guided_execute_rendered",
                "explicit_connection_form",
                "same_tab_reload_authenticated",
                "new_tab_requires_connection",
            )
        },
    }


class _Input(io.BytesIO):
    def close(self) -> None:
        self.retained = self.getvalue()
        super().close()


class _Process:
    def __init__(self, payload: bytes, stderr: bytes = b"") -> None:
        self.stdin = _Input()
        self.stdout = io.BytesIO(payload)
        self.stderr = io.BytesIO(stderr)
        self.returncode = 0
        self.killed = False

    def wait(self, timeout: float) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True


def _process_fixture(
    monkeypatch: pytest.MonkeyPatch, process: _Process
) -> tuple[list[Any], list[Any]]:
    launches: list[Any] = []
    terminated: list[Any] = []

    def launch(command: list[str], **kwargs: Any) -> _Process:
        launches.append((command, kwargs))
        return process

    monkeypatch.setattr(support.subprocess, "Popen", launch)
    monkeypatch.setattr(support.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    monkeypatch.setattr(support, "attach_process_tree", lambda _process: 123)
    monkeypatch.setattr(
        support, "terminate_process_tree", lambda item, job: terminated.append((item, job))
    )
    return launches, terminated


def test_browser_probe_code_uses_stdin_not_args_environment_or_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process(json.dumps(_report()).encode())
    launches, terminated = _process_fixture(monkeypatch, process)
    monkeypatch.setenv("NODE_OPTIONS", "--inspect=12345")
    monkeypatch.setenv("BLUEFIRE_BROWSER_CAPABILITY", "must-not-inherit")
    code = "C" * 64
    assert (
        support._browser_probe_result(
            ["node", "probe.mjs", "core.mjs", "edge", "profile", "8765"], code
        )
        == _report()
    )
    assert code not in repr(launches)
    assert "NODE_OPTIONS" not in launches[0][1]["env"]
    assert "BLUEFIRE_BROWSER_CAPABILITY" not in launches[0][1]["env"]
    assert json.loads(process.stdin.retained) == {"capability": code}
    assert terminated == [(process, 123)]


@pytest.mark.parametrize(
    "kind", ["overflow", "stderr", "capability", "partial", "malformed", "numeric_boolean"]
)
def test_browser_probe_rejects_unbounded_private_or_incomplete_output(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    payload = json.dumps(_report()).encode()
    stderr = b""
    if kind == "overflow":
        payload = b"x" * (16 * 1024 + 1)
    elif kind == "stderr":
        stderr = b"private diagnostic"
    elif kind == "capability":
        payload = ("C" * 64).encode()
    elif kind == "partial":
        payload = b"{}"
    elif kind == "numeric_boolean":
        payload = json.dumps({**_report(), "explicit_connection_form": 1}).encode()
    else:
        payload = b"not json"
    process = _Process(payload, stderr)
    _, terminated = _process_fixture(monkeypatch, process)
    with pytest.raises(support.SupportError, match="packaged UI runtime"):
        support._browser_probe_result(["node", "probe.mjs"], "C" * 64)
    assert terminated == [(process, 123)]
    if kind == "overflow":
        assert process.killed


def test_browser_probe_failure_before_containment_still_terminates_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process(b"")
    _, terminated = _process_fixture(monkeypatch, process)

    def fail(_process: Any) -> None:
        raise support.SupportError("containment", "containment failed")

    monkeypatch.setattr(support, "attach_process_tree", fail)
    with pytest.raises(support.SupportError, match="containment failed"):
        support._browser_probe_result(["node", "probe.mjs"], "C" * 64)
    assert terminated == [(process, None)]


def test_browser_runtime_fails_closed_without_node(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(runtime.NODE_BINARY_ENV, raising=False)
    monkeypatch.delenv(runtime.NODE_SHA256_ENV, raising=False)
    with pytest.raises(ValueError, match="Node 22"):
        runtime.browser_probe_runtime(tmp_path, tmp_path)


def test_browser_probe_timeout_always_terminates_the_contained_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process(b"")
    _, terminated = _process_fixture(monkeypatch, process)

    def timed_out(timeout: float) -> int:
        raise subprocess.TimeoutExpired("probe", timeout)

    monkeypatch.setattr(process, "wait", timed_out)
    with pytest.raises(support.SupportError, match="timed out"):
        support._browser_probe_result(["node", "probe.mjs"], "C" * 64)
    assert terminated == [(process, 123)]


def test_browser_probe_failure_removes_only_its_owned_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edge = tmp_path / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    edge.parent.mkdir(parents=True)
    edge.write_bytes(b"fixture")
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path))
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    paths = [tmp_path / name for name in ("node.exe", "index.mjs", "p.mjs")]
    for path in paths:
        path.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    neighbor = tmp_path / "preserved.txt"
    neighbor.write_text("unchanged", encoding="utf-8")

    def fail(command: list[str], capability: str) -> None:
        assert capability not in repr(command)
        assert profile.is_dir()
        raise support.SupportError("probe_failed", "probe failed")

    monkeypatch.setattr(support, "_browser_probe_result", fail)
    monkeypatch.setattr(runtime, "verify_browser_probe_runtime", lambda *_args: None)
    identity = tmp_path / "identity.json"
    identity.write_text("{}", encoding="utf-8")
    with pytest.raises(support.SupportError, match="probe failed"):
        support.probe_packaged_ui(
            8765,
            "C" * 64,
            profile,
            node=paths[0],
            module=paths[1],
            probe=paths[2],
            identity_path=identity,
        )
    assert not profile.exists()
    assert neighbor.read_text(encoding="utf-8") == "unchanged"


@pytest.fixture
def runtime_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    node = tmp_path / "node.exe"
    node.write_bytes(b"fixture")
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    lock = {
        "importers": {".": {"devDependencies": {"@playwright/test": {"version": "1.2.3"}}}},
        "snapshots": {
            "@playwright/test@1.2.3": {"dependencies": {"playwright": "1.2.3"}},
            "playwright@1.2.3": {"dependencies": {"playwright-core": "1.2.3"}},
        },
    }
    (frontend / "pnpm-lock.yaml").write_text(json.dumps(lock), encoding="utf-8")
    package = (
        frontend
        / "node_modules"
        / ".pnpm"
        / "playwright-core@1.2.3"
        / "node_modules"
        / "playwright-core"
    )
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "playwright-core", "version": "1.2.3"}), encoding="utf-8"
    )
    module = package / "index.mjs"
    module.write_text("export {};", encoding="utf-8")
    monkeypatch.setenv(runtime.NODE_BINARY_ENV, str(node))
    monkeypatch.setenv(runtime.NODE_SHA256_ENV, hashlib.sha256(b"fixture").hexdigest())
    return node, module


def test_browser_runtime_requires_exact_locked_playwright_core(
    tmp_path: Path, runtime_fixture: tuple[Path, Path]
) -> None:
    node, module = runtime_fixture
    actual_node, actual_module, identity = runtime.browser_probe_runtime(tmp_path, tmp_path)
    assert (actual_node, actual_module) == (node.resolve(), module.resolve())
    assert identity["node"]["explicit_digest_match"] is True
    assert identity["playwright_core"]["observed_files"] == 2
    runtime.verify_browser_probe_runtime(actual_node, actual_module, identity)
    package = module.parent
    (package / "package.json").write_text(
        json.dumps({"name": "playwright-core", "version": "9.9.9"}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="locked pnpm"):
        runtime.browser_probe_runtime(tmp_path, tmp_path)


@pytest.mark.parametrize(
    "change", ["relative_node", "missing_digest", "wrong_digest", "changed_node"]
)
def test_browser_runtime_rejects_unreviewed_node_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_fixture: tuple[Path, Path],
    change: str,
) -> None:
    node, _module = runtime_fixture
    if change == "relative_node":
        monkeypatch.setenv(runtime.NODE_BINARY_ENV, "node.exe")
    elif change == "missing_digest":
        monkeypatch.delenv(runtime.NODE_SHA256_ENV)
    elif change == "wrong_digest":
        monkeypatch.setenv(runtime.NODE_SHA256_ENV, "0" * 64)
    else:
        node.write_bytes(b"changed")
    with pytest.raises(ValueError):
        runtime.browser_probe_runtime(tmp_path, tmp_path)


@pytest.mark.parametrize("changed", ["node", "entry", "dependency"])
def test_browser_runtime_rechecks_observed_bytes_before_launch(
    tmp_path: Path,
    runtime_fixture: tuple[Path, Path],
    changed: str,
) -> None:
    node, module, identity = runtime.browser_probe_runtime(tmp_path, tmp_path)
    path = {"node": node, "entry": module, "dependency": module.parent / "new.js"}[changed]
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed before launch"):
        runtime.verify_browser_probe_runtime(node, module, identity)


@pytest.mark.parametrize("escape", ["package", "entry", "nested"])
def test_browser_runtime_rejects_dependency_path_escape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_fixture: tuple[Path, Path],
    escape: str,
) -> None:
    _node, module = runtime_fixture
    original = Path.resolve
    target = module.parent if escape == "package" else module
    if escape == "nested":
        target = module.parent / "lib"
        target.mkdir()

    def escaped(path: Path, strict: bool = False) -> Path:
        return tmp_path / "outside" if path == target else original(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", escaped)
    with pytest.raises(ValueError, match="confinement"):
        runtime.browser_probe_runtime(tmp_path, tmp_path)


@pytest.mark.parametrize(
    "tampering", ["private_path", "numeric_boolean", "false_claim", "unbounded"]
)
def test_browser_tooling_report_rejects_extra_fields_and_overclaims(
    tmp_path: Path,
    runtime_fixture: tuple[Path, Path],
    tampering: str,
) -> None:
    _node, _module, identity = runtime.browser_probe_runtime(tmp_path, tmp_path)
    runtime.validate_browser_tooling_report(identity)
    if tampering == "private_path":
        identity["node"]["path"] = str(tmp_path)
    elif tampering == "numeric_boolean":
        identity["node"]["explicit_digest_match"] = 1
    elif tampering == "false_claim":
        identity["playwright_core"]["integrity_scope"] = "verified by lockfile"
    else:
        identity["playwright_core"]["observed_files"] = 10001
    with pytest.raises(ValueError, match="report is invalid"):
        runtime.validate_browser_tooling_report(identity)


def test_acceptance_environment_preserves_explicit_tool_selection_not_node_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(runtime.NODE_BINARY_ENV, "reviewed-absolute-path")
    monkeypatch.setenv(runtime.NODE_SHA256_ENV, "a" * 64)
    monkeypatch.setenv("NODE_OPTIONS", "--inspect=12345")
    environment = acceptance_process._workflow_environment()
    assert environment[runtime.NODE_BINARY_ENV] == "reviewed-absolute-path"
    assert environment[runtime.NODE_SHA256_ENV] == "a" * 64
    assert "NODE_OPTIONS" not in environment


def test_browser_probe_javascript_contract_with_fake_browser() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for the fake-browser contract tests")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, "--test", str(root / "tools" / "test_install_gate_browser_probe.mjs")],
        cwd=root,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", errors="replace")[-4000:]
