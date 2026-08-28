"""Run the installed-wheel Gate 01 journey through the production HTTP surface."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.metadata
import importlib.util
import json
import os
import queue
import re
import site
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

SUMMARY_SCHEMA = "bluefire.gate01-helper-summary.v1"
PACKAGE_SCHEMA = "bluefire.gate01-installed-package.v1"
UI_SCHEMA = "bluefire.gate01-ui-health.v1"
JOURNEY_SCHEMA = "bluefire.gate01-journey.v1"
PROFILE_ID = "sandbox-restricted-owned.v1"
SCENARIO_ID = "scenario.restricted.persistence-canary.v1"
COLLECTOR_ID = "collector.filesystem.sandbox.v1"
RUNNER_ID = "bluefire-rust-runner.v1"
_LAUNCH = re.compile(
    r"^BlueFire local console: http://127\.0\.0\.1:([0-9]{1,5})/"
    r"#bluefire-session=([A-Za-z0-9_-]{64})$"
)
_MAX_HTTP_BYTES = 16 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUPPORT: Any | None = None


class JourneyError(RuntimeError):
    """A path-free failure safe to return through the acceptance log."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise JourneyError(code, message)


def _load_support(path: Path, destination: Path, forbid_root: Path) -> Any:
    # ``-I`` ignores PYTHONDONTWRITEBYTECODE, so enforce this in-process before
    # SourceFileLoader can persist a helper cache containing its absolute path.
    sys.dont_write_bytecode = True
    support_path = path.resolve(strict=True)
    evidence_root = destination.resolve(strict=True)
    checkout = forbid_root.resolve(strict=True)
    _require(
        support_path.parent == evidence_root and not support_path.is_relative_to(checkout),
        "support_module_invalid",
        "installed journey support module is outside its isolated helper directory",
    )
    spec = importlib.util.spec_from_file_location("bluefire_gate01_journey_support", support_path)
    _require(
        spec is not None and spec.loader is not None,
        "support_module_invalid",
        "installed journey support module could not be loaded",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _require(
        all(
            hasattr(module, name)
            for name in (
                "SupportError",
                "attach_process_tree",
                "cleanup_all",
                "cleanup_journey",
                "terminate_process_tree",
                "probe_packaged_ui",
                "remove_ephemeral_tree",
                "validate_preflight",
                "validate_job_approval_pointers",
                "validate_fresh_replay_approval",
                "validate_package_version",
                "validate_approval",
                "validate_run",
                "wait_for_job",
                "validate_bundles",
            )
        ),
        "support_module_invalid",
        "installed journey support module has an invalid interface",
    )
    return module


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _module_inside(module: Any, root: Path) -> bool:
    location = Path(str(module.__file__)).resolve(strict=True)
    return location.is_relative_to(root.resolve(strict=True))


def _installed_package_report(forbid_root: Path) -> dict[str, Any]:
    import cryptography
    import nacl
    import yaml

    import bluefire

    prefix = Path(sys.prefix).resolve(strict=True)
    package_root = Path(str(bluefire.__file__)).resolve(strict=True)
    purelib = Path(sysconfig.get_path("purelib")).resolve(strict=True)
    distribution = importlib.metadata.distribution("bluefire-nexus")
    _SUPPORT.validate_package_version(distribution.version, bluefire.__version__)
    direct_url = distribution.read_text("direct_url.json")
    console_name = "bluefire.exe" if os.name == "nt" else "bluefire"
    console = prefix / ("Scripts" if os.name == "nt" else "bin") / console_name
    dependency_modules = {
        "PyYAML": yaml,
        "cryptography": cryptography,
        "PyNaCl": nacl,
    }
    dependency_versions = {name: importlib.metadata.version(name) for name in dependency_modules}
    _require(sys.flags.isolated == 1, "fresh_python_not_isolated", "fresh Python is not isolated")
    _require(
        prefix != Path(sys.base_prefix).resolve(),
        "fresh_venv_missing",
        "fresh virtual environment is unavailable",
    )
    _require(
        package_root.is_relative_to(purelib) and purelib.is_relative_to(prefix),
        "wheel_import_outside_venv",
        "BlueFire was not imported from the fresh environment",
    )
    _require(
        not package_root.is_relative_to(forbid_root.resolve(strict=True)),
        "checkout_import_detected",
        "BlueFire was imported from the checkout",
    )
    _require(
        all(not Path(entry or ".").resolve().is_relative_to(forbid_root) for entry in sys.path),
        "checkout_on_sys_path",
        "the checkout is present on the isolated import path",
    )
    _require(
        all(_module_inside(module, purelib) for module in dependency_modules.values()),
        "dependency_outside_venv",
        "a runtime dependency escaped the fresh environment",
    )
    _require(
        not direct_url or '"editable": true' not in direct_url.casefold(),
        "editable_install_detected",
        "the fresh environment contains an editable BlueFire install",
    )
    _require(
        console.is_file(), "console_entrypoint_missing", "the installed console entry is missing"
    )
    return {
        "schema_version": PACKAGE_SCHEMA,
        "verified": True,
        "package_version": distribution.version,
        "fresh_environment": {
            "isolated_mode": True,
            "virtual_environment": True,
            "user_site_enabled": bool(site.ENABLE_USER_SITE),
            "package_under_environment_site": True,
            "checkout_on_import_path": False,
            "editable_install": False,
            "console_entrypoint": True,
        },
        "dependencies": dependency_versions,
        "source_overrides_absent": all(
            name not in os.environ for name in ("BLUEFIRE_RUNNER_BINARY", "BLUEFIRE_SANDBOX_ROOT")
        ),
    }


def _drain_stream(
    stream: Any,
    capability_queue: queue.Queue[tuple[int, str]],
) -> None:
    try:
        for raw_line in iter(stream.readline, ""):
            line = raw_line.rstrip("\r\n")
            match = _LAUNCH.fullmatch(line)
            if match is not None and capability_queue.empty():
                capability_queue.put_nowait((int(match.group(1)), match.group(2)))
    finally:
        stream.close()


def _discard_stream(stream: Any) -> None:
    try:
        for _line in iter(stream.readline, ""):
            pass
    finally:
        stream.close()


def _launch_ui(
    *,
    evidence_dir: Path,
    runs_dir: Path,
) -> tuple[subprocess.Popen[str], int, int, str, Mapping[str, str]]:
    runtime = evidence_dir / "runtime"
    work = runtime / "work"
    state = runtime / "state"
    temporary = runtime / "temp"
    home = runtime / "home"
    for path in (work, state, temporary, home):
        path.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "BLUEFIRE_RUNNER_BINARY",
        "BLUEFIRE_SANDBOX_ROOT",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": os.fspath(home),
            "USERPROFILE": os.fspath(home),
            "TEMP": os.fspath(temporary),
            "TMP": os.fspath(temporary),
            "LOCALAPPDATA": os.fspath(state),
            "XDG_STATE_HOME": os.fspath(state),
        }
    )
    command = [
        sys.executable,
        "-I",
        "-m",
        "bluefire.cli",
        "--runs-dir",
        os.fspath(runs_dir),
        "ui",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
    ]
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process: subprocess.Popen[str] | None = None
    job_handle: int | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=work,
            env=environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        job_handle = int(_SUPPORT.attach_process_tree(process))
        _require(
            process.stdout is not None and process.stderr is not None,
            "ui_pipes_unavailable",
            "production UI output pipes are unavailable",
        )
        capability_queue: queue.Queue[tuple[int, str]] = queue.Queue(maxsize=1)
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, capability_queue),
            name="gate01-ui-stderr",
            daemon=True,
        ).start()
        threading.Thread(
            target=_discard_stream,
            args=(process.stdout,),
            name="gate01-ui-stdout",
            daemon=True,
        ).start()
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            try:
                port, capability = capability_queue.get(timeout=0.2)
                _require(1 <= port <= 65535, "ui_port_invalid", "production UI port is invalid")
                return process, job_handle, port, capability, environment
            except queue.Empty:
                if process.poll() is not None:
                    break
        raise JourneyError("ui_launch_failed", "production UI did not announce loopback readiness")
    except BaseException:
        if process is not None:
            _SUPPORT.terminate_process_tree(process, job_handle)
        raise


def _raw_request(
    port: int,
    method: str,
    path: str,
    *,
    cookie: str | None = None,
    capability: str | None = None,
    body: Mapping[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, Mapping[str, str], bytes]:
    headers = {
        "Accept": "application/json, text/html, text/css, application/javascript",
        "Origin": f"http://127.0.0.1:{port}",
    }
    payload: bytes | None = None
    if cookie is not None:
        headers["Cookie"] = cookie
    if capability is not None:
        headers["X-BlueFire-Browser-Bootstrap"] = capability
        headers["Content-Length"] = "0"
    elif body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(payload))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        content = response.read(_MAX_HTTP_BYTES + 1)
        _require(
            len(content) <= _MAX_HTTP_BYTES,
            "http_response_too_large",
            "production HTTP response exceeded its bound",
        )
        response_headers = {key.casefold(): value for key, value in response.getheaders()}
        return response.status, response_headers, content
    except (OSError, http.client.HTTPException) as exc:
        raise JourneyError(
            "http_request_failed",
            f"production {method} {path} request failed ({type(exc).__name__})",
        ) from exc
    finally:
        connection.close()


def _json_request(
    port: int,
    method: str,
    path: str,
    *,
    cookie: str,
    body: Mapping[str, Any] | None = None,
    expected: int = 200,
    timeout: float = 60.0,
) -> Mapping[str, Any]:
    status, _headers, payload = _raw_request(
        port,
        method,
        path,
        cookie=cookie,
        body=body,
        timeout=timeout,
    )
    _require(
        status == expected,
        "http_status_unexpected",
        f"production {method} {path} returned an unexpected status",
    )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JourneyError(
            "http_json_invalid", f"production {method} {path} returned invalid JSON"
        ) from exc
    _require(
        isinstance(value, Mapping),
        "http_json_shape_invalid",
        f"production {method} {path} JSON is invalid",
    )
    return value


def _ui_health(
    port: int,
    capability: str,
) -> tuple[str, Mapping[str, Any], Mapping[str, Any], dict[str, Any]]:
    status, index_headers, index = _raw_request(port, "GET", "/")
    _require(
        status == 200
        and index_headers.get("content-type", "").startswith("text/html")
        and b'<div id="root"></div>' in index
        and b'<script type="module" crossorigin src="/ui/app.js"></script>' in index
        and b'<link rel="stylesheet" crossorigin href="/ui/styles.css">' in index,
        "ui_index_invalid",
        "packaged UI index did not load",
    )
    assets: dict[str, dict[str, Any]] = {}
    for path, marker, media_type in (
        ("/ui/app.js", b"BlueFire", ("text/javascript", "application/javascript")),
        ("/ui/styles.css", b"--", ("text/css",)),
    ):
        asset_status, asset_headers, payload = _raw_request(port, "GET", path)
        _require(
            asset_status == 200
            and len(payload) >= 512
            and marker in payload
            and asset_headers.get("content-type", "").split(";", 1)[0] in media_type,
            "ui_asset_invalid",
            "a packaged production UI asset did not load",
        )
        assets[path] = {"size_bytes": len(payload), "sha256": _sha256_bytes(payload)}
    session_status, session_headers, session_payload = _raw_request(
        port,
        "POST",
        "/api/v1/session",
        capability=capability,
    )
    set_cookie = session_headers.get("set-cookie", "")
    cookie = set_cookie.partition(";")[0]
    _require(
        session_status == 204
        and session_payload == b""
        and cookie.startswith("bluefire_session=")
        and "httponly" in set_cookie.casefold()
        and "samesite=strict" in set_cookie.casefold()
        and "path=/api/v1" in set_cookie.casefold(),
        "ui_session_invalid",
        "production UI session exchange was invalid",
    )
    replay_status, _replay_headers, _replay_payload = _raw_request(
        port,
        "POST",
        "/api/v1/session",
        capability=capability,
    )
    _require(
        replay_status == 401,
        "ui_capability_reusable",
        "production UI launch capability was reusable",
    )
    session_check, _check_headers, check_payload = _raw_request(
        port,
        "GET",
        "/api/v1/session",
        cookie=cookie,
    )
    _require(
        session_check == 204 and check_payload == b"",
        "ui_session_unhealthy",
        "production UI session health check failed",
    )
    catalog = _json_request(port, "GET", "/api/v1/catalog", cookie=cookie)
    scenarios = _json_request(port, "GET", "/api/v1/scenarios", cookie=cookie)
    scenario_rows = scenarios.get("scenarios")
    _require(
        isinstance(catalog.get("behaviors"), list)
        and isinstance(scenario_rows, list)
        and any(isinstance(row, Mapping) and row.get("id") == SCENARIO_ID for row in scenario_rows),
        "ui_catalog_unhealthy",
        "production UI catalog health check failed",
    )
    report = {
        "schema_version": UI_SCHEMA,
        "verified": True,
        "launch": {
            "command": [
                "{python}",
                "-I",
                "-m",
                "bluefire.cli",
                "--runs-dir",
                "{runs-dir}",
                "ui",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ],
            "loopback_only": True,
            "ephemeral_port": True,
            "capability_fragment_only": True,
            "capability_single_use": True,
            "strict_session_cookie": True,
        },
        "assets": assets,
        "api": {
            "session_healthy": True,
            "catalog_behavior_count": len(catalog["behaviors"]),
            "scenario_count": len(scenario_rows),
            "seeded_scenario_present": True,
        },
    }
    return cookie, catalog, scenarios, report


def _run_request() -> dict[str, Any]:
    return {
        "scenario_id": SCENARIO_ID,
        "mode": "execute",
        "autonomy": "off",
        "runner_profile_id": PROFILE_ID,
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
        "collectors": [COLLECTOR_ID],
    }


def _journey(
    port: int,
    cookie: str,
    sandbox_root: Path,
    catalog: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, str]]:
    bootstrap = _json_request(
        port,
        "POST",
        "/api/v1/runner/bootstrap",
        cookie=cookie,
        body={"profile_id": PROFILE_ID, "allow_upgrade": False},
    )
    recovered = _json_request(
        port,
        "POST",
        "/api/v1/runner/bootstrap",
        cookie=cookie,
        body={"profile_id": PROFILE_ID, "allow_upgrade": False},
    )
    runner = bootstrap.get("runner")
    binary_digest = runner.get("binary_digest") if isinstance(runner, Mapping) else None
    public_text = json.dumps([bootstrap, recovered], sort_keys=True).casefold()
    _require(
        bootstrap.get("state") == "stopped"
        and recovered.get("state") == "stopped"
        and bootstrap.get("enrollment") == "active"
        and recovered.get("enrollment") == "active"
        and isinstance(runner, Mapping)
        and runner.get("id") == RUNNER_ID
        and runner.get("source") == "packaged"
        and runner.get("managed_binary") is True
        and runner.get("managed_sandbox") is True
        and isinstance(binary_digest, str)
        and _DIGEST.fullmatch(binary_digest) is not None
        and recovered.get("runner") == runner
        and not any(word in public_text for word in ("hmac", "private_key", "certificate")),
        "runner_bootstrap_invalid",
        "packaged runner bootstrap or local trust recovery was invalid",
    )
    started = _json_request(
        port,
        "POST",
        "/api/v1/runner/start",
        cookie=cookie,
        body={"profile_id": PROFILE_ID},
        timeout=120.0,
    )
    status = _json_request(
        port,
        "GET",
        "/api/v1/runner",
        cookie=cookie,
    )
    health = status.get("health")
    _require(
        started.get("state") == "ready"
        and status.get("state") == "ready"
        and status.get("process") == "authenticated"
        and status.get("runner") == runner
        and isinstance(health, Mapping)
        and health.get("transport") == "mutual-tls-loopback"
        and health.get("tls") == "TLSv1.3"
        and health.get("runner_binary_digest") == binary_digest
        and health.get("accepting_execute") is True,
        "runner_start_invalid",
        "authenticated packaged runner readiness was invalid",
    )
    request = _run_request()
    preflight = _json_request(
        port,
        "POST",
        "/api/v1/runs/preflight",
        cookie=cookie,
        body=request,
    )
    initial_binding, initial_envelope_digest = _SUPPORT.validate_preflight(preflight, catalog)
    submission = _json_request(
        port,
        "POST",
        "/api/v1/runs",
        cookie=cookie,
        body=request,
        expected=202,
    )
    job = submission.get("job")
    approval_request = submission.get("approval_request")
    submitted_preflight = submission.get("preflight")
    _require(
        isinstance(job, Mapping)
        and job.get("state") in {"queued", "awaiting_approval"}
        and isinstance(job.get("job_id"), str)
        and isinstance(submitted_preflight, Mapping),
        "execute_job_gate_invalid",
        "Execute job did not stop at its durable approval gate",
    )
    binding, envelope_digest = _SUPPORT.validate_preflight(submitted_preflight, catalog)
    _require(
        initial_envelope_digest == envelope_digest
        and all(
            initial_binding[field] == binding[field]
            for field in (
                "plan_digest",
                "target_scope_digest",
                "profile_id",
                "maximum_tier",
            )
        ),
        "execute_preflight_changed",
        "Execute intent changed between explicit preflight and durable job creation",
    )
    approval_id = _SUPPORT.validate_approval(
        approval_request,
        binding=binding,
        status="pending",
        approved_by=None,
    )
    job_id = str(job["job_id"])
    awaiting = _SUPPORT.wait_for_job(
        lambda: _json_request(port, "GET", f"/api/v1/jobs/{job_id}", cookie=cookie),
        wanted="awaiting_approval",
        timeout=30.0,
    )
    _require(
        _SUPPORT.validate_approval(
            awaiting.get("approval_request"),
            binding=binding,
            status="pending",
            approved_by=None,
        )
        == approval_id,
        "execute_approval_request_invalid",
        "Execute job approval request was not durably pending",
    )
    approved = _json_request(
        port,
        "POST",
        f"/api/v1/jobs/{job_id}/approval",
        cookie=cookie,
        body={"approved_by": "gate01-release-operator"},
        expected=202,
    )
    _require(
        isinstance(approved.get("job"), Mapping)
        and approved["job"].get("state") in {"running", "completed"}
        and _SUPPORT.validate_approval(
            approved.get("approval_request"),
            binding=binding,
            status="consumed",
            approved_by="gate01-release-operator",
        )
        == approval_id,
        "execute_approval_invalid",
        "one-time Execute approval was not consumed",
    )
    settled = _SUPPORT.wait_for_job(
        lambda: _json_request(port, "GET", f"/api/v1/jobs/{job_id}", cookie=cookie),
        wanted="completed",
        timeout=180.0,
    )
    _require(
        settled.get("state") == "completed"
        and isinstance(settled.get("result_ref"), str)
        and _SUPPORT.validate_approval(
            settled.get("approval_request"),
            binding=binding,
            status="claimed",
            approved_by="gate01-release-operator",
        )
        == approval_id,
        "execute_job_failed",
        "approved Execute job did not complete",
    )
    job_pointer = _SUPPORT.validate_job_approval_pointers(
        (job, awaiting, approved["job"], settled),
        job_id=job_id,
        approval_id=approval_id,
    )
    source_id = str(settled["result_ref"])
    source = _json_request(port, "GET", f"/api/v1/runs/{source_id}", cookie=cookie)
    source_summary = _SUPPORT.validate_run(
        source,
        sandbox_root=sandbox_root,
        approval_binding=binding,
        approved_by="gate01-release-operator",
        replay_of=None,
    )
    replay = _json_request(
        port,
        "POST",
        f"/api/v1/runs/{source_id}/replays",
        cookie=cookie,
        body={
            "exact": True,
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
            "collectors": [COLLECTOR_ID],
            "approval": {"confirmed": True, "approved_by": "gate01-replay-operator"},
        },
        expected=201,
        timeout=240.0,
    )
    replay_summary = _SUPPORT.validate_run(
        replay,
        sandbox_root=sandbox_root,
        approval_binding=None,
        approved_by="gate01-replay-operator",
        replay_of=source_id,
    )
    replay_id = str(replay["run_id"])
    _SUPPORT.validate_fresh_replay_approval(
        source,
        replay,
        source_summary,
        replay_summary,
        source_approval_id=approval_id,
        source_binding=binding,
    )
    comparison = _json_request(
        port,
        "POST",
        "/api/v1/comparisons",
        cookie=cookie,
        body={"run_ids": [source_id, replay_id]},
    )
    summaries = comparison.get("summaries")
    deltas = comparison.get("deltas")
    _require(
        comparison.get("schema_version") == "bluefire.comparison.v1"
        and comparison.get("run_ids") == [source_id, replay_id]
        and comparison.get("baseline_run_id") == source_id
        and isinstance(comparison.get("comparison_id"), str)
        and isinstance(summaries, list)
        and len(summaries) == 2
        and all(isinstance(summary, Mapping) for summary in summaries)
        and [summary.get("run_id") for summary in summaries] == [source_id, replay_id]
        and all(
            summary.get("profile_id") == PROFILE_ID
            and summary.get("target_scope")
            == {
                "state": "bound",
                "scope_ref_count": 1,
                "scope_digest": binding["target_scope_digest"],
            }
            for summary in summaries
        )
        and isinstance(deltas, list)
        and len(deltas) == 1
        and isinstance(deltas[0], Mapping)
        and deltas[0].get("from_run_id") == source_id
        and deltas[0].get("to_run_id") == replay_id
        and deltas[0].get("target_scope_changed") is False,
        "comparison_invalid",
        "source and replay comparison was invalid",
    )
    report = {
        "schema_version": JOURNEY_SCHEMA,
        "verified": True,
        "selection": {
            "scenario_id": SCENARIO_ID,
            "runner_profile_id": PROFILE_ID,
            "collector_id": COLLECTOR_ID,
            "scope_refs": ["sandbox.workspace"],
        },
        "packaged_runner": {
            "source": "packaged",
            "managed_binary": True,
            "managed_sandbox": True,
            "runner_id": RUNNER_ID,
            "binary_digest": binary_digest,
            "bootstrap_state": "stopped",
            "recovery_reused_exact_identity": True,
        },
        "local_trust": {
            "enrollment": "active",
            "manual_certificate_input": False,
            "manual_hmac_input": False,
            "authenticated_transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
        },
        "preflight": {
            "status": "approval_required",
            "exact_binding_present": True,
            "exact_envelope_present": True,
            "collector_bound": True,
            "approval_binding": binding,
            "envelope_digest": envelope_digest,
        },
        "approval_job": {
            **job_pointer,
            "approval_id": approval_id,
            "approval_binding": binding,
            "initial_state": "awaiting_approval",
            "approval_status": "consumed",
            "run_approval_status": "claimed",
            "terminal_state": "completed",
        },
        "source_run": source_summary,
        "replay_run": replay_summary,
        "fresh_replay_approval": True,
        "comparison": {
            "comparison_id": str(comparison["comparison_id"]),
            "run_ids": [source_id, replay_id],
            "delta_count": 1,
        },
    }
    return report, (source_id, replay_id)


def _teardown(port: int, cookie: str) -> dict[str, Any]:
    stopped = _json_request(
        port,
        "POST",
        "/api/v1/runner/stop",
        cookie=cookie,
        body={"profile_id": PROFILE_ID},
        timeout=120.0,
    )
    revoked = _json_request(
        port,
        "POST",
        "/api/v1/runner/revoke",
        cookie=cookie,
        body={},
    )
    removed = _json_request(
        port,
        "POST",
        "/api/v1/runner/remove",
        cookie=cookie,
        body={"confirm_runner_id": RUNNER_ID},
    )
    _require(
        stopped.get("state") == "stopped"
        and revoked.get("enrollment") == "revoked"
        and removed.get("state") == "unbootstrapped",
        "runner_teardown_invalid",
        "managed runner teardown was incomplete",
    )
    return {
        "stopped": True,
        "trust_revoked": True,
        "state_removed": True,
        "final_state": "unbootstrapped",
    }


def _remove_product_database(runs_dir: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = runs_dir / ("bluefire-product.sqlite3" + suffix)
        if path.exists():
            path.unlink()


def run(evidence_dir: Path, forbid_root: Path) -> Mapping[str, Any]:
    _require(os.name == "nt", "unsupported_gate01_host", "Gate 01 managed trust requires Windows")
    destination = evidence_dir.resolve(strict=True)
    checkout = forbid_root.resolve(strict=True)
    runs_dir = destination / "runs"
    runs_dir.mkdir(exist_ok=False)
    package_report = _installed_package_report(checkout)
    probe_process: subprocess.Popen[str] | None = None
    probe_job: int | None = None
    process: subprocess.Popen[str] | None = None
    process_job: int | None = None
    cookie: str | None = None
    port: int | None = None
    teardown: Mapping[str, Any] | None = None
    journey_report: dict[str, Any] | None = None
    run_ids: tuple[str, str] = ("", "")
    try:
        probe_process, probe_job, probe_port, probe_capability, _environment = _launch_ui(
            evidence_dir=destination,
            runs_dir=runs_dir,
        )
        runtime_probe = _SUPPORT.probe_packaged_ui(
            probe_port,
            probe_capability,
            destination / "runtime" / "browser-profile",
        )
        probe_capability = ""
        owned_probe, owned_probe_job = probe_process, probe_job
        probe_process, probe_job = None, None
        _SUPPORT.terminate_process_tree(owned_probe, owned_probe_job)
        process, process_job, port, capability, _environment = _launch_ui(
            evidence_dir=destination,
            runs_dir=runs_dir,
        )
        cookie, catalog, _scenarios, ui_report = _ui_health(port, capability)
        ui_report["runtime_probe"] = runtime_probe
        capability = ""  # The consumed launch capability is never persisted.
        sandbox_root = destination / "runtime" / "state" / "BlueFire Nexus" / "runtime" / "sandbox"
        journey_report, run_ids = _journey(port, cookie, sandbox_root, catalog)
        teardown = _teardown(port, cookie)
    finally:
        fallback_teardown = None
        if process is not None and port is not None and cookie is not None and teardown is None:

            def fallback_teardown_action() -> None:
                if process.poll() is None:
                    _teardown(port, cookie)

            fallback_teardown = fallback_teardown_action
        _SUPPORT.cleanup_journey(
            probe=(probe_process, probe_job) if probe_process is not None else None,
            service=(process, process_job) if process is not None else None,
            fallback_teardown=fallback_teardown,
            runtime_root=destination / "runtime",
            expected_parent=destination,
        )
    _require(
        journey_report is not None and teardown is not None and all(run_ids),
        "journey_incomplete",
        "installed-wheel journey did not complete",
    )
    _SUPPORT.validate_bundles(runs_dir, run_ids)
    _remove_product_database(runs_dir)
    journey_report["teardown"] = dict(teardown)
    _write_json(destination / "gate01-package-runtime-report.json", package_report)
    _write_json(destination / "gate01-ui-health-report.json", ui_report)
    _write_json(destination / "gate01-journey-report.json", journey_report)
    return {
        "schema_version": SUMMARY_SCHEMA,
        "status": "passed",
        "checks": [
            "fresh_install",
            "ui_launch",
            "packaged_runner",
            "local_trust",
            "execute_journey",
            "observe_cleanup_replay_compare",
        ],
        "run_count": len(run_ids),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--forbid-root", type=Path, required=True)
    parser.add_argument("--support-module", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    global _SUPPORT
    args = _parser().parse_args(argv)
    try:
        _SUPPORT = _load_support(args.support_module, args.evidence_dir, args.forbid_root)
        summary = run(args.evidence_dir, args.forbid_root)
    except JourneyError as exc:
        summary = {
            "schema_version": SUMMARY_SCHEMA,
            "status": "failed",
            "error_code": exc.code,
            "message": str(exc),
        }
        print(json.dumps(summary, sort_keys=True))
        return 2
    except Exception as exc:
        if _SUPPORT is not None and isinstance(exc, _SUPPORT.SupportError):
            error_code, message = exc.code, str(exc)
        else:
            error_code = "unexpected_runtime_failure"
            message = "installed-wheel journey encountered a bounded runtime failure"
        summary = {
            "schema_version": SUMMARY_SCHEMA,
            "status": "failed",
            "error_code": error_code,
            "message": message,
            "failure_type": type(exc).__name__,
        }
        print(json.dumps(summary, sort_keys=True))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
