"""Verify an interrupted installed comparison explanation needs an explicit new turn.

Copy this file, verify_installed_reopen.py, and the browser driver outside the
checkout. Run with the isolated Python that has the exact wheel installed.
This verifier has no native runner or effectful comparison authority.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

_support_path = Path(__file__).resolve().with_name("verify_installed_reopen.py")
_support_spec = importlib.util.spec_from_file_location(
    "bluefire_installed_reopen_support", _support_path
)
if _support_spec is None or _support_spec.loader is None:
    raise RuntimeError("Copied installed process support is unavailable")
support = importlib.util.module_from_spec(_support_spec)
_support_spec.loader.exec_module(support)

MODEL = "bluefire-local-comparison-replacement-v1"
PURPOSE = "bluefire_experiment_assistance"
_MAX_BODY = 262144
_MAX_REPORT = 1024 * 1024
_JOB = re.compile(r"job-[0-9a-f]{32}\Z")
_AUTH = re.compile(r"ai-authorization-[0-9a-f]{32}\Z")
_SNAPSHOT = re.compile(r"run-comparison-[0-9a-f]{64}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def valid_model_request(value: object, *, length: int, authorization: str | None) -> bool:
    if not isinstance(value, dict):
        return False
    form = value.get("text")
    form = form.get("format") if isinstance(form, dict) else None
    return (
        set(value)
        == {
            "model",
            "instructions",
            "input",
            "max_output_tokens",
            "store",
            "parallel_tool_calls",
            "tools",
            "tool_choice",
            "text",
        }
        and isinstance(form, dict)
        and set(form) == {"type", "name", "schema", "strict"}
        and form.get("type") == "json_schema"
        and form.get("name") == PURPOSE
        and form.get("strict") is True
        and isinstance(form.get("schema"), dict)
        and isinstance(value.get("instructions"), str)
        and isinstance(value.get("input"), str)
        and value.get("model") == MODEL
        and value.get("max_output_tokens") == 64
        and value.get("store") is False
        and value.get("parallel_tool_calls") is False
        and value.get("tools") == []
        and value.get("tool_choice") == "none"
        and authorization is None
        and 0 < length <= _MAX_BODY
    )


class HeldComparisonFixture:
    """Two bounded structured requests; the first receives no response."""

    def __init__(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def send_json(self, status: int, value: object) -> None:
                raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

            def do_GET(self) -> None:
                if self.path != "/__fixture/state":
                    self.send_json(404, {"error": "not_found"})
                    return
                with owner.lock:
                    owner.state_reads += 1
                    if owner.state_reads > 250:
                        owner.failed = True
                    state = {
                        "request_count": owner.request_count,
                        "failed": owner.failed,
                        "first_held": owner.request_count == 1 and not owner.abort_first.is_set(),
                    }
                self.send_json(200, state)

            def do_POST(self) -> None:
                size = self.headers.get("Content-Length", "")
                if (
                    self.path != "/v1/responses"
                    or not size.isascii()
                    or not size.isdecimal()
                    or len(size) > 7
                    or (len(size) > 1 and size.startswith("0"))
                ):
                    owner.fail()
                    self.send_json(400, {"error": "request_out_of_scope"})
                    return
                length = int(size)
                if not 0 < length <= _MAX_BODY:
                    owner.fail()
                    self.send_json(413, {"error": "request_size"})
                    return
                try:
                    request = json.loads(self.rfile.read(length))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    owner.fail()
                    self.send_json(400, {"error": "invalid_json"})
                    return
                if not valid_model_request(
                    request, length=length, authorization=self.headers.get("Authorization")
                ):
                    owner.fail()
                    self.send_json(400, {"error": "request_out_of_scope"})
                    return
                with owner.lock:
                    if owner.request_count >= 2 or owner.request_bytes + length > 2 * _MAX_BODY:
                        owner.failed = True
                        self.send_json(429, {"error": "request_budget"})
                        return
                    owner.request_count += 1
                    owner.request_bytes += length
                    index = owner.request_count
                if index == 1:
                    owner.first_arrived.set()
                    # The supervisor releases this only after the first CLI group is reaped.
                    if not owner.abort_first.wait(90):
                        owner.fail()
                    return
                if not owner.abort_first.is_set():
                    owner.fail()
                    self.send_json(409, {"error": "restart_order"})
                    return
                self.send_json(
                    200,
                    {
                        "id": "fixture-comparison-replacement-2",
                        "model": MODEL,
                        "status": "completed",
                        "output_text": json.dumps(
                            {
                                "message": "The saved synthetic runs have recorded outcomes. This explanation does not establish live effects or prevention.",
                                "steps": [],
                            },
                            separators=(",", ":"),
                        ),
                        "usage": {"input_tokens": 16, "output_tokens": 24},
                    },
                )

            def log_message(self, _format: str, *_args: object) -> None:
                return

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def handle_error(self, _request: object, _client: object) -> None:
                owner.fail()

        self.lock = threading.Lock()
        self.first_arrived = threading.Event()
        self.abort_first = threading.Event()
        self.request_count = 0
        self.request_bytes = 0
        self.state_reads = 0
        self.failed = False
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=False)
        self.started = False

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def fail(self) -> None:
        with self.lock:
            self.failed = True

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def close(self) -> bool:
        self.abort_first.set()
        if self.started:
            self.server.shutdown()
        self.server.server_close()
        if self.started:
            self.thread.join(timeout=5)
        return not self.started or not self.thread.is_alive()


def _read_json(path: Path, max_bytes: int = _MAX_REPORT) -> dict[str, object]:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise RuntimeError("browser evidence exceeded its size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("browser evidence has an invalid shape")
    return cast(dict[str, object], value)


def _phase_one_valid(value: dict[str, object]) -> bool:
    runs = value.get("run_ids")
    grant = value.get("first_authorization")
    return (
        set(value)
        == {
            "schema_version",
            "snapshot_id",
            "snapshot_digest",
            "run_ids",
            "original_job_id",
            "context_digest",
            "original_request_digest",
            "first_authorization",
        }
        and value.get("schema_version") == "bluefire.assistant-replacement.phase-one.v1"
        and isinstance(value.get("snapshot_id"), str)
        and _SNAPSHOT.fullmatch(cast(str, value["snapshot_id"])) is not None
        and isinstance(value.get("snapshot_digest"), str)
        and _DIGEST.fullmatch(cast(str, value["snapshot_digest"])) is not None
        and isinstance(runs, list)
        and len(runs) == 2
        and len(set(map(str, runs))) == 2
        and all(
            isinstance(item, str) and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", item)
            for item in runs
        )
        and isinstance(value.get("original_job_id"), str)
        and _JOB.fullmatch(cast(str, value["original_job_id"])) is not None
        and isinstance(value.get("context_digest"), str)
        and _DIGEST.fullmatch(cast(str, value["context_digest"])) is not None
        and isinstance(value.get("original_request_digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", cast(str, value["original_request_digest"])) is not None
        and isinstance(grant, dict)
        and set(grant)
        == {
            "authorization_id",
            "expires_at_ms",
            "requests",
            "request_bytes",
            "reserved_output_tokens",
            "remaining_requests",
            "remaining_request_bytes",
            "remaining_reserved_output_tokens",
        }
        and isinstance(grant.get("authorization_id"), str)
        and _AUTH.fullmatch(cast(str, grant["authorization_id"])) is not None
        and type(grant.get("expires_at_ms")) is int
        and cast(int, grant["expires_at_ms"]) > 0
        and grant.get("requests") == 1
        and type(grant.get("request_bytes")) is int
        and 0 < cast(int, grant["request_bytes"]) <= _MAX_BODY
        and grant.get("reserved_output_tokens") == 64
        and grant.get("remaining_requests") == 0
        and grant.get("remaining_request_bytes") == 524288 - grant["request_bytes"]
        and grant.get("remaining_reserved_output_tokens") == 0
    )


def _screenshot_manifest_valid(value: object) -> bool:
    if not isinstance(value, list) or len(value) != 2:
        return False
    for index, file in enumerate(
        ("assistant-blocked-original-1440x900.png", "assistant-completed-replacement-1440x900.png")
    ):
        row = value[index]
        if not isinstance(row, dict) or set(row) != {"file", "sha256", "bytes"}:
            return False
        if (
            row.get("file") != file
            or not isinstance(row.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            or type(row.get("bytes")) is not int
            or not 0 < row["bytes"] <= 4 * 1024 * 1024
        ):
            return False
    return True


def _browser_report_passed(value: dict[str, object], phase_one: dict[str, object]) -> bool:
    original = value.get("original")
    replacement = value.get("replacement")
    counts = value.get("write_counts")
    authorization = value.get("authorization")
    prior = authorization.get("prior") if isinstance(authorization, dict) else None
    renewed = authorization.get("replacement") if isinstance(authorization, dict) else None
    setup = counts.get("setup") if isinstance(counts, dict) else None
    recovery = counts.get("recovery") if isinstance(counts, dict) else None
    return (
        value.get("schema_version") == "bluefire.installed-assistant-replacement.browser.v1"
        and value.get("status") == "passed"
        and value.get("installed_service") is True
        and value.get("native_execution") is False
        and value.get("live_model_inference") is False
        and value.get("same_turn_continuation") is False
        and value.get("same_run_inspection_retry") is False
        and value.get("blocked_requests") == []
        and value.get("errors") == []
        and value.get("phase_one") == phase_one
        and value.get("snapshot_id") == phase_one.get("snapshot_id")
        and value.get("snapshot_digest") == phase_one.get("snapshot_digest")
        and value.get("run_ids") == phase_one.get("run_ids")
        and value.get("provider_request_count") == 2
        and _screenshot_manifest_valid(value.get("screenshots"))
        and value.get("checks")
        == [
            "two_real_service_synthetic_simulations_and_immutable_comparison",
            "labeled_loopback_provider_authorized_for_one_bounded_explanation",
            "original_comparison_request_and_first_model_call_retained_before_process_loss",
            "restart_kept_original_blocked_without_provider_replay_or_continue_action",
            "new_service_session_required_fresh_normal_settings_authorization",
            "visible_explicit_new_request_created_distinct_completed_explanation",
            "snapshot_run_order_and_request_context_remained_unchanged_without_effectful_writes",
        ]
        and isinstance(original, dict)
        and original
        == {
            "job_id": phase_one.get("original_job_id"),
            "state": "interrupted",
            "status": "blocked",
        }
        and isinstance(replacement, dict)
        and isinstance(replacement.get("job_id"), str)
        and _JOB.fullmatch(cast(str, replacement["job_id"])) is not None
        and replacement
        == {
            "job_id": replacement["job_id"],
            "state": "completed",
            "status": "completed",
        }
        and replacement["job_id"] != phase_one.get("original_job_id")
        and isinstance(prior, dict)
        and prior
        == {
            **cast(dict[str, object], phase_one["first_authorization"]),
            "status_after_restart": "context_unavailable",
        }
        and isinstance(renewed, dict)
        and set(renewed)
        == {
            "authorization_id",
            "expires_at_ms",
            "requests",
            "request_bytes",
            "reserved_output_tokens",
            "remaining_requests",
            "remaining_request_bytes",
            "remaining_reserved_output_tokens",
        }
        and isinstance(renewed.get("authorization_id"), str)
        and _AUTH.fullmatch(cast(str, renewed["authorization_id"])) is not None
        and renewed["authorization_id"] != prior["authorization_id"]
        and type(renewed.get("expires_at_ms")) is int
        and cast(int, renewed["expires_at_ms"]) > 0
        and renewed.get("requests") == 1
        and type(renewed.get("request_bytes")) is int
        and 0 < cast(int, renewed["request_bytes"]) <= _MAX_BODY
        and renewed.get("reserved_output_tokens") == 64
        and renewed.get("remaining_requests") == 0
        and renewed.get("remaining_request_bytes") == 524288 - renewed["request_bytes"]
        and renewed.get("remaining_reserved_output_tokens") == 0
        and setup
        == {
            "run_preflight": 2,
            "run": 2,
            "comparison": 1,
            "provider_save": 1,
            "provider_activate": 1,
            "authorization": 1,
            "assistant_turn": 1,
            "session": 1,
        }
        and recovery
        == {
            "authorization": 1,
            "assistant_turn": 1,
            "session": 1,
            "other_attempts": 0,
        }
    )


def _browser_failure_diagnostic(value: dict[str, object]) -> dict[str, object]:
    """Retain only finite, non-secret progress already observed by the driver."""
    result: dict[str, object] = {}
    errors = value.get("errors")
    allowed_stages = {
        "launch",
        "first-session",
        "synthetic-comparison",
        "provider-authorization",
        "first-explanation",
        "wait-for-restarted-cli",
        "fresh-session",
        "visible-blocked-original",
        "fresh-normal-authorization",
        "explicit-replacement",
        "cleanup",
    }
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        stage = errors[0].get("stage")
        if isinstance(stage, str) and stage in allowed_stages:
            result["browser_stage"] = stage
    replacement = value.get("replacement_diagnostic")
    replacement_fields = {
        "substage": {
            "provider_selection",
            "submission_fill",
            "submission_click",
            "submission_response",
            "submission_status",
            "submission_body",
            "submission_identity",
            "request_identity",
            "terminal_poll",
            "terminal_job",
            "terminal_turn",
            "completion_heading",
            "empty_plan",
            "empty_results",
            "provider_count",
            "retained_records",
            "authorization_usage",
            "capture",
            "write_counts",
            "unknown",
        },
        "error_category": {"assertion", "timeout", "type", "json", "other"},
        "submission_status": {"unobserved", "accepted", "client_error", "server_error", "other"},
        "job_state": {
            "queued",
            "awaiting_approval",
            "running",
            "cancelling",
            "cancelled",
            "completed",
            "failed",
            "interrupted",
            "unknown",
        },
        "turn_status": {
            "planning",
            "working",
            "off",
            "awaiting_review",
            "awaiting_execute_approval",
            "ready_to_continue",
            "cancelling",
            "cancelled",
            "blocked",
            "completed",
            "unknown",
        },
        "job_error_shape": {"missing", "absent", "object", "invalid"},
        "result_ref_shape": {"missing", "absent", "string", "invalid"},
        "plan_shape": {"missing", "empty", "nonempty", "invalid"},
        "results_shape": {"missing", "empty", "nonempty", "invalid"},
    }
    if (
        result.get("browser_stage") == "explicit-replacement"
        and isinstance(replacement, dict)
        and set(replacement) == set(replacement_fields)
        and all(
            isinstance(replacement[key], str) and replacement[key] in allowed_values
            for key, allowed_values in replacement_fields.items()
        )
    ):
        result["replacement_diagnostic"] = {key: replacement[key] for key in replacement_fields}
    keys = {
        "first_session",
        "second_session",
        "run_preflight",
        "run",
        "comparison",
        "provider_save",
        "provider_activate",
        "authorization",
        "assistant_turn",
        "recovery_other_denied",
    }
    attempted = value.get("attempted_writes")
    if (
        isinstance(attempted, dict)
        and set(attempted) == keys
        and all(type(attempted[key]) is int and 0 <= attempted[key] <= 1000 for key in keys)
    ):
        result["attempted_writes"] = {key: attempted[key] for key in sorted(keys)}
    states = value.get("observed_states")
    allowed = {
        "original_before_loss": ({"queued", "running", "other"}, {"working", "off", "other"}),
        "original_after_restart": ({"interrupted"}, {"blocked"}),
        "replacement": ({"completed"}, {"completed"}),
    }
    if isinstance(states, dict):
        projected = {}
        for key, (jobs, turns) in allowed.items():
            row = states.get(key)
            if (
                isinstance(row, dict)
                and set(row) == {"job", "turn"}
                and isinstance(row["job"], str)
                and isinstance(row["turn"], str)
                and row["job"] in jobs
                and row["turn"] in turns
            ):
                projected[key] = {"job": row["job"], "turn": row["turn"]}
        if projected:
            result["observed_states"] = projected
    return result


def _hard_stop_first(process: subprocess.Popen[bytes]) -> bool:
    """A process loss, not graceful cancellation, at the observed held boundary."""
    try:
        support._kill_process_group(process.pid, support._signal_number("SIGKILL"))
    except ProcessLookupError:
        return False
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        return False
    try:
        support._kill_process_group(process.pid, 0)
    except ProcessLookupError:
        return bool(process.returncode == -cast(int, support._signal_number("SIGKILL")))
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "forbid-root",
        "node",
        "playwright",
        "browser-driver",
        "browser-cache",
        "wheel",
        "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("This verifier requires isolated installed Python on Linux")
    forbidden = args.forbid_root.resolve(strict=True)
    paths = {
        name: getattr(args, name.replace("-", "_")).resolve(strict=True)
        for name in ("node", "playwright", "browser-driver", "browser-cache", "wheel")
    }
    output = args.output.resolve()
    if (
        output.exists()
        or output.is_relative_to(forbidden)
        or Path.cwd().is_relative_to(forbidden)
        or any(
            path.is_relative_to(forbidden)
            for path in (
                Path(__file__).resolve(),
                Path(support.__file__).resolve(),
                paths["browser-driver"],
            )
        )
    ):
        raise RuntimeError("Use a fresh owned output and copied verifier files outside checkout")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PLAYWRIGHT_BROWSERS_PATH": str(paths["browser-cache"]),
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    }
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-assistant-replacement.v1",
        "status": "failed_or_incomplete",
        "scope": "interrupted_comparison_explanation_explicit_replacement",
        "live_model_inference": False,
        "native_execution": False,
        "same_turn_continuation": False,
        "same_run_inspection_retry": False,
        "service_groups_started": 0,
        "service_groups_stopped": 0,
        "first_service_group_stopped": False,
        "second_service_group_stopped": False,
        "browser_group_started": False,
        "browser_group_stopped": False,
        "fixture_thread_stopped": False,
        "temporary_runtime_removed": False,
    }
    fixture = HeldComparisonFixture()
    services: list[subprocess.Popen[bytes]] = []
    streams: list[
        tuple[dict[str, object], threading.Lock, list[threading.Thread], subprocess.Popen[bytes]]
    ] = []
    browser: subprocess.Popen[bytes] | None = None
    original_cwd = Path.cwd()
    runtime_created = False
    stage = "runtime_setup"
    try:
        runtime.mkdir(mode=0o700)
        runtime_created = True
        for name in ("home", "state", "temp", "work"):
            (runtime / name).mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update(env)
        os.chdir(runtime / "work")
        stage = "installed_identity"
        import bluefire

        package = Path(bluefire.__file__).resolve(strict=True).parent
        site = Path(sysconfig.get_path("purelib")).resolve(strict=True)
        distribution = importlib.metadata.distribution("bluefire-nexus")
        if (
            not package.is_relative_to(site)
            or package.is_relative_to(forbidden)
            or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve()
            or any(Path(entry or ".").resolve().is_relative_to(forbidden) for entry in sys.path)
            or '"editable": true' in (distribution.read_text("direct_url.json") or "").lower()
        ):
            raise RuntimeError("BlueFire must come from a non-editable installed wheel")
        report.update(
            {
                "installed_outside_checkout": True,
                "product_version": distribution.version,
                "wheel_sha256": support._digest(paths["wheel"]),
                "verifier_sha256": support._digest(Path(__file__).resolve()),
                "support_sha256": support._digest(Path(support.__file__).resolve()),
                "browser_driver_sha256": support._digest(paths["browser-driver"]),
                "environment_names": sorted(env),
                "platform": platform.system().lower(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
            }
        )
        stage = "fixture_start"
        fixture.start()

        def start_service(port: int) -> tuple[subprocess.Popen[bytes], int, str]:
            command = support._installed_cli_command(sys.executable, runtime / "runs")
            # The only revised argument is the second process's loopback port.
            command[command.index("--port") + 1] = str(port)
            child = subprocess.Popen(
                command,
                env=env,
                cwd=runtime / "work",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            services.append(child)
            report["service_groups_started"] = len(services)
            state: dict[str, object] = {"overflow": False}
            lock = threading.Lock()
            readers = [
                threading.Thread(
                    target=support._read_cli_stream,
                    args=(child.stdout,),
                    kwargs={"stderr": False, "state": state, "lock": lock},
                    daemon=True,
                ),
                threading.Thread(
                    target=support._read_cli_stream,
                    args=(child.stderr,),
                    kwargs={"stderr": True, "state": state, "lock": lock},
                    daemon=True,
                ),
            ]
            for reader in readers:
                reader.start()
            streams.append((state, lock, readers, child))
            ready_port, capability = support._wait_ready(child, state, lock)
            if port and ready_port != port:
                raise RuntimeError("restarted CLI changed the retained loopback origin")
            return child, ready_port, capability

        stage = "first_service_start"
        first, port, first_capability = start_service(0)
        first_capability_digest = support._capability_digest(first_capability)
        stage = "browser_start"
        browser = subprocess.Popen(
            [
                str(paths["node"]),
                str(paths["browser-driver"]),
                str(paths["playwright"]),
                str(output),
                str(port),
                str(fixture.port),
            ],
            env=env,
            cwd=runtime / "work",
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        report["browser_group_started"] = True
        assert browser.stdin is not None
        browser.stdin.write(json.dumps({"capability": first_capability}).encode("ascii") + b"\n")
        browser.stdin.flush()
        first_capability = ""
        stage = "held_request"
        deadline = time.monotonic() + 150
        marker = output / "phase-one.json"
        while time.monotonic() < deadline and not marker.is_file():
            if browser.poll() is not None or first.poll() is not None or fixture.failed:
                break
            time.sleep(0.05)
        if not marker.is_file() or not fixture.first_arrived.is_set() or fixture.request_count != 1:
            raise RuntimeError("the held first comparison request was not established")
        phase_one = _read_json(marker, 16 * 1024)
        if not _phase_one_valid(phase_one):
            raise RuntimeError("first comparison identity is invalid")
        stage = "first_process_loss"
        if not _hard_stop_first(first):
            raise RuntimeError("first CLI process group was not fully reaped")
        report["first_service_group_stopped"] = True
        fixture.abort_first.set()
        stage = "second_service_start"
        second, restarted_port, second_capability = start_service(port)
        if (
            restarted_port != port
            or support._capability_digest(second_capability) == first_capability_digest
        ):
            # The browser independently checks the fresh session exchange.
            raise RuntimeError("restarted CLI session is invalid")
        report["fresh_capability_confirmed"] = True
        browser.stdin.write(json.dumps({"capability": second_capability}).encode("ascii") + b"\n")
        browser.stdin.flush()
        second_capability = ""
        stage = "explicit_replacement"
        try:
            browser.wait(timeout=180)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("browser recovery journey exceeded its deadline") from exc
        if browser.returncode != 0:
            raise RuntimeError("browser recovery journey failed")
        stage = "browser_contract"
        journey = _read_json(output / "browser-report.json")
        if not _browser_report_passed(journey, phase_one):
            raise RuntimeError("browser recovery report failed its bounded contract")
        screenshots = cast(list[dict[str, object]], journey["screenshots"])
        for screenshot in screenshots:
            image_path = output / cast(str, screenshot["file"])
            if (
                not image_path.is_file()
                or image_path.stat().st_size != screenshot["bytes"]
                or support._digest(image_path) != screenshot["sha256"]
            ):
                raise RuntimeError("a selected Assistant frame failed its file hash")
        report["phase_one"] = phase_one
        report["screenshots"] = screenshots
        report["browser_report_sha256"] = support._digest(output / "browser-report.json")
        report["provider_requests"] = fixture.request_count
        report["provider_request_bytes"] = fixture.request_bytes
        if fixture.failed or fixture.request_count != 2:
            raise RuntimeError("loopback provider request budget or contract failed")
        stage = "final_process_stop"
        if not support._stop_group(second):
            raise RuntimeError("second CLI process group did not stop")
        report["second_service_group_stopped"] = True
        report["status"] = "passed"
    except (
        OSError,
        ImportError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        RuntimeError,
        json.JSONDecodeError,
        AssertionError,
    ) as error:
        report["error_type"] = type(error).__name__
        report["failure_stage"] = stage
    finally:
        fixture.abort_first.set()
        if browser is not None:
            try:
                report["browser_group_stopped"] = support._stop_group(browser)
            except OSError:
                report["browser_group_stopped"] = False
        for index, child in enumerate(services, 1):
            try:
                stopped = child.poll() is not None and not _group_exists(child.pid)
                if not stopped:
                    stopped = support._stop_group(child)
                report[
                    "first_service_group_stopped" if index == 1 else "second_service_group_stopped"
                ] = stopped
            except OSError:
                pass
        report["service_groups_stopped"] = sum(
            report[key] is True
            for key in ("first_service_group_stopped", "second_service_group_stopped")
        )
        report["fixture_thread_stopped"] = fixture.close()
        report["provider_requests"] = fixture.request_count
        report["provider_request_bytes"] = fixture.request_bytes
        report["fixture_failed"] = fixture.failed
        browser_report_path = output / "browser-report.json"
        if browser_report_path.is_file():
            try:
                report["browser_progress"] = _browser_failure_diagnostic(
                    _read_json(browser_report_path)
                )
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                report["browser_progress"] = {"report_status": "invalid_or_unavailable"}
        diagnostics = []
        for index, (state, lock, readers, child) in enumerate(streams, 1):
            for reader in readers:
                reader.join(timeout=3)
            with lock:
                diagnostics.append(
                    {
                        "pass": index,
                        **support._cli_output_diagnostic(state, returncode=child.poll()),
                    }
                )
        report["cli_output_diagnostics"] = diagnostics
        try:
            os.chdir(original_cwd)
        except OSError:
            report["status"] = "failed_or_incomplete"
        safe = (
            (not report["browser_group_started"] or report["browser_group_stopped"])
            and report["service_groups_stopped"] == report["service_groups_started"]
            and report["fixture_thread_stopped"] is True
            and runtime_created
        )
        if safe:
            try:
                shutil.rmtree(runtime)
                report["temporary_runtime_removed"] = True
            except OSError:
                report["status"] = "failed_or_incomplete"
        else:
            report["status"] = "failed_or_incomplete"
        if report["status"] != "passed" and "failure_stage" not in report:
            report["failure_stage"] = "cleanup"
        support._write_new(output / "receipt.json", report)
    print(json.dumps(report, sort_keys=True))
    return (
        0
        if (
            report["status"] == "passed"
            and report["temporary_runtime_removed"] is True
            and report["service_groups_stopped"] == 2
            and report["browser_group_stopped"] is True
        )
        else 1
    )


def _group_exists(pid: int) -> bool:
    try:
        support._kill_process_group(pid, 0)
    except ProcessLookupError:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
