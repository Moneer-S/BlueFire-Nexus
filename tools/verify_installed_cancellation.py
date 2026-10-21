"""Verify cancellation and page-reload recovery in an installed Linux wheel UI."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

_MODEL = "bluefire-local-cancel-fixture-v1"
_PURPOSE = "bluefire_experiment_assistance"
_MAX_REQUEST_BYTES = 1_048_576


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
        return hasher.hexdigest()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def cleanup_confirmed(value: object) -> bool:
    required = {
        "browser_process_group",
        "fixture_thread",
        "service_http_server",
        "service_thread",
        "service",
        "temporary_state_removed",
    }
    return (
        isinstance(value, dict)
        and set(value) == required
        and value.get("browser_process_group") in {"not_started", "stopped"}
        and value.get("fixture_thread") in {"not_started", "stopped"}
        and value.get("service_http_server") in {"not_started", "closed"}
        and value.get("service_thread") in {"not_started", "stopped"}
        and value.get("service") in {"not_started", "closed"}
        and value.get("temporary_state_removed") is True
    )


def valid_fixture_request(value: object, *, body_bytes: int, authorization: str | None) -> bool:
    if not isinstance(value, dict):
        return False
    text = value.get("text")
    form = text.get("format") if isinstance(text, dict) else None
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
        and isinstance(text, dict)
        and set(text) == {"format"}
        and isinstance(form, dict)
        and set(form) == {"type", "name", "schema", "strict"}
        and form.get("type") == "json_schema"
        and form.get("name") == _PURPOSE
        and form.get("strict") is True
        and isinstance(form.get("schema"), dict)
        and isinstance(value.get("instructions"), str)
        and isinstance(value.get("input"), str)
        and value.get("model") == _MODEL
        and value.get("max_output_tokens") == 64
        and value.get("store") is False
        and value.get("parallel_tool_calls") is False
        and value.get("tools") == []
        and value.get("tool_choice") == "none"
        and authorization is None
        and 0 < body_bytes <= _MAX_REQUEST_BYTES
    )


class HeldAssistantFixture:
    """One exact structured request held until the UI cancellation is durable."""

    def __init__(self) -> None:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def _send(self, status: int, value: object) -> None:
                body = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_GET(self) -> None:
                if self.path != "/__fixture/state":
                    self._send(404, {"error": "not_found"})
                    return
                with fixture.lock:
                    fixture.state_reads += 1
                    if fixture.state_reads > 250:
                        fixture.failed = True
                    self._send(
                        200,
                        {
                            "request_count": fixture.request_count,
                            "request_bytes": fixture.request_bytes,
                            "released": fixture.release.is_set(),
                            "failed": fixture.failed,
                        },
                    )

            def do_POST(self) -> None:
                raw_length = self.headers.get("Content-Length", "0")
                if (
                    self.path != "/v1/responses"
                    or not raw_length.isascii()
                    or not raw_length.isdecimal()
                    or len(raw_length) > 7
                    or (len(raw_length) > 1 and raw_length.startswith("0"))
                ):
                    fixture._fail()
                    self._send(400, {"error": "request_out_of_scope"})
                    return
                length = int(raw_length)
                if not 0 < length <= _MAX_REQUEST_BYTES:
                    fixture._fail()
                    self._send(413, {"error": "request_size"})
                    return
                try:
                    value = json.loads(self.rfile.read(length))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    fixture._fail()
                    self._send(400, {"error": "invalid_json"})
                    return
                if not valid_fixture_request(
                    value, body_bytes=length, authorization=self.headers.get("Authorization")
                ):
                    fixture._fail()
                    self._send(400, {"error": "request_out_of_scope"})
                    return
                with fixture.lock:
                    if fixture.request_count != 0:
                        fixture.failed = True
                        self._send(429, {"error": "request_budget"})
                        return
                    fixture.request_count = 1
                    fixture.request_bytes = length
                if not fixture.release.wait(45):
                    fixture._fail()
                    self._send(504, {"error": "fixture_deadline"})
                    return
                response = {
                    "id": "fixture-response-1",
                    "model": _MODEL,
                    "status": "completed",
                    "output_text": json.dumps(
                        {
                            "message": "Create a separate registered proposal for native review.",
                            "steps": [
                                {
                                    "capability_id": "graph.propose_and_validate",
                                    "detector_ref": "none",
                                    "reason": "Use the current registered catalog.",
                                }
                            ],
                        },
                        separators=(",", ":"),
                    ),
                    "usage": {"input_tokens": 16, "output_tokens": 24},
                }
                try:
                    self._send(200, response)
                except OSError:
                    # Cancellation closes the supervised transport before release.
                    return

            def log_message(self, _format: str, *_args: object) -> None:
                return

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def handle_error(self, _request: object, _client_address: object) -> None:
                return

        self.lock = threading.Lock()
        self.release = threading.Event()
        self.request_count = 0
        self.request_bytes = 0
        self.state_reads = 0
        self.failed = False
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.started = False

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def _fail(self) -> None:
        with self.lock:
            self.failed = True

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def close(self) -> bool:
        self.release.set()
        if self.started:
            self.server.shutdown()
        self.server.server_close()
        if self.started:
            self.thread.join(timeout=5)
        return not self.started or not self.thread.is_alive()


def stop_group(
    process: subprocess.Popen[bytes], *, killpg: Callable[[int, int], None] | None = None
) -> bool:
    signal_group = os.killpg if killpg is None else killpg
    try:
        signal_group(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        pass
    for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 5)):
        try:
            signal_group(process.pid, 0)
        except ProcessLookupError:
            break
        try:
            signal_group(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
    try:
        signal_group(process.pid, 0)
    except ProcessLookupError:
        if process.poll() is None:
            process.wait(timeout=5)
        return process.poll() is not None
    return False


def _report_passed(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    expected_checks = {
        "ephemeral_browser_session_connected",
        "provider_activation_and_one_request_usage_authorized_in_ui",
        "assistant_job_started_from_current_graph_context",
        "authorized_local_fixture_request_held_before_response",
        "normal_assistant_stop_reached_durable_cancelled_terminal",
        "page_reload_recovered_same_saved_cancelled_operation_from_server",
    }
    operation = value.get("cancelled_operation")
    counts = value.get("counts")
    return (
        value.get("schema_version") == "bluefire.installed-assistant-cancellation.v1"
        and value.get("status") == "passed"
        and value.get("installed_service") is True
        and value.get("local_fixture_only") is True
        and value.get("live_model_inference") is False
        and value.get("native_execution") is False
        and "error" not in value
        and isinstance(value.get("checks"), list)
        and all(isinstance(check, str) for check in value["checks"])
        and expected_checks <= set(value["checks"])
        and value.get("blocked_requests") == []
        and isinstance(operation, dict)
        and set(operation) == {"job_id", "job_state", "turn_status", "result_count"}
        and operation.get("job_state") == "cancelled"
        and operation.get("turn_status") == "cancelled"
        and type(operation.get("result_count")) is int
        and operation.get("result_count") == 0
        and isinstance(operation.get("job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", operation["job_id"]) is not None
        and isinstance(value.get("reloaded_operation"), dict)
        and value["reloaded_operation"] == operation
        and isinstance(counts, dict)
        and counts
        == {
            "session": 1,
            "provider_save": 1,
            "activation": 1,
            "authorization": 1,
            "graph_context": 1,
            "graph_context_get": 1,
            "assistance_submit": 1,
            "cancel": 1,
        }
        and all(type(count) is int for count in counts.values())
        and value.get("browser_context_closed") is True
        and value.get("browser_closed") is True
        and value.get("cleanup_passed") is True
    )


def safe_driver_report(value: object) -> dict[str, object] | None:
    allowed = {
        "schema_version",
        "status",
        "installed_service",
        "local_fixture_only",
        "live_model_inference",
        "native_execution",
        "checks",
        "blocked_requests",
        "cancelled_operation",
        "reloaded_operation",
        "counts",
        "browser_context_closed",
        "browser_closed",
        "cleanup_passed",
    }
    if (
        not isinstance(value, dict)
        or not allowed <= set(value)
        or set(value) - (allowed | {"error"})
    ):
        return None
    if "error" in value:
        error = value["error"]
        if (
            not isinstance(error, dict)
            or set(error) != {"stage", "error_type"}
            or not isinstance(error.get("stage"), str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", error["stage"])
            or not isinstance(error.get("error_type"), str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error["error_type"])
        ):
            return None
    operation = value.get("cancelled_operation")
    reloaded = value.get("reloaded_operation")
    counts = value.get("counts")
    checks = value.get("checks")
    blocked = value.get("blocked_requests")
    expected_counts = {
        "session",
        "provider_save",
        "activation",
        "authorization",
        "graph_context",
        "graph_context_get",
        "assistance_submit",
        "cancel",
    }
    if (
        not isinstance(checks, list)
        or len(checks) > 16
        or any(
            not isinstance(item, str) or not re.fullmatch(r"[a-z_]{1,96}", item) for item in checks
        )
        or not isinstance(blocked, list)
        or len(blocked) > 32
        or any(
            not isinstance(item, dict)
            or set(item) != {"method", "path", "reason"}
            or item.get("method") not in {"GET", "HEAD", "POST"}
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[a-zA-Z0-9_./{}-]{1,160}", item["path"])
            or not isinstance(item.get("reason"), str)
            or not re.fullmatch(r"[a-z0-9_]{1,64}", item["reason"])
            for item in blocked
        )
        or not isinstance(operation, dict)
        or set(operation) != {"job_id", "job_state", "turn_status", "result_count"}
        or not isinstance(operation.get("job_id"), str)
        or not re.fullmatch(r"job-[0-9a-f]{32}", operation["job_id"])
        or operation.get("job_state") not in {"cancelled", "failed", "completed", "interrupted"}
        or operation.get("turn_status") not in {"cancelled", "blocked", "completed", "failed"}
        or type(operation.get("result_count")) is not int
        or not isinstance(reloaded, dict)
        or set(reloaded) != {"job_id", "job_state", "turn_status", "result_count"}
        or reloaded != operation
        or not isinstance(counts, dict)
        or set(counts) != expected_counts
        or any(type(count) is not int or not 0 <= count <= 2 for count in counts.values())
        or any(
            type(value.get(key)) is not bool
            for key in (
                "installed_service",
                "local_fixture_only",
                "live_model_inference",
                "native_execution",
                "browser_context_closed",
                "browser_closed",
                "cleanup_passed",
            )
        )
    ):
        return None
    return {key: value[key] for key in sorted(value)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--playwright", required=True, type=Path)
    parser.add_argument("--browser-driver", required=True, type=Path)
    parser.add_argument("--browser-cache", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("Use isolated installed Linux Python for this verifier")

    forbidden = args.forbid_root.resolve(strict=True)
    output = args.output.resolve()
    node = args.node.resolve(strict=True)
    playwright = args.playwright.resolve(strict=True)
    driver = args.browser_driver.resolve(strict=True)
    cache = args.browser_cache.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    if (
        output.is_relative_to(forbidden)
        or output.exists()
        or driver.is_relative_to(forbidden)
        or Path.cwd().is_relative_to(forbidden)
    ):
        raise RuntimeError(
            "Copy the driver outside checkout and use a fresh external output folder"
        )
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    report: dict[str, object] = {
        "schema_version": "bluefire.private-installed-assistant-cancellation.v1",
        "status": "failed_or_incomplete",
        "scope": "installed_assistant_stop_and_page_reload_recovery",
        "fixture_only": True,
        "live_model_inference": False,
        "native_execution": False,
        "assistant_inflight_process_restart_recovery": False,
        "not_proven": [
            "native job or Assistant-triggered native execution cancellation",
            "Assistant recovery across a BlueFire service process restart",
            "live model inference or external endpoint behavior",
        ],
    }
    environment: dict[str, str] = {}
    service = None
    server = None
    service_thread: threading.Thread | None = None
    service_thread_started = False
    fixture: HeldAssistantFixture | None = None
    process: subprocess.Popen[bytes] | None = None
    capability = ""
    cleanup: dict[str, object] = {
        "browser_process_group": "not_started",
        "fixture_thread": "not_started",
        "service_http_server": "not_started",
        "service_thread": "not_started",
        "service": "not_started",
        "temporary_state_removed": False,
    }
    try:
        runtime.mkdir(mode=0o700)
        for name in ("home", "state", "temp", "work"):
            (runtime / name).mkdir(mode=0o700)
        environment = {
            "PATH": os.pathsep.join((str(node.parent), "/usr/bin", "/bin")),
            "HOME": str(runtime / "home"),
            "XDG_STATE_HOME": str(runtime / "state"),
            "XDG_CONFIG_HOME": str(runtime / "state"),
            "XDG_CACHE_HOME": str(runtime / "temp"),
            "TMPDIR": str(runtime / "temp"),
            "LANG": "C.UTF-8",
            "PLAYWRIGHT_BROWSERS_PATH": str(cache),
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        }
        os.environ.clear()
        os.environ.update(environment)
        os.chdir(runtime / "work")

        import bluefire
        from bluefire.api import create_server, generate_browser_bootstrap_capability
        from bluefire.service import BlueFireService

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
            raise RuntimeError("BlueFire must be wheel-installed outside checkout")
        build_info = json.loads((package / "_build_info.json").read_text(encoding="utf-8"))
        report["identity"] = {
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "product_version": distribution.version,
            "source_revision": build_info.get("source_revision"),
            "source_provenance": build_info.get("source_provenance"),
            "wheel_sha256": digest(wheel),
            "ui_sha256": {
                name: digest(package / "ui" / name)
                for name in ("index.html", "app.js", "styles.css")
            },
            "harness_sha256": digest(Path(__file__)),
            "browser_driver_sha256": digest(driver),
            "node_sha256": digest(node),
            "playwright_sha256": digest(playwright),
            "environment_names": sorted(environment),
            "installed_outside_checkout": True,
        }
        service = BlueFireService(runs_dir=runtime / "runs")
        capability = generate_browser_bootstrap_capability()
        server = create_server(
            service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
        )
        service_thread = threading.Thread(target=server.serve_forever, daemon=True)
        fixture = HeldAssistantFixture()
        service_thread.start()
        service_thread_started = True
        fixture.start()
        process = subprocess.Popen(
            [
                str(node),
                str(driver),
                str(playwright),
                str(output),
                str(server.server_address[1]),
                str(fixture.port),
            ],
            cwd=runtime / "work",
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        assert process.stdin is not None
        process.stdin.write(json.dumps({"capability": capability}).encode("utf-8"))
        process.stdin.close()
        capability = ""
        try:
            process.wait(timeout=240)
        except subprocess.TimeoutExpired:
            report["browser_driver_timeout"] = True
        report["browser_returncode"] = process.returncode
        driver_path = output / "installed-cancellation-report.json"
        if driver_path.is_file() and driver_path.stat().st_size <= 65_536:
            raw_driver_report = json.loads(driver_path.read_text(encoding="utf-8"))
            driver_report = safe_driver_report(raw_driver_report)
            if driver_report is not None:
                report["browser_journey"] = driver_report
            report["status"] = (
                "passed"
                if process.returncode == 0 and _report_passed(driver_report)
                else "failed_or_incomplete"
            )
        else:
            report["driver_report_present"] = False
        with fixture.lock:
            report["fixture"] = {
                "request_count": fixture.request_count,
                "request_bytes": fixture.request_bytes,
                "failed": fixture.failed,
            }
        if fixture.request_count != 1 or fixture.failed:
            report["status"] = "failed_or_incomplete"
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["status"] = "failed_or_incomplete"
    finally:
        capability = ""
        if process is not None:
            try:
                cleanup["browser_process_group"] = (
                    "stopped" if stop_group(process) else "stop_failed"
                )
            except (OSError, subprocess.SubprocessError):
                cleanup["browser_process_group"] = "stop_failed"
        if fixture is not None:
            try:
                cleanup["fixture_thread"] = (
                    "stopped"
                    if fixture.close() and fixture.started
                    else "not_started" if not fixture.started else "stop_failed"
                )
            except (OSError, RuntimeError):
                cleanup["fixture_thread"] = "stop_failed"
        if server is not None:
            try:
                if service_thread_started:
                    server.shutdown()
                server.server_close()
                cleanup["service_http_server"] = "closed"
            except (OSError, RuntimeError):
                cleanup["service_http_server"] = "close_failed"
        if service is not None:
            try:
                service.close()
                cleanup["service"] = "closed"
            except Exception:
                cleanup["service"] = "close_failed"
        if service_thread_started and service_thread is not None:
            service_thread.join(timeout=10)
            cleanup["service_thread"] = (
                "stopped" if not service_thread.is_alive() else "stop_failed"
            )
        cleanup_ok = cleanup_confirmed({**cleanup, "temporary_state_removed": True})
        try:
            os.chdir(output)
        except OSError:
            cleanup_ok = False
        if cleanup_ok:
            try:
                if runtime.exists():
                    shutil.rmtree(runtime)
            except OSError:
                cleanup_ok = False
        cleanup["temporary_state_removed"] = cleanup_ok and not runtime.exists()
        if not cleanup_confirmed(cleanup):
            report["status"] = "failed_or_incomplete"
        report["cleanup"] = cleanup
        write_new(output / "installed-cancellation-receipt.json", report)
        print(json.dumps({"status": report["status"], "cleanup": cleanup}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
