"""Exercise the installed wheel's real HTTP service and packaged desktop UI.

Run this copied verifier with the wheel-only interpreter, outside the checkout.
The default Linux browser journey permits saved generated work and AI-Off
simulation; it does not establish native execution. An optional receiver driver
can run one scoped installed retained-redaction workflow, but not live inference
or external access.
"""

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
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


_FIXTURE_PURPOSES = ("bluefire_experiment_assistance", "bluefire_ai_graph_draft")
_FIXTURE_MODEL = "bluefire-local-graph-fixture-v1"
_RECEIVER_PROFILE = "sandbox-endpoint-deep-lab.v1"
_RECEIVER_SCENARIO = "scenario.receiver-defense.redaction-validation.v1"
_RECEIVER_COPY_SCENARIO = re.compile(
    r"scenario\.receiver-defense\.redaction-validation\.copy\."
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.v1"
)


def _contains_receiver_session_token_field(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            key in {"session_id", "receiver_session_id"}
            or _contains_receiver_session_token_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_receiver_session_token_field(item) for item in value)
    return False


def _receiver_report_for_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Receiver driver report has an invalid shape")
    if _contains_receiver_session_token_field(value):
        raise ValueError("Receiver driver report contains a forbidden credential field")
    if not isinstance(value.get("cleanup"), dict):
        raise ValueError("Receiver driver report has an invalid shape")
    keys = (
        "status",
        "workflow",
        "runner_profile",
        "target_scope",
        "generated_record_count",
        "unique_receiver_session_count",
        "source_starter_scenario_id",
        "saved_scenario_copy",
        "run_id",
        "original_owner_job_id",
        "linked_owner_job_id",
        "baseline",
        "original_control",
        "linked_retest",
        "phase_evidence",
        "checks",
        "request_counts",
        "blocked_requests",
        "cleanup",
        "owner_status",
    )
    return {
        key: value.get(key, [] if key in {"checks", "blocked_requests"} else {}) for key in keys
    }


def _valid_receiver_artifact(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"sha256", "size_bytes"}
        and isinstance(value.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        and type(value.get("size_bytes")) is int
        and value["size_bytes"] > 0
    )


def _receiver_driver_passed(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if _contains_receiver_session_token_field(value):
        return False
    cleanup = value.get("cleanup")
    baseline = value.get("baseline")
    counts = value.get("request_counts")
    copy = value.get("saved_scenario_copy")
    original_control = value.get("original_control")
    linked = value.get("linked_retest")
    evidence = value.get("phase_evidence")
    linked_phases = linked.get("phases") if isinstance(linked, dict) else None
    terminal = baseline.get("receiver_terminal") if isinstance(baseline, dict) else None
    generated_count = value.get("generated_record_count")
    record_count = terminal.get("record_count") if isinstance(terminal, dict) else None
    redacted_count = terminal.get("redacted_record_count") if isinstance(terminal, dict) else None
    retained_count = terminal.get("retained_record_count") if isinstance(terminal, dict) else None
    return (
        value.get("schema_version") == "bluefire.installed-receiver-retained-redaction.v1"
        and value.get("status") == "passed"
        and value.get("installed_wheel_service") is True
        and value.get("native_execution_required") is True
        and value.get("workflow") == "retained_redaction_original_and_linked_retest"
        and value.get("external_credentials") is False
        and value.get("live_model_inference") is False
        and type(generated_count) is int
        and generated_count == 8
        and value.get("runner_profile") == _RECEIVER_PROFILE
        and value.get("target_scope") == ["sandbox.workspace", "network.loopback"]
        and isinstance(value.get("checks"), list)
        and isinstance(value.get("blocked_requests"), list)
        and not value["blocked_requests"]
        and isinstance(value.get("errors"), list)
        and not value["errors"]
        and isinstance(cleanup, dict)
        and cleanup.get("original_owner_completed_retained") is True
        and cleanup.get("linked_owner_completed_retained") is True
        and cleanup.get("runner_stopped") is True
        and value.get("owner_status") == "completed"
        and type(value.get("unique_receiver_session_count")) is int
        and value["unique_receiver_session_count"] == 5
        and isinstance(counts, dict)
        and type(counts.get("owner")) is int
        and counts["owner"] == 2
        and all(
            type(counts.get(name)) is int and counts[name] == 5
            for name in ("prepare", "review", "approval")
        )
        and type(counts.get("cancel")) is int
        and counts["cancel"] == 0
        and type(counts.get("save_scenario")) is int
        and counts.get("save_scenario") == 1
        and isinstance(value.get("checks"), list)
        and "packaged_starter_duplicated_and_saved_through_ui" in value["checks"]
        and "original_baseline_protected_and_legitimate_use_completed_with_retained_policy"
        in value["checks"]
        and "fresh_retest_created_through_retained_control_ui_with_original_lineage"
        in value["checks"]
        and "linked_fresh_protected_refusal_and_legitimate_use_completed_under_retained_policy"
        in value["checks"]
        and value.get("source_starter_scenario_id") == _RECEIVER_SCENARIO
        and isinstance(copy, dict)
        and set(copy) == {"scenario_id", "version", "digest"}
        and isinstance(copy.get("scenario_id"), str)
        and _RECEIVER_COPY_SCENARIO.fullmatch(copy["scenario_id"]) is not None
        and type(copy.get("version")) is int
        and copy["version"] == 1
        and isinstance(copy.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", copy["digest"]) is not None
        and isinstance(baseline, dict)
        and baseline.get("status") == "completed"
        and baseline.get("execution_state") == "completed"
        and baseline.get("mode") == "execute"
        and baseline.get("scenario_id") == copy.get("scenario_id")
        and baseline.get("run_profile") == _RECEIVER_PROFILE
        and baseline.get("receiver_decision") == "accepted"
        and baseline.get("observation_state") == "verified"
        and isinstance(terminal, dict)
        and terminal.get("decision") == "accepted"
        and terminal.get("authenticated") is True
        and type(record_count) is int
        and record_count == generated_count
        and type(redacted_count) is int
        and redacted_count == 0
        and type(retained_count) is int
        and 0 < retained_count <= record_count
        and isinstance(value.get("original_owner_job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", value["original_owner_job_id"]) is not None
        and value.get("receiver_job_id") == value.get("original_owner_job_id")
        and isinstance(value.get("linked_owner_job_id"), str)
        and re.fullmatch(r"job-[0-9a-f]{32}", value["linked_owner_job_id"]) is not None
        and value["original_owner_job_id"] != value["linked_owner_job_id"]
        and isinstance(original_control, dict)
        and original_control.get("status") == "retained"
        and original_control.get("receiver_state") == "stopped"
        and isinstance(original_control.get("control_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", original_control["control_digest"]) is not None
        and original_control.get("source_baseline_run_id") == value.get("run_id")
        and isinstance(linked, dict)
        and linked.get("status") == "completed"
        and linked.get("source_control_job_id") == value.get("original_owner_job_id")
        and linked.get("source_control_digest") == original_control.get("control_digest")
        and linked.get("source_baseline_run_id") == value.get("run_id")
        and linked.get("retained_control_status") == "retained"
        and linked.get("receiver_state") == "stopped"
        and isinstance(linked_phases, list)
        and len(linked_phases) == 2
        and [
            (
                (row.get("phase"), row.get("status"), row.get("decision"))
                if isinstance(row, dict)
                else None
            )
            for row in linked_phases
        ]
        == [("protected", "completed", "policy_refused"), ("legitimate", "completed", "accepted")]
        and isinstance(evidence, list)
        and len(evidence) == 5
        and [row.get("phase") for row in evidence if isinstance(row, dict)]
        == ["baseline", "protected", "legitimate", "protected", "legitimate"]
        and [row.get("owner_role") for row in evidence if isinstance(row, dict)]
        == ["original", "original", "original", "linked", "linked"]
        and all(
            isinstance(row, dict)
            and row.get("owner_job_id")
            == (
                value["original_owner_job_id"]
                if row.get("owner_role") == "original"
                else value["linked_owner_job_id"]
            )
            and row.get("status") == "completed"
            and row.get("execution_state") == "completed"
            and row.get("observation_state") == "verified"
            and row.get("terminal_decision") == row.get("decision")
            and row.get("terminal_authenticated") is True
            and type(row.get("terminal_record_count")) is int
            and row["terminal_record_count"] == generated_count
            and type(row.get("terminal_redacted_record_count")) is int
            and 0 <= row["terminal_redacted_record_count"] <= generated_count
            and type(row.get("terminal_retained_record_count")) is int
            and 0 <= row["terminal_retained_record_count"] <= generated_count
            and row["terminal_redacted_record_count"] + row["terminal_retained_record_count"]
            == generated_count
            and _valid_receiver_artifact(row.get("artifact"))
            and isinstance(row.get("execution_job_id"), str)
            and re.fullmatch(r"job-[0-9a-f]{32}", row["execution_job_id"]) is not None
            and isinstance(row.get("preparation_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", row["preparation_digest"]) is not None
            and isinstance(row.get("run_id"), str)
            and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", row["run_id"]) is not None
            and isinstance(row.get("cleanup"), dict)
            and row["cleanup"] == {"receiver": "verified_closed", "run": "complete"}
            for row in evidence
        )
        and len({row["execution_job_id"] for row in evidence}) == 5
        and len({row["run_id"] for row in evidence}) == 5
        and evidence[0].get("decision") == "accepted"
        and evidence[0].get("terminal_redacted_record_count") == 0
        and evidence[0].get("terminal_retained_record_count") == generated_count
        and evidence[0].get("run_id") == value.get("run_id")
        and evidence[1].get("decision") == "policy_refused"
        and evidence[1].get("artifact") == evidence[0].get("artifact")
        and evidence[2].get("decision") == "accepted"
        and evidence[2].get("artifact") != evidence[0].get("artifact")
        and evidence[2].get("legitimate_use")
        == {"baseline_run_id": value.get("run_id"), "established": True}
        and evidence[2].get("terminal_redacted_record_count") == generated_count
        and evidence[2].get("terminal_retained_record_count") == 0
        and evidence[3].get("decision") == "policy_refused"
        and evidence[3].get("artifact") == evidence[0].get("artifact")
        and evidence[4].get("decision") == "accepted"
        and evidence[4].get("artifact") != evidence[0].get("artifact")
        and evidence[4].get("legitimate_use")
        == {"baseline_run_id": value.get("run_id"), "established": True}
        and evidence[4].get("terminal_redacted_record_count") == generated_count
        and evidence[4].get("terminal_retained_record_count") == 0
        and linked_phases[0].get("run_id") == evidence[3].get("run_id")
        and linked_phases[1].get("run_id") == evidence[4].get("run_id")
        and evidence[1].get("owner_job_id") == value.get("original_owner_job_id")
        and evidence[2].get("owner_job_id") == value.get("original_owner_job_id")
        and evidence[3].get("owner_job_id") == value.get("linked_owner_job_id")
        and evidence[4].get("owner_job_id") == value.get("linked_owner_job_id")
    )


def _resolve_receiver_driver(
    driver_argument: Path | None, forbidden: Path
) -> tuple[Path | None, Path | None, Path | None]:
    if driver_argument is None:
        return None, None, None
    driver = driver_argument.resolve(strict=True)
    guards = driver.with_name("receiver-guards.mjs").resolve(strict=True)
    deadline = driver.with_name("receiver-deadline.mjs").resolve(strict=True)
    if (
        not driver.is_file()
        or not guards.is_file()
        or not deadline.is_file()
        or driver.is_relative_to(forbidden)
        or guards.is_relative_to(forbidden)
        or deadline.is_relative_to(forbidden)
        or guards.parent != driver.parent
        or deadline.parent != driver.parent
    ):
        raise RuntimeError(
            "Copy the receiver driver and its adjacent guard and deadline modules outside checkout"
        )
    return driver, guards, deadline


_RUNTIME_PROCESS_CLEANUP_KEYS = (
    "browser_process_group_stopped",
    "assistant_process_group_stopped",
    "receiver_process_group_stopped",
    "fixture_thread_stopped",
    "service_thread_stopped",
    "assistant_service_thread_stopped",
    "receiver_service_closed",
    "receiver_service_thread_stopped",
    "receiver_driver_cleanup_confirmed",
)


def _runtime_process_cleanup_confirmed(report: dict[str, object]) -> bool:
    return all(report.get(key) is True for key in _RUNTIME_PROCESS_CLEANUP_KEYS)


def _runtime_cleanup_confirmed(report: dict[str, object]) -> bool:
    return (
        _runtime_process_cleanup_confirmed(report) and report.get("temporary_state_removed") is True
    )


def _receiver_retained_redaction_accepted(report: dict[str, object]) -> bool:
    return report.get(
        "receiver_retained_redaction_driver_passed"
    ) is True and _runtime_cleanup_confirmed(report)


def _fixture_outputs() -> dict[str, dict[str, object]]:
    return {
        "bluefire_experiment_assistance": {
            "message": "Create a separate registered proposal for native review.",
            "steps": [
                {
                    "capability_id": "graph.propose_and_validate",
                    "detector_ref": "none",
                    "reason": "Use the current registered catalog.",
                }
            ],
        },
        "bluefire_ai_graph_draft": {
            "schema_version": "bluefire.ai-graph-draft.v1",
            "title": "Create and transform a bounded fixture",
            "purpose": "Prepare a typed fixture and normalize it for later inspection.",
            "start": "create_fixture",
            "steps": [
                {
                    "id": "create_fixture",
                    "behavior_id": "sandbox.fixture.create.v1",
                    "parameters": {"record_count": 4},
                },
                {
                    "id": "transform_fixture",
                    "behavior_id": "sandbox.fixture.transform.v1",
                    "parameters": {"redact_values": True},
                },
            ],
            "edges": [
                {
                    "from_step": "create_fixture",
                    "outcome": "success",
                    "to_step": "transform_fixture",
                }
            ],
            "rationale": "Both nodes are registered and their typed artifacts connect.",
            "assumptions": ["The operator will review this unsaved draft."],
        },
    }


def _fixture_request_allowed(
    request: object,
    *,
    purpose: object,
    model: object,
    body_bytes: int,
    authorization: str | None,
    request_index: int,
    accumulated_bytes: int,
) -> bool:
    if not isinstance(request, dict):
        return False
    text = request.get("text")
    format_document = text.get("format") if isinstance(text, dict) else None
    return (
        set(request)
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
        and isinstance(format_document, dict)
        and set(format_document) == {"type", "name", "schema", "strict"}
        and format_document.get("type") == "json_schema"
        and format_document.get("strict") is True
        and isinstance(format_document.get("schema"), dict)
        and isinstance(request.get("instructions"), str)
        and isinstance(request.get("input"), str)
        and request.get("max_output_tokens") == 64
        and request.get("store") is False
        and request.get("parallel_tool_calls") is False
        and request.get("tools") == []
        and request.get("tool_choice") == "none"
        and authorization is None
        and request_index < len(_FIXTURE_PURPOSES)
        and purpose == _FIXTURE_PURPOSES[request_index]
        and format_document.get("name") == purpose
        and model == _FIXTURE_MODEL
        and body_bytes > 0
        and body_bytes <= 1_048_576
        and accumulated_bytes + body_bytes <= 2_097_152
    )


class LocalGraphFixture:
    """Strict two-request structured-output endpoint; stores no prompt or response text."""

    def __init__(self) -> None:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def _send(self, status: int, payload: object) -> None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def do_GET(self) -> None:
                if self.path != "/__fixture/state":
                    self._send(404, {"error": "not_found"})
                    return
                with fixture.lock:
                    fixture.state_reads += 1
                    if fixture.state_reads > 250:
                        fixture.failed = True
                        self._send(429, {"error": "state_read_limit"})
                        return
                    state = {
                        "request_count": len(fixture.purposes),
                        "purposes": list(fixture.purposes),
                        "request_bytes": fixture.request_bytes,
                        "released": fixture.release.is_set(),
                        "failed": fixture.failed,
                    }
                self._send(200, state)

            def do_POST(self) -> None:
                raw_length = self.headers.get("Content-Length", "0")
                if (
                    not raw_length.isascii()
                    or not raw_length.isdecimal()
                    or len(raw_length) > 7
                    or (len(raw_length) > 1 and raw_length.startswith("0"))
                ):
                    fixture._fail()
                    self._send(400, {"error": "invalid_length"})
                    return
                length = int(raw_length)
                with fixture.lock:
                    if fixture.post_count >= 3 or fixture.post_bytes + length > 2_097_152:
                        fixture.failed = True
                        self._send(429, {"error": "fixture_budget_exceeded"})
                        return
                    fixture.post_count += 1
                    fixture.post_bytes += length
                if self.path == "/__fixture/release":
                    if length != 0:
                        fixture._fail()
                        self._send(400, {"error": "release_body_not_allowed"})
                        return
                    with fixture.lock:
                        if fixture.release_called:
                            fixture.failed = True
                            self._send(409, {"error": "release_already_used"})
                            return
                        fixture.release_called = True
                    fixture.release.set()
                    self._send(200, {"released": True})
                    return
                if self.path != "/v1/responses":
                    self._send(404, {"error": "not_found"})
                    return
                if length == 0:
                    fixture._fail()
                    self._send(400, {"error": "invalid_length"})
                    return
                if length > 1_048_576:
                    fixture._fail()
                    self._send(413, {"error": "request_too_large"})
                    return
                try:
                    request = json.loads(self.rfile.read(length))
                    purpose = request["text"]["format"]["name"]
                    model = request["model"]
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                    fixture._fail()
                    self._send(400, {"error": "invalid_request"})
                    return
                with fixture.lock:
                    index = len(fixture.purposes)
                    if not _fixture_request_allowed(
                        request,
                        purpose=purpose,
                        model=model,
                        body_bytes=length,
                        authorization=self.headers.get("Authorization"),
                        request_index=index,
                        accumulated_bytes=fixture.request_bytes,
                    ):
                        fixture.failed = True
                        self._send(400, {"error": "request_out_of_scope"})
                        return
                    fixture.purposes.append(purpose)
                    fixture.request_bytes += length
                if purpose == "bluefire_ai_graph_draft" and not fixture.release.wait(30):
                    fixture._fail()
                    self._send(504, {"error": "fixture_deadline"})
                    return
                output = _fixture_outputs()[purpose]
                self._send(
                    200,
                    {
                        "id": f"fixture-response-{index + 1}",
                        "model": _FIXTURE_MODEL,
                        "status": "completed",
                        "output_text": json.dumps(output, separators=(",", ":")),
                        "usage": {"input_tokens": 16, "output_tokens": 24},
                    },
                )

            def log_message(self, _format: str, *_args: object) -> None:
                return

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def handle_error(self, _request: object, _client_address: object) -> None:
                return

        self.lock = threading.Lock()
        self.release = threading.Event()
        self.purposes: list[str] = []
        self.request_bytes = 0
        self.post_count = 0
        self.post_bytes = 0
        self.state_reads = 0
        self.release_called = False
        self.failed = False
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def _fail(self) -> None:
        with self.lock:
            self.failed = True

    def start(self) -> None:
        self.thread.start()

    def close(self) -> bool:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return not self.thread.is_alive()


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            process.wait(timeout=10)
            return True
        time.sleep(0.2)
    process.wait(timeout=10)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--playwright", required=True, type=Path)
    parser.add_argument("--browser-driver", required=True, type=Path)
    parser.add_argument("--assistant-driver", type=Path)
    parser.add_argument("--receiver-driver", type=Path)
    parser.add_argument("--browser-cache", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("Use isolated installed Linux Python for this verifier")
    forbidden = args.forbid_root.resolve(strict=True)
    output = args.output.resolve()
    driver = args.browser_driver.resolve(strict=True)
    assistant_driver = args.assistant_driver.resolve(strict=True) if args.assistant_driver else None
    receiver_driver, receiver_guards, receiver_deadline = _resolve_receiver_driver(
        args.receiver_driver, forbidden
    )
    wheel = args.wheel.resolve(strict=True)
    node = args.node.resolve(strict=True)
    playwright = args.playwright.resolve(strict=True)
    cache = args.browser_cache.resolve(strict=True)
    if output.is_relative_to(forbidden) or output.exists():
        raise RuntimeError("A fresh output folder outside checkout is required")
    if (
        not driver.is_file()
        or (assistant_driver is not None and not assistant_driver.is_file())
        or driver.is_relative_to(forbidden)
        or (assistant_driver is not None and assistant_driver.is_relative_to(forbidden))
        or Path.cwd().is_relative_to(forbidden)
    ):
        raise RuntimeError("Copy the browser driver outside checkout before verification")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    runtime.mkdir(mode=0o700)
    for name in ("home", "state", "temp", "work"):
        (runtime / name).mkdir(mode=0o700)
    hosted_image = {
        name: os.environ.get(name)
        for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
    }
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
        raise RuntimeError("The package must be wheel-installed outside checkout")
    build_info = json.loads((package / "_build_info.json").read_text(encoding="utf-8"))
    write_new(
        output / "identity.json",
        {
            "schema_version": "bluefire.installed-browser-identity.v1",
            "os_release": platform.freedesktop_os_release(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hosted_image": hosted_image,
            "python_version": platform.python_version(),
            "product_version": distribution.version,
            "source_revision": build_info["source_revision"],
            "source_provenance": build_info["source_provenance"],
            "wheel_filename": wheel.name,
            "wheel_sha256": digest(wheel),
            "ui_sha256": {
                name: digest(package / "ui" / name)
                for name in ("index.html", "app.js", "styles.css")
            },
            "installed_outside_checkout": True,
            "harness_sha256": digest(Path(__file__)),
            "browser_driver_sha256": digest(driver),
            "assistant_driver_sha256": digest(assistant_driver) if assistant_driver else None,
            "receiver_driver_sha256": digest(receiver_driver) if receiver_driver else None,
            "receiver_guard_sha256": digest(receiver_guards) if receiver_guards else None,
            "environment_names": sorted(environment),
            "not_proven": [
                "CLI launch",
                "native execution beyond the optional retained-redaction receiver journey",
                "effective-access validation",
                "live model inference",
                "Assistant recovery across process restart",
                "AD, AWS, or external endpoint access",
                "other operating systems or Linux security configurations",
            ],
        },
    )
    service = BlueFireService(runs_dir=runtime / "runs")
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    child = None
    assistant_child = None
    assistant_capability = ""
    assistant_server = None
    assistant_thread = None
    fixture = None
    receiver_service = None
    receiver_capability = ""
    receiver_server = None
    receiver_thread = None
    receiver_child = None
    receiver_driver_report: dict[str, object] | None = None
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-browser-verification.v1",
        "status": "failed_or_incomplete",
        "real_installed_service": True,
        "simulation_assistant_native_execution": False,
        "receiver_native_retained_redaction": False,
        "receiver_driver_cleanup_confirmed": receiver_driver is None,
        "live_model_inference": False,
        "assistant_process_group_stopped": True,
        "fixture_thread_stopped": True,
    }
    thread.start()
    try:
        child = subprocess.Popen(
            [str(node), str(driver), str(playwright), str(output), str(server.server_address[1])],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        child.communicate(json.dumps({"capability": capability}).encode(), timeout=240)
        capability = ""
        report["browser_returncode"] = child.returncode
        if child.returncode == 0:
            report["status"] = "passed"
        if assistant_driver is not None and child.returncode == 0:
            fixture = LocalGraphFixture()
            fixture.start()
            assistant_capability = generate_browser_bootstrap_capability()
            assistant_server = create_server(
                service,
                host="127.0.0.1",
                port=0,
                browser_bootstrap_capability=assistant_capability,
            )
            assistant_thread = threading.Thread(target=assistant_server.serve_forever, daemon=True)
            assistant_thread.start()
            assistant_child = subprocess.Popen(
                [
                    str(node),
                    str(assistant_driver),
                    str(playwright),
                    str(output),
                    str(assistant_server.server_address[1]),
                    str(fixture.port),
                ],
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            assistant_child.communicate(
                json.dumps({"capability": assistant_capability}).encode(), timeout=240
            )
            assistant_capability = ""
            assistant_report_path = output / "assistant-browser-report.json"
            assistant_report = json.loads(assistant_report_path.read_text(encoding="utf-8"))
            with fixture.lock:
                fixture_summary = {
                    "model": _FIXTURE_MODEL,
                    "endpoint_kind": "local_loopback_structured_fixture",
                    "request_count": len(fixture.purposes),
                    "purposes": list(fixture.purposes),
                    "request_bytes": fixture.request_bytes,
                    "failed": fixture.failed,
                }
            report["assistant_fixture"] = {
                "status": assistant_report.get("status"),
                "driver_sha256": digest(assistant_driver),
                "provider": fixture_summary,
                "checks": assistant_report.get("checks", []),
                "screenshots": assistant_report.get("screenshots", []),
                "blocked_requests": assistant_report.get("blocked_requests", []),
            }
            report["assistant_browser_returncode"] = assistant_child.returncode
            if (
                assistant_child.returncode != 0
                or assistant_report.get("status") != "passed"
                or fixture.failed
                or fixture_summary["request_count"] != 2
                or fixture_summary["purposes"] != list(_FIXTURE_PURPOSES)
            ):
                report["status"] = "failed_or_incomplete"
        if receiver_driver is not None and report["status"] == "passed":
            receiver_service = BlueFireService(runs_dir=runtime / "receiver-runs")
            receiver_capability = generate_browser_bootstrap_capability()
            receiver_server = create_server(
                receiver_service,
                host="127.0.0.1",
                port=0,
                browser_bootstrap_capability=receiver_capability,
            )
            receiver_thread = threading.Thread(target=receiver_server.serve_forever, daemon=True)
            receiver_thread.start()
            receiver_child = subprocess.Popen(
                [
                    str(node),
                    str(receiver_driver),
                    str(playwright),
                    str(output),
                    str(receiver_server.server_address[1]),
                ],
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            receiver_child.communicate(
                json.dumps({"capability": receiver_capability}).encode(), timeout=360
            )
            receiver_capability = ""
            receiver_report_path = output / "installed-receiver-report.json"
            receiver_driver_report = json.loads(receiver_report_path.read_text(encoding="utf-8"))
            receiver_receipt = _receiver_report_for_receipt(receiver_driver_report)
            driver_cleanup = receiver_driver_report["cleanup"]
            report["receiver_driver_cleanup_confirmed"] = (
                driver_cleanup.get("original_owner_completed_retained") is True
                and driver_cleanup.get("linked_owner_completed_retained") is True
                and driver_cleanup.get("runner_stopped") is True
                and receiver_driver_report.get("owner_status") == "completed"
            )
            report["receiver_retained_redaction"] = {
                **receiver_receipt,
                "driver_sha256": digest(receiver_driver),
                "guard_sha256": digest(receiver_guards),
                "deadline_sha256": digest(receiver_deadline),
                "browser_returncode": receiver_child.returncode,
            }
            report["receiver_retained_redaction_driver_passed"] = (
                receiver_child.returncode == 0 and _receiver_driver_passed(receiver_driver_report)
            )
            if not report["receiver_retained_redaction_driver_passed"]:
                report["status"] = "failed_or_incomplete"
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        report["error_type"] = type(error).__name__
        report["status"] = "failed_or_incomplete"
    finally:
        capability = ""
        assistant_capability = ""
        receiver_capability = ""
        cleanup_errors = []
        report["browser_process_group_stopped"] = child is None
        try:
            if child is not None:
                report["browser_process_group_stopped"] = stop_group(child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("browser_process_group")
        report["assistant_process_group_stopped"] = assistant_child is None
        try:
            if assistant_child is not None:
                report["assistant_process_group_stopped"] = stop_group(assistant_child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("assistant_browser_process_group")
        report["receiver_process_group_stopped"] = receiver_child is None
        try:
            if receiver_child is not None:
                report["receiver_process_group_stopped"] = stop_group(receiver_child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("receiver_browser_process_group")
        if fixture is not None:
            try:
                report["fixture_thread_stopped"] = fixture.close()
                if fixture.failed:
                    report["status"] = "failed_or_incomplete"
            except (OSError, RuntimeError):
                report["fixture_thread_stopped"] = False
                cleanup_errors.append("assistant_fixture")
        if assistant_server is not None:
            for name, operation in (
                ("assistant_http_shutdown", assistant_server.shutdown),
                ("assistant_http_close", assistant_server.server_close),
            ):
                try:
                    operation()
                except Exception:
                    cleanup_errors.append(name)
            if assistant_thread is not None:
                assistant_thread.join(timeout=10)
        report["assistant_service_thread_stopped"] = (
            assistant_thread is None or not assistant_thread.is_alive()
        ) and not cleanup_errors
        if receiver_server is not None:
            for name, operation in (
                ("receiver_http_shutdown", receiver_server.shutdown),
                ("receiver_http_close", receiver_server.server_close),
            ):
                try:
                    operation()
                except Exception:
                    cleanup_errors.append(name)
        if receiver_service is not None:
            try:
                receiver_service.close()
                report["receiver_service_closed"] = True
            except Exception:
                report["receiver_service_closed"] = False
                cleanup_errors.append("receiver_service_close")
        else:
            report["receiver_service_closed"] = True
        if receiver_thread is not None:
            receiver_thread.join(timeout=10)
        report["receiver_service_thread_stopped"] = (
            receiver_thread is None or not receiver_thread.is_alive()
        ) and not cleanup_errors
        for name, operation in (
            ("http_shutdown", server.shutdown),
            ("http_close", server.server_close),
            ("service_close", service.close),
        ):
            try:
                operation()
            except Exception:
                cleanup_errors.append(name)
        thread.join(timeout=10)
        report["service_thread_stopped"] = not thread.is_alive() and not cleanup_errors
        os.chdir(output)
        if _runtime_process_cleanup_confirmed(report):
            try:
                shutil.rmtree(runtime)
            except OSError:
                cleanup_errors.append("temporary_state")
        report["temporary_state_removed"] = not runtime.exists()
        report["receiver_native_retained_redaction"] = _receiver_retained_redaction_accepted(report)
        report["cleanup_errors"] = cleanup_errors
        if not _runtime_cleanup_confirmed(report):
            report["status"] = "failed_or_incomplete"
        write_new(output / "receipt.json", report)
        print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
