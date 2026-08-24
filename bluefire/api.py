"""Loopback-only HTTP shell for the BlueFire platform service.

The module deliberately contains no orchestration logic.  A caller injects a
``PlatformService`` implementation and the request handler only performs HTTP
validation, dispatch, and JSON serialization.  This keeps the CLI and browser
on the same policy-enforcing control-plane path.
"""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import re
import socket
import sys
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import parse_qsl, unquote, urlsplit

JsonObject = Mapping[str, Any]
JsonResult = Mapping[str, Any] | Sequence[Any]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_REQUEST_BODY = 1_048_576
API_PREFIX = "/api/v1"

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")
_DETECTION_ID = re.compile(r"^detection-[0-9a-f]{20}$")
_PROPOSAL_RECORD_ID = re.compile(r"^proposal-review-[0-9a-f]{32}$")
_MANAGEMENT_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SCENARIO_VERSION = re.compile(r"^[1-9][0-9]{0,9}$")
_RESOURCE_ROUTE_KINDS = {
    "actions": "action",
    "collectors": "collector",
    "comparisons": "comparison",
    "detection-backends": "detection_backend",
    "detections": "detection",
    "model-providers": "model_provider",
    "plugins": "plugin",
    "research-sources": "research_source",
    "runner-profiles": "runner_profile",
    "runners": "runner",
}
_UI_ROOT = Path(__file__).with_name("ui").resolve()
_STATIC_ROUTES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/ui/app.js": "app.js",
    "/ui/styles.css": "styles.css",
}
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'none'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "manifest-src 'none'; "
        "media-src 'none'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "style-src-attr 'unsafe-inline'; "
        "worker-src 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), usb=()",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@runtime_checkable
class PlatformService(Protocol):
    """Application boundary consumed by both the API shell and other clients.

    Every return value must be JSON serializable.  Request mappings are already
    syntactically valid JSON objects, but domain validation belongs to the
    service so browser, CLI, and future adapters share identical semantics.
    """

    def catalog(self) -> JsonResult:
        """Return the neutral behavior catalog and runner-profile metadata."""

    def scenarios(self) -> JsonResult:
        """Return saved/versioned scenario summaries or documents."""

    def draft_ai_graph(self, request: JsonObject) -> JsonResult:
        """Return one strict, normalized, deliberately unsaved graph draft."""

    def settings(self) -> JsonResult:
        """List secret-safe local product settings."""

    def upsert_setting(self, key: str, request: JsonObject) -> JsonResult:
        """Create or replace one local product setting."""

    def scenario_versions(self) -> JsonResult:
        """List active saved scenario versions."""

    def save_scenario_version(self, request: JsonObject) -> JsonResult:
        """Validate and save one content-addressed scenario version."""

    def scenario_version(self, scenario_id: str, *, version: int | None = None) -> JsonResult:
        """Get an active or exact saved scenario version."""

    def resources(self, kind: str) -> JsonResult:
        """List one allowlisted product resource kind."""

    def resource(self, kind: str, resource_id: str) -> JsonResult:
        """Get one allowlisted product resource."""

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Create or replace one secret-safe product resource."""

    def detection_health(self) -> JsonResult:
        """Return Detection Lab persistence and backend readiness."""

    def detection_candidates(self) -> JsonResult:
        """List strict persisted detection candidates."""

    def detection_candidate(self, candidate_id: str) -> JsonResult:
        """Return one strict persisted detection candidate."""

    def upsert_detection_hypothesis(self, request: JsonObject) -> JsonResult:
        """Create or update one unprogressed hypothesis."""

    def parse_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Parse or compile one detection candidate."""

    def exercise_detection_fixtures(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Exercise one parsed candidate against malicious fixtures."""

    def exercise_detection_observed(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Exercise one candidate against immutable observed run evidence."""

    def evaluate_detection_benign(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Evaluate one exercised candidate against benign fixtures."""

    def reject_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Reject one non-terminal candidate."""

    def activate_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Validate and activate one persisted runtime resource."""

    def deactivate_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Deactivate one persisted runtime resource."""

    def probe_runner_profile(self, resource_id: str, request: JsonObject) -> JsonResult:
        """Return a sanitized bounded inventory probe for one stored runner profile."""

    def validate(self, request: JsonObject) -> JsonResult:
        """Validate a scenario graph without executing it."""

    def preflight(self, request: JsonObject) -> JsonResult:
        """Resolve capability, policy, approval, and cleanup readiness."""

    def run(self, request: JsonObject) -> JsonResult:
        """Create a Simulate or Execute run after service-side preflight."""

    def submit_run(self, request: JsonObject) -> JsonResult:
        """Create a durable background run job."""

    def job(self, job_id: str) -> JsonResult:
        """Return one durable job snapshot."""

    def retry_job(self, job_id: str) -> JsonResult:
        """Create a safe replacement for one interrupted scenario-run job."""

    def approve_job(self, job_id: str, request: JsonObject) -> JsonResult:
        """Approve one exact Execute job intent."""

    def proposal_reviews(self, job_id: str) -> JsonResult:
        """List durable AI proposal reviews for one job."""

    def proposal_review(self, job_id: str, proposal_record_id: str) -> JsonResult:
        """Return one exact AI proposal review envelope."""

    def accept_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Accept a registered proposal for deterministic continuation."""

    def reject_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Reject a registered proposal without graph mutation."""

    def pause_job(self, job_id: str) -> JsonResult:
        """Request cooperative pause."""

    def resume_job(self, job_id: str) -> JsonResult:
        """Resume a cooperatively paused job."""

    def cancel_job(self, job_id: str) -> JsonResult:
        """Request cooperative cancellation."""

    def list(self) -> JsonResult:
        """Return run summaries suitable for history and comparison."""

    def detail(self, run_id: str) -> JsonResult:
        """Return one run, including current node and evidence state."""

    def events(self, run_id: str, *, after_sequence: int, limit: int) -> JsonResult:
        """Return one validated page from the tamper-evident run event stream."""

    def replay(self, run_id: str, request: JsonObject) -> JsonResult:
        """Create a lineage-linked replay from an immutable prior run."""

    def compare(self, request: JsonObject) -> JsonResult:
        """Compare two or more runs from canonical records."""


@dataclass(slots=True)
class APIError(Exception):
    """Safe, explicit service error that may cross the HTTP boundary."""

    status: int
    code: str
    message: str
    details: JsonResult | None = None


class BlueFireHTTPServer(ThreadingHTTPServer):
    """Threaded local server carrying only immutable adapter configuration."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        service: PlatformService,
        ui_root: Path,
        max_request_body: int,
    ) -> None:
        self.service = service
        self.ui_root = ui_root
        self.max_request_body = max_request_body
        super().__init__(server_address, handler_class)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Ignore routine browser disconnects without hiding application defects."""

        error = sys.exc_info()[1]
        if isinstance(error, ConnectionError):
            return
        super().handle_error(request, client_address)


class _BlueFireIPv6HTTPServer(BlueFireHTTPServer):
    address_family = socket.AF_INET6


def _loopback_name(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_bind(host: str, port: int) -> None:
    if not isinstance(host, str) or not _loopback_name(host):
        raise ValueError("the API must bind to a loopback address")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")


def _validate_ui_root(ui_root: str | Path | None) -> Path:
    root = Path(ui_root).resolve() if ui_root is not None else _UI_ROOT
    if not root.is_dir():
        raise ValueError(f"UI asset directory does not exist: {root}")
    return root


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _valid_management_identifier(value: str) -> bool:
    return 1 <= len(value) <= 200 and _MANAGEMENT_IDENTIFIER.fullmatch(value) is not None


class BlueFireRequestHandler(BaseHTTPRequestHandler):
    """Strict request adapter; domain behavior remains in ``PlatformService``."""

    protocol_version = "HTTP/1.1"
    server_version = "BlueFireLoopback/1"
    sys_version = ""

    @property
    def platform_server(self) -> BlueFireHTTPServer:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._request_path()
        if path is None or not self._validate_host():
            return
        if path in _STATIC_ROUTES:
            self._serve_asset(path, include_body=True)
            return
        if path == f"{API_PREFIX}/ai/drafts":
            if self._management_query_free():
                self._method_not_allowed("POST")
            return
        if path == f"{API_PREFIX}/settings":
            if self._management_query_free():
                self._dispatch(lambda: self.platform_server.service.settings())
            return
        if path == f"{API_PREFIX}/scenario-versions":
            if self._management_query_free():
                self._dispatch(lambda: self.platform_server.service.scenario_versions())
            return
        setting_key = self._setting_key(path)
        if setting_key is not None:
            if setting_key:
                self._method_not_allowed("POST")
            return
        scenario_version = self._scenario_version_request(path)
        if scenario_version is not None:
            scenario_id, version = scenario_version
            if scenario_id:
                self._dispatch(
                    lambda: self.platform_server.service.scenario_version(
                        scenario_id,
                        version=version,
                    )
                )
            return
        resource_action = self._resource_action_request(path)
        if resource_action is not None:
            kind, _resource_id, _action = resource_action
            if kind:
                self._method_not_allowed("POST")
            return
        resource_request = self._resource_request(path)
        if resource_request is not None:
            kind, resource_id = resource_request
            if not kind:
                return
            if resource_id is None:
                self._dispatch(lambda: self.platform_server.service.resources(kind))
            else:
                self._dispatch(lambda: self.platform_server.service.resource(kind, resource_id))
            return
        if path == f"{API_PREFIX}/detection-lab/health":
            if self._management_query_free():
                self._dispatch(lambda: self.platform_server.service.detection_health())
            return
        detection_request = self._detection_request(path)
        if detection_request is not None:
            candidate_id, detection_action = detection_request
            if candidate_id == "":
                return
            if detection_action is not None:
                self._method_not_allowed("POST")
            elif candidate_id is None:
                self._dispatch(lambda: self.platform_server.service.detection_candidates())
            else:
                self._dispatch(
                    lambda: self.platform_server.service.detection_candidate(candidate_id)
                )
            return
        if path == f"{API_PREFIX}/catalog":
            self._dispatch(lambda: self.platform_server.service.catalog())
            return
        if path == f"{API_PREFIX}/scenarios":
            self._dispatch(lambda: self.platform_server.service.scenarios())
            return
        if path == f"{API_PREFIX}/runs":
            self._dispatch(lambda: self.platform_server.service.list())
            return
        proposal_request = self._proposal_review_request(path)
        if proposal_request is not None:
            proposal_job_id, proposal_record_id, action = proposal_request
            if not proposal_job_id:
                return
            if action is not None:
                self._method_not_allowed("POST")
            elif proposal_record_id is None:
                self._dispatch(
                    lambda: self.platform_server.service.proposal_reviews(proposal_job_id)
                )
            else:
                self._dispatch(
                    lambda: self.platform_server.service.proposal_review(
                        proposal_job_id, proposal_record_id
                    )
                )
            return
        job_id = self._job_detail_id(path)
        if job_id is not None:
            if not job_id:
                return
            self._dispatch(lambda: self.platform_server.service.job(job_id))
            return
        if path in {
            f"{API_PREFIX}/scenarios/validate",
            f"{API_PREFIX}/runs/preflight",
            f"{API_PREFIX}/comparisons",
        } or (path.startswith(f"{API_PREFIX}/runs/") and path.endswith("/replays")):
            self._method_not_allowed("POST")
            return
        event_request = self._run_events_request(path)
        if event_request is not None:
            run_id, after_sequence, limit = event_request
            if not run_id:
                return
            self._dispatch(
                lambda: self.platform_server.service.events(
                    run_id,
                    after_sequence=after_sequence,
                    limit=limit,
                )
            )
            return
        detail_run_id = self._run_detail_id(path)
        if detail_run_id is not None:
            if not detail_run_id:
                return
            self._dispatch(lambda: self.platform_server.service.detail(detail_run_id))
            return
        self._not_found()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._request_path()
        if path is None or not self._validate_host():
            return
        if path in _STATIC_ROUTES:
            self._serve_asset(path, include_body=False)
            return
        self._method_not_allowed("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._request_path()
        if path is None or not self._validate_host() or not self._validate_same_origin():
            return
        body = self._read_json_object()
        if body is None:
            return
        if path == f"{API_PREFIX}/ai/drafts":
            if self._management_query_free():
                self._dispatch(lambda: self.platform_server.service.draft_ai_graph(body))
            return
        if path == f"{API_PREFIX}/scenario-versions":
            if self._management_query_free():
                self._dispatch(lambda: self.platform_server.service.save_scenario_version(body))
            return
        setting_key = self._setting_key(path)
        if setting_key is not None:
            if setting_key:
                self._dispatch(
                    lambda: self.platform_server.service.upsert_setting(setting_key, body)
                )
            return
        scenario_version = self._scenario_version_request(path)
        if scenario_version is not None:
            scenario_id, _version = scenario_version
            if scenario_id:
                self._method_not_allowed("GET")
            return
        resource_action = self._resource_action_request(path)
        if resource_action is not None:
            kind, action_resource_id, action = resource_action
            if not kind:
                return
            if body:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "resource_action_invalid",
                    "Resource lifecycle actions require an empty JSON object.",
                )
                return
            operations = {
                "activate": lambda: self.platform_server.service.activate_resource(
                    kind,
                    action_resource_id,
                    body,
                ),
                "deactivate": lambda: self.platform_server.service.deactivate_resource(
                    kind,
                    action_resource_id,
                    body,
                ),
                "probe": lambda: self.platform_server.service.probe_runner_profile(
                    action_resource_id,
                    body,
                ),
            }
            self._dispatch(operations[action])
            return
        resource_request = self._resource_request(path)
        if resource_request is not None:
            kind, resource_id = resource_request
            if not kind:
                return
            if resource_id is None:
                self._method_not_allowed("GET")
            else:
                self._dispatch(
                    lambda: self.platform_server.service.save_resource(kind, resource_id, body)
                )
            return
        if path == f"{API_PREFIX}/detection-lab/health":
            if self._management_query_free():
                self._method_not_allowed("GET")
            return
        detection_request = self._detection_request(path)
        if detection_request is not None:
            candidate_id, detection_action = detection_request
            if candidate_id == "":
                return
            if candidate_id is None:
                self._dispatch(
                    lambda: self.platform_server.service.upsert_detection_hypothesis(body),
                    success_status=HTTPStatus.CREATED,
                )
            elif detection_action is None:
                self._method_not_allowed("GET")
            else:
                operations = {
                    "parse": lambda: self.platform_server.service.parse_detection_candidate(
                        candidate_id, body
                    ),
                    "exercise-fixtures": lambda: (
                        self.platform_server.service.exercise_detection_fixtures(candidate_id, body)
                    ),
                    "exercise-observed": lambda: (
                        self.platform_server.service.exercise_detection_observed(candidate_id, body)
                    ),
                    "evaluate-benign": lambda: (
                        self.platform_server.service.evaluate_detection_benign(candidate_id, body)
                    ),
                    "reject": lambda: self.platform_server.service.reject_detection_candidate(
                        candidate_id, body
                    ),
                }
                self._dispatch(operations[detection_action])
            return
        if path == f"{API_PREFIX}/settings":
            if self._management_query_free():
                self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/scenarios/validate":
            self._dispatch(lambda: self.platform_server.service.validate(body))
            return
        if path == f"{API_PREFIX}/runs/preflight":
            self._dispatch(lambda: self.platform_server.service.preflight(body))
            return
        if path == f"{API_PREFIX}/runs":
            self._dispatch(
                lambda: self.platform_server.service.submit_run(body),
                success_status=HTTPStatus.ACCEPTED,
            )
            return
        proposal_request = self._proposal_review_request(path)
        if proposal_request is not None:
            proposal_job_id, proposal_record_id, proposal_action = proposal_request
            if not proposal_job_id:
                return
            if proposal_record_id is None or proposal_action is None:
                self._method_not_allowed("GET")
                return
            operations = {
                "accept": lambda: self.platform_server.service.accept_proposal_review(
                    proposal_job_id, proposal_record_id, body
                ),
                "reject": lambda: self.platform_server.service.reject_proposal_review(
                    proposal_job_id, proposal_record_id, body
                ),
            }
            self._dispatch(operations[proposal_action], success_status=HTTPStatus.ACCEPTED)
            return
        job_action = self._job_action_request(path)
        if job_action is not None:
            job_id, action = job_action
            if not job_id:
                return
            if action == "retry" and body:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "retry_invalid",
                    "Retry requires an empty JSON object.",
                )
                return
            operations = {
                "approval": lambda: self.platform_server.service.approve_job(job_id, body),
                "pause": lambda: self.platform_server.service.pause_job(job_id),
                "resume": lambda: self.platform_server.service.resume_job(job_id),
                "cancel": lambda: self.platform_server.service.cancel_job(job_id),
                "retry": lambda: self.platform_server.service.retry_job(job_id),
            }
            self._dispatch(operations[action], success_status=HTTPStatus.ACCEPTED)
            return
        if path == f"{API_PREFIX}/comparisons":
            self._dispatch(lambda: self.platform_server.service.compare(body))
            return
        run_id = self._run_replay_id(path)
        if run_id is not None:
            if not run_id:
                return
            self._dispatch(
                lambda: self.platform_server.service.replay(run_id, body),
                success_status=HTTPStatus.CREATED,
            )
            return
        if path in _STATIC_ROUTES:
            self._method_not_allowed("GET, HEAD")
            return
        if path in {
            f"{API_PREFIX}/catalog",
            f"{API_PREFIX}/scenarios",
        }:
            self._method_not_allowed("GET")
            return
        detail_id = self._run_detail_id(path)
        if detail_id is not None:
            if not detail_id:
                return
            self._method_not_allowed("GET")
            return
        if self._run_events_request(path) is not None:
            self._method_not_allowed("GET")
            return
        self._not_found()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed("GET, HEAD, POST")

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed("GET, HEAD, POST")

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed("GET, HEAD, POST")

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed("GET, HEAD, POST")

    def log_message(self, _format: str, *args: Any) -> None:
        """Do not leak local request paths to stderr by default."""

    def _request_path(self) -> str | None:
        try:
            parsed_target = urlsplit(self.path)
            if parsed_target.scheme or parsed_target.netloc:
                raise ValueError("absolute request targets are not accepted")
            raw_path = parsed_target.path
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "Request path is invalid.")
            return None
        candidate = raw_path
        for _ in range(3):
            try:
                decoded = unquote(candidate, errors="strict")
            except (UnicodeDecodeError, ValueError):
                self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "Request path is invalid.")
                return None
            if decoded == candidate:
                break
            candidate = decoded
        if "\\" in candidate or "\x00" in candidate:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "Request path is invalid.")
            return None
        if any(part in {".", ".."} for part in candidate.split("/")):
            self._error(HTTPStatus.BAD_REQUEST, "path_traversal", "Path traversal is not allowed.")
            return None
        if not candidate.startswith("/") or candidate.startswith("//"):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "Request path is invalid.")
            return None
        return candidate

    def _validate_host(self) -> bool:
        authorities = self.headers.get_all("Host", [])
        authority = authorities[0] if len(authorities) == 1 else ""
        try:
            parsed = urlsplit(f"//{authority}")
            hostname = parsed.hostname or ""
            port = parsed.port or 80
        except ValueError:
            parsed = urlsplit("")
            hostname, port = "", None
        server_port = int(self.platform_server.server_address[1])
        if (
            not _loopback_name(hostname)
            or port != server_port
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.path or parsed.query or parsed.fragment)
        ):
            reject = self._reject_unread_body if self.command == "POST" else self._error
            reject(
                HTTPStatus.MISDIRECTED_REQUEST,
                "invalid_host",
                "Host must identify this loopback listener.",
            )
            return False
        return True

    def _validate_same_origin(self) -> bool:
        origins = self.headers.get_all("Origin", [])
        authorities = self.headers.get_all("Host", [])
        origin = origins[0] if len(origins) == 1 else ""
        authority = authorities[0] if len(authorities) == 1 else ""
        try:
            parsed_origin = urlsplit(origin)
            parsed_host = urlsplit(f"//{authority}")
            origin_port = parsed_origin.port or 80
            host_port = parsed_host.port or 80
        except ValueError:
            parsed_origin = urlsplit("")
            parsed_host = urlsplit("")
            origin_port = None
            host_port = None
        same = (
            parsed_origin.scheme == "http"
            and not parsed_origin.username
            and not parsed_origin.password
            and _loopback_name(parsed_origin.hostname or "")
            and (parsed_origin.hostname or "").casefold() == (parsed_host.hostname or "").casefold()
            and origin_port == host_port == int(self.platform_server.server_address[1])
            and not parsed_origin.path
            and not parsed_origin.query
            and not parsed_origin.fragment
        )
        if not same:
            self._reject_unread_body(
                HTTPStatus.FORBIDDEN,
                "origin_rejected",
                "POST requests require this listener's same-origin Origin header.",
            )
            return False
        return True

    def _read_json_object(self) -> dict[str, Any] | None:
        if self.headers.get_all("Transfer-Encoding", []):
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST,
                "unsupported_transfer_encoding",
                "Transfer-Encoding is not supported.",
            )
            return None
        raw_lengths = self.headers.get_all("Content-Length", [])
        if not raw_lengths:
            self._reject_unread_body(
                HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required."
            )
            return None
        raw_length = raw_lengths[0]
        if len(raw_lengths) != 1 or not raw_length.isascii() or not raw_length.isdigit():
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST, "invalid_length", "Content-Length is invalid."
            )
            return None
        length = int(raw_length, 10)
        if length > self.platform_server.max_request_body:
            self.close_connection = True
            self._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"JSON request bodies are limited to {self.platform_server.max_request_body} bytes.",
                extra_headers={"Connection": "close"},
            )
            return None
        content_types = self.headers.get_all("Content-Type", [])
        content_type = content_types[0] if len(content_types) == 1 else ""
        media_type, separator, parameters = content_type.partition(";")
        if media_type.strip().casefold() != "application/json":
            self._reject_unread_body(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_type_required",
                "Content-Type must be application/json.",
            )
            return None
        if separator and parameters.strip().casefold() not in {"charset=utf-8", 'charset="utf-8"'}:
            self._reject_unread_body(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_charset",
                "JSON requests must use UTF-8.",
            )
            return None
        if length == 0:
            self._error(HTTPStatus.BAD_REQUEST, "empty_body", "A JSON object is required.")
            return None
        payload = self.rfile.read(length)
        if len(payload) != length:
            self._error(HTTPStatus.BAD_REQUEST, "incomplete_body", "Request body is incomplete.")
            return None
        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "Request body must be valid JSON.")
            return None
        if not isinstance(value, dict):
            self._error(
                HTTPStatus.BAD_REQUEST, "object_required", "Request body must be a JSON object."
            )
            return None
        return value

    def _reject_unread_body(self, status: int, code: str, message: str) -> None:
        """Reject before reading a body and close instead of parsing it as another request."""

        self.close_connection = True
        self._error(status, code, message, extra_headers={"Connection": "close"})

    def _run_detail_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        if not path.startswith(prefix):
            return None
        run_id = path[len(prefix) :]
        if "/" in run_id:
            return None
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _job_detail_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        job_id = path[len(prefix) :]
        if "/" in job_id:
            return None
        if not _JOB_ID.fullmatch(job_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ""
        return job_id

    def _job_action_request(self, path: str) -> tuple[str, str] | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix) :]
        parts = remainder.split("/")
        if len(parts) != 2 or parts[1] not in {
            "approval",
            "pause",
            "resume",
            "cancel",
            "retry",
        }:
            return None
        if not _JOB_ID.fullmatch(parts[0]):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ("", parts[1])
        return parts[0], parts[1]

    def _proposal_review_request(
        self,
        path: str,
    ) -> tuple[str, str | None, str | None] | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix) :].split("/")
        if len(parts) < 2 or parts[1] != "proposals":
            return None
        if len(parts) not in {2, 3, 4} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_path",
                "Proposal review path is invalid.",
            )
            return ("", None, None)
        job_id = parts[0]
        if not _JOB_ID.fullmatch(job_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ("", None, None)
        if len(parts) == 2:
            return job_id, None, None
        proposal_record_id = parts[2]
        if not _PROPOSAL_RECORD_ID.fullmatch(proposal_record_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_id",
                "Proposal review identifier is invalid.",
            )
            return ("", None, None)
        if len(parts) == 3:
            return job_id, proposal_record_id, None
        action = parts[3]
        if action not in {"accept", "reject"}:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_action",
                "Proposal review action must be accept or reject.",
            )
            return ("", None, None)
        return job_id, proposal_record_id, action

    def _management_query_free(self) -> bool:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_management_query",
                "Management routes do not accept query parameters or fragments.",
            )
            return False
        return True

    def _setting_key(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/settings/"
        if not path.startswith(prefix):
            return None
        key = path[len(prefix) :]
        if not self._management_query_free():
            return ""
        if not _valid_management_identifier(key):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_setting_key",
                "Setting key must be a stable lowercase identifier of at most 200 characters.",
            )
            return ""
        return key

    def _scenario_version_request(self, path: str) -> tuple[str, int | None] | None:
        prefix = f"{API_PREFIX}/scenario-versions/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) == 1:
            scenario_id, version_raw = parts[0], None
        elif len(parts) == 3 and parts[1] == "versions":
            scenario_id, version_raw = parts[0], parts[2]
        else:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version_path",
                "Scenario-version path is invalid.",
            )
            return ("", None)
        if not _valid_management_identifier(scenario_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_id",
                "Scenario ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None)
        if version_raw is None:
            return scenario_id, None
        if not _SCENARIO_VERSION.fullmatch(version_raw):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version",
                "Scenario version must be a positive decimal integer.",
            )
            return ("", None)
        version = int(version_raw, 10)
        if version > 2**31 - 1:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version",
                "Scenario version must be a positive 32-bit integer.",
            )
            return ("", None)
        return scenario_id, version

    def _resource_request(self, path: str) -> tuple[str, str | None] | None:
        prefix = f"{API_PREFIX}/resources/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) not in {1, 2} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_path",
                "Resource path is invalid.",
            )
            return ("", None)
        kind = _RESOURCE_ROUTE_KINDS.get(parts[0])
        if kind is None:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_kind",
                "Resource kind is not managed by this API.",
            )
            return ("", None)
        if len(parts) == 1:
            return kind, None
        resource_id = parts[1]
        if not _valid_management_identifier(resource_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_id",
                "Resource ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None)
        return kind, resource_id

    def _detection_request(self, path: str) -> tuple[str | None, str | None] | None:
        collection = f"{API_PREFIX}/detections"
        if path == collection:
            if not self._management_query_free():
                return ("", None)
            return (None, None)
        prefix = collection + "/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) not in {1, 2} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_path",
                "Detection lifecycle path is invalid.",
            )
            return ("", None)
        candidate_id = parts[0]
        if not _DETECTION_ID.fullmatch(candidate_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_id",
                "Detection candidate identifier is invalid.",
            )
            return ("", None)
        if len(parts) == 1:
            return (candidate_id, None)
        action = parts[1]
        if action not in {
            "parse",
            "exercise-fixtures",
            "exercise-observed",
            "evaluate-benign",
            "reject",
        }:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_action",
                "Detection lifecycle action is invalid.",
            )
            return ("", None)
        return (candidate_id, action)

    def _resource_action_request(self, path: str) -> tuple[str, str, str] | None:
        prefix = f"{API_PREFIX}/resources/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix) :].split("/")
        if len(parts) != 3 or parts[0] not in {
            "model-providers",
            "plugins",
            "runner-profiles",
        }:
            return None
        if not self._management_query_free():
            return ("", "", "")
        kind = _RESOURCE_ROUTE_KINDS[parts[0]]
        resource_id = parts[1]
        action = parts[2]
        if not _valid_management_identifier(resource_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_id",
                "Resource ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", "", "")
        allowed_actions = {"activate", "deactivate"}
        if kind == "runner_profile":
            allowed_actions.add("probe")
        if action not in allowed_actions:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_action",
                "Runtime resource action is invalid.",
            )
            return ("", "", "")
        return kind, resource_id, action

    def _run_replay_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/replays"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _run_events_request(self, path: str) -> tuple[str, int, int] | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/events"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ("", 0, 250)
        try:
            pairs = parse_qsl(
                urlsplit(self.path).query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=2,
            )
        except ValueError:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination query parameters are invalid.",
            )
            return ("", 0, 250)
        values: dict[str, str] = {}
        for key, value in pairs:
            if key not in {"after_sequence", "limit"} or key in values:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_event_page",
                    "Event pagination accepts one after_sequence and one limit value.",
                )
                return ("", 0, 250)
            values[key] = value
        after_raw = values.get("after_sequence", "0")
        limit_raw = values.get("limit", "250")
        if (
            not after_raw.isascii()
            or not after_raw.isdigit()
            or not limit_raw.isascii()
            or not limit_raw.isdigit()
        ):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination values must be non-negative decimal integers.",
            )
            return ("", 0, 250)
        after_sequence = int(after_raw, 10)
        limit = int(limit_raw, 10)
        if after_sequence > 2**63 - 1 or not 1 <= limit <= 1_000:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination requires after_sequence <= 2^63-1 and limit between 1 and 1000.",
            )
            return ("", 0, 250)
        return run_id, after_sequence, limit

    def _serve_asset(self, route: str, *, include_body: bool) -> None:
        filename = _STATIC_ROUTES[route]
        target = (self.platform_server.ui_root / filename).resolve()
        if target.parent != self.platform_server.ui_root or not target.is_file():
            self._not_found()
            return
        try:
            payload = target.read_bytes()
        except OSError:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "asset_unavailable",
                "The local UI asset is unavailable.",
            )
            return
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if media_type.startswith("text/") or media_type in {
            "application/javascript",
            "application/json",
        }:
            media_type = f"{media_type}; charset=utf-8"
        self._send(
            HTTPStatus.OK, payload if include_body else b"", media_type, content_length=len(payload)
        )

    def _dispatch(
        self,
        operation: Any,
        *,
        success_status: int = HTTPStatus.OK,
    ) -> None:
        try:
            result = operation()
            payload = json.dumps(
                result,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except APIError as exc:
            self._error(exc.status, exc.code, exc.message, exc.details)
            return
        except (TypeError, ValueError):
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "invalid_service_response",
                "The platform service returned an invalid response.",
            )
            return
        except Exception:  # pragma: no cover - defensive adapter boundary
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "service_error",
                "The platform service could not complete the request.",
            )
            return
        self._send(success_status, payload, "application/json; charset=utf-8")

    def _not_found(self) -> None:
        self._error(HTTPStatus.NOT_FOUND, "not_found", "Route not found.")

    def _method_not_allowed(self, allow: str) -> None:
        self._error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method not allowed for this route.",
            extra_headers={"Allow": allow},
        )

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        details: JsonResult | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        error: dict[str, Any] = {"error": {"code": code, "message": message}}
        if details is not None:
            error["error"]["details"] = details
        payload = json.dumps(error, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(
            status,
            payload,
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        content_length: int | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Length", str(len(payload) if content_length is None else content_length)
        )
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and payload:
            self.wfile.write(payload)


def create_server(
    service: PlatformService,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ui_root: str | Path | None = None,
    max_request_body: int = MAX_REQUEST_BODY,
) -> BlueFireHTTPServer:
    """Create, but do not start, a loopback-only platform HTTP server."""

    _validate_bind(host, port)
    if isinstance(max_request_body, bool) or not isinstance(max_request_body, int):
        raise ValueError("max_request_body must be a positive integer")
    if not 1 <= max_request_body <= 16 * 1024 * 1024:
        raise ValueError("max_request_body must be between 1 byte and 16 MiB")
    root = _validate_ui_root(ui_root)
    server_type = (
        _BlueFireIPv6HTTPServer
        if host != "localhost" and ipaddress.ip_address(host).version == 6
        else BlueFireHTTPServer
    )
    return server_type(
        (host, port),
        BlueFireRequestHandler,
        service=service,
        ui_root=root,
        max_request_body=max_request_body,
    )


def serve(
    service: PlatformService,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ui_root: str | Path | None = None,
    max_request_body: int = MAX_REQUEST_BODY,
) -> None:
    """Serve until interrupted; intended for the eventual CLI entry point."""

    server = create_server(
        service,
        host=host,
        port=port,
        ui_root=ui_root,
        max_request_body=max_request_body,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        close_service = getattr(service, "close", None)
        if callable(close_service):
            close_service()


__all__ = [
    "APIError",
    "API_PREFIX",
    "BlueFireHTTPServer",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "MAX_REQUEST_BODY",
    "PlatformService",
    "create_server",
    "serve",
]
