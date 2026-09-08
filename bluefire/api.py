"""Loopback-only HTTP shell for the BlueFire platform service.

The module deliberately contains no orchestration logic.  A caller injects a
``PlatformService`` implementation and the request handler only performs HTTP
validation, dispatch, and JSON serialization.  This keeps the CLI and browser
on the same policy-enforcing control-plane path.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import re
import secrets
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from .api_context import API_PREFIX, JsonResult, PlatformService
from .api_context import JsonObject as JsonObject
from .api_routes import APIRoutes
from .application_errors import APIError

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_REQUEST_BODY = 1_048_576
_REVIEWED_T1082_INTAKE_ROUTE = f"{API_PREFIX}/research-intakes/mitre-attack-t1082-v19-2"

BROWSER_BOOTSTRAP_FRAGMENT_KEY = "bluefire-session"
BROWSER_BOOTSTRAP_HEADER = "X-BlueFire-Browser-Bootstrap"
BROWSER_SESSION_COOKIE = "bluefire_session"
BROWSER_BOOTSTRAP_LIFETIME_SECONDS = 5 * 60
BROWSER_SESSION_LIFETIME_SECONDS = 8 * 60 * 60

_BROWSER_TOKEN = re.compile(r"^[A-Za-z0-9_-]{64}$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_COOKIE_VALUE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$")

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
        # Radix Dialog computes one scroll-lock stylesheet from the local
        # scrollbar width. Its content hash is platform-dependent, so styles
        # permit inline CSS while scripts remain strictly self-hosted.
        "style-src 'self' 'unsafe-inline'; "
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


def generate_browser_bootstrap_capability() -> str:
    """Return a URL-fragment-safe capability with 384 bits of entropy."""

    capability = secrets.token_urlsafe(48)
    if _BROWSER_TOKEN.fullmatch(capability) is None:  # pragma: no cover - defensive invariant
        raise RuntimeError("the browser bootstrap capability generator returned an invalid token")
    return capability


def browser_console_url(host: str, port: int, capability: str) -> str:
    """Build the CLI launch URL without putting the capability in an HTTP request target."""

    _validate_bind(host, port)
    if port == 0:
        raise ValueError("a browser console URL requires a non-zero listener port")
    if _BROWSER_TOKEN.fullmatch(capability) is None:
        raise ValueError("browser bootstrap capability is invalid")
    address = (
        f"[{host}]" if host != "localhost" and ipaddress.ip_address(host).version == 6 else host
    )
    return f"http://{address}:{port}/#{BROWSER_BOOTSTRAP_FRAGMENT_KEY}={capability}"


class _BrowserSessionAuthority:
    """Concurrency-safe, memory-only authority for one browser launch session."""

    def __init__(self, bootstrap_capability: str) -> None:
        if _BROWSER_TOKEN.fullmatch(bootstrap_capability) is None:
            raise ValueError("browser bootstrap capability is invalid")
        now = time.monotonic()
        self._bootstrap_digest: bytes | None = hashlib.sha256(
            bootstrap_capability.encode("ascii")
        ).digest()
        self._bootstrap_expires_at = now + BROWSER_BOOTSTRAP_LIFETIME_SECONDS
        self._sessions: dict[bytes, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("ascii")).digest()

    def exchange(self, capability: str) -> str | None:
        """Consume the exact launch capability and mint one bounded session."""

        if _BROWSER_TOKEN.fullmatch(capability) is None:
            return None
        candidate_digest = self._digest(capability)
        with self._lock:
            now = time.monotonic()
            expected_digest = self._bootstrap_digest
            if expected_digest is None:
                return None
            if now >= self._bootstrap_expires_at:
                self._bootstrap_digest = None
                return None
            if not secrets.compare_digest(candidate_digest, expected_digest):
                return None
            # Consume before generating or returning anything. Only one concurrent
            # request can cross this boundary, even if entropy generation fails.
            self._bootstrap_digest = None
            session = secrets.token_urlsafe(48)
            if _BROWSER_TOKEN.fullmatch(session) is None:  # pragma: no cover - invariant
                return None
            self._sessions = {
                self._digest(session): now + BROWSER_SESSION_LIFETIME_SECONDS,
            }
            return session

    def validates(self, session: str) -> bool:
        """Return whether a syntactically exact session is present and unexpired."""

        if _BROWSER_TOKEN.fullmatch(session) is None:
            return False
        digest = self._digest(session)
        with self._lock:
            now = time.monotonic()
            expires_at = self._sessions.get(digest)
            if expires_at is None:
                return False
            if now >= expires_at:
                del self._sessions[digest]
                return False
            return True


class BlueFireHTTPServer(ThreadingHTTPServer):
    """Threaded local server with adapter configuration and ephemeral browser sessions."""

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
        browser_sessions: _BrowserSessionAuthority,
    ) -> None:
        self.service = service
        self.ui_root = ui_root
        self.max_request_body = max_request_body
        self.browser_sessions = browser_sessions
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


class BlueFireRequestHandler(BaseHTTPRequestHandler):
    """Strict request adapter; domain behavior remains in ``PlatformService``."""

    protocol_version = "HTTP/1.1"
    server_version = "BlueFireLoopback/1"
    sys_version = ""

    @property
    def platform_server(self) -> BlueFireHTTPServer:
        return self.server  # type: ignore[return-value]

    @property
    def _routes(self) -> APIRoutes:
        return APIRoutes(self)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._request_path()
        if path is None or not self._validate_host():
            return
        if path in _STATIC_ROUTES:
            self._serve_asset(path, include_body=True)
            return
        if self._is_api_path(path) and not self._require_browser_session():
            return
        if path == f"{API_PREFIX}/session":
            if self._routes._management_query_free():
                self._send(HTTPStatus.NO_CONTENT, b"", "application/json; charset=utf-8")
            return
        preparation_run_id = self._routes._run_replay_preparation_id(path)
        if preparation_run_id is not None:
            if preparation_run_id:
                self._method_not_allowed("POST")
            return
        resolution_run_id = self._routes._run_replay_submission_resolution_id(path)
        if resolution_run_id is not None:
            if resolution_run_id:
                self._method_not_allowed("POST")
            return
        replay_job_run_id = self._routes._run_replay_job_id(path)
        if replay_job_run_id is not None:
            if replay_job_run_id:
                self._method_not_allowed("POST")
            return
        if path in {f"{API_PREFIX}/ai/drafts", f"{API_PREFIX}/ai/providers/check"}:
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        if path == _REVIEWED_T1082_INTAKE_ROUTE:
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        if path == f"{API_PREFIX}/settings":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.settings())
            return
        action_package_request = self._routes._action_package_request(path)
        if action_package_request is not None:
            package_id, package_version, package_action = action_package_request
            if package_id == "":
                return
            if package_version is not None or package_action is not None:
                self._method_not_allowed("POST")
            elif package_id is None:
                self._dispatch(lambda: self.platform_server.service.action_packages())
            else:
                self._dispatch(lambda: self.platform_server.service.action_package(package_id))
            return
        action_package_publisher_request = self._routes._action_package_publisher_request(path)
        if action_package_publisher_request is not None:
            publisher_id, _key_id, _action = action_package_publisher_request
            if publisher_id != "":
                self._method_not_allowed("POST")
            return
        if path == f"{API_PREFIX}/scenario-versions":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.scenario_versions())
            return
        if path == f"{API_PREFIX}/runner":
            valid, profile_id = self._routes._runner_status_query()
            if valid:
                self._dispatch(
                    lambda: self.platform_server.service.runner_status(profile_id=profile_id)
                )
            return
        if path in {
            f"{API_PREFIX}/runner/bootstrap",
            f"{API_PREFIX}/runner/start",
            f"{API_PREFIX}/runner/stop",
            f"{API_PREFIX}/runner/revoke",
            f"{API_PREFIX}/runner/remove",
        }:
            self._method_not_allowed("POST")
            return
        setting_key = self._routes._setting_key(path)
        if setting_key is not None:
            if setting_key:
                self._method_not_allowed("POST")
            return
        scenario_version = self._routes._scenario_version_request(path)
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
        resource_action = self._routes._resource_action_request(path)
        if resource_action is not None:
            kind, _resource_id, _action = resource_action
            if kind:
                self._method_not_allowed("POST")
            return
        resource_request = self._routes._resource_request(path)
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
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.detection_health())
            return
        if path == f"{API_PREFIX}/detections/from-run":
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        detection_request = self._routes._detection_request(path)
        if detection_request is not None:
            candidate_id, detection_action = detection_request
            if candidate_id == "":
                return
            if detection_action == "evaluations" and candidate_id is not None:
                self._dispatch(
                    lambda: self.platform_server.service.detection_run_evaluations(candidate_id)
                )
            elif detection_action is not None:
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
        if path == f"{API_PREFIX}/jobs":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.active_jobs())
            return
        proposal_request = self._routes._proposal_review_request(path)
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
        receiver = self._routes._receiver_defense_request(path, listing=True)
        if receiver is not None:
            if receiver[0] == "read":
                self._dispatch(
                    lambda: self.platform_server.service.receiver_defense_job(receiver[1])
                )
            elif receiver[0] == "jobs":
                self._dispatch(
                    lambda: self.platform_server.service.receiver_defense_jobs(
                        cursor=receiver[1] or None
                    )
                )
            elif receiver[0]:
                self._method_not_allowed("POST")
            return
        graph_context = self._routes._graph_context_request(path)
        if graph_context is not None:
            if graph_context[0]:
                self._dispatch(
                    lambda: self.platform_server.service.assistance_graph_context(graph_context[1])
                )
            return
        if path == f"{API_PREFIX}/assistance/receiver-context":
            self._method_not_allowed("POST")
            return
        if path == f"{API_PREFIX}/assistance/run-context":
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        run_preparation = self._routes._assistance_run_request(path)
        if run_preparation is not None:
            if run_preparation[0]:
                if run_preparation[1]:
                    self._method_not_allowed("POST")
                else:
                    self._dispatch(
                        lambda: self.platform_server.service.assistance_run_job(run_preparation[0])
                    )
            return
        if path in {
            f"{API_PREFIX}/assistance/detection-source",
            f"{API_PREFIX}/assistance/detection-context",
        }:
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        creation = self._routes._detection_create_request(path)
        if creation is not None:
            if creation[0]:
                if creation[1]:
                    self._method_not_allowed("POST")
                else:
                    self._dispatch(
                        lambda: self.platform_server.service.detection_create_job(creation[0])
                    )
            return
        graph_job = self._routes._graph_job_request(path)
        if graph_job is not None:
            if graph_job[0]:
                if graph_job[1]:
                    self._method_not_allowed("POST")
                else:
                    self._dispatch(lambda: self.platform_server.service.graph_ai_job(graph_job[0]))
            return
        assistance_context = self._routes._assistance_context_request(path)
        if assistance_context is not None:
            if assistance_context[0]:
                self._dispatch(
                    lambda: self.platform_server.service.assistance_context(*assistance_context)
                )
            return
        if path == f"{API_PREFIX}/assistance/turns":
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        assistance_turn = self._routes._assistance_turn_request(path)
        if assistance_turn is not None:
            assistance_id, continuing = assistance_turn
            if assistance_id:
                if continuing:
                    self._method_not_allowed("POST")
                else:
                    self._dispatch(
                        lambda: self.platform_server.service.assistance_turn(assistance_id)
                    )
            return
        method_context_id = self._routes._run_method_comparison_id(path, context=True)
        if method_context_id is not None:
            if method_context_id:
                self._dispatch(
                    lambda: self.platform_server.service.method_comparison_context(
                        method_context_id
                    )
                )
            return
        method_submission_id = self._routes._run_method_comparison_id(path)
        if method_submission_id is not None:
            if method_submission_id:
                self._method_not_allowed("POST")
            return
        if path.endswith(("/detection-revision-decisions", "/method-comparison-decisions")):
            decision_request = self._routes._job_action_request(path)
            if decision_request is not None:
                if decision_request[0]:
                    self._method_not_allowed("POST")
                return
        job_id = self._routes._job_detail_id(path)
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
        event_request = self._routes._run_events_request(path)
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
        bundle_id = self._routes._run_bundle_id(path)
        if bundle_id is not None:
            if bundle_id:
                self._send_run_bundle(bundle_id)
            return
        detail_run_id = self._routes._run_detail_id(path)
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
        if self._is_api_path(path) and not self._require_browser_session():
            return
        bundle_id = self._routes._run_bundle_id(path)
        if bundle_id is not None:
            if bundle_id:
                self._method_not_allowed("GET")
            return
        if path == _REVIEWED_T1082_INTAKE_ROUTE:
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        action_package_allow = self._routes._action_package_route_allow(path)
        if action_package_allow is not None:
            if action_package_allow:
                self._method_not_allowed(action_package_allow)
            return
        self._method_not_allowed("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = self._request_path()
        if path is None or not self._validate_host() or not self._validate_same_origin():
            return
        if path == f"{API_PREFIX}/session":
            self._exchange_browser_session()
            return
        if self._is_api_path(path) and not self._require_browser_session(unread_body=True):
            return
        body = self._read_json_object()
        if body is None:
            return
        if path == _REVIEWED_T1082_INTAKE_ROUTE:
            if self._routes._management_query_free():
                self._dispatch(
                    lambda: self.platform_server.service.intake_reviewed_t1082(body),
                    success_status=HTTPStatus.CREATED,
                )
            return
        if path == f"{API_PREFIX}/runner":
            self._method_not_allowed("GET")
            return
        runner_action = path.removeprefix(f"{API_PREFIX}/runner/")
        if runner_action in {"bootstrap", "start", "stop", "revoke", "remove"}:
            profile_id = body.get("profile_id")
            if runner_action == "bootstrap":
                if set(body) - {"profile_id", "allow_upgrade"}:
                    self._error(
                        HTTPStatus.BAD_REQUEST,
                        "runner_action_invalid",
                        "Runner bootstrap accepts only profile_id and allow_upgrade.",
                    )
                    return
                self._dispatch(
                    lambda: self.platform_server.service.bootstrap_runner(
                        profile_id=profile_id,
                        allow_upgrade=body.get("allow_upgrade", False),
                    )
                )
                return
            if runner_action in {"start", "stop"}:
                if set(body) - {"profile_id"}:
                    self._error(
                        HTTPStatus.BAD_REQUEST,
                        "runner_action_invalid",
                        "Runner start and stop accept only profile_id.",
                    )
                    return
                runner_lifecycle_operation = (
                    self.platform_server.service.start_runner
                    if runner_action == "start"
                    else self.platform_server.service.stop_runner
                )
                self._dispatch(lambda: runner_lifecycle_operation(profile_id=profile_id))
                return
            if runner_action == "revoke":
                if body:
                    self._error(
                        HTTPStatus.BAD_REQUEST,
                        "runner_action_invalid",
                        "Runner revocation requires an empty JSON object.",
                    )
                    return
                self._dispatch(lambda: self.platform_server.service.revoke_runner())
                return
            confirm_runner_id = body.get("confirm_runner_id")
            if set(body) != {"confirm_runner_id"} or not isinstance(confirm_runner_id, str):
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "runner_action_invalid",
                    "Runner removal requires only confirm_runner_id.",
                )
                return
            self._dispatch(
                lambda: self.platform_server.service.remove_runner(
                    confirm_runner_id=confirm_runner_id
                )
            )
            return
        if path == f"{API_PREFIX}/ai/providers/check":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.check_ai_provider(body))
            return
        if path == f"{API_PREFIX}/ai/drafts":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.draft_ai_graph(body))
            return
        action_package_request = self._routes._action_package_request(path)
        if action_package_request is not None:
            package_id, package_version, package_action = action_package_request
            if package_id == "":
                return
            if package_id is None:
                self._dispatch(
                    lambda: self.platform_server.service.install_action_package(body),
                    success_status=HTTPStatus.CREATED,
                )
            elif package_version is None or package_action is None:
                self._method_not_allowed("GET")
            else:
                package_operations = {
                    "activate": self.platform_server.service.activate_action_package,
                    "deactivate": self.platform_server.service.deactivate_action_package,
                    "remove": self.platform_server.service.remove_action_package,
                }
                package_operation = package_operations[package_action]
                self._dispatch(lambda: package_operation(package_id, package_version, body))
            return
        action_package_publisher_request = self._routes._action_package_publisher_request(path)
        if action_package_publisher_request is not None:
            publisher_id, key_id, action = action_package_publisher_request
            if publisher_id == "":
                return
            if publisher_id is None:
                self._dispatch(
                    lambda: self.platform_server.service.trust_action_package_publisher(body),
                    success_status=HTTPStatus.CREATED,
                )
            else:
                assert key_id is not None and action is not None
                self._dispatch(
                    lambda: self.platform_server.service.transition_action_package_publisher(
                        publisher_id,
                        key_id,
                        action,
                        body,
                    )
                )
            return
        if path == f"{API_PREFIX}/scenario-versions":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.save_scenario_version(body))
            return
        setting_key = self._routes._setting_key(path)
        if setting_key is not None:
            if setting_key:
                self._dispatch(
                    lambda: self.platform_server.service.upsert_setting(setting_key, body)
                )
            return
        scenario_version = self._routes._scenario_version_request(path)
        if scenario_version is not None:
            scenario_id, _version = scenario_version
            if scenario_id:
                self._method_not_allowed("GET")
            return
        resource_action = self._routes._resource_action_request(path)
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
            resource_operations = {
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
            self._dispatch(resource_operations[action])
            return
        resource_request = self._routes._resource_request(path)
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
            if self._routes._management_query_free():
                self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/detections/from-run":
            if self._routes._management_query_free():
                self._dispatch(
                    lambda: self.platform_server.service.detection_hypothesis_from_run(body),
                    success_status=HTTPStatus.CREATED,
                )
            return
        detection_request = self._routes._detection_request(path)
        if detection_request is not None:
            candidate_id, detection_action = detection_request
            if candidate_id == "":
                return
            if candidate_id is None:
                self._dispatch(
                    lambda: self.platform_server.service.upsert_detection_hypothesis(body),
                    success_status=HTTPStatus.CREATED,
                )
            elif detection_action is None or detection_action == "evaluations":
                self._method_not_allowed("GET")
            else:
                detection_operations = {
                    "ai-revision-jobs": lambda: (
                        self.platform_server.service.submit_detection_ai_revision(
                            candidate_id, body
                        )
                    ),
                    "evaluate-run": lambda: self.platform_server.service.evaluate_detection_run(
                        candidate_id, body
                    ),
                    "clone": lambda: self.platform_server.service.clone_detection_candidate(
                        candidate_id, body
                    ),
                    "tune": lambda: self.platform_server.service.tune_detection_candidate(
                        candidate_id, body
                    ),
                    "revise-source": lambda: self.platform_server.service.revise_detection_source(
                        candidate_id, body
                    ),
                    "compare": lambda: self.platform_server.service.compare_detection_candidates(
                        candidate_id, body
                    ),
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
                self._dispatch(
                    detection_operations[detection_action],
                    success_status=(
                        HTTPStatus.ACCEPTED
                        if detection_action == "ai-revision-jobs"
                        else (
                            HTTPStatus.CREATED
                            if detection_action in {"clone", "tune", "revise-source"}
                            else HTTPStatus.OK
                        )
                    ),
                )
            return
        if path == f"{API_PREFIX}/settings":
            if self._routes._management_query_free():
                self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/scenarios/validate":
            self._dispatch(lambda: self.platform_server.service.validate(body))
            return
        presentation_id = self._routes._run_presentation_id(path)
        if presentation_id is not None:
            if presentation_id:
                self._dispatch(
                    lambda: self.platform_server.service.rename_run(presentation_id, body)
                )
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
        if path == f"{API_PREFIX}/jobs":
            if self._routes._management_query_free():
                self._method_not_allowed("GET")
            return
        proposal_request = self._routes._proposal_review_request(path)
        if proposal_request is not None:
            proposal_job_id, proposal_record_id, proposal_action = proposal_request
            if not proposal_job_id:
                return
            if proposal_record_id is None or proposal_action is None:
                self._method_not_allowed("GET")
                return
            proposal_operations = {
                "accept": lambda: self.platform_server.service.accept_proposal_review(
                    proposal_job_id, proposal_record_id, body
                ),
                "reject": lambda: self.platform_server.service.reject_proposal_review(
                    proposal_job_id, proposal_record_id, body
                ),
            }
            self._dispatch(
                proposal_operations[proposal_action],
                success_status=HTTPStatus.ACCEPTED,
            )
            return
        job_action = self._routes._job_action_request(path)
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
            job_operations = {
                "method-comparison-decisions": lambda: (
                    self.platform_server.service.decide_method_comparison(job_id, body)
                ),
                "detection-revision-decisions": lambda: (
                    self.platform_server.service.decide_detection_ai_revision(job_id, body)
                ),
                "approval": lambda: self.platform_server.service.approve_job(job_id, body),
                "pause": lambda: self.platform_server.service.pause_job(job_id),
                "resume": lambda: self.platform_server.service.resume_job(job_id),
                "cancel": lambda: self.platform_server.service.cancel_job(job_id),
                "retry": lambda: self.platform_server.service.retry_job(job_id),
            }
            self._dispatch(job_operations[action], success_status=HTTPStatus.ACCEPTED)
            return
        if path == f"{API_PREFIX}/comparisons":
            self._dispatch(lambda: self.platform_server.service.compare(body))
            return
        receiver = self._routes._receiver_defense_request(path)
        if receiver is not None:
            operations = {
                "context": lambda: self.platform_server.service.receiver_defense_context(body),
                "jobs": lambda: self.platform_server.service.submit_receiver_defense(body),
                "prepare": lambda: self.platform_server.service.prepare_receiver_defense(
                    receiver[1], body
                ),
                "review": lambda: self.platform_server.service.review_receiver_defense(
                    receiver[1], body
                ),
            }
            if receiver[0] in operations:
                self._dispatch(operations[receiver[0]])
            elif receiver[0]:
                self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/assistance/graph-context":
            self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/assistance/receiver-context":
            if self._routes._management_query_free():
                self._dispatch(
                    lambda: self.platform_server.service.assistance_receiver_context(body)
                )
            return
        if path == f"{API_PREFIX}/assistance/run-context":
            if self._routes._management_query_free():
                self._dispatch(lambda: self.platform_server.service.assistance_run_context(body))
            return
        run_preparation = self._routes._assistance_run_request(path)
        if run_preparation is not None:
            if run_preparation[0]:
                if run_preparation[1]:
                    self._dispatch(
                        lambda: self.platform_server.service.review_assistance_run(
                            run_preparation[0], body
                        )
                    )
                else:
                    self._method_not_allowed("GET")
            return
        if path in {
            f"{API_PREFIX}/assistance/detection-source",
            f"{API_PREFIX}/assistance/detection-context",
        }:
            if self._routes._management_query_free():
                self._dispatch(
                    lambda: (
                        self.platform_server.service.detection_creation_source(body)
                        if path.endswith("/detection-source")
                        else self.platform_server.service.detection_creation_context(body)
                    )
                )
            return
        creation = self._routes._detection_create_request(path)
        if creation is not None:
            if creation[0]:
                if creation[1]:
                    self._dispatch(
                        lambda: (
                            self.platform_server.service.validate_detection_create(
                                creation[0], body
                            )
                            if creation[1] == "validate"
                            else self.platform_server.service.review_detection_create(
                                creation[0], body
                            )
                        )
                    )
                else:
                    self._method_not_allowed("GET")
            return
        graph_job = self._routes._graph_job_request(path)
        if graph_job is not None:
            if graph_job[0]:
                if graph_job[1]:
                    self._dispatch(
                        lambda: (
                            self.platform_server.service.validate_graph_ai(graph_job[0], body)
                            if graph_job[1] == "validate"
                            else self.platform_server.service.review_graph_ai(graph_job[0], body)
                        )
                    )
                else:
                    self._method_not_allowed("GET")
            return
        if path == f"{API_PREFIX}/assistance/turns":
            if self._routes._management_query_free():
                self._dispatch(
                    lambda: self.platform_server.service.submit_assistance_turn(body),
                    success_status=HTTPStatus.ACCEPTED,
                )
            return
        if path == f"{API_PREFIX}/assistance/context":
            self._method_not_allowed("GET")
            return
        assistance_turn = self._routes._assistance_turn_request(path)
        if assistance_turn is not None:
            assistance_id, continuing = assistance_turn
            if assistance_id:
                if continuing:
                    self._dispatch(
                        lambda: self.platform_server.service.continue_assistance_turn(
                            assistance_id, body
                        ),
                        success_status=HTTPStatus.ACCEPTED,
                    )
                else:
                    self._method_not_allowed("GET")
            return
        method_run_id = self._routes._run_method_comparison_id(path)
        if method_run_id is not None:
            if method_run_id:
                self._dispatch(
                    lambda: self.platform_server.service.submit_method_comparison(
                        method_run_id, body
                    ),
                    success_status=HTTPStatus.ACCEPTED,
                )
            return
        method_context_id = self._routes._run_method_comparison_id(path, context=True)
        if method_context_id is not None:
            if method_context_id:
                self._method_not_allowed("GET")
            return
        preparation_run_id = self._routes._run_replay_preparation_id(path)
        if preparation_run_id is not None:
            if preparation_run_id:
                self._dispatch(
                    lambda: self.platform_server.service.prepare_replay(preparation_run_id, body)
                )
            return
        resolution_run_id = self._routes._run_replay_submission_resolution_id(path)
        if resolution_run_id is not None:
            if resolution_run_id:
                self._dispatch(
                    lambda: self.platform_server.service.resolve_replay_submission(
                        resolution_run_id, body
                    )
                )
            return
        replay_job_run_id = self._routes._run_replay_job_id(path)
        if replay_job_run_id is not None:
            if replay_job_run_id:
                self._dispatch(
                    lambda: self.platform_server.service.submit_replay(replay_job_run_id, body),
                    success_status=HTTPStatus.ACCEPTED,
                )
            return
        run_id = self._routes._run_replay_id(path)
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
        bundle_id = self._routes._run_bundle_id(path)
        if bundle_id is not None:
            if bundle_id:
                self._method_not_allowed("GET")
            return
        detail_id = self._routes._run_detail_id(path)
        if detail_id is not None:
            if not detail_id:
                return
            self._method_not_allowed("GET")
            return
        if self._routes._run_events_request(path) is not None:
            self._method_not_allowed("GET")
            return
        self._not_found()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self._unsupported_method()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._unsupported_method()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._unsupported_method()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._unsupported_method()

    def log_message(self, _format: str, *args: Any) -> None:
        """Do not leak local request paths to stderr by default."""

    @staticmethod
    def _is_api_path(path: str) -> bool:
        return path == API_PREFIX or path.startswith(f"{API_PREFIX}/")

    def _unsupported_method(self) -> None:
        path = self._request_path()
        if path is None or not self._validate_host():
            return
        if self._is_api_path(path) and not self._require_browser_session(unread_body=True):
            return
        bundle_id = self._routes._run_bundle_id(path)
        if bundle_id is not None:
            if bundle_id:
                self._method_not_allowed("GET")
            return
        if path == _REVIEWED_T1082_INTAKE_ROUTE:
            if self._routes._management_query_free():
                self._method_not_allowed("POST")
            return
        action_package_allow = self._routes._action_package_route_allow(path)
        if action_package_allow is not None:
            if action_package_allow:
                self._method_not_allowed(action_package_allow)
            return
        self._method_not_allowed("GET, HEAD, POST")

    def _request_session_cookie(self) -> str | None:
        raw_headers = self.headers.get_all("Cookie", [])
        if len(raw_headers) != 1 or len(raw_headers[0]) > 4096:
            return None
        cookies: dict[str, str] = {}
        for raw_pair in raw_headers[0].split(";"):
            pair = raw_pair.strip()
            if not pair or "=" not in pair:
                return None
            name, value = pair.split("=", 1)
            if (
                name in cookies
                or _COOKIE_NAME.fullmatch(name) is None
                or _COOKIE_VALUE.fullmatch(value) is None
            ):
                return None
            cookies[name] = value
        return cookies.get(BROWSER_SESSION_COOKIE)

    def _require_browser_session(self, *, unread_body: bool = False) -> bool:
        session = self._request_session_cookie()
        if session is not None and self.platform_server.browser_sessions.validates(session):
            return True
        reject = self._reject_unread_body if unread_body else self._error
        reject(
            HTTPStatus.UNAUTHORIZED,
            "browser_session_required",
            "A valid local browser session is required. Relaunch with `bluefire ui`.",
        )
        return False

    def _exchange_browser_session(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST,
                "browser_session_bootstrap_invalid",
                "The browser session bootstrap request is invalid.",
            )
            return
        if self.headers.get_all("Transfer-Encoding", []):
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST,
                "browser_session_bootstrap_invalid",
                "The browser session bootstrap request is invalid.",
            )
            return
        raw_lengths = self.headers.get_all("Content-Length", [])
        if len(raw_lengths) != 1 or raw_lengths[0] != "0":
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST,
                "browser_session_bootstrap_invalid",
                "The browser session bootstrap request is invalid.",
            )
            return
        if self.headers.get_all("Content-Type", []):
            self._reject_unread_body(
                HTTPStatus.BAD_REQUEST,
                "browser_session_bootstrap_invalid",
                "The browser session bootstrap request is invalid.",
            )
            return
        capabilities = self.headers.get_all(BROWSER_BOOTSTRAP_HEADER, [])
        capability = capabilities[0] if len(capabilities) == 1 else ""
        session = self.platform_server.browser_sessions.exchange(capability)
        if session is None:
            self._reject_unread_body(
                HTTPStatus.UNAUTHORIZED,
                "browser_session_bootstrap_refused",
                "The browser launch capability is invalid, expired, or already used.",
            )
            return
        cookie = (
            f"{BROWSER_SESSION_COOKIE}={session}; HttpOnly; "
            f"Max-Age={BROWSER_SESSION_LIFETIME_SECONDS}; Path={API_PREFIX}; SameSite=Strict"
        )
        self._send(
            HTTPStatus.NO_CONTENT,
            b"",
            "application/json; charset=utf-8",
            extra_headers={"Set-Cookie": cookie},
        )

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
            HTTPStatus.OK,
            payload if include_body else b"",
            media_type,
            content_length=len(payload),
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

    def _send_run_bundle(self, run_id: str) -> None:
        try:
            payload = self.platform_server.service.run_bundle(run_id)
        except APIError as exc:
            self._error(exc.status, exc.code, exc.message, exc.details)
            return
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR, "service_error", "Run bundle export failed."
            )
            return
        self._send(
            HTTPStatus.OK,
            payload,
            "application/zip",
            extra_headers={"Content-Disposition": f'attachment; filename="{run_id}.zip"'},
        )

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
    browser_bootstrap_capability: str,
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
    browser_sessions = _BrowserSessionAuthority(browser_bootstrap_capability)
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
        browser_sessions=browser_sessions,
    )


def serve(
    service: PlatformService,
    *,
    browser_bootstrap_capability: str,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ui_root: str | Path | None = None,
    max_request_body: int = MAX_REQUEST_BODY,
    on_ready: Callable[[BlueFireHTTPServer], None] | None = None,
) -> None:
    """Bind, announce readiness, and serve while always closing owned resources."""

    server: BlueFireHTTPServer | None = None
    try:
        server = create_server(
            service,
            browser_bootstrap_capability=browser_bootstrap_capability,
            host=host,
            port=port,
            ui_root=ui_root,
            max_request_body=max_request_body,
        )
        if on_ready is not None:
            on_ready(server)
        server.serve_forever()
    finally:
        if server is not None:
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
