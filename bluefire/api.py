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
from urllib.parse import unquote, urlsplit

JsonObject = Mapping[str, Any]
JsonResult = Mapping[str, Any] | Sequence[Any]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_REQUEST_BODY = 1_048_576
API_PREFIX = "/api/v1"

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
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

    def validate(self, request: JsonObject) -> JsonResult:
        """Validate a scenario graph without executing it."""

    def preflight(self, request: JsonObject) -> JsonResult:
        """Resolve capability, policy, approval, and cleanup readiness."""

    def run(self, request: JsonObject) -> JsonResult:
        """Create a Simulate or Execute run after service-side preflight."""

    def list(self) -> JsonResult:
        """Return run summaries suitable for history and comparison."""

    def detail(self, run_id: str) -> JsonResult:
        """Return one run, including current node and evidence state."""

    def replay(self, run_id: str, request: JsonObject) -> JsonResult:
        """Create a lineage-linked replay from an immutable prior run."""

    def compare(self, request: JsonObject) -> JsonResult:
        """Compare two or more runs from canonical records."""


@dataclass(frozen=True, slots=True)
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
        if path == f"{API_PREFIX}/catalog":
            self._dispatch(lambda: self.platform_server.service.catalog())
            return
        if path == f"{API_PREFIX}/scenarios":
            self._dispatch(lambda: self.platform_server.service.scenarios())
            return
        if path == f"{API_PREFIX}/runs":
            self._dispatch(lambda: self.platform_server.service.list())
            return
        if path in {
            f"{API_PREFIX}/scenarios/validate",
            f"{API_PREFIX}/runs/preflight",
            f"{API_PREFIX}/comparisons",
        } or (path.startswith(f"{API_PREFIX}/runs/") and path.endswith("/replays")):
            self._method_not_allowed("POST")
            return
        run_id = self._run_detail_id(path)
        if run_id is not None:
            if not run_id:
                return
            self._dispatch(lambda: self.platform_server.service.detail(run_id))
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
        if path == f"{API_PREFIX}/scenarios/validate":
            self._dispatch(lambda: self.platform_server.service.validate(body))
            return
        if path == f"{API_PREFIX}/runs/preflight":
            self._dispatch(lambda: self.platform_server.service.preflight(body))
            return
        if path == f"{API_PREFIX}/runs":
            self._dispatch(
                lambda: self.platform_server.service.run(body),
                success_status=HTTPStatus.CREATED,
            )
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
