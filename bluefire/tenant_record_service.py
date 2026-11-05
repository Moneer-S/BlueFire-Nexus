"""Fixed HTTP application for the generated tenant authorization lab.

This module does not start a process.  A prepared-lab guest may pass the
handler class to a loopback-bound ``HTTPServer`` after it establishes the
owned service and observer identities.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from .tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecord,
    TenantRecordFixture,
    TenantRecordLabError,
    verify_lab_session,
)
from .tenant_record_observer import (
    BoundedTenantAuditLog,
    TenantAuditRow,
    TenantRecordObservationError,
)
from .util import canonical_json_bytes

MAX_REQUEST_TARGET_CHARS = 2048
MAX_HEADER_VALUE_CHARS = 8192
_ROUTE_PATHS = {
    "record_lookup": "/records/{record_id}",
    "bounded_export": "/exports?tenant={tenant_id}",
}


class TenantRecordServiceError(ValueError):
    """Raised for an invalid trusted service configuration."""


@dataclass(frozen=True, slots=True)
class TenantResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_id() -> str:
    return "request-" + secrets.token_hex(12)


def _normalized_headers(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    items = headers.items() if isinstance(headers, Mapping) else headers
    for key, value in items:
        name = key.strip().lower()
        if (
            not name
            or name in result
            or not isinstance(value, str)
            or len(value) > MAX_HEADER_VALUE_CHARS
            or any(ord(character) < 32 and character != "\t" for character in value)
        ):
            raise TenantRecordServiceError("request headers are invalid")
        result[name] = value.strip()
    return result


class TenantRecordApplication:
    """Pure request handler with a protected controller-owned audit sink."""

    def __init__(
        self,
        *,
        fixture: TenantRecordFixture,
        config: TenantDefenseConfig,
        audit_log: BoundedTenantAuditLog,
        signing_key: bytes | None = None,
        allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "tenant-record.test"),
        clock: Callable[[], datetime] = _now,
        request_id_factory: Callable[[], str] = _request_id,
    ) -> None:
        if config.fixture_digest != fixture.digest:
            raise TenantRecordServiceError("service configuration does not match the fixture")
        if config.mode == "signed_session":
            if type(signing_key) is not bytes or len(signing_key) < 32:
                raise TenantRecordServiceError(
                    "hardened service requires its protected signing key"
                )
        elif signing_key is not None:
            raise TenantRecordServiceError(
                "baseline service cannot receive session signing material"
            )
        if not allowed_hosts or any(
            not isinstance(host, str) or not host or len(host) > 253 or "/" in host
            for host in allowed_hosts
        ):
            raise TenantRecordServiceError("service host allowlist is invalid")
        self.fixture = fixture
        self.config = config
        self.audit_log = audit_log
        self._signing_key = signing_key
        self._allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self._clock = clock
        self._request_id_factory = request_id_factory

    def _host_allowed(self, value: str) -> bool:
        if (
            not value
            or len(value) > 512
            or "@" in value
            or any(character.isspace() for character in value)
        ):
            return False
        host = value
        port = ""
        if value.startswith("["):
            end = value.find("]")
            if end < 0:
                return False
            host = value[: end + 1]
            suffix = value[end + 1 :]
            if suffix:
                if not suffix.startswith(":"):
                    return False
                port = suffix[1:]
        elif value.count(":") <= 1:
            if ":" in value:
                host, port = value.rsplit(":", 1)
        if port and (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535):
            return False
        return host.lower() in self._allowed_hosts

    def _identity(
        self, headers: Mapping[str, str], *, source_identity: str
    ) -> tuple[str | None, str]:
        if self.config.mode == "client_asserted":
            tenant = headers.get("x-bluefire-lab-tenant")
            if tenant in {self.fixture.probe_tenant_id, self.fixture.protected_tenant_id}:
                return tenant, "allowed_client_asserted"
            return None, "denied_identity_mismatch"
        authorization = headers.get("authorization", "")
        if not authorization.startswith("BlueFireLab "):
            return None, "denied_missing_session"
        if source_identity != "ordinary_user":
            return None, "denied_identity_mismatch"
        try:
            payload = verify_lab_session(
                authorization.removeprefix("BlueFireLab "),
                self.fixture,
                self.config,
                signing_key=self._signing_key or b"",
                now=self._clock(),
            )
        except TenantRecordLabError:
            return None, "denied_invalid_session"
        return str(payload["tenant_id"]), "allowed_signed_session"

    def handle(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        *,
        source_identity: str,
    ) -> TenantResponse:
        if source_identity not in {"engine_worker", "ordinary_user", "controller_probe"}:
            raise TenantRecordServiceError("request source identity is not admitted")
        request_id = self._request_id_factory()
        if not isinstance(request_id, str) or not request_id.startswith("request-"):
            raise TenantRecordServiceError("request identity factory returned an invalid identity")
        try:
            normalized = _normalized_headers(headers)
        except TenantRecordServiceError:
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="unknown",
                requested_tenant=None,
                authenticated_tenant=None,
                status=400,
                decision="invalid_request",
                records=(),
                payload={"error": "invalid_request"},
            )
        if (
            method != "GET"
            or not isinstance(target, str)
            or not 1 <= len(target) <= MAX_REQUEST_TARGET_CHARS
        ):
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="unknown",
                requested_tenant=None,
                authenticated_tenant=None,
                status=405 if method != "GET" else 400,
                decision="invalid_request",
                records=(),
                payload={"error": "invalid_request"},
            )
        if not self._host_allowed(normalized.get("host", "")):
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="unknown",
                requested_tenant=None,
                authenticated_tenant=None,
                status=400,
                decision="invalid_request",
                records=(),
                payload={"error": "invalid_host"},
            )
        if normalized.get("content-length", "0") not in {"", "0"}:
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="unknown",
                requested_tenant=None,
                authenticated_tenant=None,
                status=400,
                decision="invalid_request",
                records=(),
                payload={"error": "request_body_not_supported"},
            )
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return self._invalid_target(request_id, source_identity)
        if parsed.path == "/health" and not parsed.query:
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="health",
                requested_tenant=None,
                authenticated_tenant=None,
                status=200,
                decision="public_health",
                records=(),
                payload={
                    "status": "ready",
                    "target_snapshot_id": self.config.target_snapshot_id,
                    "service_generation": self.config.service_generation,
                    "observer": "ready",
                },
            )
        if parsed.path == "/openapi.json" and not parsed.query:
            own_records = [
                record.record_id
                for record in self.fixture.records_for(self.fixture.probe_tenant_id)
            ]
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="metadata",
                requested_tenant=None,
                authenticated_tenant=None,
                status=200,
                decision="public_metadata",
                records=(),
                payload={
                    "service": "tenant-record-lab",
                    "routes": [
                        {"name": name, "shape": _ROUTE_PATHS[name]}
                        for name in self.fixture.route_order
                    ],
                    "starting_identity": {
                        "tenant_id": self.fixture.probe_tenant_id,
                        "record_ids": own_records,
                    },
                    "known_tenants": [
                        self.fixture.probe_tenant_id,
                        self.fixture.protected_tenant_id,
                    ],
                    "record_directory": [record.record_id for record in self.fixture.records],
                },
            )
        tenant, identity_decision = self._identity(normalized, source_identity=source_identity)
        if tenant is None:
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route=self._route_name(parsed.path),
                requested_tenant=self._requested_tenant(parsed.path, parsed.query),
                authenticated_tenant=None,
                status=(
                    401
                    if identity_decision in {"denied_missing_session", "denied_invalid_session"}
                    else 403
                ),
                decision=identity_decision,
                records=(),
                payload={"error": "authorization_required"},
            )
        if parsed.path.startswith("/records/") and not parsed.query:
            record_id = parsed.path.removeprefix("/records/")
            matches = [record for record in self.fixture.records if record.record_id == record_id]
            record_tenant = matches[0].tenant_id if len(matches) == 1 else None
            if len(matches) == 1 and record_tenant == tenant:
                return self._response(
                    request_id=request_id,
                    source_identity=source_identity,
                    route="record_lookup",
                    requested_tenant=record_tenant,
                    authenticated_tenant=tenant,
                    status=200,
                    decision=identity_decision,
                    records=(matches[0],),
                    payload={"records": [matches[0].to_dict()]},
                )
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="record_lookup",
                requested_tenant=record_tenant,
                authenticated_tenant=tenant,
                status=404,
                decision="not_found",
                records=(),
                payload={"error": "record_not_found"},
            )
        if parsed.path == "/exports":
            try:
                pairs = parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=1,
                    errors="strict",
                )
            except (ValueError, UnicodeError):
                pairs = []
            requested = pairs[0][1] if len(pairs) == 1 and pairs[0][0] == "tenant" else None
            if requested is None:
                return self._invalid_target(request_id, source_identity)
            if requested != tenant:
                return self._response(
                    request_id=request_id,
                    source_identity=source_identity,
                    route="bounded_export",
                    requested_tenant=requested,
                    authenticated_tenant=tenant,
                    status=403,
                    decision="denied_identity_mismatch",
                    records=(),
                    payload={"error": "tenant_mismatch"},
                )
            records = self.fixture.records_for(tenant)
            return self._response(
                request_id=request_id,
                source_identity=source_identity,
                route="bounded_export",
                requested_tenant=requested,
                authenticated_tenant=tenant,
                status=200,
                decision=identity_decision,
                records=records,
                payload={"records": [record.to_dict() for record in records]},
            )
        return self._response(
            request_id=request_id,
            source_identity=source_identity,
            route="unknown",
            requested_tenant=None,
            authenticated_tenant=tenant,
            status=404,
            decision="not_found",
            records=(),
            payload={"error": "route_not_found"},
        )

    def _invalid_target(self, request_id: str, source_identity: str) -> TenantResponse:
        return self._response(
            request_id=request_id,
            source_identity=source_identity,
            route="unknown",
            requested_tenant=None,
            authenticated_tenant=None,
            status=400,
            decision="invalid_request",
            records=(),
            payload={"error": "invalid_request_target"},
        )

    @staticmethod
    def _route_name(path: str) -> str:
        if path.startswith("/records/"):
            return "record_lookup"
        if path == "/exports":
            return "bounded_export"
        return "unknown"

    def _requested_tenant(self, path: str, query: str) -> str | None:
        if path.startswith("/records/") and not query:
            record_id = path.removeprefix("/records/")
            matches = [record for record in self.fixture.records if record.record_id == record_id]
            return matches[0].tenant_id if len(matches) == 1 else None
        if path != "/exports":
            return None
        try:
            pairs = parse_qsl(query, strict_parsing=True, max_num_fields=1, errors="strict")
        except (ValueError, UnicodeError):
            return None
        return pairs[0][1] if len(pairs) == 1 and pairs[0][0] == "tenant" else None

    def _response(
        self,
        *,
        request_id: str,
        source_identity: str,
        route: str,
        requested_tenant: str | None,
        authenticated_tenant: str | None,
        status: int,
        decision: str,
        records: tuple[TenantRecord, ...],
        payload: Mapping[str, Any],
    ) -> TenantResponse:
        body = canonical_json_bytes(payload) + b"\n"
        response_headers = {
            "content-type": "application/json; charset=utf-8",
            "content-length": str(len(body)),
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "x-bluefire-lab-request": request_id,
        }
        response_headers_sha256 = _digest(canonical_json_bytes(response_headers))
        recorded_at = self._clock()
        if recorded_at.tzinfo is None or recorded_at.utcoffset() != timezone.utc.utcoffset(
            recorded_at
        ):
            raise TenantRecordServiceError("service clock must return a UTC timestamp")
        timestamp = recorded_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        self.audit_log.append_factory(
            lambda sequence: TenantAuditRow(
                sequence=sequence,
                request_id=request_id,
                timestamp=timestamp,
                source_identity=source_identity,
                route=route,
                requested_tenant=requested_tenant,
                authenticated_tenant=authenticated_tenant,
                response_status=status,
                response_bytes=len(body),
                response_sha256=_digest(body),
                response_headers_sha256=response_headers_sha256,
                returned_record_ids=tuple(record.record_id for record in records),
                returned_record_digests=tuple(record.digest for record in records),
                decision=decision,
                target_snapshot_id=self.config.target_snapshot_id,
                service_generation=self.config.service_generation,
            )
        )
        return TenantResponse(
            status=status,
            headers=response_headers,
            body=body,
        )


def tenant_record_handler(
    application: TenantRecordApplication,
    *,
    source_identity: Callable[[str], str],
) -> type[BaseHTTPRequestHandler]:
    """Create a stdlib handler; the caller retains bind and lifecycle authority."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "BlueFireTenantLab/1"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler interface
            try:
                response = application.handle(
                    "GET",
                    self.path,
                    list(self.headers.raw_items()),
                    source_identity=source_identity(self.client_address[0]),
                )
            except (TenantRecordServiceError, TenantRecordObservationError):
                self.send_error(500, "Lab observation unavailable")
                return
            # The bounded application owns every response header so its target-side
            # digest and the independently observed wire response are identical.
            self.send_response_only(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler interface
            self.send_error(405, "Method not allowed")

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler
