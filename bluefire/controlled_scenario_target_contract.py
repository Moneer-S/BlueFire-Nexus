"""Exact controlled Test-scenario shell command and HTTP response grammar."""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Mapping

from .controlled_strix_scenario import ScenarioObservationRequest
from .tenant_record_lab import TenantRecordFixture
from .util import canonical_json_bytes

_STATUS = re.compile(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\Z")
_REQUIRED_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "cache-control",
        "x-content-type-options",
        "x-bluefire-lab-request",
    }
)


class ScenarioSidecarTargetError(ValueError):
    """One target response could not be attributed to the pending tool call."""


def captured_http(stdout: bytes) -> tuple[int, dict[str, str], bytes]:
    """Parse one curl --include response without accepting a proxy preface."""
    if not isinstance(stdout, bytes) or len(stdout) > 128 * 1024:
        raise ScenarioSidecarTargetError("captured target output exceeds its bound")
    separator = b"\r\n\r\n" if b"\r\n\r\n" in stdout else b"\n\n"
    if stdout.count(separator) != 1:
        raise ScenarioSidecarTargetError("captured target output is ambiguous")
    head, body = stdout.split(separator, 1)
    if len(head) > 16 * 1024 or len(body) > 64 * 1024:
        raise ScenarioSidecarTargetError("captured target output exceeds its bound")
    try:
        lines = head.decode("ascii").replace("\r\n", "\n").split("\n")
        match = _STATUS.fullmatch(lines[0])
        if match is None:
            raise ValueError("HTTP status")
        status = int(match.group(1))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                raise ValueError("HTTP header")
            name, value = line.split(":", 1)
            key = name.strip().lower()
            if not key or key in headers or not re.fullmatch(r"[a-z0-9-]+", key):
                raise ValueError("HTTP header identity")
            headers[key] = value.strip()
    except (UnicodeError, ValueError, IndexError) as exc:
        raise ScenarioSidecarTargetError("captured HTTP response is invalid") from exc
    if not _REQUIRED_HEADERS <= headers.keys():
        raise ScenarioSidecarTargetError("captured target response headers are incomplete")
    return status, headers, body


def match_captured_http(
    stdout: bytes,
    *,
    source_status: int,
    source_headers: Mapping[str, str],
    source_body: bytes,
) -> None:
    """Require the full model-visible response to equal the target source."""
    status, headers, body = captured_http(stdout)
    try:
        normalized = {name.strip().lower(): value.strip() for name, value in source_headers.items()}
    except (AttributeError, TypeError) as exc:
        raise ScenarioSidecarTargetError("protected target headers are invalid") from exc
    if (
        len(normalized) != len(source_headers)
        or status != source_status
        or headers != normalized
        or body != source_body
    ):
        raise ScenarioSidecarTargetError("captured shell and protected target event differ")


def pending_command(
    request: ScenarioObservationRequest, argv: Any, protected_tenant_id: str
) -> None:
    """Require the fixed Test-provider command, with no shell composition."""
    try:
        args = json.loads(request.arguments_json)
        command = args["cmd"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ScenarioSidecarTargetError("pending command is invalid") from exc
    prefix = "curl --silent --show-error --include --max-time 5 "
    if request.phase_id == "discover_target":
        expected = prefix + shlex.quote(request.target_url)
    elif request.phase_id in {"try_record_lookup", "try_bounded_export"}:
        expected = (
            prefix
            + "--header "
            + shlex.quote("x-bluefire-lab-tenant: " + protected_tenant_id)
            + " "
            + shlex.quote(request.target_url)
        )
    else:
        raise ScenarioSidecarTargetError("pending target phase is unsupported")
    if (
        not isinstance(args, dict)
        or set(args) != {"cmd", "yield_time_ms"}
        or canonical_json_bytes(args).decode("ascii") != request.arguments_json
        or args["yield_time_ms"] != 5000
        or command != expected
        or argv != ["bash", "-lc", command]
    ):
        raise ScenarioSidecarTargetError("captured shell command differs from pending call")


def expected_discovery_body(fixture: TenantRecordFixture) -> bytes:
    """Derive the advertised metadata from generated target data."""
    routes = tuple(
        (
            name,
            {
                "record_lookup": "/records/{record_id}",
                "bounded_export": "/exports?tenant={tenant_id}",
            }[name],
        )
        for name in fixture.route_order
    )
    public = {
        "service": "tenant-record-lab",
        "routes": [{"name": name, "shape": shape} for name, shape in routes],
        "starting_identity": {
            "tenant_id": fixture.probe_tenant_id,
            "record_ids": [
                record.record_id for record in fixture.records_for(fixture.probe_tenant_id)
            ],
        },
        "known_tenants": [fixture.probe_tenant_id, fixture.protected_tenant_id],
        "record_directory": [record.record_id for record in fixture.records],
    }
    return canonical_json_bytes(public) + b"\n"
