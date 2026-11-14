"""Controller retention of independent tenant sidecar request observations.

The trusted source is the fixed target sidecar's Docker stdout under its
separately owned, pre-admission container identity. A model tool result is
never accepted as an observation. The controller persists the exact source
record before returning it to a scenario provider or final run writer.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine_relay import EngineRelayError
from .tenant_http_target_profile import canonical_tenant_http_request
from .tenant_record_observer import AUDIT_SCHEMA, TenantAuditRow, _response_headers_digest
from .util import canonical_json_bytes, content_hash

OBSERVATION_SCHEMA = "bluefire.tenant-target-sidecar-observation.v1"
READY_SCHEMA = "bluefire.tenant-target-sidecar-ready.v1"
RECEIPT_SCHEMA = "bluefire.tenant-target-sidecar-retained-request.v1"
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_REQUEST = re.compile(r"request-[0-9a-f]{24}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "target_snapshot_ref",
        "service_generation",
        "request_target",
        "target_request_id",
        "source_identity",
        "response_status",
        "response_headers",
        "response_body_b64",
        "audit_row",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "attempt_id",
        "container_id",
        "image_digest",
        "network_id",
        "network_name",
        "target_alias",
        "target_address",
        "target_snapshot_ref",
        "service_generation",
        "owner_journal_ref",
    }
)


class TenantSidecarObservationError(ValueError):
    """A source record, retention operation, or identity join is unavailable."""


def _body(value: object) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > 100_000
        or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None
    ):
        raise TenantSidecarObservationError("sidecar response body encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise TenantSidecarObservationError("sidecar response body encoding is invalid") from exc
    if (
        len(decoded) > 65_536
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise TenantSidecarObservationError("sidecar response body is outside its bound")
    return decoded


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise TenantSidecarObservationError("sidecar source has duplicate fields")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise TenantSidecarObservationError("sidecar source has a non-finite value")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise TenantSidecarObservationError("sidecar source is invalid JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise TenantSidecarObservationError("sidecar source is not canonical")
    return value


def _binding(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
        raise TenantSidecarObservationError("sidecar source binding is incomplete")
    row = dict(value)
    attempt = row["attempt_id"]
    if not isinstance(attempt, str) or _ATTEMPT.fullmatch(attempt) is None:
        raise TenantSidecarObservationError("sidecar attempt identity is invalid")
    if (
        not isinstance(row["container_id"], str)
        or _CONTAINER.fullmatch(row["container_id"]) is None
        or not isinstance(row["network_id"], str)
        or _CONTAINER.fullmatch(row["network_id"]) is None
    ):
        raise TenantSidecarObservationError("sidecar container or network identity is invalid")
    for field_name in ("image_digest", "target_snapshot_ref", "owner_journal_ref"):
        if not isinstance(row[field_name], str) or _DIGEST.fullmatch(row[field_name]) is None:
            raise TenantSidecarObservationError("sidecar source digest is invalid")
    if (
        row["target_alias"] != f"bf-target-{attempt.removeprefix('engine-attempt-')}"
        or row["network_name"] != f"bluefire-engine-{attempt.removeprefix('engine-attempt-')}"
        or not isinstance(row["target_address"], str)
        or not row["target_address"]
        or not isinstance(row["service_generation"], str)
        or not row["service_generation"]
    ):
        raise TenantSidecarObservationError("sidecar network or generation binding is invalid")
    return row


def _private_root(path: Path) -> Path:
    """Reject a pathname that another account can swap before reopen."""

    if not path.is_absolute():
        raise TenantSidecarObservationError("sidecar observation root must be absolute")
    current = path
    while True:
        details = current.lstat()
        if current.is_symlink() or not stat.S_ISDIR(details.st_mode):
            raise TenantSidecarObservationError("sidecar observation ancestor is unsafe")
        mode = stat.S_IMODE(details.st_mode)
        if current == path:
            if details.st_uid != os.geteuid() or mode != 0o700:
                raise TenantSidecarObservationError("sidecar observation root is not private")
        elif mode & 0o022:
            # A root-owned sticky /tmp is the only shared ancestor permitted.
            if not (current == Path("/tmp") and details.st_uid == 0 and mode & stat.S_ISVTX):
                raise TenantSidecarObservationError("sidecar observation ancestor is writable")
        if current.parent == current:
            break
        current = current.parent
    return path.resolve(strict=True)


@dataclass(frozen=True, slots=True)
class SidecarTargetObservation:
    attempt_id: str
    target_request_id: str
    request_target: str
    target_snapshot_ref: str
    service_generation: str
    source_identity: str
    response_status: int
    response_headers: dict[str, str]
    audit_row: TenantAuditRow
    source_binding: dict[str, str]
    source_receipt_ref: str
    docker_log_record_ref: str
    response_body: bytes = field(repr=False)

    @property
    def admitted_target_url(self) -> str:
        return f"http://{self.source_binding['target_alias']}:8080{self.request_target}"


def _checked_record(
    value: Mapping[str, Any], binding: Mapping[str, str]
) -> SidecarTargetObservation:
    if type(value) is not dict or set(value) != _FIELDS:
        raise TenantSidecarObservationError("sidecar observation fields changed")
    if (
        value["schema_version"] != OBSERVATION_SCHEMA
        or value["attempt_id"] != binding["attempt_id"]
        or value["target_snapshot_ref"] != binding["target_snapshot_ref"]
        or value["service_generation"] != binding["service_generation"]
        or value["source_identity"] != "engine_worker"
        or not isinstance(value["target_request_id"], str)
        or _REQUEST.fullmatch(value["target_request_id"]) is None
    ):
        raise TenantSidecarObservationError("sidecar observation identity changed")
    path = value["request_target"]
    try:
        route, _record, _tenant, _assertion, _headers = canonical_tenant_http_request(path, ())
    except (EngineRelayError, ValueError, TypeError) as exc:
        raise TenantSidecarObservationError(
            "sidecar request path is outside the lab grammar"
        ) from exc
    if not isinstance(value["response_headers"], dict):
        raise TenantSidecarObservationError("sidecar response headers are invalid")
    headers = value["response_headers"]
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in headers.items()):
        raise TenantSidecarObservationError("sidecar response headers are invalid")
    body = _body(value["response_body_b64"])
    audit_mapping = value["audit_row"]
    if not isinstance(audit_mapping, dict) or audit_mapping.get("schema_version") != AUDIT_SCHEMA:
        raise TenantSidecarObservationError("sidecar target audit is invalid")
    try:
        audit = TenantAuditRow(
            **{
                key: tuple(item)
                if key in {"returned_record_ids", "returned_record_digests"}
                else item
                for key, item in audit_mapping.items()
                if key != "schema_version"
            }
        )
    except (TypeError, ValueError) as exc:
        raise TenantSidecarObservationError("sidecar target audit is invalid") from exc
    if audit.to_dict() != audit_mapping:
        raise TenantSidecarObservationError("sidecar target audit is noncanonical")
    if (
        audit.request_id != value["target_request_id"]
        or headers.get("x-bluefire-lab-request") != audit.request_id
        or audit.route != route
        or audit.source_identity != "engine_worker"
        or audit.service_generation != binding["service_generation"]
        or value["response_status"] != audit.response_status
        or len(body) != audit.response_bytes
        or "sha256:" + hashlib.sha256(body).hexdigest() != audit.response_sha256
        or _response_headers_digest(headers) != audit.response_headers_sha256
    ):
        raise TenantSidecarObservationError("sidecar response differs from target audit")
    raw = canonical_json_bytes(dict(value))
    return SidecarTargetObservation(
        attempt_id=value["attempt_id"],
        target_request_id=value["target_request_id"],
        request_target=path,
        target_snapshot_ref=value["target_snapshot_ref"],
        service_generation=value["service_generation"],
        source_identity="engine_worker",
        response_status=audit.response_status,
        response_headers=dict(headers),
        response_body=body,
        audit_row=audit,
        source_binding=dict(binding),
        source_receipt_ref="",  # set after the protected record is reopened
        docker_log_record_ref="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


class OwnedTenantSidecarObservationReader:
    """Bounded Docker-log capture with owner-private, immutable reopen."""

    def __init__(
        self,
        *,
        root: Path,
        source_binding: Mapping[str, Any],
        read_owned_logs: Callable[[int], bytes],
        observed_identity: Callable[[], Mapping[str, Any]],
        max_log_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if os.name != "posix" or not callable(read_owned_logs) or not callable(observed_identity):
            raise TenantSidecarObservationError("sidecar observation requires Linux owner")
        if type(max_log_bytes) is not int or not 4096 <= max_log_bytes <= 8 * 1024 * 1024:
            raise TenantSidecarObservationError("sidecar log bound is invalid")
        self.source_binding = _binding(source_binding)
        self.root = _private_root(Path(root))
        self._read_owned_logs = read_owned_logs
        self._observed_identity = observed_identity
        if _binding(self._observed_identity()) != self.source_binding:
            raise TenantSidecarObservationError("sidecar owner identity differs from source")
        self._max_log_bytes = max_log_bytes

    def _path(self, request_id: str) -> Path:
        if not isinstance(request_id, str) or _REQUEST.fullmatch(request_id) is None:
            raise TenantSidecarObservationError("sidecar request ID is invalid")
        return self.root / f"{request_id}.json"

    def observe_request(self, target_request_id: str) -> SidecarTargetObservation:
        path = self._path(target_request_id)
        if _binding(self._observed_identity()) != self.source_binding:
            raise TenantSidecarObservationError("sidecar owner identity changed")
        raw_log = self._read_owned_logs(self._max_log_bytes)
        if type(raw_log) is not bytes or len(raw_log) > self._max_log_bytes:
            raise TenantSidecarObservationError("sidecar Docker log is unavailable")
        lines = raw_log.splitlines()
        if not 2 <= len(lines) <= 257 or not raw_log.endswith(b"\n"):
            raise TenantSidecarObservationError("sidecar Docker log is incomplete")
        matches: list[dict[str, Any]] = []
        for index, raw_line in enumerate(lines):
            if not raw_line or len(raw_line) > 128 * 1024:
                raise TenantSidecarObservationError("sidecar Docker log line is invalid")
            row = _strict_json(raw_line)
            if index == 0:
                if (
                    set(row)
                    != {
                        "schema_version",
                        "attempt_id",
                        "packet_digest",
                        "child_ready_digest",
                        "target_snapshot_ref",
                        "service_generation",
                        "target_authority",
                    }
                    or row["schema_version"] != READY_SCHEMA
                    or row["attempt_id"] != self.source_binding["attempt_id"]
                    or row["target_snapshot_ref"] != self.source_binding["target_snapshot_ref"]
                    or row["service_generation"] != self.source_binding["service_generation"]
                    or row["target_authority"] != self.source_binding["target_alias"] + ":8080"
                    or any(
                        not isinstance(row[name], str) or _DIGEST.fullmatch(row[name]) is None
                        for name in ("packet_digest", "child_ready_digest")
                    )
                ):
                    raise TenantSidecarObservationError("sidecar readiness differs from owner")
                continue
            if row.get("schema_version") != OBSERVATION_SCHEMA:
                raise TenantSidecarObservationError("sidecar Docker log event is unknown")
            if row.get("target_request_id") == target_request_id:
                matches.append(row)
        if len(matches) != 1:
            raise TenantSidecarObservationError("exact sidecar target response is unavailable")
        observed = _checked_record(matches[0], self.source_binding)
        source_document = {
            "schema_version": RECEIPT_SCHEMA,
            "source_binding": self.source_binding,
            "record": matches[0],
            "docker_log_record_ref": observed.docker_log_record_ref,
        }
        source_ref = content_hash(source_document)
        encoded = canonical_json_bytes({**source_document, "source_receipt_ref": source_ref})
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return self.reopen_request(self.source_binding["attempt_id"], target_request_id)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise TenantSidecarObservationError("sidecar source retention is uncertain") from exc
        reopened = self.reopen_request(self.source_binding["attempt_id"], target_request_id)
        if reopened.source_receipt_ref != source_ref:
            raise TenantSidecarObservationError("sidecar source changed during retention")
        return reopened

    def reopen_request(self, attempt_id: str, target_request_id: str) -> SidecarTargetObservation:
        if attempt_id != self.source_binding["attempt_id"]:
            raise TenantSidecarObservationError("sidecar attempt changed")
        path = self._path(target_request_id)
        details = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size > 128 * 1024
        ):
            raise TenantSidecarObservationError("sidecar retained source is unsafe")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                details.st_dev,
                details.st_ino,
                details.st_size,
                details.st_mtime_ns,
            ):
                raise TenantSidecarObservationError("sidecar retained source changed before read")
            raw = os.read(descriptor, 128 * 1024 + 1)
        finally:
            os.close(descriptor)
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
        ):
            raise TenantSidecarObservationError("sidecar retained source changed after read")
        if len(raw) > 128 * 1024:
            raise TenantSidecarObservationError("sidecar retained source exceeds its bound")
        retained = _strict_json(raw)
        if (
            set(retained)
            != {
                "schema_version",
                "source_binding",
                "record",
                "docker_log_record_ref",
                "source_receipt_ref",
            }
            or retained["schema_version"] != RECEIPT_SCHEMA
        ):
            raise TenantSidecarObservationError("sidecar retained source fields changed")
        ref = retained.pop("source_receipt_ref")
        if not isinstance(ref, str) or ref != content_hash(retained):
            raise TenantSidecarObservationError("sidecar retained source digest changed")
        if retained["source_binding"] != self.source_binding:
            raise TenantSidecarObservationError("sidecar retained owner changed")
        observed = _checked_record(retained["record"], self.source_binding)
        if (
            observed.target_request_id != target_request_id
            or observed.docker_log_record_ref != retained["docker_log_record_ref"]
        ):
            raise TenantSidecarObservationError("sidecar retained target record changed")
        return SidecarTargetObservation(
            **{
                name: getattr(observed, name)
                for name in SidecarTargetObservation.__dataclass_fields__
                if name != "source_receipt_ref"
            },
            source_receipt_ref=ref,
        )


__all__ = [
    "OBSERVATION_SCHEMA",
    "OwnedTenantSidecarObservationReader",
    "SidecarTargetObservation",
    "TenantSidecarObservationError",
]
