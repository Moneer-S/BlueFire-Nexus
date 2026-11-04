"""Strict package-owned child for the generated tenant-record target.

The child accepts one fixed launcher grammar and one controller-created packet.
It is deliberately not a general HTTP server or process launcher: target data,
defense mode, source admissions, limits, bind address, and output paths are all
validated before a listener is created.  Source identity is derived from a
controller-minted bearer value, never from a caller-selected identity label.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence, cast

from .runner_private_files import _PinnedPrivateDirectory
from .tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecordFixture,
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from .tenant_record_observer import (
    AUDIT_SCHEMA,
    MAX_AUDIT_EVENTS,
    BoundedTenantAuditLog,
    TenantAuditRow,
)
from .tenant_record_service import TenantRecordApplication
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

PACKET_SCHEMA = "bluefire.tenant-record-target-packet.v1"
READY_SCHEMA = "bluefire.tenant-record-target-ready.v1"
SOURCE_HEADER = "x-bluefire-lab-source-token"
TARGET_LOGICAL_AUTHORITY = "tenant-record.test"
MAX_PACKET_BYTES = 128 * 1024
MAX_AUDIT_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 256
MAX_RUNTIME_SECONDS = 900
EXIT_CONFIGURATION = 78

_RUN_ID = re.compile(r"^engine-lab-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SOURCE_IDENTITIES = ("engine_worker", "ordinary_user", "controller_probe")


class TenantTargetChildError(RuntimeError):
    """Raised when the fixed target child cannot establish its boundary."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantTargetChildError(f"{label} digest is invalid")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise TenantTargetChildError(f"{label} timestamp is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise TenantTargetChildError(f"{label} timestamp is invalid") from exc
    if parsed.utcoffset() != timedelta(0):
        raise TenantTargetChildError(f"{label} timestamp is invalid")
    return value


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise TenantTargetChildError("target clock must return UTC")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TenantTargetChildError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _exact(value: Mapping[str, object], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise TenantTargetChildError(f"{label} fields are invalid")


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TenantTargetChildError(f"{label} is outside its bound")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise TenantTargetChildError(f"{label} must be a boolean")
    return value


def _text(value: object, label: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TenantTargetChildError(f"{label} is invalid")
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64(value: object, label: str, minimum: int, maximum: int) -> bytes:
    text = _text(value, label, 4 * maximum + 4)
    if re.fullmatch(r"[A-Za-z0-9_-]+", text) is None:
        raise TenantTargetChildError(f"{label} encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise TenantTargetChildError(f"{label} encoding is invalid") from exc
    if not minimum <= len(decoded) <= maximum or _b64(decoded) != text:
        raise TenantTargetChildError(f"{label} encoding is invalid")
    return decoded


@dataclass(frozen=True, slots=True)
class SourceAdmission:
    source_identity: str
    token: bytes = field(repr=False)
    token_digest: str

    def __post_init__(self) -> None:
        if self.source_identity not in _SOURCE_IDENTITIES:
            raise TenantTargetChildError("target source identity is invalid")
        if type(self.token) is not bytes or not 32 <= len(self.token) <= 64:
            raise TenantTargetChildError("target source token is invalid")
        if self.token_digest != _sha256(self.token):
            raise TenantTargetChildError("target source token digest changed")

    @classmethod
    def create(cls, source_identity: str, token: bytes) -> "SourceAdmission":
        return cls(source_identity, token, _sha256(token))

    def to_mapping(self) -> dict[str, str]:
        return {
            "source_identity": self.source_identity,
            "token_b64": _b64(self.token),
            "token_digest": self.token_digest,
        }

    @classmethod
    def from_mapping(cls, value: object) -> "SourceAdmission":
        row = _mapping(value, "target source admission")
        _exact(row, {"source_identity", "token_b64", "token_digest"}, "source admission")
        token = _decode_b64(row["token_b64"], "target source token", 32, 64)
        return cls(
            _text(row["source_identity"], "target source identity", 32),
            token,
            _digest(row["token_digest"], "target source token"),
        )


@dataclass(frozen=True, slots=True)
class TenantTargetPacket:
    run_id: str
    attempt_id: str
    fixture_seed: bytes = field(repr=False)
    held_out: bool
    expected_fixture_digest: str
    defense_mode: str
    expected_config_digest: str
    signing_key: bytes | None = field(repr=False)
    key_id: str | None
    application_nonce: str | None
    admissions: tuple[SourceAdmission, ...] = field(repr=False)
    max_requests: int
    max_audit_events: int
    max_audit_bytes: int
    max_runtime_seconds: int
    created_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if _RUN_ID.fullmatch(self.run_id) is None or _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise TenantTargetChildError("target packet owner identity is invalid")
        if type(self.fixture_seed) is not bytes or not 16 <= len(self.fixture_seed) <= 64:
            raise TenantTargetChildError("target fixture seed is invalid")
        _boolean(self.held_out, "held-out fixture marker")
        _digest(self.expected_fixture_digest, "target fixture")
        _digest(self.expected_config_digest, "target defense configuration")
        if self.defense_mode not in {"client_asserted", "signed_session"}:
            raise TenantTargetChildError("target defense mode is invalid")
        if self.defense_mode == "client_asserted":
            if (
                self.signing_key is not None
                or self.key_id is not None
                or self.application_nonce is not None
            ):
                raise TenantTargetChildError("baseline target packet contains signing material")
        elif (
            type(self.signing_key) is not bytes
            or not 32 <= len(self.signing_key) <= 64
            or not isinstance(self.key_id, str)
            or _ID.fullmatch(self.key_id) is None
            or not isinstance(self.application_nonce, str)
            or _ID.fullmatch(self.application_nonce) is None
        ):
            raise TenantTargetChildError("hardened target packet lacks signing material")
        if tuple(item.source_identity for item in self.admissions) != _SOURCE_IDENTITIES:
            raise TenantTargetChildError("target source admissions are incomplete or unordered")
        if len({item.token_digest for item in self.admissions}) != len(self.admissions):
            raise TenantTargetChildError("target source admissions reuse a token")
        _integer(self.max_requests, "target request limit", 1, MAX_REQUESTS)
        _integer(self.max_audit_events, "target audit event limit", 1, MAX_AUDIT_EVENTS)
        if self.max_requests > self.max_audit_events:
            raise TenantTargetChildError("request limit exceeds the auditable event limit")
        _integer(self.max_audit_bytes, "target audit byte limit", 4096, MAX_AUDIT_BYTES)
        _integer(self.max_runtime_seconds, "target runtime limit", 1, MAX_RUNTIME_SECONDS)
        created = parse_iso8601_datetime(_timestamp(self.created_at, "packet creation"))
        expires = parse_iso8601_datetime(_timestamp(self.expires_at, "packet expiry"))
        if expires <= created or (expires - created).total_seconds() != self.max_runtime_seconds:
            raise TenantTargetChildError("target packet lifetime does not match its runtime bound")
        fixture, config = self.materialize()
        if (
            fixture.digest != self.expected_fixture_digest
            or config.digest != self.expected_config_digest
        ):
            raise TenantTargetChildError("target packet material does not match its digests")

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        attempt_id: str,
        fixture_seed: bytes,
        held_out: bool,
        defense_mode: str,
        admissions: Mapping[str, bytes],
        created_at: str,
        max_runtime_seconds: int,
        signing_key: bytes | None = None,
        key_id: str | None = None,
        application_nonce: str | None = None,
        max_requests: int = 64,
        max_audit_events: int = 64,
        max_audit_bytes: int = 512 * 1024,
    ) -> "TenantTargetPacket":
        created = parse_iso8601_datetime(_timestamp(created_at, "packet creation"))
        expires_at = _utc_text(created + timedelta(seconds=max_runtime_seconds))
        fixture = generate_tenant_record_fixture(fixture_seed, held_out=held_out)
        baseline = baseline_defense_config(fixture)
        if defense_mode == "client_asserted":
            config = baseline
        elif defense_mode == "signed_session":
            config = hardened_defense_config(
                fixture,
                signing_key=signing_key or b"",
                key_id=key_id or "",
                application_nonce=application_nonce or "",
                prior=baseline,
            )
        else:
            raise TenantTargetChildError("target defense mode is invalid")
        if set(admissions) != set(_SOURCE_IDENTITIES):
            raise TenantTargetChildError("target source admissions are incomplete")
        return cls(
            run_id=run_id,
            attempt_id=attempt_id,
            fixture_seed=fixture_seed,
            held_out=held_out,
            expected_fixture_digest=fixture.digest,
            defense_mode=defense_mode,
            expected_config_digest=config.digest,
            signing_key=signing_key,
            key_id=key_id,
            application_nonce=application_nonce,
            admissions=tuple(
                SourceAdmission.create(identity, admissions[identity])
                for identity in _SOURCE_IDENTITIES
            ),
            max_requests=max_requests,
            max_audit_events=max_audit_events,
            max_audit_bytes=max_audit_bytes,
            max_runtime_seconds=max_runtime_seconds,
            created_at=created_at,
            expires_at=expires_at,
        )

    def materialize(self) -> tuple[TenantRecordFixture, TenantDefenseConfig]:
        fixture = generate_tenant_record_fixture(self.fixture_seed, held_out=self.held_out)
        baseline = baseline_defense_config(fixture)
        if self.defense_mode == "client_asserted":
            return fixture, baseline
        return fixture, hardened_defense_config(
            fixture,
            signing_key=self.signing_key or b"",
            key_id=self.key_id or "",
            application_nonce=self.application_nonce or "",
            prior=baseline,
        )

    @property
    def admission_digests(self) -> dict[str, str]:
        return {item.source_identity: item.token_digest for item in self.admissions}

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": PACKET_SCHEMA,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "fixture_seed_b64": _b64(self.fixture_seed),
            "held_out": self.held_out,
            "expected_fixture_digest": self.expected_fixture_digest,
            "defense": {
                "mode": self.defense_mode,
                "expected_config_digest": self.expected_config_digest,
                "signing_key_b64": None if self.signing_key is None else _b64(self.signing_key),
                "key_id": self.key_id,
                "application_nonce": self.application_nonce,
            },
            "admissions": [item.to_mapping() for item in self.admissions],
            "max_requests": self.max_requests,
            "max_audit_events": self.max_audit_events,
            "max_audit_bytes": self.max_audit_bytes,
            "max_runtime_seconds": self.max_runtime_seconds,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping()) + b"\n"

    @property
    def digest(self) -> str:
        return _sha256(self.to_bytes())

    @classmethod
    def from_bytes(cls, value: bytes) -> "TenantTargetPacket":
        if (
            type(value) is not bytes
            or not 1 <= len(value) <= MAX_PACKET_BYTES
            or not value.endswith(b"\n")
        ):
            raise TenantTargetChildError("target packet is empty or oversized")
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise TenantTargetChildError("target packet is invalid JSON") from exc
        row = _mapping(decoded, "target packet")
        _exact(
            row,
            {
                "schema_version",
                "run_id",
                "attempt_id",
                "fixture_seed_b64",
                "held_out",
                "expected_fixture_digest",
                "defense",
                "admissions",
                "max_requests",
                "max_audit_events",
                "max_audit_bytes",
                "max_runtime_seconds",
                "created_at",
                "expires_at",
            },
            "target packet",
        )
        if row["schema_version"] != PACKET_SCHEMA or canonical_json_bytes(row) + b"\n" != value:
            raise TenantTargetChildError("target packet is not canonical")
        defense = _mapping(row["defense"], "target defense")
        _exact(
            defense,
            {"mode", "expected_config_digest", "signing_key_b64", "key_id", "application_nonce"},
            "target defense",
        )
        raw_admissions = row["admissions"]
        if not isinstance(raw_admissions, list) or len(raw_admissions) != 3:
            raise TenantTargetChildError("target source admissions are incomplete")
        signing = defense["signing_key_b64"]
        return cls(
            run_id=_text(row["run_id"], "target run identity", 64),
            attempt_id=_text(row["attempt_id"], "target attempt identity", 64),
            fixture_seed=_decode_b64(row["fixture_seed_b64"], "target fixture seed", 16, 64),
            held_out=_boolean(row["held_out"], "held-out fixture marker"),
            expected_fixture_digest=_digest(row["expected_fixture_digest"], "target fixture"),
            defense_mode=_text(defense["mode"], "target defense mode", 32),
            expected_config_digest=_digest(defense["expected_config_digest"], "target config"),
            signing_key=(
                None if signing is None else _decode_b64(signing, "target signing key", 32, 64)
            ),
            key_id=(None if defense["key_id"] is None else _text(defense["key_id"], "key ID", 64)),
            application_nonce=(
                None
                if defense["application_nonce"] is None
                else _text(defense["application_nonce"], "application nonce", 64)
            ),
            admissions=tuple(SourceAdmission.from_mapping(item) for item in raw_admissions),
            max_requests=_integer(row["max_requests"], "target request limit", 1, MAX_REQUESTS),
            max_audit_events=_integer(
                row["max_audit_events"], "target audit event limit", 1, MAX_AUDIT_EVENTS
            ),
            max_audit_bytes=_integer(
                row["max_audit_bytes"], "target audit byte limit", 4096, MAX_AUDIT_BYTES
            ),
            max_runtime_seconds=_integer(
                row["max_runtime_seconds"], "target runtime limit", 1, MAX_RUNTIME_SECONDS
            ),
            created_at=_timestamp(row["created_at"], "packet creation"),
            expires_at=_timestamp(row["expires_at"], "packet expiry"),
        )


@dataclass(frozen=True, slots=True)
class TargetReadyReceipt:
    pid: int
    host: str
    port: int
    packet_digest: str
    fixture_digest: str
    config_digest: str
    target_snapshot_id: str
    service_generation: str
    admission_digests: Mapping[str, str]
    max_audit_events: int
    max_audit_bytes: int
    max_requests: int
    max_runtime_seconds: int
    started_at: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise TenantTargetChildError("target readiness PID is invalid")
        _loopback_host(self.host)
        _port(self.port, allow_zero=False)
        for label, value in (
            ("packet", self.packet_digest),
            ("fixture", self.fixture_digest),
            ("configuration", self.config_digest),
        ):
            _digest(value, label)
        if (
            _ID.fullmatch(self.target_snapshot_id) is None
            or _ID.fullmatch(self.service_generation) is None
        ):
            raise TenantTargetChildError("target readiness identity is invalid")
        if set(self.admission_digests) != set(_SOURCE_IDENTITIES) or any(
            _DIGEST.fullmatch(value) is None for value in self.admission_digests.values()
        ):
            raise TenantTargetChildError("target readiness admissions are invalid")
        object.__setattr__(
            self,
            "admission_digests",
            MappingProxyType(
                {identity: self.admission_digests[identity] for identity in _SOURCE_IDENTITIES}
            ),
        )
        _integer(self.max_audit_events, "readiness audit limit", 1, MAX_AUDIT_EVENTS)
        _integer(self.max_audit_bytes, "readiness audit byte limit", 4096, MAX_AUDIT_BYTES)
        _integer(self.max_requests, "readiness request limit", 1, MAX_REQUESTS)
        _integer(self.max_runtime_seconds, "readiness runtime limit", 1, MAX_RUNTIME_SECONDS)
        _timestamp(self.started_at, "target readiness")

    def body(self) -> dict[str, object]:
        return {
            "schema_version": READY_SCHEMA,
            "role": "target",
            "pid": self.pid,
            "host": self.host,
            "port": self.port,
            "packet_digest": self.packet_digest,
            "fixture_digest": self.fixture_digest,
            "config_digest": self.config_digest,
            "target_snapshot_id": self.target_snapshot_id,
            "service_generation": self.service_generation,
            "admission_digests": {
                identity: self.admission_digests[identity] for identity in _SOURCE_IDENTITIES
            },
            "audit_schema": AUDIT_SCHEMA,
            "max_audit_events": self.max_audit_events,
            "max_audit_bytes": self.max_audit_bytes,
            "max_requests": self.max_requests,
            "max_runtime_seconds": self.max_runtime_seconds,
            "started_at": self.started_at,
        }

    @property
    def ready_digest(self) -> str:
        return content_hash(self.body())

    def to_mapping(self) -> dict[str, object]:
        return {**self.body(), "ready_digest": self.ready_digest}

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping()) + b"\n"

    @classmethod
    def from_bytes(cls, value: bytes) -> "TargetReadyReceipt":
        if type(value) is not bytes or not value.endswith(b"\n") or len(value) > 16 * 1024:
            raise TenantTargetChildError("target readiness receipt is invalid")
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise TenantTargetChildError("target readiness receipt is invalid") from exc
        row = _mapping(decoded, "target readiness receipt")
        fields = {
            "schema_version",
            "role",
            "pid",
            "host",
            "port",
            "packet_digest",
            "fixture_digest",
            "config_digest",
            "target_snapshot_id",
            "service_generation",
            "admission_digests",
            "audit_schema",
            "max_audit_events",
            "max_audit_bytes",
            "max_requests",
            "max_runtime_seconds",
            "started_at",
            "ready_digest",
        }
        _exact(row, fields, "target readiness receipt")
        if (
            row["schema_version"] != READY_SCHEMA
            or row["role"] != "target"
            or row["audit_schema"] != AUDIT_SCHEMA
            or canonical_json_bytes(row) + b"\n" != value
        ):
            raise TenantTargetChildError("target readiness receipt is not canonical")
        admissions = _mapping(row["admission_digests"], "target readiness admissions")
        receipt = cls(
            pid=_integer(row["pid"], "target readiness PID", 1, 2**63 - 1),
            host=_text(row["host"], "target readiness host", 64),
            port=_integer(row["port"], "target readiness port", 1, 65535),
            packet_digest=_digest(row["packet_digest"], "target packet"),
            fixture_digest=_digest(row["fixture_digest"], "target fixture"),
            config_digest=_digest(row["config_digest"], "target config"),
            target_snapshot_id=_text(row["target_snapshot_id"], "target snapshot", 64),
            service_generation=_text(row["service_generation"], "service generation", 64),
            admission_digests={
                key: _digest(value, "target admission") for key, value in admissions.items()
            },
            max_audit_events=_integer(
                row["max_audit_events"], "readiness audit limit", 1, MAX_AUDIT_EVENTS
            ),
            max_audit_bytes=_integer(
                row["max_audit_bytes"], "readiness audit byte limit", 4096, MAX_AUDIT_BYTES
            ),
            max_requests=_integer(row["max_requests"], "readiness request limit", 1, MAX_REQUESTS),
            max_runtime_seconds=_integer(
                row["max_runtime_seconds"], "readiness runtime limit", 1, MAX_RUNTIME_SECONDS
            ),
            started_at=_timestamp(row["started_at"], "target readiness"),
        )
        if row["ready_digest"] != receipt.ready_digest:
            raise TenantTargetChildError("target readiness digest changed")
        return receipt


class RequestBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = _integer(maximum, "target request limit", 1, MAX_REQUESTS)
        self._count = 0
        self._lock = threading.Lock()

    def consume(self) -> bool:
        with self._lock:
            if self._count >= self.maximum:
                return False
            self._count += 1
            return True

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._count >= self.maximum


class AuditFileSink:
    def __init__(self, path: Path, *, maximum_bytes: int) -> None:
        self.path = path
        self.maximum_bytes = _integer(
            maximum_bytes, "target audit byte limit", 4096, MAX_AUDIT_BYTES
        )
        try:
            self._fd = _open_protected_output(path)
        except OSError as exc:
            raise TenantTargetChildError("target audit output cannot be created") from exc
        self._bytes = 0
        self._sequence = 0
        self._closed = False
        self._lock = threading.Lock()

    def append(self, row: TenantAuditRow) -> None:
        data = canonical_json_bytes(row.to_dict()) + b"\n"
        with self._lock:
            if self._closed or row.sequence != self._sequence + 1:
                raise TenantTargetChildError("target audit sequence is unavailable")
            if self._bytes + len(data) > self.maximum_bytes:
                raise TenantTargetChildError("target audit output exceeded its byte limit")
            _write_all(self._fd, data)
            os.fsync(self._fd)
            self._bytes += len(data)
            self._sequence = row.sequence

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                os.close(self._fd)
                self._closed = True


@dataclass(frozen=True, slots=True)
class ChildResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class TargetChildService:
    def __init__(
        self,
        *,
        application: TenantRecordApplication,
        audit_log: BoundedTenantAuditLog,
        audit_sink: AuditFileSink,
        admissions: tuple[SourceAdmission, ...],
        budget: RequestBudget,
        numeric_authority: str,
    ) -> None:
        if numeric_authority not in {"127.0.0.1", "[::1]"}:
            raise TenantTargetChildError("target numeric authority is invalid")
        self._application = application
        self._audit_log = audit_log
        self._audit_sink = audit_sink
        self._admissions = admissions
        self._budget = budget
        self._numeric_authority = numeric_authority
        self._failed = False

    @property
    def terminal(self) -> bool:
        return self._failed or self._budget.exhausted

    def handle(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
    ) -> ChildResponse:
        if self._failed:
            return _error_response(503, "target_unavailable")
        if not self._budget.consume():
            return _error_response(429, "request_limit_reached")
        try:
            source_identity, filtered = self._admit(headers)
        except TenantTargetChildError:
            return _error_response(403, "source_not_admitted")
        filtered = self._constrain_authority(filtered)
        before = self._audit_log.snapshot()
        try:
            response = self._application.handle(
                method, target, filtered, source_identity=source_identity
            )
            after = self._audit_log.snapshot()
            if len(after) != len(before) + 1:
                raise TenantTargetChildError("target request did not create one audit row")
            self._audit_sink.append(after[-1])
        except Exception:
            self._failed = True
            return _error_response(500, "target_observation_unavailable")
        return ChildResponse(response.status, response.headers, response.body)

    def handle_get(
        self, target: str, headers: Mapping[str, str] | Sequence[tuple[str, str]]
    ) -> ChildResponse:
        return self.handle("GET", target, headers)

    def _admit(
        self, headers: Mapping[str, str] | Sequence[tuple[str, str]]
    ) -> tuple[str, list[tuple[str, str]]]:
        items = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        supplied: list[str] = []
        filtered: list[tuple[str, str]] = []
        for name, value in items:
            if not isinstance(name, str) or not isinstance(value, str):
                raise TenantTargetChildError("target request headers are invalid")
            lowered = name.strip().lower()
            if lowered == SOURCE_HEADER:
                supplied.append(value.strip())
            elif lowered == "x-bluefire-lab-source-identity":
                raise TenantTargetChildError("caller-selected source identity is forbidden")
            else:
                filtered.append((name, value))
        if len(supplied) != 1:
            raise TenantTargetChildError("target source admission is missing")
        token = _decode_b64(supplied[0], "request source token", 32, 64)
        matches = [
            item.source_identity
            for item in self._admissions
            if hmac.compare_digest(item.token, token)
        ]
        if len(matches) != 1:
            raise TenantTargetChildError("target source admission is invalid")
        return matches[0], filtered

    def _constrain_authority(self, headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
        positions = [
            index for index, (name, _value) in enumerate(headers) if name.strip().lower() == "host"
        ]
        if len(positions) != 1:
            # Preserve missing or duplicate Host fields so the application
            # records the malformed request through its protected audit path.
            return headers
        index = positions[0]
        name, authority = headers[index]
        exact_name = name == name.strip()
        allowed = exact_name and (
            authority == TARGET_LOGICAL_AUTHORITY
            or authority == self._numeric_authority
            or self._numeric_authority_with_port(authority)
        )
        if allowed:
            return headers
        # The application owns the canonical invalid-host response and audit
        # row.  Replace only the rejected authority so its more permissive
        # general-purpose host parser cannot bless a port-qualified logical
        # authority that is not the controller's retained mechanism.
        constrained = list(headers)
        constrained[index] = (name, "")
        return constrained

    def _numeric_authority_with_port(self, authority: str) -> bool:
        prefix = self._numeric_authority + ":"
        if not authority.startswith(prefix):
            return False
        port = authority.removeprefix(prefix)
        return bool(port) and port.isascii() and port.isdigit() and 1 <= int(port) <= 65535


def _error_response(status: int, code: str) -> ChildResponse:
    body = canonical_json_bytes({"error": code})
    return ChildResponse(
        status,
        {
            "content-type": "application/json",
            "content-length": str(len(body)),
            "cache-control": "no-store",
        },
        body,
    )


def target_http_handler(service: TargetChildService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "BlueFireTenantLab/1"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802
            self._respond("GET")

        def do_HEAD(self) -> None:  # noqa: N802
            self._respond("HEAD", include_body=False)

        def do_POST(self) -> None:  # noqa: N802
            self._respond("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._respond("PUT")

        def do_PATCH(self) -> None:  # noqa: N802
            self._respond("PATCH")

        def do_DELETE(self) -> None:  # noqa: N802
            self._respond("DELETE")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._respond("OPTIONS")

        def do_TRACE(self) -> None:  # noqa: N802
            self._respond("TRACE")

        def do_CONNECT(self) -> None:  # noqa: N802
            self._respond("CONNECT")

        def _respond(self, method: str, *, include_body: bool = True) -> None:
            response = service.handle(method, self.path, list(self.headers.raw_items()))
            self.send_response_only(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if include_body:
                self.wfile.write(response.body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


class TargetServer(Protocol):
    server_address: tuple[object, ...]
    timeout: float

    def handle_request(self) -> None: ...
    def server_close(self) -> None: ...


ServerFactory = Callable[[tuple[str, int], type[BaseHTTPRequestHandler]], TargetServer]
ProtectionCheck = Callable[[Path, Path], bool]


@dataclass(frozen=True, slots=True)
class FixedTargetArguments:
    packet: Path
    audit: Path
    ready_file: Path
    host: str
    port: int


def parse_fixed_target_arguments(argv: Sequence[str]) -> FixedTargetArguments:
    if (
        len(argv) != 11
        or any(not isinstance(value, str) for value in argv)
        or tuple(argv[index] for index in (0, 1, 3, 5, 7, 9))
        != ("--fixed-target", "--packet", "--audit", "--ready-file", "--host", "--port")
    ):
        raise TenantTargetChildError("target child command is not the fixed grammar")
    packet, audit, ready = (Path(argv[index]) for index in (2, 4, 6))
    if not all(
        path.is_absolute() and path == path.resolve(strict=False) for path in (packet, audit, ready)
    ):
        raise TenantTargetChildError("target child paths must be absolute")
    if (
        packet.name != "packet.json"
        or audit.name != "audit.jsonl"
        or ready.name != "ready.json"
        or packet.parent != audit.parent
        or packet.parent != ready.parent
    ):
        raise TenantTargetChildError("target child paths are not the derived workspace")
    host = _loopback_host(argv[8])
    if not re.fullmatch(r"0|[1-9][0-9]{0,4}", argv[10]):
        raise TenantTargetChildError("target child port is invalid")
    port = _port(int(argv[10]), allow_zero=True)
    return FixedTargetArguments(packet, audit, ready, host, port)


def _loopback_host(value: object) -> str:
    if value not in {"127.0.0.1", "::1"}:
        raise TenantTargetChildError("target child host must be numeric loopback")
    return cast(str, value)


def _port(value: object, *, allow_zero: bool) -> int:
    minimum = 0 if allow_zero else 1
    return _integer(value, "target child port", minimum, 65535)


def _read_packet(path: Path, protection_check: ProtectionCheck) -> tuple[bytes, TenantTargetPacket]:
    if path.is_symlink() or _is_reparse(path) or not path.is_file():
        raise TenantTargetChildError("target packet path is not a regular owned file")
    parent = path.parent
    if parent.is_symlink() or _is_reparse(parent) or not protection_check(parent, path):
        raise TenantTargetChildError("target packet workspace is not protected")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_PACKET_BYTES
        ):
            raise TenantTargetChildError("target packet path is not a bounded owned file")
        chunks: list[bytes] = []
        remaining = MAX_PACKET_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)

        def identity(item: os.stat_result) -> tuple[int, int, int, int]:
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns

        if (
            identity(before) != identity(after)
            or identity(after) != identity(current)
            or after.st_nlink != 1
        ):
            raise TenantTargetChildError("target packet identity changed while reading")
    except OSError as exc:
        raise TenantTargetChildError("target packet cannot be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    packet = TenantTargetPacket.from_bytes(value)
    return value, packet


def _default_protection_check(parent: Path, packet: Path) -> bool:
    try:
        with _PinnedPrivateDirectory(parent, verify_permissions_only=True) as directory:
            directory.file_identity(packet.name, maximum=MAX_PACKET_BYTES, apply_permissions=False)
    except Exception:
        return False
    return True


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise TenantTargetChildError("target output write made no progress")
        view = view[written:]


def _open_protected_output(path: Path) -> int:
    """Create one private regular output and return the same file opened for append."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    before = os.fstat(descriptor)
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("target output is not one regular file")
        if os.name == "nt":
            os.close(descriptor)
            descriptor = -1
            from .windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl_path

            try:
                apply_owner_private_acl_path(path, directory=False)
            except WindowsOwnerAclError as exc:
                raise OSError("target output protection is unavailable") from exc
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_APPEND
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        else:
            getattr(os, "fchmod")(descriptor, 0o600)  # noqa: B009 - absent on Windows
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise OSError("target output identity changed during protection")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _publish_new(path: Path, value: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd: int | None = None
    linked = False
    try:
        fd = _open_protected_output(temporary)
        _write_all(fd, value)
        os.fsync(fd)
        os.close(fd)
        fd = None
        if os.name == "nt":
            # MoveFileEx without REPLACE_EXISTING is an atomic no-replace
            # publication on Windows; os.link is not uniformly admitted by
            # hardened local filesystem policy.
            os.rename(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
        linked = True
        _sync_directory(path.parent)
    except OSError as exc:
        raise TenantTargetChildError("target readiness cannot be published atomically") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink(missing_ok=True)
        except OSError as exc:
            if not linked:
                raise TenantTargetChildError("target readiness staging cannot be removed") from exc


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _default_server_factory(
    endpoint: tuple[str, int], handler: type[BaseHTTPRequestHandler]
) -> TargetServer:
    if endpoint[0] == "::1":

        class IPv6HTTPServer(HTTPServer):
            address_family = socket.AF_INET6

        return cast(TargetServer, IPv6HTTPServer(endpoint, handler))
    return cast(TargetServer, HTTPServer(endpoint, handler))


def run_target_child(
    arguments: FixedTargetArguments,
    *,
    protection_check: ProtectionCheck = _default_protection_check,
    server_factory: ServerFactory = _default_server_factory,
    utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.monotonic,
    stop_event: threading.Event | None = None,
) -> TargetReadyReceipt:
    packet_bytes, packet = _read_packet(arguments.packet, protection_check)
    if _sha256(packet_bytes) != packet.digest:
        raise TenantTargetChildError("target packet digest changed while reading")
    now = utc_now()
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise TenantTargetChildError("target clock must return UTC")
    parsed_now = now.astimezone(timezone.utc)
    if not (
        parse_iso8601_datetime(packet.created_at)
        <= parsed_now
        < parse_iso8601_datetime(packet.expires_at)
    ):
        raise TenantTargetChildError("target packet is not within its admitted lifetime")
    if arguments.audit.exists() or arguments.ready_file.exists():
        raise TenantTargetChildError("target output already exists")
    fixture, config = packet.materialize()
    audit_log = BoundedTenantAuditLog(max_events=packet.max_audit_events)
    sink = AuditFileSink(arguments.audit, maximum_bytes=packet.max_audit_bytes)
    budget = RequestBudget(packet.max_requests)
    allowed_host = "[::1]" if arguments.host == "::1" else arguments.host
    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=audit_log,
        signing_key=packet.signing_key,
        # The listener remains bound to a numeric loopback address.  The
        # package-owned logical authority is the controller's fixed request
        # identity for the retained mechanism; it is not a DNS or routing
        # input and cannot select another target.
        allowed_hosts=(allowed_host, TARGET_LOGICAL_AUTHORITY),
    )
    service = TargetChildService(
        application=application,
        audit_log=audit_log,
        audit_sink=sink,
        admissions=packet.admissions,
        budget=budget,
        numeric_authority=allowed_host,
    )
    server: TargetServer | None = None
    try:
        server = server_factory((arguments.host, arguments.port), target_http_handler(service))
        address = server.server_address
        if (
            not isinstance(address, tuple)
            or len(address) < 2
            or address[0] != arguments.host
            or isinstance(address[1], bool)
            or not isinstance(address[1], int)
            or not 1 <= address[1] <= 65535
        ):
            raise TenantTargetChildError("target server bound an unexpected endpoint")
        bound_host = arguments.host
        bound_port = address[1]
        started_mono = monotonic()
        started = utc_now()
        started_at = _utc_text(started)
        expiry = parse_iso8601_datetime(packet.expires_at)
        remaining_lifetime = (expiry - started).total_seconds()
        if remaining_lifetime <= 0:
            raise TenantTargetChildError("target packet expired before readiness")
        receipt = TargetReadyReceipt(
            pid=os.getpid(),
            host=bound_host,
            port=bound_port,
            packet_digest=packet.digest,
            fixture_digest=fixture.digest,
            config_digest=config.digest,
            target_snapshot_id=config.target_snapshot_id,
            service_generation=config.service_generation,
            admission_digests=packet.admission_digests,
            max_audit_events=packet.max_audit_events,
            max_audit_bytes=packet.max_audit_bytes,
            max_requests=packet.max_requests,
            max_runtime_seconds=packet.max_runtime_seconds,
            started_at=started_at,
        )
        _publish_new(arguments.ready_file, receipt.to_bytes())
        event = stop_event or threading.Event()
        deadline = started_mono + min(packet.max_runtime_seconds, remaining_lifetime)
        while not event.is_set() and not service.terminal:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            server.timeout = min(0.25, remaining)
            server.handle_request()
        return receipt
    finally:
        if server is not None:
            server.server_close()
        sink.close()


def _install_signal_handlers(event: threading.Event) -> None:
    def stop(_signum: int, _frame: object) -> None:
        event.set()

    for name in ("SIGINT", "SIGTERM"):
        number = getattr(signal, name, None)
        if number is not None:
            signal.signal(number, stop)


def main(argv: Sequence[str] | None = None) -> int:
    import sys

    try:
        arguments = parse_fixed_target_arguments(tuple(sys.argv[1:] if argv is None else argv))
        event = threading.Event()
        _install_signal_handlers(event)
        run_target_child(arguments, stop_event=event)
    except (TenantTargetChildError, OSError, ValueError):
        return EXIT_CONFIGURATION
    return 0


__all__ = [
    "PACKET_SCHEMA",
    "READY_SCHEMA",
    "SOURCE_HEADER",
    "ChildResponse",
    "FixedTargetArguments",
    "SourceAdmission",
    "TargetChildService",
    "TargetReadyReceipt",
    "TenantTargetChildError",
    "TenantTargetPacket",
    "main",
    "parse_fixed_target_arguments",
    "run_target_child",
    "target_http_handler",
]


if __name__ == "__main__":  # pragma: no cover - launcher qualification owns live execution
    raise SystemExit(main())
