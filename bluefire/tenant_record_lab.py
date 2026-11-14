"""Fixed generated tenant-record lab contracts; no process or network launch.

The lab is deliberately small enough to reproduce while preserving a real
authorization boundary.  All records are generated test data.  Session keys
remain controller-owned and are never included in configuration or evidence.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, cast

from .util import canonical_json_bytes, content_hash

FIXTURE_SCHEMA = "bluefire.tenant-record-fixture.v1"
CONFIG_SCHEMA = "bluefire.tenant-record-defense-config.v1"
CHANGE_SCHEMA = "bluefire.tenant-record-defense-change.v1"
SESSION_SCHEMA = "bluefire.tenant-record-session.v1"
MAX_RECORDS = 16
MAX_JSONL_BYTES = 64 * 1024
MAX_SESSION_SECONDS = 15 * 60

_ID = re.compile(r"[a-z][a-z0-9-]{7,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class TenantRecordLabError(ValueError):
    """Raised when a generated-lab contract is malformed or inconsistent."""


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _derived_id(seed: bytes, label: str, prefix: str) -> str:
    suffix = hashlib.sha256(seed + b"\x00" + label.encode("ascii")).hexdigest()[:20]
    return f"{prefix}-{suffix}"


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise TenantRecordLabError("timestamp must be canonical UTC text")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TenantRecordLabError("timestamp is invalid") from exc
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise TenantRecordLabError("timestamp must be UTC")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TenantRecord:
    record_id: str
    tenant_id: str
    label: str
    generated_value: str

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.record_id) is None or _ID.fullmatch(self.tenant_id) is None:
            raise TenantRecordLabError("record identity is invalid")
        if (
            not isinstance(self.label, str)
            or re.fullmatch(r"generated-[1-9][0-9]?", self.label) is None
        ):
            raise TenantRecordLabError("record label is invalid")
        if (
            not isinstance(self.generated_value, str)
            or re.fullmatch(r"testdata-[0-9a-f]{20}", self.generated_value) is None
        ):
            raise TenantRecordLabError("record value is not bounded generated test data")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": "bluefire.tenant-record.v1",
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "label": self.label,
            "generated_value": self.generated_value,
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class TenantRecordFixture:
    fixture_id: str
    resource_generation: str
    target_snapshot_id: str
    probe_tenant_id: str
    protected_tenant_id: str
    legitimate_subject_id: str
    records: tuple[TenantRecord, ...]
    route_order: tuple[str, str]
    jsonl: bytes
    jsonl_sha256: str

    def __post_init__(self) -> None:
        for value in (
            self.fixture_id,
            self.resource_generation,
            self.target_snapshot_id,
            self.probe_tenant_id,
            self.protected_tenant_id,
            self.legitimate_subject_id,
        ):
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise TenantRecordLabError("fixture identity is invalid")
        if self.probe_tenant_id == self.protected_tenant_id:
            raise TenantRecordLabError("probe and protected tenants must differ")
        if not 2 <= len(self.records) <= MAX_RECORDS:
            raise TenantRecordLabError("fixture must contain a bounded record set")
        if self.route_order not in (
            ("record_lookup", "bounded_export"),
            ("bounded_export", "record_lookup"),
        ):
            raise TenantRecordLabError("fixture route order is invalid")
        if len(self.jsonl) > MAX_JSONL_BYTES or not self.jsonl.endswith(b"\n"):
            raise TenantRecordLabError("fixture JSONL is invalid or oversized")
        expected = b"".join(
            canonical_json_bytes(record.to_dict()) + b"\n" for record in self.records
        )
        if expected != self.jsonl or self.jsonl_sha256 != _digest_bytes(self.jsonl):
            raise TenantRecordLabError("fixture JSONL does not match its records")
        identities = {(record.tenant_id, record.record_id) for record in self.records}
        if len(identities) != len(self.records):
            raise TenantRecordLabError("fixture record identities must be unique")
        tenants = {record.tenant_id for record in self.records}
        if tenants != {self.probe_tenant_id, self.protected_tenant_id}:
            raise TenantRecordLabError("fixture must contain only probe and protected records")

    @property
    def digest(self) -> str:
        return content_hash(self.binding())

    def binding(self) -> dict[str, Any]:
        return {
            "schema_version": FIXTURE_SCHEMA,
            "fixture_id": self.fixture_id,
            "resource_generation": self.resource_generation,
            "target_snapshot_id": self.target_snapshot_id,
            "probe_tenant_id": self.probe_tenant_id,
            "protected_tenant_id": self.protected_tenant_id,
            "legitimate_subject_id": self.legitimate_subject_id,
            "record_count": len(self.records),
            "record_bindings": [
                {
                    "record_id": record.record_id,
                    "tenant_id": record.tenant_id,
                    "sha256": record.digest,
                }
                for record in self.records
            ],
            "route_order": list(self.route_order),
            "jsonl_bytes": len(self.jsonl),
            "jsonl_sha256": self.jsonl_sha256,
        }

    def records_for(self, tenant_id: str) -> tuple[TenantRecord, ...]:
        return tuple(record for record in self.records if record.tenant_id == tenant_id)


def generate_tenant_record_fixture(seed: bytes, *, held_out: bool = False) -> TenantRecordFixture:
    """Generate bounded records without retaining the controller's seed."""

    if type(seed) is not bytes or not 16 <= len(seed) <= 64:
        raise TenantRecordLabError("fixture seed must contain 16-64 private bytes")
    variant = b"held-out" if held_out else b"primary"
    material = hashlib.sha256(b"bluefire-tenant-lab\x00" + variant + seed).digest()
    probe_tenant = _derived_id(material, "probe-tenant", "tenant")
    protected_tenant = _derived_id(material, "protected-tenant", "tenant")
    records = [
        TenantRecord(
            _derived_id(material, f"record-{index}", "record"),
            tenant,
            f"generated-{index}",
            _derived_id(material, f"value-{index}", "testdata"),
        )
        for index, tenant in enumerate(
            (probe_tenant, protected_tenant, protected_tenant, probe_tenant), start=1
        )
    ]
    if held_out:
        records = [records[2], records[0], records[3], records[1]]
    rows = tuple(records)
    jsonl = b"".join(canonical_json_bytes(record.to_dict()) + b"\n" for record in rows)
    return TenantRecordFixture(
        fixture_id=_derived_id(material, "fixture", "fixture"),
        resource_generation=_derived_id(material, "resource-generation", "generation"),
        target_snapshot_id=_derived_id(material, "target-snapshot", "snapshot"),
        probe_tenant_id=probe_tenant,
        protected_tenant_id=protected_tenant,
        legitimate_subject_id=_derived_id(material, "legitimate-subject", "subject"),
        records=rows,
        route_order=(
            ("bounded_export", "record_lookup") if held_out else ("record_lookup", "bounded_export")
        ),
        jsonl=jsonl,
        jsonl_sha256=_digest_bytes(jsonl),
    )


@dataclass(frozen=True, slots=True)
class TenantDefenseConfig:
    mode: str
    fixture_digest: str
    target_snapshot_id: str
    service_generation: str
    application_nonce: str | None
    session_key_id: str | None
    session_key_digest: str | None

    def __post_init__(self) -> None:
        if self.mode not in {"client_asserted", "signed_session"}:
            raise TenantRecordLabError("unsupported tenant identity mode")
        if _DIGEST.fullmatch(self.fixture_digest) is None:
            raise TenantRecordLabError("fixture digest is invalid")
        for value in (self.target_snapshot_id, self.service_generation):
            if _ID.fullmatch(value) is None:
                raise TenantRecordLabError("defense configuration identity is invalid")
        if self.mode == "client_asserted":
            if (
                self.application_nonce is not None
                or self.session_key_id is not None
                or self.session_key_digest is not None
            ):
                raise TenantRecordLabError("baseline configuration cannot expose a session key")
        elif (
            not isinstance(self.application_nonce, str)
            or _ID.fullmatch(self.application_nonce) is None
            or not isinstance(self.session_key_id, str)
            or _ID.fullmatch(self.session_key_id) is None
            or not isinstance(self.session_key_digest, str)
            or _DIGEST.fullmatch(self.session_key_digest) is None
        ):
            raise TenantRecordLabError("signed-session configuration requires a key reference")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CONFIG_SCHEMA,
            "mode": self.mode,
            "fixture_digest": self.fixture_digest,
            "target_snapshot_id": self.target_snapshot_id,
            "service_generation": self.service_generation,
            "application_nonce": self.application_nonce,
            "session_key_id": self.session_key_id,
            "session_key_digest": self.session_key_digest,
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def baseline_defense_config(fixture: TenantRecordFixture) -> TenantDefenseConfig:
    return TenantDefenseConfig(
        mode="client_asserted",
        fixture_digest=fixture.digest,
        target_snapshot_id=fixture.target_snapshot_id,
        service_generation=_derived_id(
            bytes.fromhex(fixture.digest.removeprefix("sha256:")), "baseline-service", "service"
        ),
        application_nonce=None,
        session_key_id=None,
        session_key_digest=None,
    )


def hardened_defense_config(
    fixture: TenantRecordFixture,
    *,
    signing_key: bytes,
    key_id: str,
    application_nonce: str,
    prior: TenantDefenseConfig,
) -> TenantDefenseConfig:
    if type(signing_key) is not bytes or len(signing_key) < 32:
        raise TenantRecordLabError("session signing key must contain at least 32 bytes")
    if prior.fixture_digest != fixture.digest or prior.mode != "client_asserted":
        raise TenantRecordLabError("hardened configuration requires the exact baseline preimage")
    if not isinstance(application_nonce, str) or _ID.fullmatch(application_nonce) is None:
        raise TenantRecordLabError("defense application nonce is invalid")
    generation_seed = hashlib.sha256(
        bytes.fromhex(prior.digest.removeprefix("sha256:"))
        + b"\x00"
        + application_nonce.encode("ascii")
    ).digest()
    return TenantDefenseConfig(
        mode="signed_session",
        fixture_digest=fixture.digest,
        target_snapshot_id=_derived_id(generation_seed, "hardened-snapshot", "snapshot"),
        service_generation=_derived_id(generation_seed, "hardened-service", "service"),
        application_nonce=application_nonce,
        session_key_id=key_id,
        session_key_digest=_digest_bytes(signing_key),
    )


def defense_change_receipt(
    before: TenantDefenseConfig,
    after: TenantDefenseConfig,
    *,
    responsible_actor: str,
    applied_at: str,
) -> dict[str, Any]:
    if before.mode != "client_asserted" or after.mode != "signed_session":
        raise TenantRecordLabError("defense change must move from baseline to signed sessions")
    if before.fixture_digest != after.fixture_digest:
        raise TenantRecordLabError("defense change cannot replace generated records")
    if not isinstance(responsible_actor, str) or _ID.fullmatch(responsible_actor) is None:
        raise TenantRecordLabError("responsible actor is invalid")
    _utc(applied_at)
    preimage = canonical_json_bytes(before.to_dict())
    approved = canonical_json_bytes(after.to_dict())
    body = {
        "schema_version": CHANGE_SCHEMA,
        "preimage_digest": _digest_bytes(preimage),
        "approved_configuration_digest": _digest_bytes(approved),
        "target_snapshot_before": before.target_snapshot_id,
        "target_snapshot_after": after.target_snapshot_id,
        "service_generation_before": before.service_generation,
        "service_generation_after": after.service_generation,
        "responsible_actor": responsible_actor,
        "applied_at": applied_at,
        "rollback_material_digest": _digest_bytes(preimage),
    }
    return {**body, "change_id": "change-" + content_hash(body).removeprefix("sha256:")[:20]}


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise TenantRecordLabError("session token encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise TenantRecordLabError("session token encoding is invalid") from exc
    if _b64encode(decoded) != value:
        raise TenantRecordLabError("session token encoding is not canonical")
    return decoded


def mint_lab_session(
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    *,
    signing_key: bytes,
    subject_id: str,
    tenant_id: str,
    issued_at: datetime,
    lifetime_seconds: int,
) -> str:
    if config.mode != "signed_session" or config.fixture_digest != fixture.digest:
        raise TenantRecordLabError("session requires the exact hardened configuration")
    if _digest_bytes(signing_key) != config.session_key_digest:
        raise TenantRecordLabError("session signing key does not match the configured key")
    if subject_id != fixture.legitimate_subject_id or tenant_id != fixture.protected_tenant_id:
        raise TenantRecordLabError("session subject is not the declared legitimate identity")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_SESSION_SECONDS:
        raise TenantRecordLabError("session lifetime is outside the bounded lab window")
    expires = issued_at + timedelta(seconds=lifetime_seconds)
    payload = {
        "schema_version": SESSION_SCHEMA,
        "key_id": config.session_key_id,
        "subject_id": subject_id,
        "tenant_id": tenant_id,
        "target_snapshot_id": config.target_snapshot_id,
        "service_generation": config.service_generation,
        "application_nonce": config.application_nonce,
        "issued_at": _utc_text(issued_at),
        "expires_at": _utc_text(expires),
    }
    encoded = canonical_json_bytes(payload)
    signature = hmac.digest(signing_key, encoded, "sha256")
    return "v1." + _b64encode(encoded) + "." + _b64encode(signature)


def verify_lab_session(
    token: str,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    *,
    signing_key: bytes,
    now: datetime,
) -> Mapping[str, Any]:
    if (
        type(signing_key) is not bytes
        or len(signing_key) < 32
        or config.mode != "signed_session"
        or _digest_bytes(signing_key) != config.session_key_digest
    ):
        raise TenantRecordLabError("session verifier is not bound to the hardened configuration")
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise TenantRecordLabError("session verification time must be UTC")
    if not isinstance(token, str) or len(token) > 8192:
        raise TenantRecordLabError("session token is invalid")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        raise TenantRecordLabError("session token is invalid")
    encoded, supplied_signature = _b64decode(parts[1]), _b64decode(parts[2])
    expected_signature = hmac.digest(signing_key, encoded, "sha256")
    if len(supplied_signature) != len(expected_signature) or not hmac.compare_digest(
        supplied_signature, expected_signature
    ):
        raise TenantRecordLabError("session signature is invalid")
    try:
        payload = json.loads(encoded)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise TenantRecordLabError("session payload is invalid") from exc
    expected_fields = {
        "schema_version",
        "key_id",
        "subject_id",
        "tenant_id",
        "target_snapshot_id",
        "service_generation",
        "application_nonce",
        "issued_at",
        "expires_at",
    }
    if (
        not isinstance(payload, Mapping)
        or set(payload) != expected_fields
        or canonical_json_bytes(payload) != encoded
    ):
        raise TenantRecordLabError("session payload is not canonical")
    expected = {
        "schema_version": SESSION_SCHEMA,
        "key_id": config.session_key_id,
        "subject_id": fixture.legitimate_subject_id,
        "tenant_id": fixture.protected_tenant_id,
        "target_snapshot_id": config.target_snapshot_id,
        "service_generation": config.service_generation,
        "application_nonce": config.application_nonce,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise TenantRecordLabError("session is not bound to this target and identity")
    issued, expires = _utc(cast(str, payload["issued_at"])), _utc(cast(str, payload["expires_at"]))
    lifetime = expires - issued
    if (
        not timedelta(0) < lifetime <= timedelta(seconds=MAX_SESSION_SECONDS)
        or not issued <= now < expires
    ):
        raise TenantRecordLabError("session is expired or not yet valid")
    return cast(Mapping[str, Any], payload)
