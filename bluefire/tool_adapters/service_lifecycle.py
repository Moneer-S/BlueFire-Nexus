"""Owned user-service identity and cleanup evidence; no execution or authority.

This prerequisite is deliberately separate from the v1 workspace/process-tree
adapter contract. Parsing an identity cannot admit a method or authorize cleanup.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, cast

from ..contracts import ContractError
from ..evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from ..util import canonical_json_bytes, content_hash

IDENTITY_SCHEMA = "bluefire.owned-user-service.v1"
OBSERVATION_SCHEMA = "bluefire.user-service-observation.v1"
OBSERVER = "observer.systemd-user.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


def _object(value: Any, fields: str, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields.split()):
        raise ContractError(f"{label} must contain exactly its declared fields")
    return value


def _text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid service {label}")
    return value


def _time(value: Any) -> datetime:
    _text(value, _UTC, "UTC timestamp")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ContractError("invalid service UTC timestamp") from exc


def _identity_bytes(value: Any) -> bytes:
    data = _object(
        value,
        "schema_version authorization_digest runner_profile_id workspace_id "
        "target_scope_digest owner_uid boot_id manager_id unit_nonce "
        "unit_content_digest created_at cleanup_due_at",
        "owned user service",
    )
    if data["schema_version"] != IDENTITY_SCHEMA:
        raise ContractError("unsupported owned-service identity schema")
    for key in ("authorization_digest", "target_scope_digest", "unit_content_digest"):
        _text(data[key], _DIGEST, key)
    for key in ("runner_profile_id", "workspace_id"):
        _text(data[key], _ID, key)
    for key in ("manager_id", "unit_nonce"):
        if _text(data[key], _NONCE, key) == "0" * 32:
            raise ContractError("service identity cannot use an empty nonce")
    if _text(data["boot_id"], _BOOT, "boot identity") == "00000000-0000-0000-0000-000000000000":
        raise ContractError("service identity cannot use an empty boot identity")
    if type(data["owner_uid"]) is not int or not 1 <= data["owner_uid"] < 2**32 - 1:
        raise ContractError("user-service owner must be a non-root numeric UID")
    lifetime = _time(data["cleanup_due_at"]) - _time(data["created_at"])
    if not timedelta(0) < lifetime <= timedelta(hours=1):
        raise ContractError("owned-service lifetime must be positive and at most one hour")
    return canonical_json_bytes(data)


@dataclass(frozen=True, slots=True)
class OwnedUserService:
    """Immutable identity to bind into a future reviewed resource receipt.

    The trusted adapter must reserve a fresh nonce and establish initial absence
    before effects. An identity digest is integrity metadata, not a signature or
    proof that a caller owns a unit. No caller-selected unit/path/command is stored.
    """

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > 4096:
            raise ContractError("service identity must be bounded immutable bytes")
        try:
            normalized = _identity_bytes(json.loads(self._canonical))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise ContractError("invalid service identity encoding") from exc
        if normalized != self._canonical:
            raise ContractError("service identity must use canonical encoding")

    @classmethod
    def from_mapping(cls, value: Any) -> OwnedUserService:
        return cls(_identity_bytes(value))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @property
    def unit_name(self) -> str:
        return f"bluefire-{self.to_dict()['unit_nonce']}.service"


@dataclass(frozen=True, slots=True)
class ServiceCleanupAssessment:
    status: str
    reasons: tuple[str, ...]
    evidence_id: str | None = None
    record_hash: str | None = None


def assess_service_cleanup(
    identity: OwnedUserService,
    evidence: EvidenceRecord | None,
    *,
    cleanup_started_at: str,
    evaluated_at: str,
) -> ServiceCleanupAssessment:
    """Assess a fresh observation, never grant permission or dispatch a command.

    A future observer must independently check the manager, owned files/install
    links and full unit cgroup. An action exit code or stopped main PID cannot
    establish cleanup. Existing exact-plan approvals gain no service authority.
    """
    started, evaluated = _time(cleanup_started_at), _time(evaluated_at)
    scope = identity.to_dict()
    if started < _time(scope["created_at"]) or evaluated < started:
        raise ContractError("cleanup evaluation has an invalid time window")

    def unknown(reason: str) -> ServiceCleanupAssessment:
        return ServiceCleanupAssessment("unknown", (reason,))

    if evidence is None:
        return unknown("observation_missing")
    try:
        document = evidence.to_dict()
        if len(canonical_json_bytes(document)) > 16 * 1024:
            return unknown("observation_size_exceeded")
        record = EvidenceRecord.from_mapping(document)
    except (EvidenceError, TypeError, ValueError):
        return unknown("observation_integrity_invalid")
    if record.provenance is not EvidenceProvenance.OBSERVED or record.producer != OBSERVER:
        return unknown("independent_service_observer_required")
    try:
        observed = _time(record.timestamp)
    except ContractError:
        return unknown("observation_time_invalid")
    if observed < started or observed > evaluated or evaluated - observed > timedelta(seconds=5):
        return unknown("observation_outside_cleanup_window")
    try:
        facts = _object(
            record.content,
            "schema_version identity_digest owner_uid boot_id manager_id unit_name "
            "manager_state unit_load_state unit_active_state unit_file_state "
            "enable_links_state cgroup_state",
            "service observation",
        )
        if facts["schema_version"] != OBSERVATION_SCHEMA:
            raise ContractError("unsupported service observation schema")
        choices = {
            "manager_state": {"available", "unavailable"},
            "unit_load_state": {"absent", "loaded", "unknown"},
            "unit_active_state": {"active", "inactive", "failed", "unknown"},
            "unit_file_state": {"absent", "owned", "changed", "unknown"},
            "enable_links_state": {"absent", "owned", "changed", "unknown"},
            "cgroup_state": {"empty", "populated", "unknown"},
        }
        for name, allowed in choices.items():
            if not isinstance(facts[name], str) or facts[name] not in allowed:
                raise ContractError("invalid service observation state")
    except ContractError:
        return unknown("observation_shape_invalid")
    mismatches = []
    if record.runner_profile_id != scope["runner_profile_id"]:
        mismatches.append("runner_profile_changed")
    if record.target_scope_ref != scope["target_scope_digest"]:
        mismatches.append("target_scope_changed")
    for key, expected in {
        "identity_digest": identity.digest,
        "owner_uid": scope["owner_uid"],
        "boot_id": scope["boot_id"],
        "manager_id": scope["manager_id"],
        "unit_name": identity.unit_name,
    }.items():
        if type(facts[key]) is not type(expected) or facts[key] != expected:
            mismatches.append(key + "_changed")
    if mismatches:
        return ServiceCleanupAssessment(
            "identity_mismatch", tuple(mismatches), record.evidence_id, record.record_hash
        )
    if facts["unit_file_state"] == "changed" or facts["enable_links_state"] == "changed":
        return ServiceCleanupAssessment(
            "identity_mismatch",
            ("owned_resources_changed",),
            record.evidence_id,
            record.record_hash,
        )
    if facts["manager_state"] != "available" or any(facts[key] == "unknown" for key in choices):
        return ServiceCleanupAssessment(
            "unknown", ("observation_incomplete",), record.evidence_id, record.record_hash
        )
    required = {
        "unit_load_state": "absent",
        "unit_active_state": "inactive",
        "unit_file_state": "absent",
        "enable_links_state": "absent",
        "cgroup_state": "empty",
    }
    residue = tuple(key + "_remains" for key, absent in required.items() if facts[key] != absent)
    return ServiceCleanupAssessment(
        "residue" if residue else "verified_absent", residue, record.evidence_id, record.record_hash
    )
