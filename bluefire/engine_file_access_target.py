"""Pure, closed target policy for one enrolled Linux file-read mechanism.

This document is review material, not a probe client, a bearer token, or
execution authority. An admission controller must independently reopen the
attempt, durable control, original read operation records, live enrollment,
resource, and current snapshot before accepting it. The historical snapshot
must be rebuilt from immutable controller records; a matching supplied value
or self-hash is not provenance. The controller must separately enforce the
request budget; this value does not count or dispatch reads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .engine_attempt_contract import AttemptRole, EngineAttemptBinding
from .engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION
from .engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    EngineFileAccessSnapshotError,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
    verify_file_access_snapshot_pair,
)
from .file_access_contract import (
    MAX_BYTES,
    MAX_ENROLLMENT_MS,
    MAX_REQUEST_MS,
    MAX_REQUESTS,
    PROBE_ACTION,
    VerifiedFileAccessBinding,
    canonical_file_access_binding,
)
from .util import content_hash, json_clone, parse_iso8601_datetime

SCHEMA = "bluefire.engine-file-read-target.v2"
TARGET_POLICY_VERSION = "file-access.uid1002-read.v1"
_ATTEMPT_ID = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = frozenset(
    {
        "schema_version",
        "target_policy_version",
        "attempt_id",
        "attempt_binding_digest",
        "mechanism",
        "historical_snapshot",
        "snapshot",
        "request_budget",
        "max_read_bytes",
        "per_request_ms",
        "issued_at_ms",
        "deadline_ms",
    }
)


class EngineFileReadTargetError(ValueError):
    """A file-read target is widened, malformed, or stale."""


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EngineFileReadTargetError(f"{label} is outside its finite bound")
    return value


@dataclass(frozen=True, slots=True)
class EngineFileReadTargetPolicy:
    """One proposed UID 1002 read target, with no dispatch operation."""

    schema_version: str
    target_policy_version: str
    attempt_id: str
    attempt_binding_digest: str
    mechanism: FileAccessReadMechanism
    historical_snapshot: FileAccessTargetSnapshot
    snapshot: FileAccessTargetSnapshot
    request_budget: int
    max_read_bytes: int
    per_request_ms: int
    issued_at_ms: int
    deadline_ms: int

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.schema_version != SCHEMA:
            raise EngineFileReadTargetError("file-read target version is unsupported")
        if self.target_policy_version != TARGET_POLICY_VERSION:
            raise EngineFileReadTargetError("file-read target policy version is unsupported")
        if not isinstance(self.attempt_id, str) or _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise EngineFileReadTargetError("file-read target attempt is invalid")
        if (
            not isinstance(self.attempt_binding_digest, str)
            or _DIGEST.fullmatch(self.attempt_binding_digest) is None
        ):
            raise EngineFileReadTargetError("file-read target attempt binding is invalid")
        if (
            type(self.mechanism) is not FileAccessReadMechanism
            or type(self.historical_snapshot) is not FileAccessTargetSnapshot
            or type(self.snapshot) is not FileAccessTargetSnapshot
        ):
            raise EngineFileReadTargetError("file-read target mechanism or snapshots are invalid")
        try:
            mechanism = FileAccessReadMechanism.from_mapping(self.mechanism.to_dict())
            historical = FileAccessTargetSnapshot.from_mapping(self.historical_snapshot.to_dict())
            snapshot = FileAccessTargetSnapshot.from_mapping(self.snapshot.to_dict())
            historical.matches_mechanism(mechanism)
            snapshot.matches_mechanism(mechanism)
            if historical.to_dict()["phase"] != HISTORICAL_BASELINE:
                raise EngineFileReadTargetError("original file-read snapshot is not historical")
            if snapshot.to_dict()["phase"] == HISTORICAL_BASELINE:
                if snapshot.to_dict() != historical.to_dict():
                    raise EngineFileReadTargetError("baseline target differs from historical read")
            else:
                verify_file_access_snapshot_pair(historical, snapshot, mechanism=mechanism)
        except (EngineFileAccessSnapshotError, TypeError, ValueError) as exc:
            raise EngineFileReadTargetError("file-read target identity is invalid") from exc
        _integer(self.request_budget, 1, MAX_REQUESTS, "read request budget")
        _integer(self.max_read_bytes, MAX_BYTES, MAX_BYTES, "read byte ceiling")
        _integer(self.per_request_ms, MAX_REQUEST_MS, MAX_REQUEST_MS, "read request deadline")
        _integer(self.issued_at_ms, 1, 2**63 - 1, "target issue time")
        _integer(
            self.deadline_ms,
            self.issued_at_ms + 1,
            min(2**63 - 1, self.issued_at_ms + MAX_ENROLLMENT_MS),
            "target deadline",
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> EngineFileReadTargetPolicy:
        """Parse review material exactly; parsing never authenticates its source."""

        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise EngineFileReadTargetError("file-read target fields do not match the contract")
        try:
            mechanism = FileAccessReadMechanism.from_mapping(value["mechanism"])
            historical = FileAccessTargetSnapshot.from_mapping(value["historical_snapshot"])
            snapshot = FileAccessTargetSnapshot.from_mapping(value["snapshot"])
        except (EngineFileAccessSnapshotError, TypeError, ValueError) as exc:
            raise EngineFileReadTargetError("file-read target identity is invalid") from exc
        return cls(
            schema_version=value["schema_version"],
            target_policy_version=value["target_policy_version"],
            attempt_id=value["attempt_id"],
            attempt_binding_digest=value["attempt_binding_digest"],
            mechanism=mechanism,
            historical_snapshot=historical,
            snapshot=snapshot,
            request_budget=value["request_budget"],
            max_read_bytes=value["max_read_bytes"],
            per_request_ms=value["per_request_ms"],
            issued_at_ms=value["issued_at_ms"],
            deadline_ms=value["deadline_ms"],
        )

    @classmethod
    def from_controller(
        cls,
        *,
        attempt: EngineAttemptBinding,
        mechanism: FileAccessReadMechanism,
        historical_snapshot: FileAccessTargetSnapshot,
        snapshot: FileAccessTargetSnapshot,
        historical_binding: VerifiedFileAccessBinding,
        current_binding: VerifiedFileAccessBinding,
        now_ms: int,
        request_budget: int,
        deadline_ms: int,
    ) -> EngineFileReadTargetPolicy:
        """Prepare a policy from caller-supplied controller evidence, without effects.

        The caller must independently reopen those inputs from durable records
        and live state. The historical binding is a retained 0640 revision,
        not a fresh observation of the now-hardened file. A
        ``VerifiedFileAccessBinding`` alone is not admission.
        """

        if type(attempt) is not EngineAttemptBinding:
            raise EngineFileReadTargetError("file-read target attempt binding is invalid")
        policy = cls(
            schema_version=SCHEMA,
            target_policy_version=TARGET_POLICY_VERSION,
            attempt_id=attempt.attempt_id,
            attempt_binding_digest=attempt.binding_digest,
            mechanism=mechanism,
            historical_snapshot=historical_snapshot,
            snapshot=snapshot,
            request_budget=request_budget,
            max_read_bytes=MAX_BYTES,
            per_request_ms=MAX_REQUEST_MS,
            issued_at_ms=now_ms,
            deadline_ms=deadline_ms,
        )
        policy._compare_current(
            attempt=attempt,
            current_mechanism=mechanism,
            current_historical_snapshot=historical_snapshot,
            current_snapshot=snapshot,
            historical_binding=historical_binding,
            current_binding=current_binding,
            now_ms=now_ms,
        )
        return policy

    @property
    def read_action_id(self) -> str:
        """The sole fixed native method; no path or command selector exists."""

        return PROBE_ACTION

    @property
    def policy_digest(self) -> str:
        """Canonical draft identity for a separate protected admission record."""

        return content_hash(self.to_dict())

    def require_current(
        self,
        *,
        expected_policy_digest: str,
        attempt: EngineAttemptBinding,
        current_mechanism: FileAccessReadMechanism,
        current_historical_snapshot: FileAccessTargetSnapshot,
        current_snapshot: FileAccessTargetSnapshot,
        historical_binding: VerifiedFileAccessBinding,
        current_binding: VerifiedFileAccessBinding,
        now_ms: int,
    ) -> None:
        """Compare with a protected expected digest and reopened controller facts.

        The caller must load ``expected_policy_digest`` from its independent
        protected admission or reservation and rebuild the historical snapshot
        with ``FileAccessTargetSnapshot.from_controller_records`` using fetched
        immutable revision and operation rows. A digest copied from this policy
        is only a self-check and does not grant authority.
        """

        if (
            not isinstance(expected_policy_digest, str)
            or _DIGEST.fullmatch(expected_policy_digest) is None
            or self.policy_digest != expected_policy_digest
        ):
            raise EngineFileReadTargetError("file-read target differs from protected policy")
        self._compare_current(
            attempt=attempt,
            current_mechanism=current_mechanism,
            current_historical_snapshot=current_historical_snapshot,
            current_snapshot=current_snapshot,
            historical_binding=historical_binding,
            current_binding=current_binding,
            now_ms=now_ms,
        )

    def _compare_current(
        self,
        *,
        attempt: EngineAttemptBinding,
        current_mechanism: FileAccessReadMechanism,
        current_historical_snapshot: FileAccessTargetSnapshot,
        current_snapshot: FileAccessTargetSnapshot,
        historical_binding: VerifiedFileAccessBinding,
        current_binding: VerifiedFileAccessBinding,
        now_ms: int,
    ) -> None:
        """Check a draft against separately reopened controller facts.

        This pure comparison cannot prove provenance, reserve requests, or
        launch the probe. A public admission call must use ``require_current``.
        """

        self._validate()
        if (
            type(attempt) is not EngineAttemptBinding
            or type(current_mechanism) is not FileAccessReadMechanism
            or type(current_historical_snapshot) is not FileAccessTargetSnapshot
            or type(current_snapshot) is not FileAccessTargetSnapshot
            or type(historical_binding) is not VerifiedFileAccessBinding
            or type(current_binding) is not VerifiedFileAccessBinding
        ):
            raise EngineFileReadTargetError("current file-read evidence is invalid")
        _integer(now_ms, self.issued_at_ms, self.deadline_ms - 1, "current time")
        try:
            reopened_mechanism = FileAccessReadMechanism.from_mapping(current_mechanism.to_dict())
            reopened_historical = FileAccessTargetSnapshot.from_mapping(
                current_historical_snapshot.to_dict()
            )
            reopened_snapshot = FileAccessTargetSnapshot.from_mapping(current_snapshot.to_dict())
            canonical_file_access_binding(historical_binding.to_dict())
            binding = canonical_file_access_binding(current_binding.to_dict())
            reopened_mechanism.matches_verified_binding(historical_binding)
            reopened_mechanism.matches_verified_binding(current_binding)
            reopened_historical.matches_mechanism(reopened_mechanism)
            reopened_historical.matches_verified_binding(historical_binding)
            reopened_snapshot.matches_mechanism(reopened_mechanism)
            reopened_snapshot.matches_verified_binding(current_binding)
            if reopened_snapshot.to_dict()["phase"] == HISTORICAL_BASELINE:
                if reopened_snapshot.to_dict() != reopened_historical.to_dict():
                    raise EngineFileReadTargetError("baseline target differs from historical read")
            else:
                verify_file_access_snapshot_pair(
                    reopened_historical, reopened_snapshot, mechanism=reopened_mechanism
                )
            created_at_ms = int(parse_iso8601_datetime(attempt.created_at).timestamp() * 1000)
        except (EngineFileAccessSnapshotError, TypeError, ValueError) as exc:
            raise EngineFileReadTargetError("current file-read evidence is invalid") from exc
        expected_phase = (
            HISTORICAL_BASELINE
            if attempt.role is AttemptRole.BASELINE
            else CURRENT_HARDENED
            if attempt.role is AttemptRole.ADAPTIVE_SEARCH
            else None
        )
        if (
            attempt.engine_id != "strix"
            or expected_phase is None
            or reopened_snapshot.to_dict()["phase"] != expected_phase
            or attempt.scope_version != ENGINE_CAPABILITY_SCOPE_VERSION
            or attempt.scope_ref != reopened_mechanism.mechanism_ref
            or attempt.target_snapshot_ref != reopened_snapshot.target_snapshot_ref
            or attempt.attempt_id != self.attempt_id
            or attempt.binding_digest != self.attempt_binding_digest
            or reopened_mechanism.to_dict() != self.mechanism.to_dict()
            or reopened_historical.to_dict() != self.historical_snapshot.to_dict()
            or reopened_historical.target_snapshot_ref
            != self.historical_snapshot.target_snapshot_ref
            or reopened_snapshot.to_dict() != self.snapshot.to_dict()
            or self.request_budget > attempt.action_limit
            or self.issued_at_ms < created_at_ms
            or self.deadline_ms > created_at_ms + attempt.wall_clock_seconds * 1000
            or self.deadline_ms > binding["expires_at_ms"]
        ):
            raise EngineFileReadTargetError("file-read target changed or exceeded its attempt")

    def to_dict(self) -> dict[str, Any]:
        self._validate()
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "target_policy_version": self.target_policy_version,
                    "attempt_id": self.attempt_id,
                    "attempt_binding_digest": self.attempt_binding_digest,
                    "mechanism": self.mechanism.to_dict(),
                    "historical_snapshot": self.historical_snapshot.to_dict(),
                    "snapshot": self.snapshot.to_dict(),
                    "request_budget": self.request_budget,
                    "max_read_bytes": self.max_read_bytes,
                    "per_request_ms": self.per_request_ms,
                    "issued_at_ms": self.issued_at_ms,
                    "deadline_ms": self.deadline_ms,
                }
            )
        )


__all__ = [
    "EngineFileReadTargetError",
    "EngineFileReadTargetPolicy",
    "SCHEMA",
    "TARGET_POLICY_VERSION",
]
