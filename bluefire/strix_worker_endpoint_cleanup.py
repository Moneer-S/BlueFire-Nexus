"""Live, distinct-UID cleanup authority for one Strix worker endpoint.

The worker owns its private control directory while it is running, so the
unprivileged controller must not try to remove those paths by name.  A native
helper retains the already-verified directory authority and performs one
fd-relative cleanup.  This module validates that live result and emits a
durable receipt.  The receipt is evidence only and cannot recreate the helper
or authorize another cleanup.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, cast

from .util import canonical_json_bytes, content_hash

OWNER_SCHEMA = "bluefire.strix-worker-endpoint-cleanup-owner.v1"
RECEIPT_SCHEMA = "bluefire.strix-worker-endpoint-cleanup-receipt.v1"

_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
KernelIdentity = tuple[int, int]


class WorkerEndpointCleanupError(RuntimeError):
    """The retained endpoint cleanup authority or its result is invalid."""


def _text(value: Any, label: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkerEndpointCleanupError(f"{label} is invalid")
    return value


def _attempt(value: Any) -> str:
    result = _text(value, "worker attempt", 47)
    if _ATTEMPT.fullmatch(result) is None:
        raise WorkerEndpointCleanupError("worker attempt is invalid")
    return result


def _digest(value: Any, label: str) -> str:
    result = _text(value, label, 71)
    if _DIGEST.fullmatch(result) is None:
        raise WorkerEndpointCleanupError(f"{label} is invalid")
    return result


def _identity(value: Any, label: str) -> KernelIdentity:
    if (
        not isinstance(value, (tuple, list))
        or len(value) != 2
        or any(type(item) is not int for item in value)
        or not 0 <= value[0] < 2**64
        or not 1 <= value[1] < 2**64
    ):
        raise WorkerEndpointCleanupError(f"{label} is invalid")
    return int(value[0]), int(value[1])


def _optional_identity(value: Any, label: str) -> KernelIdentity | None:
    return None if value is None else _identity(value, label)


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerEndpointCleanupError(f"{label} fields do not match the contract")
    return value


@dataclass(frozen=True, slots=True)
class WorkerEndpointCleanupObservationV1:
    """One native helper result captured before its retained authority closes."""

    helper_ref: str
    directory_authority_ref: str
    endpoint_authority_ref: str
    launch_authority_ref: str | None
    directory_identity: KernelIdentity
    endpoint_identity: KernelIdentity
    launch_identity: KernelIdentity | None
    directory_identity_verified: bool
    endpoint_identity_verified: bool
    launch_identity_verified: bool
    retained_directory_handle: bool
    retained_endpoint_handle: bool
    retained_launch_handle: bool
    endpoint_entry_matches_retained_handle: bool
    launch_entry_matches_retained_handle: bool
    fd_relative_cleanup: bool
    symlink_followed: bool
    endpoint_absent: bool
    launch_absent: bool
    directory_absent: bool


class WorkerEndpointCleanupHelperV1(Protocol):
    """Non-serializable, one-shot authority retained by the native helper."""

    @property
    def helper_ref(self) -> str: ...

    @property
    def directory_authority_ref(self) -> str: ...

    @property
    def endpoint_authority_ref(self) -> str: ...

    def launch_authority_ref(self, *, launch_identity: KernelIdentity) -> str: ...

    def cleanup(
        self,
        *,
        directory_identity: KernelIdentity,
        endpoint_identity: KernelIdentity,
        launch_identity: KernelIdentity | None,
    ) -> WorkerEndpointCleanupObservationV1: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerEndpointCleanupReceiptV1:
    """Durable cleanup evidence that carries no live path authority."""

    _canonical: bytes

    @property
    def document(self) -> Mapping[str, Any]:
        import json

        return cast(Mapping[str, Any], json.loads(self._canonical))

    @classmethod
    def from_mapping(cls, value: Any) -> "WorkerEndpointCleanupReceiptV1":
        fields = {
            "schema_version",
            "attempt_id",
            "claim_digest",
            "worker_containment_ref",
            "cleanup_owner_ref",
            "helper_ref",
            "directory_authority_ref",
            "endpoint_authority_ref",
            "launch_authority_ref",
            "directory_identity",
            "endpoint_identity",
            "launch_identity",
            "launch_was_published",
            "directory_identity_verified",
            "endpoint_identity_verified",
            "launch_identity_verified",
            "retained_directory_handle",
            "retained_endpoint_handle",
            "retained_launch_handle",
            "endpoint_entry_matches_retained_handle",
            "launch_entry_matches_retained_handle",
            "fd_relative_cleanup",
            "symlink_followed",
            "endpoint_absent",
            "launch_absent",
            "directory_absent",
            "receipt_ref",
        }
        row = _exact(value, fields, "worker endpoint cleanup receipt")
        launch_identity = _optional_identity(row["launch_identity"], "worker launch identity")
        launch_authority_ref = (
            None
            if row["launch_authority_ref"] is None
            else _digest(row["launch_authority_ref"], "cleanup launch authority")
        )
        canonical: dict[str, Any] = {
            "schema_version": _text(row["schema_version"], "cleanup receipt version"),
            "attempt_id": _attempt(row["attempt_id"]),
            "claim_digest": _digest(row["claim_digest"], "worker claim"),
            "worker_containment_ref": _digest(
                row["worker_containment_ref"], "worker containment reference"
            ),
            "cleanup_owner_ref": _digest(row["cleanup_owner_ref"], "cleanup owner"),
            "helper_ref": _digest(row["helper_ref"], "cleanup helper"),
            "directory_authority_ref": _digest(
                row["directory_authority_ref"], "cleanup directory authority"
            ),
            "endpoint_authority_ref": _digest(
                row["endpoint_authority_ref"], "cleanup endpoint authority"
            ),
            "launch_authority_ref": launch_authority_ref,
            "directory_identity": list(
                _identity(row["directory_identity"], "worker control directory identity")
            ),
            "endpoint_identity": list(
                _identity(row["endpoint_identity"], "worker endpoint identity")
            ),
            "launch_identity": list(launch_identity) if launch_identity is not None else None,
            "launch_was_published": row["launch_was_published"],
            "directory_identity_verified": row["directory_identity_verified"],
            "endpoint_identity_verified": row["endpoint_identity_verified"],
            "launch_identity_verified": row["launch_identity_verified"],
            "retained_directory_handle": row["retained_directory_handle"],
            "retained_endpoint_handle": row["retained_endpoint_handle"],
            "retained_launch_handle": row["retained_launch_handle"],
            "endpoint_entry_matches_retained_handle": row[
                "endpoint_entry_matches_retained_handle"
            ],
            "launch_entry_matches_retained_handle": row[
                "launch_entry_matches_retained_handle"
            ],
            "fd_relative_cleanup": row["fd_relative_cleanup"],
            "symlink_followed": row["symlink_followed"],
            "endpoint_absent": row["endpoint_absent"],
            "launch_absent": row["launch_absent"],
            "directory_absent": row["directory_absent"],
            "receipt_ref": _digest(row["receipt_ref"], "cleanup receipt"),
        }
        boolean_fields = fields - {
            "schema_version",
            "attempt_id",
            "claim_digest",
            "worker_containment_ref",
            "cleanup_owner_ref",
            "helper_ref",
            "directory_authority_ref",
            "endpoint_authority_ref",
            "launch_authority_ref",
            "directory_identity",
            "endpoint_identity",
            "launch_identity",
            "receipt_ref",
        }
        if any(type(canonical[name]) is not bool for name in boolean_fields):
            raise WorkerEndpointCleanupError("cleanup receipt booleans are invalid")
        launch_was_published = launch_identity is not None
        if (
            canonical["schema_version"] != RECEIPT_SCHEMA
            or canonical["launch_was_published"] is not launch_was_published
            or canonical["directory_identity_verified"] is not True
            or canonical["endpoint_identity_verified"] is not True
            or canonical["launch_identity_verified"] is not launch_was_published
            or canonical["retained_directory_handle"] is not True
            or canonical["retained_endpoint_handle"] is not True
            or canonical["retained_launch_handle"] is not launch_was_published
            or canonical["endpoint_entry_matches_retained_handle"] is not True
            or canonical["launch_entry_matches_retained_handle"] is not launch_was_published
            or (canonical["launch_authority_ref"] is not None) is not launch_was_published
            or canonical["fd_relative_cleanup"] is not True
            or canonical["symlink_followed"] is not False
            or canonical["endpoint_absent"] is not True
            or canonical["launch_absent"] is not True
            or canonical["directory_absent"] is not True
        ):
            raise WorkerEndpointCleanupError(
                "worker endpoint cleanup does not prove exact complete absence"
            )
        expected_owner_ref = content_hash(
            {
                "schema_version": OWNER_SCHEMA,
                "attempt_id": canonical["attempt_id"],
                "claim_digest": canonical["claim_digest"],
                "worker_containment_ref": canonical["worker_containment_ref"],
                "directory_identity": canonical["directory_identity"],
                "endpoint_identity": canonical["endpoint_identity"],
                "helper_ref": canonical["helper_ref"],
                "directory_authority_ref": canonical["directory_authority_ref"],
                "endpoint_authority_ref": canonical["endpoint_authority_ref"],
            }
        )
        if canonical["cleanup_owner_ref"] != expected_owner_ref:
            raise WorkerEndpointCleanupError("cleanup owner reference is invalid")
        unsigned = {name: item for name, item in canonical.items() if name != "receipt_ref"}
        if canonical["receipt_ref"] != content_hash(unsigned):
            raise WorkerEndpointCleanupError("worker endpoint cleanup receipt digest is invalid")
        return cls(canonical_json_bytes(canonical))

    @property
    def receipt_ref(self) -> str:
        return str(self.document["receipt_ref"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self.document)


class WorkerEndpointCleanupOwnerV1:
    """One live helper authority bound to one worker endpoint generation."""

    schema_version = OWNER_SCHEMA

    def __init__(
        self,
        *,
        attempt_id: str,
        claim_digest: str,
        worker_containment_ref: str,
        directory_identity: KernelIdentity,
        endpoint_identity: KernelIdentity,
        helper: WorkerEndpointCleanupHelperV1,
    ) -> None:
        self._attempt_id = _attempt(attempt_id)
        self._claim_digest = _digest(claim_digest, "worker claim")
        self._worker_containment_ref = _digest(
            worker_containment_ref, "worker containment reference"
        )
        self._directory_identity = _identity(
            directory_identity, "worker control directory identity"
        )
        self._endpoint_identity = _identity(endpoint_identity, "worker endpoint identity")
        self._helper = helper
        self._helper_ref = _digest(helper.helper_ref, "cleanup helper")
        self._directory_authority_ref = _digest(
            helper.directory_authority_ref, "cleanup directory authority"
        )
        self._endpoint_authority_ref = _digest(
            helper.endpoint_authority_ref, "cleanup endpoint authority"
        )
        self._owner_ref = content_hash(
            {
                "schema_version": OWNER_SCHEMA,
                "attempt_id": self._attempt_id,
                "claim_digest": self._claim_digest,
                "worker_containment_ref": self._worker_containment_ref,
                "directory_identity": list(self._directory_identity),
                "endpoint_identity": list(self._endpoint_identity),
                "helper_ref": self._helper_ref,
                "directory_authority_ref": self._directory_authority_ref,
                "endpoint_authority_ref": self._endpoint_authority_ref,
            }
        )
        self._receipt: WorkerEndpointCleanupReceiptV1 | None = None
        self._launch_identity: KernelIdentity | None = None
        self._attempted = False
        self._closed = False
        self._lock = threading.Lock()

    @property
    def cleanup_owner_ref(self) -> str:
        return self._owner_ref

    @property
    def directory_identity(self) -> KernelIdentity:
        return self._directory_identity

    @property
    def endpoint_identity(self) -> KernelIdentity:
        return self._endpoint_identity

    def cleanup(
        self, *, launch_identity: tuple[int, int] | None
    ) -> WorkerEndpointCleanupReceiptV1:
        with self._lock:
            return self._cleanup_locked(launch_identity=launch_identity)

    def _cleanup_locked(
        self, *, launch_identity: tuple[int, int] | None
    ) -> WorkerEndpointCleanupReceiptV1:
        requested_launch = _optional_identity(launch_identity, "worker launch identity")
        if self._receipt is not None:
            if requested_launch != self._launch_identity:
                raise WorkerEndpointCleanupError(
                    "cleanup was already completed for another launch identity"
                )
            return self._receipt
        if self._closed:
            raise WorkerEndpointCleanupError("worker endpoint cleanup owner is closed")
        if self._attempted:
            raise WorkerEndpointCleanupError("worker endpoint cleanup outcome is unavailable")

        self._attempted = True
        self._launch_identity = requested_launch
        launch_authority_ref: str | None = None
        receipt: WorkerEndpointCleanupReceiptV1 | None = None
        failure: WorkerEndpointCleanupError | None = None
        try:
            if requested_launch is not None:
                launch_authority_ref = _digest(
                    self._helper.launch_authority_ref(launch_identity=requested_launch),
                    "cleanup launch authority",
                )
            observation = self._helper.cleanup(
                directory_identity=self._directory_identity,
                endpoint_identity=self._endpoint_identity,
                launch_identity=requested_launch,
            )
            receipt = self._validate_observation(
                observation, requested_launch, launch_authority_ref
            )
        except WorkerEndpointCleanupError as exc:
            failure = exc
        except Exception as exc:
            failure = WorkerEndpointCleanupError("native worker endpoint cleanup failed")
            failure.__cause__ = exc
        try:
            self._helper.close()
        except Exception as exc:
            if failure is None:
                failure = WorkerEndpointCleanupError("native cleanup helper could not close")
                failure.__cause__ = exc
        self._closed = True
        if failure is not None:
            raise failure
        if receipt is None:  # Defensive: every success path produces a validated receipt.
            raise WorkerEndpointCleanupError("native worker endpoint cleanup outcome is unavailable")
        self._receipt = receipt
        return receipt

    def _validate_observation(
        self,
        observation: WorkerEndpointCleanupObservationV1,
        launch_identity: KernelIdentity | None,
        launch_authority_ref: str | None,
    ) -> WorkerEndpointCleanupReceiptV1:
        if not isinstance(observation, WorkerEndpointCleanupObservationV1):
            raise WorkerEndpointCleanupError("native cleanup observation is invalid")
        if (
            _digest(observation.helper_ref, "cleanup helper") != self._helper_ref
            or _digest(
                observation.directory_authority_ref, "observed cleanup directory authority"
            )
            != self._directory_authority_ref
            or _digest(
                observation.endpoint_authority_ref, "observed cleanup endpoint authority"
            )
            != self._endpoint_authority_ref
            or _identity(
                observation.directory_identity, "observed control directory identity"
            )
            != self._directory_identity
            or _identity(observation.endpoint_identity, "observed endpoint identity")
            != self._endpoint_identity
            or _optional_identity(observation.launch_identity, "observed launch identity")
            != launch_identity
            or (
                None
                if observation.launch_authority_ref is None
                else _digest(observation.launch_authority_ref, "observed launch authority")
            )
            != launch_authority_ref
        ):
            raise WorkerEndpointCleanupError("worker endpoint cleanup identity drifted")
        launch_was_published = launch_identity is not None
        required = {
            "directory_identity_verified": observation.directory_identity_verified,
            "endpoint_identity_verified": observation.endpoint_identity_verified,
            "fd_relative_cleanup": observation.fd_relative_cleanup,
            "retained_directory_handle": observation.retained_directory_handle,
            "retained_endpoint_handle": observation.retained_endpoint_handle,
            "retained_launch_handle": (
                observation.retained_launch_handle if launch_was_published else True
            ),
            "endpoint_entry_matches_retained_handle": (
                observation.endpoint_entry_matches_retained_handle
            ),
            "endpoint_absent": observation.endpoint_absent,
            "launch_absent": observation.launch_absent,
            "directory_absent": observation.directory_absent,
        }
        if any(value is not True for value in required.values()):
            raise WorkerEndpointCleanupError(
                "native cleanup did not prove exact complete endpoint absence"
            )
        if (
            observation.symlink_followed is not False
            or observation.launch_identity_verified is not launch_was_published
            or observation.retained_launch_handle is not launch_was_published
            or observation.launch_entry_matches_retained_handle is not launch_was_published
            or (observation.launch_authority_ref is not None) is not launch_was_published
        ):
            raise WorkerEndpointCleanupError("native cleanup identity proof is invalid")

        document: dict[str, Any] = {
            "schema_version": RECEIPT_SCHEMA,
            "attempt_id": self._attempt_id,
            "claim_digest": self._claim_digest,
            "worker_containment_ref": self._worker_containment_ref,
            "cleanup_owner_ref": self._owner_ref,
            "helper_ref": self._helper_ref,
            "directory_authority_ref": self._directory_authority_ref,
            "endpoint_authority_ref": self._endpoint_authority_ref,
            "launch_authority_ref": launch_authority_ref,
            "directory_identity": list(self._directory_identity),
            "endpoint_identity": list(self._endpoint_identity),
            "launch_identity": list(launch_identity) if launch_identity is not None else None,
            "launch_was_published": launch_was_published,
            "directory_identity_verified": True,
            "endpoint_identity_verified": True,
            "launch_identity_verified": launch_was_published,
            "retained_directory_handle": True,
            "retained_endpoint_handle": True,
            "retained_launch_handle": launch_was_published,
            "endpoint_entry_matches_retained_handle": True,
            "launch_entry_matches_retained_handle": launch_was_published,
            "fd_relative_cleanup": True,
            "symlink_followed": False,
            "endpoint_absent": True,
            "launch_absent": True,
            "directory_absent": True,
        }
        document["receipt_ref"] = content_hash(document)
        return WorkerEndpointCleanupReceiptV1.from_mapping(document)

    def close(self) -> None:
        """Close unspent authority; this deliberately emits no absence receipt."""

        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._helper.close()
                except Exception as exc:
                    raise WorkerEndpointCleanupError(
                        "native cleanup helper could not close"
                    ) from exc


__all__ = [
    "OWNER_SCHEMA",
    "RECEIPT_SCHEMA",
    "WorkerEndpointCleanupError",
    "WorkerEndpointCleanupHelperV1",
    "WorkerEndpointCleanupObservationV1",
    "WorkerEndpointCleanupOwnerV1",
    "WorkerEndpointCleanupReceiptV1",
]
