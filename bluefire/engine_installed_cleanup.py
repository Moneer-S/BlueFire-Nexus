"""Exact settlement contract for installed engine component bundles.

The composition owns lifecycle ordering, but an attempt factory owns the
effect-specific way that its relays, workers, leases, listeners, and transport
handles establish absence.  This contract lets that controller-owned owner
settle or reopen the exact bundle without teaching the application layer how
to retry a numeric descriptor or reconstruct a tool-specific cleanup action.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Protocol

from .util import content_hash

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCHEMA = "bluefire.installed-engine-bundle-cleanup-receipt.v1"
_STATES = frozenset({"verified_absent", "unknown"})
_ROLE_STATES = frozenset({"verified_absent", "verified_revoked", "verified_settled", "unknown"})


class InstalledEngineCleanupError(RuntimeError):
    """A cleanup owner or receipt changed its exact protected binding."""


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InstalledEngineCleanupError(f"{label} is invalid")
    return value


def _text(value: str, label: str, *, limit: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= limit
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise InstalledEngineCleanupError(f"{label} is invalid")
    return value


def _timestamp(value: str, label: str) -> datetime:
    _text(value, label, limit=100)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InstalledEngineCleanupError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InstalledEngineCleanupError(f"{label} is invalid")
    return parsed


@dataclass(frozen=True, slots=True)
class InstalledEngineCleanupResourceBinding:
    """One canonical effect owner in forward construction order."""

    role: str
    resource_ref: str

    def __post_init__(self) -> None:
        _text(self.role, "cleanup resource role", limit=100)
        _digest(self.resource_ref, "cleanup resource reference")

    def document(self) -> dict[str, str]:
        return {"role": self.role, "resource_ref": self.resource_ref}


def resource_set_ref(
    resources: tuple[InstalledEngineCleanupResourceBinding, ...],
) -> str:
    if not resources or len({row.role for row in resources}) != len(resources):
        raise InstalledEngineCleanupError("cleanup resource manifest is invalid")
    if len({row.resource_ref for row in resources}) != len(resources):
        raise InstalledEngineCleanupError("cleanup resource manifest repeats a resource")
    return content_hash(
        {
            "schema_version": "bluefire.installed-engine-cleanup-resource-set.v1",
            "resources": [resource.document() for resource in resources],
        }
    )


@dataclass(frozen=True, slots=True)
class InstalledEngineResourceCleanupOutcome:
    """One independently checked effect-owner result in close order."""

    role: str
    resource_ref: str
    state: str
    evidence_ref: str | None

    def __post_init__(self) -> None:
        _text(self.role, "cleanup resource role", limit=100)
        _digest(self.resource_ref, "cleanup resource reference")
        if self.state not in _ROLE_STATES:
            raise InstalledEngineCleanupError("cleanup resource state is invalid")
        if self.evidence_ref is not None:
            _digest(self.evidence_ref, "cleanup resource evidence reference")
        if self.state != "unknown" and self.evidence_ref is None:
            raise InstalledEngineCleanupError("verified cleanup resource outcome requires evidence")

    def document(self) -> dict[str, str | None]:
        return {
            "role": self.role,
            "resource_ref": self.resource_ref,
            "state": self.state,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True, slots=True)
class InstalledEngineBundleCleanupReceipt:
    """Canonical bundle result retained by the protected cleanup owner."""

    cleanup_ref: str
    attempt_ref: str
    activation_ref: str
    owner_ref: str
    runtime_resolution_ref: str
    resource_set_ref: str
    generation: int
    predecessor_receipt_ref: str | None
    state: str
    outcomes: tuple[InstalledEngineResourceCleanupOutcome, ...]
    settled_at: str
    receipt_ref: str
    schema_version: str = _SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA:
            raise InstalledEngineCleanupError("cleanup receipt version is unsupported")
        _digest(self.cleanup_ref, "cleanup reference")
        _digest(self.attempt_ref, "cleanup attempt reference")
        _digest(self.activation_ref, "cleanup activation reference")
        _digest(self.owner_ref, "cleanup owner reference")
        _digest(self.runtime_resolution_ref, "cleanup runtime resolution reference")
        _digest(self.resource_set_ref, "cleanup resource-set reference")
        if not isinstance(self.generation, int) or self.generation < 1:
            raise InstalledEngineCleanupError("cleanup receipt generation is invalid")
        if self.predecessor_receipt_ref is not None:
            _digest(self.predecessor_receipt_ref, "cleanup predecessor receipt")
        if (self.generation == 1) is not (self.predecessor_receipt_ref is None):
            raise InstalledEngineCleanupError("cleanup receipt predecessor is invalid")
        if self.state not in _STATES:
            raise InstalledEngineCleanupError("cleanup receipt state is invalid")
        _timestamp(self.settled_at, "cleanup settlement time")
        _digest(self.receipt_ref, "cleanup receipt reference")
        if not self.outcomes:
            raise InstalledEngineCleanupError("cleanup receipt has no resource outcomes")
        roles = [outcome.role for outcome in self.outcomes]
        refs = [outcome.resource_ref for outcome in self.outcomes]
        if len(set(roles)) != len(roles) or len(set(refs)) != len(refs):
            raise InstalledEngineCleanupError("cleanup receipt repeats a resource")
        terminal = all(outcome.state != "unknown" for outcome in self.outcomes)
        if self.state == "verified_absent" and not terminal:
            raise InstalledEngineCleanupError("cleanup bundle state contradicts its outcomes")
        if self.receipt_ref != content_hash(self.unsigned_document()):
            raise InstalledEngineCleanupError("cleanup receipt digest is invalid")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "cleanup_ref": self.cleanup_ref,
            "attempt_ref": self.attempt_ref,
            "activation_ref": self.activation_ref,
            "owner_ref": self.owner_ref,
            "runtime_resolution_ref": self.runtime_resolution_ref,
            "resource_set_ref": self.resource_set_ref,
            "generation": self.generation,
            "predecessor_receipt_ref": self.predecessor_receipt_ref,
            "state": self.state,
            "outcomes": [outcome.document() for outcome in self.outcomes],
            "settled_at": self.settled_at,
        }

    def document(self) -> dict[str, object]:
        return {**self.unsigned_document(), "receipt_ref": self.receipt_ref}

    @classmethod
    def create(
        cls,
        *,
        cleanup_ref: str,
        attempt_ref: str,
        activation_ref: str,
        owner_ref: str,
        runtime_resolution_ref: str,
        resource_set_ref: str,
        generation: int,
        predecessor_receipt_ref: str | None,
        state: str,
        outcomes: tuple[InstalledEngineResourceCleanupOutcome, ...],
        settled_at: str,
    ) -> InstalledEngineBundleCleanupReceipt:
        unsigned = {
            "schema_version": _SCHEMA,
            "cleanup_ref": cleanup_ref,
            "attempt_ref": attempt_ref,
            "activation_ref": activation_ref,
            "owner_ref": owner_ref,
            "runtime_resolution_ref": runtime_resolution_ref,
            "resource_set_ref": resource_set_ref,
            "generation": generation,
            "predecessor_receipt_ref": predecessor_receipt_ref,
            "state": state,
            "outcomes": [outcome.document() for outcome in outcomes],
            "settled_at": settled_at,
        }
        return cls(
            cleanup_ref=cleanup_ref,
            attempt_ref=attempt_ref,
            activation_ref=activation_ref,
            owner_ref=owner_ref,
            runtime_resolution_ref=runtime_resolution_ref,
            resource_set_ref=resource_set_ref,
            generation=generation,
            predecessor_receipt_ref=predecessor_receipt_ref,
            state=state,
            outcomes=outcomes,
            settled_at=settled_at,
            receipt_ref=content_hash(unsigned),
        )


class InstalledEngineBundleCleanupOwner(Protocol):
    """Protected, durable owner of one exact attempt resource set.

    ``settle`` performs the first reverse-order settlement. ``reconcile`` may
    retry only operations whose effect-specific contract makes replay safe and
    must otherwise return ``unknown``. Neither method may relaunch the attempt.
    """

    @property
    def attempt_ref(self) -> str: ...

    @property
    def activation_ref(self) -> str: ...

    @property
    def owner_ref(self) -> str: ...

    @property
    def runtime_resolution_ref(self) -> str: ...

    @property
    def resource_set_ref(self) -> str: ...

    @property
    def resource_manifest(self) -> tuple[InstalledEngineCleanupResourceBinding, ...]: ...

    def settle(self, *, cleanup_ref: str) -> InstalledEngineBundleCleanupReceipt: ...

    def reconcile(
        self, *, receipt: InstalledEngineBundleCleanupReceipt
    ) -> InstalledEngineBundleCleanupReceipt: ...


def validate_cleanup_owner(
    owner: InstalledEngineBundleCleanupOwner,
    *,
    attempt_ref: str,
    activation_ref: str,
    owner_ref: str | None = None,
    runtime_resolution_ref: str,
    resource_set_ref: str,
) -> None:
    """Validate immutable owner binding before any cleanup call."""

    _digest(attempt_ref, "expected attempt reference")
    _digest(activation_ref, "expected activation reference")
    if owner_ref is not None:
        _digest(owner_ref, "expected cleanup owner reference")
    _digest(runtime_resolution_ref, "expected runtime resolution reference")
    _digest(resource_set_ref, "expected resource-set reference")
    if (
        owner.attempt_ref != attempt_ref
        or owner.activation_ref != activation_ref
        or (owner_ref is not None and owner.owner_ref != owner_ref)
        or owner.runtime_resolution_ref != runtime_resolution_ref
        or owner.resource_set_ref != resource_set_ref
        or owner.resource_set_ref != resource_set_ref_for_owner(owner)
    ):
        raise InstalledEngineCleanupError("cleanup owner binding changed")
    _digest(owner.owner_ref, "cleanup owner reference")


def resource_set_ref_for_owner(owner: InstalledEngineBundleCleanupOwner) -> str:
    manifest = owner.resource_manifest
    if not isinstance(manifest, tuple) or any(
        not isinstance(row, InstalledEngineCleanupResourceBinding) for row in manifest
    ):
        raise InstalledEngineCleanupError("cleanup owner manifest is invalid")
    return resource_set_ref(manifest)


def validate_cleanup_receipt(
    receipt: InstalledEngineBundleCleanupReceipt,
    *,
    cleanup_ref: str,
    attempt_ref: str,
    activation_ref: str,
    owner_ref: str,
    runtime_resolution_ref: str,
    resource_set_ref: str,
    resource_manifest: tuple[InstalledEngineCleanupResourceBinding, ...],
    predecessor: InstalledEngineBundleCleanupReceipt | None,
) -> InstalledEngineBundleCleanupReceipt:
    """Require the exact request and bundle binding after a protected call."""

    if not isinstance(receipt, InstalledEngineBundleCleanupReceipt):
        raise InstalledEngineCleanupError("cleanup owner returned an invalid receipt")
    if (
        receipt.cleanup_ref != cleanup_ref
        or receipt.attempt_ref != attempt_ref
        or receipt.activation_ref != activation_ref
        or receipt.owner_ref != owner_ref
        or receipt.runtime_resolution_ref != runtime_resolution_ref
        or receipt.resource_set_ref != resource_set_ref
    ):
        raise InstalledEngineCleanupError("cleanup receipt binding changed")
    expected = tuple(reversed(resource_manifest))
    observed = tuple((outcome.role, outcome.resource_ref) for outcome in receipt.outcomes)
    if observed != tuple((row.role, row.resource_ref) for row in expected):
        raise InstalledEngineCleanupError("cleanup receipt resource coverage changed")
    if predecessor is None:
        if receipt.generation != 1 or receipt.predecessor_receipt_ref is not None:
            raise InstalledEngineCleanupError("initial cleanup receipt generation changed")
    elif receipt != predecessor:
        if (
            receipt.generation != predecessor.generation + 1
            or receipt.predecessor_receipt_ref != predecessor.receipt_ref
            or _timestamp(receipt.settled_at, "cleanup settlement time")
            < _timestamp(predecessor.settled_at, "cleanup predecessor time")
        ):
            raise InstalledEngineCleanupError("cleanup receipt successor changed")
    # Re-check the canonical digest after crossing the protected boundary.
    if receipt.receipt_ref != content_hash(receipt.unsigned_document()):
        raise InstalledEngineCleanupError("cleanup receipt digest changed")
    return receipt


def cleanup_request_ref(
    attempt_ref: str,
    activation_ref: str,
    owner_ref: str,
    runtime_resolution_ref: str,
    resource_set_ref: str,
) -> str:
    """Derive the stable idempotency identity for this exact bundle."""

    return content_hash(
        {
            "schema_version": "bluefire.installed-engine-bundle-cleanup-request.v1",
            "attempt_ref": _digest(attempt_ref, "cleanup attempt reference"),
            "activation_ref": _digest(activation_ref, "cleanup activation reference"),
            "owner_ref": _digest(owner_ref, "cleanup owner reference"),
            "runtime_resolution_ref": _digest(
                runtime_resolution_ref, "cleanup runtime resolution reference"
            ),
            "resource_set_ref": _digest(resource_set_ref, "cleanup resource-set reference"),
        }
    )


def cleanup_status_document(
    receipts: Mapping[str, InstalledEngineBundleCleanupReceipt],
    *,
    pending_bundle_count: int,
    legacy_unknown_count: int,
    collision_count: int,
    closed: bool,
    stopping: bool,
) -> dict[str, object]:
    """Return a secret-free status projection for service diagnostics."""

    if (
        not isinstance(pending_bundle_count, int)
        or pending_bundle_count < 0
        or not isinstance(legacy_unknown_count, int)
        or legacy_unknown_count < 0
        or not isinstance(collision_count, int)
        or collision_count < 0
    ):
        raise InstalledEngineCleanupError("legacy cleanup count is invalid")
    values = tuple(receipts.values())
    unresolved = pending_bundle_count + legacy_unknown_count + collision_count
    state = (
        "verified_absent"
        if closed and unresolved == 0
        else "unknown"
        if unresolved
        else "stopping"
        if stopping
        else "open"
    )
    return {
        "schema_version": "bluefire.installed-engine-cleanup-status.v1",
        "state": state,
        "pending_bundle_count": pending_bundle_count,
        "legacy_unknown_count": legacy_unknown_count,
        "collision_count": collision_count,
        "receipt_refs": sorted(receipt.receipt_ref for receipt in values),
    }
