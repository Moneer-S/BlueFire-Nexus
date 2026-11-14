"""Sealed controller/helper contract for one Linux engine boundary.

This module performs no operating-system work.  It gives a future fixed
privileged helper a closed request and receipt grammar, and gives the trusted
controller deterministic validation before those receipts can enter a runtime
admission.  Paths, commands, arguments, environment variables, credentials,
and open-ended helper operations are intentionally absent from the contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Any, Mapping, Protocol

from .util import content_hash, parse_iso8601_datetime


class LinuxEngineBoundaryError(ValueError):
    """A Linux boundary plan, request, or receipt is not exact and safe."""


_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCHEMA_PLAN = "bluefire.linux-engine-boundary-plan.v1"
_SCHEMA_PREPARE = "bluefire.linux-engine-boundary-prepare.v1"
_SCHEMA_ACTIVATION = "bluefire.linux-engine-boundary-activation.v1"
_SCHEMA_CLEANUP = "bluefire.linux-engine-boundary-cleanup.v1"
_SCHEMA_CLEANUP_RECEIPT = "bluefire.linux-engine-boundary-cleanup-receipt.v1"
_SCHEMA_REPLAY_STATE = "bluefire.linux-engine-boundary-replay-state.v1"
_MAX_PLAN_LIFETIME = timedelta(minutes=30)
_MAX_PREPARE_DELAY = timedelta(minutes=5)
_MAX_ACTIVATION_DELAY = timedelta(minutes=10)
_MAX_CLEANUP_OBSERVATION_DELAY = timedelta(minutes=10)
_CONTROLLERS = ("cpu", "io", "memory", "pids")


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LinuxEngineBoundaryError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LinuxEngineBoundaryError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    text = _text(value, label, maximum=71)
    if _DIGEST.fullmatch(text) is None:
        raise LinuxEngineBoundaryError(f"{label} must be a sha256 digest")
    return text


def _attempt(value: Any) -> str:
    text = _text(value, "attempt ID", maximum=47)
    if _ATTEMPT_ID.fullmatch(text) is None:
        raise LinuxEngineBoundaryError("attempt ID is invalid")
    return text


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise LinuxEngineBoundaryError(f"{label} is outside its bound")
    return int(value)


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise LinuxEngineBoundaryError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=40)
    try:
        parse_iso8601_datetime(text)
    except ValueError as exc:
        raise LinuxEngineBoundaryError(f"{label} is not bounded RFC 3339") from exc
    return text


def _ordered_unique_digests(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 32
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise LinuxEngineBoundaryError(f"{label} is invalid")
    rows = tuple(_digest(item, label) for item in value)
    if rows != tuple(sorted(set(rows))):
        raise LinuxEngineBoundaryError(f"{label} must be unique and sorted")
    return rows


def _ordered_unique_text(value: Any, label: str, *, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LinuxEngineBoundaryError(f"{label} is invalid")
    rows = tuple(_text(item, label, maximum=32) for item in value)
    if rows != tuple(sorted(set(rows))) or any(item not in allowed for item in rows):
        raise LinuxEngineBoundaryError(f"{label} is invalid")
    return rows


def _after(
    later: str,
    earlier: str,
    label: str,
    *,
    maximum_delay: timedelta | None = None,
    strict: bool = False,
) -> None:
    later_time = parse_iso8601_datetime(later)
    earlier_time = parse_iso8601_datetime(earlier)
    if later_time < earlier_time or (strict and later_time == earlier_time):
        raise LinuxEngineBoundaryError(f"{label} chronology is invalid")
    if maximum_delay is not None and later_time - earlier_time > maximum_delay:
        raise LinuxEngineBoundaryError(f"{label} is stale")


class RootPurpose(str, Enum):
    WORKER_WORKSPACE = "worker_workspace"
    CONTROLLER_CONTROL = "controller_control"
    CONTROLLER_ARTIFACT = "controller_artifact"


class NamespaceKind(str, Enum):
    MOUNT = "mount"
    PID = "pid"
    NETWORK = "network"
    IPC = "ipc"
    UTS = "uts"


@dataclass(frozen=True, slots=True)
class LinuxBoundaryReplayState:
    """Controller-owned durable replay head supplied to pure validators."""

    schema_version: str
    ledger_ref: str
    head_digest: str
    ancestor_head_digests: tuple[str, ...]
    consumed_prepare_request_refs: tuple[str, ...]
    consumed_cleanup_request_refs: tuple[str, ...]
    consumed_uid_lease_refs: tuple[str, ...]
    consumed_uid_generation_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxBoundaryReplayState":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "boundary replay state")
        result = cls(
            schema_version=_text(row["schema_version"], "boundary replay state version"),
            ledger_ref=_digest(row["ledger_ref"], "boundary replay ledger"),
            head_digest=_digest(row["head_digest"], "boundary replay head"),
            ancestor_head_digests=_ordered_unique_digests(
                row["ancestor_head_digests"], "boundary replay ancestor heads"
            ),
            consumed_prepare_request_refs=_ordered_unique_digests(
                row["consumed_prepare_request_refs"], "consumed boundary prepare requests"
            ),
            consumed_cleanup_request_refs=_ordered_unique_digests(
                row["consumed_cleanup_request_refs"], "consumed boundary cleanup requests"
            ),
            consumed_uid_lease_refs=_ordered_unique_digests(
                row["consumed_uid_lease_refs"], "consumed disposable identity leases"
            ),
            consumed_uid_generation_refs=_ordered_unique_digests(
                row["consumed_uid_generation_refs"],
                "consumed disposable identity generations",
            ),
        )
        result.validate()
        return result

    @classmethod
    def empty(cls, *, ledger_ref: str, head_digest: str) -> "LinuxBoundaryReplayState":
        result = cls(
            schema_version=_SCHEMA_REPLAY_STATE,
            ledger_ref=_digest(ledger_ref, "boundary replay ledger"),
            head_digest=_digest(head_digest, "boundary replay head"),
            ancestor_head_digests=(),
            consumed_prepare_request_refs=(),
            consumed_cleanup_request_refs=(),
            consumed_uid_lease_refs=(),
            consumed_uid_generation_refs=(),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_REPLAY_STATE:
            raise LinuxEngineBoundaryError("boundary replay state version is unsupported")
        _digest(self.ledger_ref, "boundary replay ledger")
        _digest(self.head_digest, "boundary replay head")
        if self.head_digest in self.ancestor_head_digests:
            raise LinuxEngineBoundaryError("boundary replay head cannot be its own ancestor")
        for rows, label in (
            (self.ancestor_head_digests, "boundary replay ancestor heads"),
            (self.consumed_prepare_request_refs, "consumed boundary prepare requests"),
            (self.consumed_cleanup_request_refs, "consumed boundary cleanup requests"),
            (self.consumed_uid_lease_refs, "consumed disposable identity leases"),
            (
                self.consumed_uid_generation_refs,
                "consumed disposable identity generations",
            ),
        ):
            if rows != tuple(sorted(set(rows))):
                raise LinuxEngineBoundaryError(f"{label} must be unique and sorted")
            for item in rows:
                _digest(item, label)

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "ledger_ref": self.ledger_ref,
            "head_digest": self.head_digest,
            "ancestor_head_digests": list(self.ancestor_head_digests),
            "consumed_prepare_request_refs": list(self.consumed_prepare_request_refs),
            "consumed_cleanup_request_refs": list(self.consumed_cleanup_request_refs),
            "consumed_uid_lease_refs": list(self.consumed_uid_lease_refs),
            "consumed_uid_generation_refs": list(self.consumed_uid_generation_refs),
        }


@dataclass(frozen=True, slots=True)
class DisposableIdentityPlan:
    uid: int
    gid: int
    generation: int
    lease_ref: str
    preflight_absence_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "DisposableIdentityPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "disposable identity")
        result = cls(
            uid=_integer(row["uid"], "disposable UID", 1_000, 2_147_483_646),
            gid=_integer(row["gid"], "disposable GID", 1_000, 2_147_483_646),
            generation=_integer(row["generation"], "disposable identity generation", 1, 2**63 - 1),
            lease_ref=_digest(row["lease_ref"], "disposable identity lease"),
            preflight_absence_digest=_digest(
                row["preflight_absence_digest"], "disposable identity preflight absence"
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        _integer(self.uid, "disposable UID", 1_000, 2_147_483_646)
        _integer(self.gid, "disposable GID", 1_000, 2_147_483_646)
        _integer(self.generation, "disposable identity generation", 1, 2**63 - 1)
        _digest(self.lease_ref, "disposable identity lease")
        _digest(self.preflight_absence_digest, "disposable identity preflight absence")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "uid": self.uid,
            "gid": self.gid,
            "generation": self.generation,
            "lease_ref": self.lease_ref,
            "preflight_absence_digest": self.preflight_absence_digest,
        }


@dataclass(frozen=True, slots=True)
class NamespacePlan:
    mount_ref: str
    pid_ref: str
    network_ref: str
    ipc_ref: str
    uts_ref: str
    host_namespace_snapshot_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "NamespacePlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "namespace plan")
        result = cls(
            **{
                field: _digest(row[field], f"namespace {field}")
                for field in cls.__dataclass_fields__
            }
        )
        result.validate()
        return result

    def validate(self) -> None:
        refs = tuple(
            _digest(getattr(self, field), f"namespace {field}")
            for field in ("mount_ref", "pid_ref", "network_ref", "ipc_ref", "uts_ref")
        )
        host = _digest(self.host_namespace_snapshot_digest, "host namespace snapshot")
        if len(set(refs)) != len(refs) or host in refs:
            raise LinuxEngineBoundaryError("namespace references are not isolated")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    def ref_for(self, kind: NamespaceKind) -> str:
        return {
            NamespaceKind.MOUNT: self.mount_ref,
            NamespaceKind.PID: self.pid_ref,
            NamespaceKind.NETWORK: self.network_ref,
            NamespaceKind.IPC: self.ipc_ref,
            NamespaceKind.UTS: self.uts_ref,
        }[kind]


@dataclass(frozen=True, slots=True)
class CgroupPlan:
    cgroup_ref: str
    memory_bytes: int
    cpu_quota_micros: int
    cpu_period_micros: int
    pids_max: int
    io_policy_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "CgroupPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "cgroup plan")
        result = cls(
            cgroup_ref=_digest(row["cgroup_ref"], "cgroup reference"),
            memory_bytes=_integer(
                row["memory_bytes"], "cgroup memory bytes", 64 * 1024**2, 64 * 1024**3
            ),
            cpu_quota_micros=_integer(
                row["cpu_quota_micros"], "cgroup CPU quota", 10_000, 8_000_000
            ),
            cpu_period_micros=_integer(
                row["cpu_period_micros"], "cgroup CPU period", 10_000, 1_000_000
            ),
            pids_max=_integer(row["pids_max"], "cgroup PID limit", 16, 4_096),
            io_policy_digest=_digest(row["io_policy_digest"], "cgroup IO policy"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        _digest(self.cgroup_ref, "cgroup reference")
        _integer(self.memory_bytes, "cgroup memory bytes", 64 * 1024**2, 64 * 1024**3)
        _integer(self.cpu_quota_micros, "cgroup CPU quota", 10_000, 8_000_000)
        _integer(self.cpu_period_micros, "cgroup CPU period", 10_000, 1_000_000)
        _integer(self.pids_max, "cgroup PID limit", 16, 4_096)
        _digest(self.io_policy_digest, "cgroup IO policy")
        if self.cpu_quota_micros > self.cpu_period_micros * 8:
            raise LinuxEngineBoundaryError("cgroup CPU quota exceeds eight cores")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @property
    def limits_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProtectedRootPlan:
    purpose: RootPurpose
    root_ref: str
    parent_ref: str
    expected_owner_uid: int
    expected_mode: int
    engine_write_allowed: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "ProtectedRootPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "protected root plan")
        try:
            purpose = RootPurpose(row["purpose"])
        except (TypeError, ValueError) as exc:
            raise LinuxEngineBoundaryError("protected root purpose is invalid") from exc
        result = cls(
            purpose=purpose,
            root_ref=_digest(row["root_ref"], "protected root reference"),
            parent_ref=_digest(row["parent_ref"], "protected root parent"),
            expected_owner_uid=_integer(
                row["expected_owner_uid"], "protected root owner", 0, 2_147_483_646
            ),
            expected_mode=_integer(row["expected_mode"], "protected root mode", 0, 0o777),
            engine_write_allowed=_boolean(
                row["engine_write_allowed"], "protected root write policy"
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if not isinstance(self.purpose, RootPurpose):
            raise LinuxEngineBoundaryError("protected root purpose is invalid")
        root = _digest(self.root_ref, "protected root reference")
        parent = _digest(self.parent_ref, "protected root parent")
        if root == parent:
            raise LinuxEngineBoundaryError("protected root and parent identities are aliased")
        _integer(self.expected_owner_uid, "protected root owner", 0, 2_147_483_646)
        if self.expected_mode != 0o700:
            raise LinuxEngineBoundaryError("protected root mode must be owner private")
        if not isinstance(self.engine_write_allowed, bool):
            raise LinuxEngineBoundaryError("protected root write policy is invalid")
        expected_write = self.purpose is RootPurpose.WORKER_WORKSPACE
        if self.engine_write_allowed is not expected_write:
            raise LinuxEngineBoundaryError("protected root write policy does not match its purpose")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "purpose": self.purpose.value,
            "root_ref": self.root_ref,
            "parent_ref": self.parent_ref,
            "expected_owner_uid": self.expected_owner_uid,
            "expected_mode": self.expected_mode,
            "engine_write_allowed": self.engine_write_allowed,
        }


def _root_plans(value: Any) -> tuple[ProtectedRootPlan, ...]:
    if not isinstance(value, list) or len(value) != len(RootPurpose):
        raise LinuxEngineBoundaryError("protected root plans are incomplete")
    roots = tuple(ProtectedRootPlan.from_mapping(item) for item in value)
    purposes = tuple(root.purpose.value for root in roots)
    expected = tuple(sorted(item.value for item in RootPurpose))
    if purposes != expected:
        raise LinuxEngineBoundaryError("protected root plans must be complete, unique, and sorted")
    refs = tuple(root.root_ref for root in roots) + tuple(root.parent_ref for root in roots)
    if len(set(refs)) != len(refs):
        raise LinuxEngineBoundaryError("protected root identities overlap")
    return roots


@dataclass(frozen=True, slots=True)
class NetworkBoundaryPlan:
    network_policy_digest: str
    bridge_ref: str
    target_alias_ref: str
    model_gateway_alias_ref: str
    daemon_ref: str
    daemon_proxy_ref: str
    target_relay_ref: str
    model_relay_ref: str
    firewall_policy_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "NetworkBoundaryPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "network boundary plan")
        result = cls(
            **{
                field: _digest(row[field], f"network boundary {field}")
                for field in cls.__dataclass_fields__
            }
        )
        result.validate()
        return result

    def validate(self) -> None:
        values = tuple(
            _digest(getattr(self, field), f"network boundary {field}")
            for field in self.__dataclass_fields__
        )
        identity_values = values[1:8]
        if len(set(identity_values)) != len(identity_values):
            raise LinuxEngineBoundaryError("network boundary identities overlap")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class LinuxAttemptBoundaryPlan:
    schema_version: str
    attempt_id: str
    owner_ref: str
    binding_digest: str
    delegation_digest: str
    authority_generation: int
    authority_record_digest: str
    admission_record_ref: str
    admission_record_digest: str
    runtime_qualification_ref: str
    replay_ledger_ref: str
    controller_uid: int
    executable_digest: str
    leader_ref: str
    supervisor_ref: str
    created_at: str
    expires_at: str
    disposable_identity: DisposableIdentityPlan
    namespaces: NamespacePlan
    cgroup: CgroupPlan
    protected_roots: tuple[ProtectedRootPlan, ...]
    network: NetworkBoundaryPlan

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxAttemptBoundaryPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "Linux boundary plan")
        result = cls(
            schema_version=_text(row["schema_version"], "Linux boundary plan version"),
            attempt_id=_attempt(row["attempt_id"]),
            owner_ref=_digest(row["owner_ref"], "Linux boundary owner"),
            binding_digest=_digest(row["binding_digest"], "Linux boundary binding"),
            delegation_digest=_digest(row["delegation_digest"], "Linux boundary delegation"),
            authority_generation=_integer(
                row["authority_generation"], "runtime authority generation", 1, 2**63 - 1
            ),
            authority_record_digest=_digest(
                row["authority_record_digest"], "runtime authority record"
            ),
            admission_record_ref=_digest(row["admission_record_ref"], "runtime admission"),
            admission_record_digest=_digest(
                row["admission_record_digest"], "runtime admission record"
            ),
            runtime_qualification_ref=_digest(
                row["runtime_qualification_ref"], "runtime qualification"
            ),
            replay_ledger_ref=_digest(row["replay_ledger_ref"], "boundary replay ledger"),
            controller_uid=_integer(row["controller_uid"], "controller UID", 0, 2_147_483_646),
            executable_digest=_digest(row["executable_digest"], "worker executable"),
            leader_ref=_digest(row["leader_ref"], "worker leader"),
            supervisor_ref=_digest(row["supervisor_ref"], "worker supervisor"),
            created_at=_timestamp(row["created_at"], "boundary creation time"),
            expires_at=_timestamp(row["expires_at"], "boundary expiry time"),
            disposable_identity=DisposableIdentityPlan.from_mapping(row["disposable_identity"]),
            namespaces=NamespacePlan.from_mapping(row["namespaces"]),
            cgroup=CgroupPlan.from_mapping(row["cgroup"]),
            protected_roots=_root_plans(row["protected_roots"]),
            network=NetworkBoundaryPlan.from_mapping(row["network"]),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_PLAN:
            raise LinuxEngineBoundaryError("Linux boundary plan version is unsupported")
        _attempt(self.attempt_id)
        identity_fields = (
            self.owner_ref,
            self.binding_digest,
            self.delegation_digest,
            self.authority_record_digest,
            self.admission_record_ref,
            self.admission_record_digest,
            self.runtime_qualification_ref,
            self.replay_ledger_ref,
            self.executable_digest,
            self.leader_ref,
            self.supervisor_ref,
        )
        if any(_DIGEST.fullmatch(item) is None for item in identity_fields):
            raise LinuxEngineBoundaryError("Linux boundary identity is invalid")
        if (
            len(
                set(
                    (
                        self.owner_ref,
                        self.admission_record_ref,
                        self.leader_ref,
                        self.supervisor_ref,
                    )
                )
            )
            != 4
        ):
            raise LinuxEngineBoundaryError("Linux boundary owner identities overlap")
        _integer(self.authority_generation, "runtime authority generation", 1, 2**63 - 1)
        _integer(self.controller_uid, "controller UID", 0, 2_147_483_646)
        _timestamp(self.created_at, "boundary creation time")
        _timestamp(self.expires_at, "boundary expiry time")
        _after(
            self.expires_at,
            self.created_at,
            "boundary lifetime",
            maximum_delay=_MAX_PLAN_LIFETIME,
            strict=True,
        )
        self.disposable_identity.validate()
        if self.disposable_identity.uid == self.controller_uid:
            raise LinuxEngineBoundaryError("disposable and controller identities overlap")
        self.namespaces.validate()
        self.cgroup.validate()
        expected_owners = {
            RootPurpose.WORKER_WORKSPACE: self.disposable_identity.uid,
            RootPurpose.CONTROLLER_CONTROL: self.controller_uid,
            RootPurpose.CONTROLLER_ARTIFACT: self.controller_uid,
        }
        for root in self.protected_roots:
            root.validate()
            if root.expected_owner_uid != expected_owners[root.purpose]:
                raise LinuxEngineBoundaryError("protected root owner does not match its purpose")
        if tuple(root.purpose.value for root in self.protected_roots) != tuple(
            sorted(item.value for item in RootPurpose)
        ):
            raise LinuxEngineBoundaryError("protected root plans are not canonical")
        self.network.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "owner_ref": self.owner_ref,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "authority_generation": self.authority_generation,
            "authority_record_digest": self.authority_record_digest,
            "admission_record_ref": self.admission_record_ref,
            "admission_record_digest": self.admission_record_digest,
            "runtime_qualification_ref": self.runtime_qualification_ref,
            "replay_ledger_ref": self.replay_ledger_ref,
            "controller_uid": self.controller_uid,
            "executable_digest": self.executable_digest,
            "leader_ref": self.leader_ref,
            "supervisor_ref": self.supervisor_ref,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "disposable_identity": self.disposable_identity.to_dict(),
            "namespaces": self.namespaces.to_dict(),
            "cgroup": self.cgroup.to_dict(),
            "protected_roots": [item.to_dict() for item in self.protected_roots],
            "network": self.network.to_dict(),
        }

    @property
    def plan_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class LinuxBoundaryPrepareRequest:
    schema_version: str
    request_ref: str
    plan_digest: str
    attempt_id: str
    owner_ref: str
    authority_generation: int
    authority_record_digest: str
    admission_record_ref: str
    admission_record_digest: str
    replay_ledger_ref: str
    replay_head_digest: str
    requested_at: str

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxBoundaryPrepareRequest":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "boundary prepare request")
        result = cls(
            schema_version=_text(row["schema_version"], "boundary prepare request version"),
            request_ref=_digest(row["request_ref"], "boundary prepare request"),
            plan_digest=_digest(row["plan_digest"], "boundary plan"),
            attempt_id=_attempt(row["attempt_id"]),
            owner_ref=_digest(row["owner_ref"], "boundary owner"),
            authority_generation=_integer(
                row["authority_generation"], "runtime authority generation", 1, 2**63 - 1
            ),
            authority_record_digest=_digest(
                row["authority_record_digest"], "runtime authority record"
            ),
            admission_record_ref=_digest(row["admission_record_ref"], "runtime admission"),
            admission_record_digest=_digest(
                row["admission_record_digest"], "runtime admission record"
            ),
            replay_ledger_ref=_digest(row["replay_ledger_ref"], "boundary replay ledger"),
            replay_head_digest=_digest(row["replay_head_digest"], "boundary replay head"),
            requested_at=_timestamp(row["requested_at"], "boundary prepare request time"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_PREPARE:
            raise LinuxEngineBoundaryError("boundary prepare request version is unsupported")
        _digest(self.request_ref, "boundary prepare request")
        _digest(self.plan_digest, "boundary plan")
        _attempt(self.attempt_id)
        _digest(self.owner_ref, "boundary owner")
        _integer(self.authority_generation, "runtime authority generation", 1, 2**63 - 1)
        _digest(self.authority_record_digest, "runtime authority record")
        _digest(self.admission_record_ref, "runtime admission")
        _digest(self.admission_record_digest, "runtime admission record")
        _digest(self.replay_ledger_ref, "boundary replay ledger")
        _digest(self.replay_head_digest, "boundary replay head")
        _timestamp(self.requested_at, "boundary prepare request time")
        if self.request_ref != self.expected_request_ref:
            raise LinuxEngineBoundaryError("boundary prepare request identity is invalid")

    @property
    def expected_request_ref(self) -> str:
        return content_hash(
            {
                "schema_version": self.schema_version,
                "plan_digest": self.plan_digest,
                "attempt_id": self.attempt_id,
                "owner_ref": self.owner_ref,
                "authority_generation": self.authority_generation,
                "authority_record_digest": self.authority_record_digest,
                "admission_record_ref": self.admission_record_ref,
                "admission_record_digest": self.admission_record_digest,
                "replay_ledger_ref": self.replay_ledger_ref,
                "replay_head_digest": self.replay_head_digest,
                "requested_at": self.requested_at,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @classmethod
    def create(
        cls,
        plan: LinuxAttemptBoundaryPlan,
        replay_state: LinuxBoundaryReplayState,
        *,
        requested_at: str,
    ) -> "LinuxBoundaryPrepareRequest":
        plan.validate()
        body = {
            "schema_version": _SCHEMA_PREPARE,
            "plan_digest": plan.plan_digest,
            "attempt_id": plan.attempt_id,
            "owner_ref": plan.owner_ref,
            "authority_generation": plan.authority_generation,
            "authority_record_digest": plan.authority_record_digest,
            "admission_record_ref": plan.admission_record_ref,
            "admission_record_digest": plan.admission_record_digest,
            "replay_ledger_ref": replay_state.ledger_ref,
            "replay_head_digest": replay_state.head_digest,
            "requested_at": _timestamp(requested_at, "boundary prepare request time"),
        }
        result = cls(
            schema_version=_SCHEMA_PREPARE,
            request_ref=content_hash(body),
            plan_digest=plan.plan_digest,
            attempt_id=plan.attempt_id,
            owner_ref=plan.owner_ref,
            authority_generation=plan.authority_generation,
            authority_record_digest=plan.authority_record_digest,
            admission_record_ref=plan.admission_record_ref,
            admission_record_digest=plan.admission_record_digest,
            replay_ledger_ref=replay_state.ledger_ref,
            replay_head_digest=replay_state.head_digest,
            requested_at=str(body["requested_at"]),
        )
        validate_prepare_request(plan, result, replay_state)
        return result


@dataclass(frozen=True, slots=True)
class NamespaceIdentity:
    kind: NamespaceKind
    namespace_ref: str
    kernel_identity_digest: str
    host_kernel_identity_digest: str
    owner_uid: int

    @classmethod
    def from_mapping(cls, value: Any) -> "NamespaceIdentity":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "namespace identity")
        try:
            kind = NamespaceKind(row["kind"])
        except (TypeError, ValueError) as exc:
            raise LinuxEngineBoundaryError("namespace identity kind is invalid") from exc
        result = cls(
            kind=kind,
            namespace_ref=_digest(row["namespace_ref"], "namespace reference"),
            kernel_identity_digest=_digest(
                row["kernel_identity_digest"], "kernel namespace identity"
            ),
            host_kernel_identity_digest=_digest(
                row["host_kernel_identity_digest"], "host kernel namespace identity"
            ),
            owner_uid=_integer(row["owner_uid"], "namespace owner UID", 0, 2_147_483_646),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if not isinstance(self.kind, NamespaceKind):
            raise LinuxEngineBoundaryError("namespace identity kind is invalid")
        _digest(self.namespace_ref, "namespace reference")
        kernel = _digest(self.kernel_identity_digest, "kernel namespace identity")
        host = _digest(self.host_kernel_identity_digest, "host kernel namespace identity")
        _integer(self.owner_uid, "namespace owner UID", 0, 2_147_483_646)
        if kernel == host:
            raise LinuxEngineBoundaryError("namespace is not distinct from the host")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": self.kind.value,
            "namespace_ref": self.namespace_ref,
            "kernel_identity_digest": self.kernel_identity_digest,
            "host_kernel_identity_digest": self.host_kernel_identity_digest,
            "owner_uid": self.owner_uid,
        }


def _namespace_identities(value: Any) -> tuple[NamespaceIdentity, ...]:
    if not isinstance(value, list) or len(value) != len(NamespaceKind):
        raise LinuxEngineBoundaryError("namespace identity set is incomplete")
    identities = tuple(NamespaceIdentity.from_mapping(item) for item in value)
    if tuple(item.kind.value for item in identities) != tuple(
        sorted(item.value for item in NamespaceKind)
    ):
        raise LinuxEngineBoundaryError("namespace identities must be complete, unique, and sorted")
    digests = tuple(item.kernel_identity_digest for item in identities)
    if len(set(digests)) != len(digests):
        raise LinuxEngineBoundaryError("kernel namespace identities overlap")
    return identities


@dataclass(frozen=True, slots=True)
class CgroupIdentity:
    cgroup_ref: str
    kernel_identity_digest: str
    limits_digest: str
    controllers: tuple[str, ...]
    delegated: bool
    empty_before_start: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "CgroupIdentity":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "cgroup identity")
        result = cls(
            cgroup_ref=_digest(row["cgroup_ref"], "cgroup reference"),
            kernel_identity_digest=_digest(row["kernel_identity_digest"], "kernel cgroup identity"),
            limits_digest=_digest(row["limits_digest"], "cgroup limits"),
            controllers=_ordered_unique_text(
                row["controllers"], "cgroup controllers", allowed=_CONTROLLERS
            ),
            delegated=_boolean(row["delegated"], "cgroup delegation"),
            empty_before_start=_boolean(row["empty_before_start"], "cgroup initial state"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        _digest(self.cgroup_ref, "cgroup reference")
        _digest(self.kernel_identity_digest, "kernel cgroup identity")
        _digest(self.limits_digest, "cgroup limits")
        if self.controllers != tuple(sorted(_CONTROLLERS)):
            raise LinuxEngineBoundaryError("cgroup controllers are incomplete")
        if self.delegated is not True or self.empty_before_start is not True:
            raise LinuxEngineBoundaryError("cgroup custody was not established")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "cgroup_ref": self.cgroup_ref,
            "kernel_identity_digest": self.kernel_identity_digest,
            "limits_digest": self.limits_digest,
            "controllers": list(self.controllers),
            "delegated": self.delegated,
            "empty_before_start": self.empty_before_start,
        }


@dataclass(frozen=True, slots=True)
class ProtectedRootIdentity:
    purpose: RootPurpose
    root_ref: str
    parent_ref: str
    object_identity_digest: str
    parent_identity_digest: str
    mount_identity_digest: str
    owner_uid: int
    mode: int
    object_type: str
    symlink: bool
    reparse: bool
    hardlink: bool
    engine_write_allowed: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "ProtectedRootIdentity":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "protected root identity")
        try:
            purpose = RootPurpose(row["purpose"])
        except (TypeError, ValueError) as exc:
            raise LinuxEngineBoundaryError("protected root identity purpose is invalid") from exc
        result = cls(
            purpose=purpose,
            root_ref=_digest(row["root_ref"], "protected root reference"),
            parent_ref=_digest(row["parent_ref"], "protected root parent"),
            object_identity_digest=_digest(
                row["object_identity_digest"], "protected root object identity"
            ),
            parent_identity_digest=_digest(
                row["parent_identity_digest"], "protected root parent identity"
            ),
            mount_identity_digest=_digest(
                row["mount_identity_digest"], "protected root mount identity"
            ),
            owner_uid=_integer(row["owner_uid"], "protected root owner", 0, 2_147_483_646),
            mode=_integer(row["mode"], "protected root mode", 0, 0o777),
            object_type=_text(row["object_type"], "protected root object type", maximum=16),
            symlink=_boolean(row["symlink"], "protected root symlink state"),
            reparse=_boolean(row["reparse"], "protected root reparse state"),
            hardlink=_boolean(row["hardlink"], "protected root hardlink state"),
            engine_write_allowed=_boolean(
                row["engine_write_allowed"], "protected root write policy"
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if not isinstance(self.purpose, RootPurpose):
            raise LinuxEngineBoundaryError("protected root identity purpose is invalid")
        _digest(self.root_ref, "protected root reference")
        _digest(self.parent_ref, "protected root parent")
        identities = (
            _digest(self.object_identity_digest, "protected root object identity"),
            _digest(self.parent_identity_digest, "protected root parent identity"),
            _digest(self.mount_identity_digest, "protected root mount identity"),
        )
        if len(set(identities)) != 3:
            raise LinuxEngineBoundaryError("protected root identities overlap")
        _integer(self.owner_uid, "protected root owner", 0, 2_147_483_646)
        if self.mode != 0o700 or self.object_type != "directory":
            raise LinuxEngineBoundaryError("protected root is not an owner-private directory")
        if self.symlink or self.reparse or self.hardlink:
            raise LinuxEngineBoundaryError("protected root is link-backed or replaceable")
        expected_write = self.purpose is RootPurpose.WORKER_WORKSPACE
        if self.engine_write_allowed is not expected_write:
            raise LinuxEngineBoundaryError("protected root write policy does not match its purpose")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "purpose": self.purpose.value,
            "root_ref": self.root_ref,
            "parent_ref": self.parent_ref,
            "object_identity_digest": self.object_identity_digest,
            "parent_identity_digest": self.parent_identity_digest,
            "mount_identity_digest": self.mount_identity_digest,
            "owner_uid": self.owner_uid,
            "mode": self.mode,
            "object_type": self.object_type,
            "symlink": self.symlink,
            "reparse": self.reparse,
            "hardlink": self.hardlink,
            "engine_write_allowed": self.engine_write_allowed,
        }


def _root_identities(value: Any) -> tuple[ProtectedRootIdentity, ...]:
    if not isinstance(value, list) or len(value) != len(RootPurpose):
        raise LinuxEngineBoundaryError("protected root identities are incomplete")
    roots = tuple(ProtectedRootIdentity.from_mapping(item) for item in value)
    if tuple(root.purpose.value for root in roots) != tuple(
        sorted(item.value for item in RootPurpose)
    ):
        raise LinuxEngineBoundaryError("protected root identities must be complete and sorted")
    object_ids = tuple(root.object_identity_digest for root in roots)
    if len(set(object_ids)) != len(object_ids):
        raise LinuxEngineBoundaryError("protected root object identities overlap")
    return roots


@dataclass(frozen=True, slots=True)
class NetworkBoundaryIdentity:
    network_policy_digest: str
    bridge_ref: str
    bridge_identity_digest: str
    target_alias_ref: str
    target_alias_identity_digest: str
    model_gateway_alias_ref: str
    model_gateway_alias_identity_digest: str
    daemon_ref: str
    daemon_identity_digest: str
    daemon_proxy_ref: str
    daemon_proxy_identity_digest: str
    target_relay_ref: str
    target_relay_identity_digest: str
    model_relay_ref: str
    model_relay_identity_digest: str
    firewall_policy_digest: str
    firewall_observation_digest: str
    default_egress_denied: bool
    host_gateway_absent: bool
    metadata_blocked: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "NetworkBoundaryIdentity":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "network boundary identity")
        result = cls(
            network_policy_digest=_digest(
                row["network_policy_digest"], "network boundary network_policy_digest"
            ),
            bridge_ref=_digest(row["bridge_ref"], "network boundary bridge_ref"),
            bridge_identity_digest=_digest(
                row["bridge_identity_digest"], "network boundary bridge_identity_digest"
            ),
            target_alias_ref=_digest(row["target_alias_ref"], "network boundary target_alias_ref"),
            target_alias_identity_digest=_digest(
                row["target_alias_identity_digest"],
                "network boundary target_alias_identity_digest",
            ),
            model_gateway_alias_ref=_digest(
                row["model_gateway_alias_ref"], "network boundary model_gateway_alias_ref"
            ),
            model_gateway_alias_identity_digest=_digest(
                row["model_gateway_alias_identity_digest"],
                "network boundary model_gateway_alias_identity_digest",
            ),
            daemon_ref=_digest(row["daemon_ref"], "network boundary daemon_ref"),
            daemon_identity_digest=_digest(
                row["daemon_identity_digest"], "network boundary daemon_identity_digest"
            ),
            daemon_proxy_ref=_digest(row["daemon_proxy_ref"], "network boundary daemon_proxy_ref"),
            daemon_proxy_identity_digest=_digest(
                row["daemon_proxy_identity_digest"],
                "network boundary daemon_proxy_identity_digest",
            ),
            target_relay_ref=_digest(row["target_relay_ref"], "network boundary target_relay_ref"),
            target_relay_identity_digest=_digest(
                row["target_relay_identity_digest"],
                "network boundary target_relay_identity_digest",
            ),
            model_relay_ref=_digest(row["model_relay_ref"], "network boundary model_relay_ref"),
            model_relay_identity_digest=_digest(
                row["model_relay_identity_digest"],
                "network boundary model_relay_identity_digest",
            ),
            firewall_policy_digest=_digest(
                row["firewall_policy_digest"], "network boundary firewall_policy_digest"
            ),
            firewall_observation_digest=_digest(
                row["firewall_observation_digest"],
                "network boundary firewall_observation_digest",
            ),
            default_egress_denied=_boolean(
                row["default_egress_denied"], "network boundary default_egress_denied"
            ),
            host_gateway_absent=_boolean(
                row["host_gateway_absent"], "network boundary host_gateway_absent"
            ),
            metadata_blocked=_boolean(row["metadata_blocked"], "network boundary metadata_blocked"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        refs = (
            self.bridge_ref,
            self.target_alias_ref,
            self.model_gateway_alias_ref,
            self.daemon_ref,
            self.daemon_proxy_ref,
            self.target_relay_ref,
            self.model_relay_ref,
        )
        identities = (
            self.bridge_identity_digest,
            self.target_alias_identity_digest,
            self.model_gateway_alias_identity_digest,
            self.daemon_identity_digest,
            self.daemon_proxy_identity_digest,
            self.target_relay_identity_digest,
            self.model_relay_identity_digest,
        )
        for field in self.__dataclass_fields__:
            if field not in {"default_egress_denied", "host_gateway_absent", "metadata_blocked"}:
                _digest(getattr(self, field), f"network boundary {field}")
        if len(set(refs)) != len(refs) or len(set(identities)) != len(identities):
            raise LinuxEngineBoundaryError("network boundary identities overlap")
        if (
            not self.default_egress_denied
            or not self.host_gateway_absent
            or not self.metadata_blocked
        ):
            raise LinuxEngineBoundaryError("network boundary is not fail-closed")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ProcessLeaderIdentity:
    leader_ref: str
    supervisor_ref: str
    pid: int
    start_ticks: int
    boot_id_digest: str
    pidfd_ref: str
    pid_namespace_ref: str
    session_id: int
    process_group_id: int
    executable_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "ProcessLeaderIdentity":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "process leader identity")
        result = cls(
            leader_ref=_digest(row["leader_ref"], "process leader"),
            supervisor_ref=_digest(row["supervisor_ref"], "process supervisor"),
            pid=_integer(row["pid"], "process leader PID", 2, 2**31 - 1),
            start_ticks=_integer(row["start_ticks"], "process leader start time", 1, 2**63 - 1),
            boot_id_digest=_digest(row["boot_id_digest"], "kernel boot identity"),
            pidfd_ref=_digest(row["pidfd_ref"], "process pidfd"),
            pid_namespace_ref=_digest(row["pid_namespace_ref"], "process PID namespace"),
            session_id=_integer(row["session_id"], "process session ID", 2, 2**31 - 1),
            process_group_id=_integer(row["process_group_id"], "process group ID", 2, 2**31 - 1),
            executable_digest=_digest(row["executable_digest"], "process executable"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        refs = (
            _digest(self.leader_ref, "process leader"),
            _digest(self.supervisor_ref, "process supervisor"),
            _digest(self.pidfd_ref, "process pidfd"),
            _digest(self.pid_namespace_ref, "process PID namespace"),
        )
        if len(set(refs)) != len(refs):
            raise LinuxEngineBoundaryError("process custody references overlap")
        _integer(self.pid, "process leader PID", 2, 2**31 - 1)
        _integer(self.start_ticks, "process leader start time", 1, 2**63 - 1)
        _digest(self.boot_id_digest, "kernel boot identity")
        _integer(self.session_id, "process session ID", 2, 2**31 - 1)
        _integer(self.process_group_id, "process group ID", 2, 2**31 - 1)
        _digest(self.executable_digest, "process executable")
        if self.session_id != self.pid or self.process_group_id != self.pid:
            raise LinuxEngineBoundaryError(
                "process leader does not own a private session and group"
            )

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class LinuxBoundaryActivationReceipt:
    schema_version: str
    request_ref: str
    plan_digest: str
    attempt_id: str
    owner_ref: str
    binding_digest: str
    delegation_digest: str
    authority_generation: int
    authority_record_digest: str
    admission_record_ref: str
    admission_record_digest: str
    uid: int
    uid_generation: int
    uid_lease_ref: str
    observed_at: str
    host_namespace_snapshot_digest: str
    namespaces: tuple[NamespaceIdentity, ...]
    cgroup: CgroupIdentity
    protected_roots: tuple[ProtectedRootIdentity, ...]
    network: NetworkBoundaryIdentity
    leader: ProcessLeaderIdentity
    effective: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxBoundaryActivationReceipt":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "boundary activation receipt")
        result = cls(
            schema_version=_text(row["schema_version"], "boundary activation version"),
            request_ref=_digest(row["request_ref"], "boundary prepare request"),
            plan_digest=_digest(row["plan_digest"], "boundary plan"),
            attempt_id=_attempt(row["attempt_id"]),
            owner_ref=_digest(row["owner_ref"], "boundary owner"),
            binding_digest=_digest(row["binding_digest"], "boundary binding"),
            delegation_digest=_digest(row["delegation_digest"], "boundary delegation"),
            authority_generation=_integer(
                row["authority_generation"], "runtime authority generation", 1, 2**63 - 1
            ),
            authority_record_digest=_digest(
                row["authority_record_digest"], "runtime authority record"
            ),
            admission_record_ref=_digest(row["admission_record_ref"], "runtime admission"),
            admission_record_digest=_digest(
                row["admission_record_digest"], "runtime admission record"
            ),
            uid=_integer(row["uid"], "disposable UID", 1_000, 2_147_483_646),
            uid_generation=_integer(
                row["uid_generation"], "disposable identity generation", 1, 2**63 - 1
            ),
            uid_lease_ref=_digest(row["uid_lease_ref"], "disposable identity lease"),
            observed_at=_timestamp(row["observed_at"], "boundary activation time"),
            host_namespace_snapshot_digest=_digest(
                row["host_namespace_snapshot_digest"], "host namespace snapshot"
            ),
            namespaces=_namespace_identities(row["namespaces"]),
            cgroup=CgroupIdentity.from_mapping(row["cgroup"]),
            protected_roots=_root_identities(row["protected_roots"]),
            network=NetworkBoundaryIdentity.from_mapping(row["network"]),
            leader=ProcessLeaderIdentity.from_mapping(row["leader"]),
            effective=_boolean(row["effective"], "boundary activation state"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_ACTIVATION:
            raise LinuxEngineBoundaryError("boundary activation version is unsupported")
        for value, label in (
            (self.request_ref, "boundary prepare request"),
            (self.plan_digest, "boundary plan"),
            (self.owner_ref, "boundary owner"),
            (self.binding_digest, "boundary binding"),
            (self.delegation_digest, "boundary delegation"),
            (self.authority_record_digest, "runtime authority record"),
            (self.admission_record_ref, "runtime admission"),
            (self.admission_record_digest, "runtime admission record"),
            (self.uid_lease_ref, "disposable identity lease"),
            (self.host_namespace_snapshot_digest, "host namespace snapshot"),
        ):
            _digest(value, label)
        _attempt(self.attempt_id)
        _integer(self.authority_generation, "runtime authority generation", 1, 2**63 - 1)
        _integer(self.uid, "disposable UID", 1_000, 2_147_483_646)
        _integer(self.uid_generation, "disposable identity generation", 1, 2**63 - 1)
        _timestamp(self.observed_at, "boundary activation time")
        _namespace_identities([item.to_dict() for item in self.namespaces])
        self.cgroup.validate()
        _root_identities([item.to_dict() for item in self.protected_roots])
        self.network.validate()
        self.leader.validate()
        if self.effective is not True:
            raise LinuxEngineBoundaryError("Linux attempt boundary is not effective")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "request_ref": self.request_ref,
            "plan_digest": self.plan_digest,
            "attempt_id": self.attempt_id,
            "owner_ref": self.owner_ref,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "authority_generation": self.authority_generation,
            "authority_record_digest": self.authority_record_digest,
            "admission_record_ref": self.admission_record_ref,
            "admission_record_digest": self.admission_record_digest,
            "uid": self.uid,
            "uid_generation": self.uid_generation,
            "uid_lease_ref": self.uid_lease_ref,
            "observed_at": self.observed_at,
            "host_namespace_snapshot_digest": self.host_namespace_snapshot_digest,
            "namespaces": [item.to_dict() for item in self.namespaces],
            "cgroup": self.cgroup.to_dict(),
            "protected_roots": [item.to_dict() for item in self.protected_roots],
            "network": self.network.to_dict(),
            "leader": self.leader.to_dict(),
            "effective": self.effective,
        }

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class LinuxBoundaryCleanupRequest:
    schema_version: str
    request_ref: str
    plan_digest: str
    activation_receipt_digest: str
    attempt_id: str
    owner_ref: str
    admission_record_ref: str
    replay_ledger_ref: str
    replay_head_digest: str
    requested_at: str

    @classmethod
    def create(
        cls,
        plan: LinuxAttemptBoundaryPlan,
        prepare_request: LinuxBoundaryPrepareRequest,
        activation: LinuxBoundaryActivationReceipt,
        replay_state: LinuxBoundaryReplayState,
        *,
        requested_at: str,
    ) -> "LinuxBoundaryCleanupRequest":
        _validate_activation_binding(plan, prepare_request, activation)
        body = {
            "schema_version": _SCHEMA_CLEANUP,
            "plan_digest": plan.plan_digest,
            "activation_receipt_digest": activation.receipt_digest,
            "attempt_id": plan.attempt_id,
            "owner_ref": plan.owner_ref,
            "admission_record_ref": plan.admission_record_ref,
            "replay_ledger_ref": replay_state.ledger_ref,
            "replay_head_digest": replay_state.head_digest,
            "requested_at": _timestamp(requested_at, "boundary cleanup request time"),
        }
        result = cls(
            schema_version=_SCHEMA_CLEANUP,
            request_ref=content_hash(body),
            plan_digest=plan.plan_digest,
            activation_receipt_digest=activation.receipt_digest,
            attempt_id=plan.attempt_id,
            owner_ref=plan.owner_ref,
            admission_record_ref=plan.admission_record_ref,
            replay_ledger_ref=replay_state.ledger_ref,
            replay_head_digest=replay_state.head_digest,
            requested_at=str(body["requested_at"]),
        )
        validate_cleanup_request(plan, prepare_request, activation, result, replay_state)
        return result

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxBoundaryCleanupRequest":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "boundary cleanup request")
        result = cls(
            schema_version=_text(row["schema_version"], "boundary cleanup request version"),
            request_ref=_digest(row["request_ref"], "boundary cleanup request"),
            plan_digest=_digest(row["plan_digest"], "boundary plan"),
            activation_receipt_digest=_digest(
                row["activation_receipt_digest"], "boundary activation receipt"
            ),
            attempt_id=_attempt(row["attempt_id"]),
            owner_ref=_digest(row["owner_ref"], "boundary owner"),
            admission_record_ref=_digest(row["admission_record_ref"], "runtime admission"),
            replay_ledger_ref=_digest(row["replay_ledger_ref"], "boundary replay ledger"),
            replay_head_digest=_digest(row["replay_head_digest"], "boundary replay head"),
            requested_at=_timestamp(row["requested_at"], "boundary cleanup request time"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_CLEANUP:
            raise LinuxEngineBoundaryError("boundary cleanup request version is unsupported")
        for value, label in (
            (self.request_ref, "boundary cleanup request"),
            (self.plan_digest, "boundary plan"),
            (self.activation_receipt_digest, "boundary activation receipt"),
            (self.owner_ref, "boundary owner"),
            (self.admission_record_ref, "runtime admission"),
            (self.replay_ledger_ref, "boundary replay ledger"),
            (self.replay_head_digest, "boundary replay head"),
        ):
            _digest(value, label)
        _attempt(self.attempt_id)
        _timestamp(self.requested_at, "boundary cleanup request time")
        if self.request_ref != self.expected_request_ref:
            raise LinuxEngineBoundaryError("boundary cleanup request identity is invalid")

    @property
    def expected_request_ref(self) -> str:
        return content_hash(
            {
                "schema_version": self.schema_version,
                "plan_digest": self.plan_digest,
                "activation_receipt_digest": self.activation_receipt_digest,
                "attempt_id": self.attempt_id,
                "owner_ref": self.owner_ref,
                "admission_record_ref": self.admission_record_ref,
                "replay_ledger_ref": self.replay_ledger_ref,
                "replay_head_digest": self.replay_head_digest,
                "requested_at": self.requested_at,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class LinuxBoundaryCleanupReceipt:
    schema_version: str
    request_ref: str
    plan_digest: str
    activation_receipt_digest: str
    attempt_id: str
    owner_ref: str
    admission_record_ref: str
    observed_at: str
    boot_id_digest: str
    daemon_identity_digest: str
    settlement: str
    leader_absent: bool
    descendants_absent: bool
    cgroup_empty: bool
    cgroup_removed: bool
    namespaces_absent: bool
    bridge_removed: bool
    target_alias_absent: bool
    model_gateway_alias_absent: bool
    firewall_removed: bool
    daemon_proxy_absent: bool
    supervisor_absent: bool
    target_relay_absent: bool
    model_relay_absent: bool
    protected_roots_absent: bool
    uid_released: bool
    residue_refs: tuple[str, ...]
    unverified_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "LinuxBoundaryCleanupReceipt":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "boundary cleanup receipt")
        bool_fields = (
            "leader_absent",
            "descendants_absent",
            "cgroup_empty",
            "cgroup_removed",
            "namespaces_absent",
            "bridge_removed",
            "target_alias_absent",
            "model_gateway_alias_absent",
            "firewall_removed",
            "daemon_proxy_absent",
            "supervisor_absent",
            "target_relay_absent",
            "model_relay_absent",
            "protected_roots_absent",
            "uid_released",
        )
        result = cls(
            schema_version=_text(row["schema_version"], "boundary cleanup receipt version"),
            request_ref=_digest(row["request_ref"], "boundary cleanup request"),
            plan_digest=_digest(row["plan_digest"], "boundary plan"),
            activation_receipt_digest=_digest(
                row["activation_receipt_digest"], "boundary activation receipt"
            ),
            attempt_id=_attempt(row["attempt_id"]),
            owner_ref=_digest(row["owner_ref"], "boundary owner"),
            admission_record_ref=_digest(row["admission_record_ref"], "runtime admission"),
            observed_at=_timestamp(row["observed_at"], "boundary cleanup observation time"),
            boot_id_digest=_digest(row["boot_id_digest"], "cleanup kernel boot identity"),
            daemon_identity_digest=_digest(
                row["daemon_identity_digest"], "cleanup daemon identity"
            ),
            settlement=_text(row["settlement"], "boundary cleanup settlement", maximum=32),
            **{field: _boolean(row[field], f"boundary cleanup {field}") for field in bool_fields},
            residue_refs=_ordered_unique_digests(row["residue_refs"], "boundary residue refs"),
            unverified_refs=_ordered_unique_digests(
                row["unverified_refs"], "boundary unverified refs"
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.schema_version != _SCHEMA_CLEANUP_RECEIPT:
            raise LinuxEngineBoundaryError("boundary cleanup receipt version is unsupported")
        for value, label in (
            (self.request_ref, "boundary cleanup request"),
            (self.plan_digest, "boundary plan"),
            (self.activation_receipt_digest, "boundary activation receipt"),
            (self.owner_ref, "boundary owner"),
            (self.admission_record_ref, "runtime admission"),
            (self.boot_id_digest, "cleanup kernel boot identity"),
            (self.daemon_identity_digest, "cleanup daemon identity"),
        ):
            _digest(value, label)
        _attempt(self.attempt_id)
        _timestamp(self.observed_at, "boundary cleanup observation time")
        if self.settlement != "verified_absent":
            raise LinuxEngineBoundaryError("boundary cleanup is not verified absent")
        bool_fields = (
            "leader_absent",
            "descendants_absent",
            "cgroup_empty",
            "cgroup_removed",
            "namespaces_absent",
            "bridge_removed",
            "target_alias_absent",
            "model_gateway_alias_absent",
            "firewall_removed",
            "daemon_proxy_absent",
            "supervisor_absent",
            "target_relay_absent",
            "model_relay_absent",
            "protected_roots_absent",
            "uid_released",
        )
        if any(getattr(self, field) is not True for field in bool_fields):
            raise LinuxEngineBoundaryError("boundary cleanup has incomplete absence proof")
        if self.residue_refs or self.unverified_refs:
            raise LinuxEngineBoundaryError("boundary cleanup retains residue or uncertainty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "request_ref": self.request_ref,
            "plan_digest": self.plan_digest,
            "activation_receipt_digest": self.activation_receipt_digest,
            "attempt_id": self.attempt_id,
            "owner_ref": self.owner_ref,
            "admission_record_ref": self.admission_record_ref,
            "observed_at": self.observed_at,
            "boot_id_digest": self.boot_id_digest,
            "daemon_identity_digest": self.daemon_identity_digest,
            "settlement": self.settlement,
            "leader_absent": self.leader_absent,
            "descendants_absent": self.descendants_absent,
            "cgroup_empty": self.cgroup_empty,
            "cgroup_removed": self.cgroup_removed,
            "namespaces_absent": self.namespaces_absent,
            "bridge_removed": self.bridge_removed,
            "target_alias_absent": self.target_alias_absent,
            "model_gateway_alias_absent": self.model_gateway_alias_absent,
            "firewall_removed": self.firewall_removed,
            "daemon_proxy_absent": self.daemon_proxy_absent,
            "supervisor_absent": self.supervisor_absent,
            "target_relay_absent": self.target_relay_absent,
            "model_relay_absent": self.model_relay_absent,
            "protected_roots_absent": self.protected_roots_absent,
            "uid_released": self.uid_released,
            "residue_refs": list(self.residue_refs),
            "unverified_refs": list(self.unverified_refs),
        }

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


class LinuxBoundaryHelper(Protocol):
    """Future fixed helper interface; implementations must accept no other grammar."""

    def prepare(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def cleanup(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _disposable_generation_ref(plan: LinuxAttemptBoundaryPlan) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.linux-disposable-identity-generation.v1",
            "uid": plan.disposable_identity.uid,
            "generation": plan.disposable_identity.generation,
        }
    )


def _replay_descends_from(
    replay_state: LinuxBoundaryReplayState,
    *,
    ledger_ref: str,
    prior_head_digest: str,
) -> None:
    replay_state.validate()
    if replay_state.ledger_ref != ledger_ref:
        raise LinuxEngineBoundaryError("boundary replay ledger changed")
    if (
        replay_state.head_digest != prior_head_digest
        and prior_head_digest not in replay_state.ancestor_head_digests
    ):
        raise LinuxEngineBoundaryError("boundary replay head is not a retained descendant")


def validate_prepare_request(
    plan: LinuxAttemptBoundaryPlan,
    request: LinuxBoundaryPrepareRequest,
    replay_state: LinuxBoundaryReplayState,
) -> None:
    """Bind a prepare request to the exact current plan and reject replay/reuse."""

    plan.validate()
    request.validate()
    replay_state.validate()
    if (
        request.plan_digest != plan.plan_digest
        or request.attempt_id != plan.attempt_id
        or request.owner_ref != plan.owner_ref
        or request.authority_generation != plan.authority_generation
        or request.authority_record_digest != plan.authority_record_digest
        or request.admission_record_ref != plan.admission_record_ref
        or request.admission_record_digest != plan.admission_record_digest
        or request.replay_ledger_ref != plan.replay_ledger_ref
        or request.replay_ledger_ref != replay_state.ledger_ref
        or request.replay_head_digest != replay_state.head_digest
    ):
        raise LinuxEngineBoundaryError("boundary prepare request is not bound to the plan")
    _after(
        request.requested_at,
        plan.created_at,
        "boundary prepare request",
        maximum_delay=_MAX_PREPARE_DELAY,
    )
    if parse_iso8601_datetime(request.requested_at) >= parse_iso8601_datetime(plan.expires_at):
        raise LinuxEngineBoundaryError("boundary prepare request is expired")
    if request.request_ref in replay_state.consumed_prepare_request_refs:
        raise LinuxEngineBoundaryError("boundary prepare request was already consumed")
    if plan.disposable_identity.lease_ref in replay_state.consumed_uid_lease_refs:
        raise LinuxEngineBoundaryError("disposable identity lease was already used")
    uid_generation_ref = _disposable_generation_ref(plan)
    if uid_generation_ref in replay_state.consumed_uid_generation_refs:
        raise LinuxEngineBoundaryError("disposable identity generation was already used")


def _validate_activation_binding(
    plan: LinuxAttemptBoundaryPlan,
    request: LinuxBoundaryPrepareRequest,
    receipt: LinuxBoundaryActivationReceipt,
) -> None:
    """Validate retained activation ownership without replaying the request claim."""

    plan.validate()
    request.validate()
    receipt.validate()
    if (
        receipt.request_ref != request.request_ref
        or receipt.plan_digest != plan.plan_digest
        or receipt.attempt_id != plan.attempt_id
        or receipt.owner_ref != plan.owner_ref
        or receipt.binding_digest != plan.binding_digest
        or receipt.delegation_digest != plan.delegation_digest
        or receipt.authority_generation != plan.authority_generation
        or receipt.authority_record_digest != plan.authority_record_digest
        or receipt.admission_record_ref != plan.admission_record_ref
        or receipt.admission_record_digest != plan.admission_record_digest
        or receipt.uid != plan.disposable_identity.uid
        or receipt.uid_generation != plan.disposable_identity.generation
        or receipt.uid_lease_ref != plan.disposable_identity.lease_ref
    ):
        raise LinuxEngineBoundaryError("boundary activation is not bound to the request and plan")
    _after(
        receipt.observed_at,
        request.requested_at,
        "boundary activation",
        maximum_delay=_MAX_ACTIVATION_DELAY,
    )
    if parse_iso8601_datetime(receipt.observed_at) >= parse_iso8601_datetime(plan.expires_at):
        raise LinuxEngineBoundaryError("boundary activation was observed after expiry")
    if receipt.host_namespace_snapshot_digest != plan.namespaces.host_namespace_snapshot_digest:
        raise LinuxEngineBoundaryError("host namespace snapshot changed from the plan")
    namespaces = {item.kind: item for item in receipt.namespaces}
    for kind in NamespaceKind:
        identity = namespaces[kind]
        if identity.namespace_ref != plan.namespaces.ref_for(kind):
            raise LinuxEngineBoundaryError("namespace identity changed from the plan")
        if identity.owner_uid != plan.controller_uid:
            raise LinuxEngineBoundaryError("namespace owner changed from the controller")
    host_snapshot = content_hash(
        {
            "schema_version": "bluefire.linux-host-namespace-snapshot.v1",
            "identities": [
                {
                    "kind": item.kind.value,
                    "identity_digest": item.host_kernel_identity_digest,
                }
                for item in receipt.namespaces
            ],
        }
    )
    if host_snapshot != receipt.host_namespace_snapshot_digest:
        raise LinuxEngineBoundaryError("host namespace snapshot is not canonical")
    if (
        receipt.cgroup.cgroup_ref != plan.cgroup.cgroup_ref
        or receipt.cgroup.limits_digest != plan.cgroup.limits_digest
    ):
        raise LinuxEngineBoundaryError("cgroup identity changed from the plan")
    planned_roots = {item.purpose: item for item in plan.protected_roots}
    for root in receipt.protected_roots:
        planned = planned_roots[root.purpose]
        if (
            root.root_ref != planned.root_ref
            or root.parent_ref != planned.parent_ref
            or root.owner_uid != planned.expected_owner_uid
            or root.mode != planned.expected_mode
            or root.engine_write_allowed is not planned.engine_write_allowed
        ):
            raise LinuxEngineBoundaryError("protected root identity changed from the plan")
    network_pairs = (
        (receipt.network.network_policy_digest, plan.network.network_policy_digest),
        (receipt.network.bridge_ref, plan.network.bridge_ref),
        (receipt.network.target_alias_ref, plan.network.target_alias_ref),
        (receipt.network.model_gateway_alias_ref, plan.network.model_gateway_alias_ref),
        (receipt.network.daemon_ref, plan.network.daemon_ref),
        (receipt.network.daemon_proxy_ref, plan.network.daemon_proxy_ref),
        (receipt.network.target_relay_ref, plan.network.target_relay_ref),
        (receipt.network.model_relay_ref, plan.network.model_relay_ref),
        (receipt.network.firewall_policy_digest, plan.network.firewall_policy_digest),
    )
    if any(actual != expected for actual, expected in network_pairs):
        raise LinuxEngineBoundaryError("network boundary identity changed from the plan")
    if (
        receipt.leader.leader_ref != plan.leader_ref
        or receipt.leader.supervisor_ref != plan.supervisor_ref
        or receipt.leader.pid_namespace_ref != plan.namespaces.pid_ref
        or receipt.leader.executable_digest != plan.executable_digest
    ):
        raise LinuxEngineBoundaryError("process leader identity changed from the plan")


def validate_activation_receipt(
    plan: LinuxAttemptBoundaryPlan,
    request: LinuxBoundaryPrepareRequest,
    receipt: LinuxBoundaryActivationReceipt,
    replay_state: LinuxBoundaryReplayState,
    *,
    retained_receipt: LinuxBoundaryActivationReceipt | None,
) -> None:
    """Validate initial activation or an exact retained retry, never a replacement."""

    if retained_receipt is None:
        validate_prepare_request(plan, request, replay_state)
    else:
        _replay_descends_from(
            replay_state,
            ledger_ref=request.replay_ledger_ref,
            prior_head_digest=request.replay_head_digest,
        )
        if (
            request.request_ref not in replay_state.consumed_prepare_request_refs
            or plan.disposable_identity.lease_ref not in replay_state.consumed_uid_lease_refs
            or _disposable_generation_ref(plan) not in replay_state.consumed_uid_generation_refs
        ):
            raise LinuxEngineBoundaryError(
                "retained activation does not have a consumed replay claim"
            )
        _validate_activation_binding(plan, request, retained_receipt)
    _validate_activation_binding(plan, request, receipt)
    if retained_receipt is not None and receipt.receipt_digest != retained_receipt.receipt_digest:
        raise LinuxEngineBoundaryError("boundary activation retry changed retained identities")


def validate_activation_revalidation(
    plan: LinuxAttemptBoundaryPlan,
    request: LinuxBoundaryPrepareRequest,
    retained_receipt: LinuxBoundaryActivationReceipt,
    observed_receipt: LinuxBoundaryActivationReceipt,
) -> None:
    """Accept a later observation only when every retained identity is unchanged."""

    _validate_activation_binding(plan, request, retained_receipt)
    _validate_activation_binding(plan, request, observed_receipt)
    _after(
        observed_receipt.observed_at,
        retained_receipt.observed_at,
        "boundary activation revalidation",
        strict=True,
    )
    retained_identity = retained_receipt.to_dict()
    observed_identity = observed_receipt.to_dict()
    retained_identity.pop("observed_at")
    observed_identity.pop("observed_at")
    if content_hash(retained_identity) != content_hash(observed_identity):
        raise LinuxEngineBoundaryError("boundary activation identities changed during revalidation")


def _validate_cleanup_request_binding(
    plan: LinuxAttemptBoundaryPlan,
    prepare_request: LinuxBoundaryPrepareRequest,
    activation: LinuxBoundaryActivationReceipt,
    request: LinuxBoundaryCleanupRequest,
) -> None:
    plan.validate()
    _validate_activation_binding(plan, prepare_request, activation)
    request.validate()
    if (
        request.plan_digest != plan.plan_digest
        or request.activation_receipt_digest != activation.receipt_digest
        or request.attempt_id != plan.attempt_id
        or request.owner_ref != plan.owner_ref
        or request.admission_record_ref != plan.admission_record_ref
        or request.replay_ledger_ref != plan.replay_ledger_ref
    ):
        raise LinuxEngineBoundaryError("boundary cleanup request is not bound to activation")
    _after(request.requested_at, activation.observed_at, "boundary cleanup request")


def validate_cleanup_request(
    plan: LinuxAttemptBoundaryPlan,
    prepare_request: LinuxBoundaryPrepareRequest,
    activation: LinuxBoundaryActivationReceipt,
    request: LinuxBoundaryCleanupRequest,
    replay_state: LinuxBoundaryReplayState,
) -> None:
    _validate_cleanup_request_binding(plan, prepare_request, activation, request)
    replay_state.validate()
    if (
        request.replay_ledger_ref != replay_state.ledger_ref
        or request.replay_head_digest != replay_state.head_digest
    ):
        raise LinuxEngineBoundaryError("boundary cleanup request is not bound to activation")
    if request.request_ref in replay_state.consumed_cleanup_request_refs:
        raise LinuxEngineBoundaryError("boundary cleanup request was already consumed")


def _validate_cleanup_receipt_binding(
    plan: LinuxAttemptBoundaryPlan,
    activation: LinuxBoundaryActivationReceipt,
    request: LinuxBoundaryCleanupRequest,
    receipt: LinuxBoundaryCleanupReceipt,
) -> None:
    receipt.validate()
    if (
        receipt.request_ref != request.request_ref
        or receipt.plan_digest != plan.plan_digest
        or receipt.activation_receipt_digest != activation.receipt_digest
        or receipt.attempt_id != plan.attempt_id
        or receipt.owner_ref != plan.owner_ref
        or receipt.admission_record_ref != plan.admission_record_ref
        or receipt.boot_id_digest != activation.leader.boot_id_digest
        or receipt.daemon_identity_digest != activation.network.daemon_identity_digest
    ):
        raise LinuxEngineBoundaryError("boundary cleanup receipt is not bound to the request")
    _after(
        receipt.observed_at,
        request.requested_at,
        "boundary cleanup observation",
        maximum_delay=_MAX_CLEANUP_OBSERVATION_DELAY,
    )


def validate_cleanup_receipt(
    plan: LinuxAttemptBoundaryPlan,
    prepare_request: LinuxBoundaryPrepareRequest,
    activation: LinuxBoundaryActivationReceipt,
    request: LinuxBoundaryCleanupRequest,
    receipt: LinuxBoundaryCleanupReceipt,
    replay_state: LinuxBoundaryReplayState,
    *,
    retained_receipt: LinuxBoundaryCleanupReceipt | None,
) -> None:
    if retained_receipt is None:
        validate_cleanup_request(plan, prepare_request, activation, request, replay_state)
    else:
        _validate_cleanup_request_binding(plan, prepare_request, activation, request)
        _replay_descends_from(
            replay_state,
            ledger_ref=request.replay_ledger_ref,
            prior_head_digest=request.replay_head_digest,
        )
        if request.request_ref not in replay_state.consumed_cleanup_request_refs:
            raise LinuxEngineBoundaryError("retained cleanup does not have a consumed replay claim")
        _validate_cleanup_receipt_binding(plan, activation, request, retained_receipt)
    _validate_cleanup_receipt_binding(plan, activation, request, receipt)
    if retained_receipt is not None and receipt.receipt_digest != retained_receipt.receipt_digest:
        raise LinuxEngineBoundaryError("boundary cleanup retry changed retained proof")
