"""Container custody verification for a reviewed external-engine attempt.

This module does not launch Docker, create a network, or enforce egress.  It
validates controller-supplied daemon snapshots, identifies attempt-owned
resources using both a trusted pre-run baseline and exact attempt labels, and
drives an injected fixed cleanup operation.  The surrounding worker must run
inside a dedicated disposable VM or daemon and must enforce the recorded
network policy independently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence

from .util import content_hash, json_clone


class EngineContainerCustodyError(ValueError):
    """Raised when a custody plan or daemon snapshot is not canonical."""


class CustodySettlement(str, Enum):
    VERIFIED_ABSENT = "verified_absent"
    RESIDUE = "residue"
    UNKNOWN = "unknown"


_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_ID = re.compile(r"^[0-9a-f]{12,64}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VOLUME_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CONTAINER_PATH = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
_LABEL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$")
_CAPABILITY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineContainerCustodyError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str], *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or pattern.fullmatch(value) is None
    ):
        raise EngineContainerCustodyError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    return _text(value, label, _DIGEST, maximum=71)


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineContainerCustodyError(f"{label} is outside its bound")
    return int(value)


def _opaque_text(value: Any, label: str, *, maximum: int, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineContainerCustodyError(f"{label} is invalid")
    return value


def _observed_limit(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -1 <= value <= maximum:
        raise EngineContainerCustodyError(f"{label} is invalid")
    return int(value)


def _string_tuple(
    value: Any,
    label: str,
    pattern: re.Pattern[str],
    *,
    maximum_items: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise EngineContainerCustodyError(f"{label} is invalid")
    items = tuple(_text(item, label, pattern) for item in value)
    if tuple(sorted(set(items))) != items:
        raise EngineContainerCustodyError(f"{label} must be unique and sorted")
    return items


def _opaque_tuple(value: Any, label: str, *, maximum_items: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise EngineContainerCustodyError(f"{label} is invalid")
    items: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item) > 260
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
        ):
            raise EngineContainerCustodyError(f"{label} is invalid")
        items.append(item)
    result = tuple(items)
    if tuple(sorted(set(result))) != result:
        raise EngineContainerCustodyError(f"{label} must be unique and sorted")
    return result


def _labels(value: Any, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > 16:
        raise EngineContainerCustodyError(f"{label} is invalid")
    rows: list[tuple[str, str]] = []
    for raw_key, raw_value in value.items():
        key = _text(raw_key, f"{label} key", _LABEL_KEY, maximum=128)
        if (
            not isinstance(raw_value, str)
            or raw_value != raw_value.strip()
            or len(raw_value) > 200
            or any(ord(character) < 32 or ord(character) == 127 for character in raw_value)
        ):
            raise EngineContainerCustodyError(f"{label} value is invalid")
        rows.append((key, raw_value))
    result = tuple(sorted(rows))
    if list(value) != [key for key, _ in result]:
        raise EngineContainerCustodyError(f"{label} must use sorted keys")
    return result


def _labels_dict(value: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return {key: item for key, item in value}


@dataclass(frozen=True, slots=True)
class MountSpec:
    mount_type: str
    source: str
    destination: str
    read_only: bool
    options_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "MountSpec":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "container mount")
        read_only = row["read_only"]
        if not isinstance(read_only, bool):
            raise EngineContainerCustodyError("container mount read-only state is invalid")
        return cls(
            mount_type=_text(row["mount_type"], "container mount type", _NAME, maximum=32),
            source=_opaque_text(
                row["source"], "container mount source", maximum=260, allow_empty=True
            ),
            destination=_text(
                row["destination"], "container mount destination", _CONTAINER_PATH, maximum=260
            ),
            read_only=read_only,
            options_digest=_digest(row["options_digest"], "container mount options"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mount_type": self.mount_type,
            "source": self.source,
            "destination": self.destination,
            "read_only": self.read_only,
            "options_digest": self.options_digest,
        }


def _mounts(value: Any, label: str, *, minimum_items: int) -> tuple[MountSpec, ...]:
    if not isinstance(value, list) or not minimum_items <= len(value) <= 8:
        raise EngineContainerCustodyError(f"{label} is invalid")
    items = tuple(MountSpec.from_mapping(item) for item in value)
    destinations = tuple(item.destination for item in items)
    if tuple(sorted(set(destinations))) != destinations:
        raise EngineContainerCustodyError(f"{label} destinations must be unique and sorted")
    return items


@dataclass(frozen=True, slots=True)
class ContainerResource:
    resource_id: str
    name: str
    labels: tuple[tuple[str, str], ...]
    image_digest: str
    network_ids: tuple[str, ...]
    mounts: tuple[MountSpec, ...]
    capabilities: tuple[str, ...]
    user: str
    privileged: bool
    devices: tuple[str, ...]
    network_mode: str
    pid_mode: str
    ipc_mode: str
    uts_mode: str
    memory_bytes: int
    nano_cpus: int
    pids_limit: int

    @classmethod
    def from_mapping(cls, value: Any) -> "ContainerResource":
        fields = frozenset(cls.__dataclass_fields__)
        row = _exact(value, fields, "container resource")
        privileged = row["privileged"]
        if not isinstance(privileged, bool):
            raise EngineContainerCustodyError("container privileged state is invalid")
        return cls(
            resource_id=_text(row["resource_id"], "container ID", _RESOURCE_ID, maximum=64),
            name=_text(row["name"], "container name", _NAME, maximum=128),
            labels=_labels(row["labels"], "container labels"),
            image_digest=_digest(row["image_digest"], "container image digest"),
            network_ids=_string_tuple(
                row["network_ids"], "container network IDs", _RESOURCE_ID, maximum_items=8
            ),
            mounts=_mounts(row["mounts"], "container mounts", minimum_items=0),
            capabilities=_string_tuple(
                row["capabilities"], "container capabilities", _CAPABILITY, maximum_items=32
            ),
            user=_opaque_text(row["user"], "container user", maximum=64, allow_empty=True),
            privileged=privileged,
            devices=_opaque_tuple(row["devices"], "container devices", maximum_items=16),
            network_mode=_opaque_text(row["network_mode"], "container network mode", maximum=80),
            pid_mode=_opaque_text(
                row["pid_mode"], "container PID mode", maximum=80, allow_empty=True
            ),
            ipc_mode=_opaque_text(
                row["ipc_mode"], "container IPC mode", maximum=80, allow_empty=True
            ),
            uts_mode=_opaque_text(
                row["uts_mode"], "container UTS mode", maximum=80, allow_empty=True
            ),
            memory_bytes=_observed_limit(
                row["memory_bytes"], "container memory bytes", 256 * 1024**3
            ),
            nano_cpus=_observed_limit(row["nano_cpus"], "container nano CPUs", 256_000_000_000),
            pids_limit=_observed_limit(row["pids_limit"], "container PID limit", 65_536),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "labels": _labels_dict(self.labels),
            "image_digest": self.image_digest,
            "network_ids": list(self.network_ids),
            "mounts": [item.to_dict() for item in self.mounts],
            "capabilities": list(self.capabilities),
            "user": self.user,
            "privileged": self.privileged,
            "devices": list(self.devices),
            "network_mode": self.network_mode,
            "pid_mode": self.pid_mode,
            "ipc_mode": self.ipc_mode,
            "uts_mode": self.uts_mode,
            "memory_bytes": self.memory_bytes,
            "nano_cpus": self.nano_cpus,
            "pids_limit": self.pids_limit,
        }


@dataclass(frozen=True, slots=True)
class VolumeResource:
    resource_id: str
    name: str
    labels: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "VolumeResource":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "volume")
        return cls(
            resource_id=_text(row["resource_id"], "volume handle", _VOLUME_HANDLE, maximum=128),
            name=_text(row["name"], "volume name", _NAME, maximum=128),
            labels=_labels(row["labels"], "volume labels"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "labels": _labels_dict(self.labels),
        }


@dataclass(frozen=True, slots=True)
class NetworkResource:
    resource_id: str
    name: str
    labels: tuple[tuple[str, str], ...]
    internal: bool
    policy_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "NetworkResource":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "network")
        internal = row["internal"]
        if not isinstance(internal, bool):
            raise EngineContainerCustodyError("network internal state is invalid")
        return cls(
            resource_id=_text(row["resource_id"], "network ID", _RESOURCE_ID, maximum=64),
            name=_text(row["name"], "network name", _NAME, maximum=128),
            labels=_labels(row["labels"], "network labels"),
            internal=internal,
            policy_digest=_digest(row["policy_digest"], "network policy"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "labels": _labels_dict(self.labels),
            "internal": self.internal,
            "policy_digest": self.policy_digest,
        }


@dataclass(frozen=True, slots=True)
class DaemonInventory:
    schema_version: str
    daemon_instance_digest: str
    containers: tuple[ContainerResource, ...]
    networks: tuple[NetworkResource, ...]
    volumes: tuple[VolumeResource, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "DaemonInventory":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "daemon inventory")
        if row["schema_version"] != "bluefire.engine-daemon-inventory.v1":
            raise EngineContainerCustodyError("daemon inventory schema is unsupported")

        def parse_rows(raw: Any, label: str, parser: Any) -> tuple[Any, ...]:
            if not isinstance(raw, list) or len(raw) > 512:
                raise EngineContainerCustodyError(f"{label} inventory is invalid")
            items = tuple(parser(item) for item in raw)
            ids = tuple(item.resource_id for item in items)
            if tuple(sorted(set(ids))) != ids:
                raise EngineContainerCustodyError(f"{label} inventory must be unique and sorted")
            return items

        return cls(
            schema_version="bluefire.engine-daemon-inventory.v1",
            daemon_instance_digest=_digest(row["daemon_instance_digest"], "daemon instance"),
            containers=parse_rows(row["containers"], "container", ContainerResource.from_mapping),
            networks=parse_rows(row["networks"], "network", NetworkResource.from_mapping),
            volumes=parse_rows(row["volumes"], "volume", VolumeResource.from_mapping),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "daemon_instance_digest": self.daemon_instance_digest,
            "containers": [item.to_dict() for item in self.containers],
            "networks": [item.to_dict() for item in self.networks],
            "volumes": [item.to_dict() for item in self.volumes],
        }

    @property
    def inventory_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ContainerCustodyPlan:
    schema_version: str
    attempt_id: str
    daemon_instance_digest: str
    disposable_boundary_ref: str
    baseline_inventory_digest: str
    required_labels: tuple[tuple[str, str], ...]
    sandbox_image_digest: str
    network_id: str
    network_policy_digest: str
    expected_mounts: tuple[MountSpec, ...]
    expected_capabilities: tuple[str, ...]
    expected_user: str
    memory_bytes: int
    nano_cpus: int
    pids_limit: int
    expected_container_count: int

    @classmethod
    def from_mapping(cls, value: Any) -> "ContainerCustodyPlan":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "container custody plan")
        if row["schema_version"] != "bluefire.engine-container-custody.v1":
            raise EngineContainerCustodyError("container custody schema is unsupported")
        labels = _labels(row["required_labels"], "required labels")
        label_map = _labels_dict(labels)
        attempt_id = _text(row["attempt_id"], "attempt ID", _ATTEMPT_ID, maximum=47)
        if label_map.get("bluefire.engine.attempt") != attempt_id:
            raise EngineContainerCustodyError("required labels do not bind the attempt")
        mounts = _mounts(row["expected_mounts"], "expected mounts", minimum_items=1)
        if any(item.mount_type != "tmpfs" or item.source for item in mounts):
            raise EngineContainerCustodyError(
                "only reviewed source-free tmpfs mounts are permitted"
            )
        return cls(
            schema_version="bluefire.engine-container-custody.v1",
            attempt_id=attempt_id,
            daemon_instance_digest=_digest(row["daemon_instance_digest"], "daemon instance"),
            disposable_boundary_ref=_digest(row["disposable_boundary_ref"], "disposable boundary"),
            baseline_inventory_digest=_digest(
                row["baseline_inventory_digest"], "baseline inventory"
            ),
            required_labels=labels,
            sandbox_image_digest=_digest(row["sandbox_image_digest"], "sandbox image"),
            network_id=_text(row["network_id"], "network ID", _RESOURCE_ID, maximum=64),
            network_policy_digest=_digest(row["network_policy_digest"], "network policy"),
            expected_mounts=mounts,
            expected_capabilities=_string_tuple(
                row["expected_capabilities"],
                "expected capabilities",
                _CAPABILITY,
                maximum_items=16,
            ),
            expected_user=_text(row["expected_user"], "expected user", _USER, maximum=64),
            memory_bytes=_bounded_int(row["memory_bytes"], "memory bytes", 1, 256 * 1024**3),
            nano_cpus=_bounded_int(row["nano_cpus"], "nano CPUs", 1, 256_000_000_000),
            pids_limit=_bounded_int(row["pids_limit"], "PID limit", 1, 65_536),
            expected_container_count=_bounded_int(
                row["expected_container_count"], "expected container count", 1, 16
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "attempt_id": self.attempt_id,
                    "daemon_instance_digest": self.daemon_instance_digest,
                    "disposable_boundary_ref": self.disposable_boundary_ref,
                    "baseline_inventory_digest": self.baseline_inventory_digest,
                    "required_labels": _labels_dict(self.required_labels),
                    "sandbox_image_digest": self.sandbox_image_digest,
                    "network_id": self.network_id,
                    "network_policy_digest": self.network_policy_digest,
                    "expected_mounts": [item.to_dict() for item in self.expected_mounts],
                    "expected_capabilities": list(self.expected_capabilities),
                    "expected_user": self.expected_user,
                    "memory_bytes": self.memory_bytes,
                    "nano_cpus": self.nano_cpus,
                    "pids_limit": self.pids_limit,
                    "expected_container_count": self.expected_container_count,
                }
            )
        )

    @property
    def plan_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class CustodyAssessment:
    owned_container_ids: tuple[str, ...]
    owned_network_ids: tuple[str, ...]
    owned_volume_ids: tuple[str, ...]
    unowned_new_ids: tuple[str, ...]
    policy_violations: tuple[str, ...]

    @property
    def qualified(self) -> bool:
        return not self.unowned_new_ids and not self.policy_violations


@dataclass(frozen=True, slots=True)
class CustodySettlementResult:
    state: CustodySettlement
    assessment: CustodyAssessment
    final_inventory_digest: str | None
    limitations: tuple[str, ...]


class FixedDockerControl(Protocol):
    """Trusted fixed operations; implementations must not accept caller commands."""

    def snapshot(self) -> Mapping[str, Any]: ...

    def remove_owned_resources(
        self,
        *,
        container_ids: Sequence[str],
        network_ids: Sequence[str],
        volume_ids: Sequence[str],
    ) -> None: ...


def _new_by_id(before: Sequence[Any], after: Sequence[Any]) -> tuple[Any, ...]:
    existing = {item.resource_id for item in before}
    return tuple(item for item in after if item.resource_id not in existing)


def _has_required_labels(
    labels: tuple[tuple[str, str], ...], required: tuple[tuple[str, str], ...]
) -> bool:
    actual = _labels_dict(labels)
    return all(actual.get(key) == value for key, value in required)


def assess_container_custody(
    plan: ContainerCustodyPlan,
    baseline: DaemonInventory,
    current: DaemonInventory,
) -> CustodyAssessment:
    """Identify attempt resources and verify their effective Docker settings."""

    if baseline.daemon_instance_digest != plan.daemon_instance_digest:
        raise EngineContainerCustodyError("baseline belongs to another daemon")
    if current.daemon_instance_digest != plan.daemon_instance_digest:
        raise EngineContainerCustodyError("current inventory belongs to another daemon")
    if baseline.inventory_digest != plan.baseline_inventory_digest:
        raise EngineContainerCustodyError("baseline inventory digest does not match the plan")

    new_containers = _new_by_id(baseline.containers, current.containers)
    new_networks = _new_by_id(baseline.networks, current.networks)
    new_volumes = _new_by_id(baseline.volumes, current.volumes)

    owned_containers = tuple(
        item for item in new_containers if _has_required_labels(item.labels, plan.required_labels)
    )
    owned_networks = tuple(
        item for item in new_networks if _has_required_labels(item.labels, plan.required_labels)
    )
    owned_volumes = tuple(
        item for item in new_volumes if _has_required_labels(item.labels, plan.required_labels)
    )
    owned_ids = {
        *(("container", item.resource_id) for item in owned_containers),
        *(("network", item.resource_id) for item in owned_networks),
        *(("volume", item.resource_id) for item in owned_volumes),
    }
    new_items = (
        *(("container", item) for item in new_containers),
        *(("network", item) for item in new_networks),
        *(("volume", item) for item in new_volumes),
    )
    unowned_new = tuple(
        sorted(
            f"{kind}:{item.resource_id}"
            for kind, item in new_items
            if (kind, item.resource_id) not in owned_ids
        )
    )

    violations: list[str] = []
    if len(owned_containers) != plan.expected_container_count:
        violations.append("container_count_mismatch")
    for kind, before, after in (
        ("container", baseline.containers, current.containers),
        ("network", baseline.networks, current.networks),
        ("volume", baseline.volumes, current.volumes),
    ):
        current_by_id = {item.resource_id: item for item in after}
        for item in before:
            observed = current_by_id.get(item.resource_id)
            if observed is None:
                violations.append(f"baseline_{kind}_missing:{item.resource_id}")
            elif observed != item:
                violations.append(f"baseline_{kind}_changed:{item.resource_id}")
    if not any(item.resource_id == plan.network_id for item in baseline.networks):
        violations.append("expected_network_missing_from_baseline")
    expected_network = next(
        (item for item in current.networks if item.resource_id == plan.network_id), None
    )
    if expected_network is None:
        violations.append("expected_network_missing")
    else:
        if not expected_network.internal:
            violations.append("expected_network_not_internal")
        if expected_network.policy_digest != plan.network_policy_digest:
            violations.append("expected_network_policy_mismatch")
    if owned_networks:
        violations.append("unexpected_network_created")
    if owned_volumes:
        violations.append("unexpected_volume_created")
    for container in owned_containers:
        prefix = f"container:{container.resource_id}:"
        if container.image_digest != plan.sandbox_image_digest:
            violations.append(prefix + "image_digest")
        if container.network_ids != (plan.network_id,):
            violations.append(prefix + "network")
        if container.network_mode == "host" or container.network_mode.startswith("container:"):
            violations.append(prefix + "host_network")
        if container.mounts != plan.expected_mounts:
            violations.append(prefix + "mounts")
        if any(item.mount_type != "tmpfs" or item.source for item in container.mounts):
            violations.append(prefix + "host_mount")
        if container.capabilities != plan.expected_capabilities:
            violations.append(prefix + "capabilities")
        if container.user != plan.expected_user:
            violations.append(prefix + "user")
        if container.privileged:
            violations.append(prefix + "privileged")
        if container.devices:
            violations.append(prefix + "devices")
        if any(
            mode not in {"", "private"}
            for mode in (container.pid_mode, container.ipc_mode, container.uts_mode)
        ):
            violations.append(prefix + "host_namespace")
        if container.memory_bytes != plan.memory_bytes:
            violations.append(prefix + "memory")
        if container.nano_cpus != plan.nano_cpus:
            violations.append(prefix + "cpu")
        if container.pids_limit != plan.pids_limit:
            violations.append(prefix + "pids")

    return CustodyAssessment(
        owned_container_ids=tuple(item.resource_id for item in owned_containers),
        owned_network_ids=tuple(item.resource_id for item in owned_networks),
        owned_volume_ids=tuple(item.resource_id for item in owned_volumes),
        unowned_new_ids=unowned_new,
        policy_violations=tuple(sorted(set(violations))),
    )


def settle_container_custody(
    plan: ContainerCustodyPlan,
    baseline: DaemonInventory,
    control: FixedDockerControl,
) -> CustodySettlementResult:
    """Stop positively owned resources and prove their absence.

    Unexpected resources are never touched. Positively owned resources are
    still stopped when an unexpected resource exists, after which the overall
    result remains unknown because the dedicated-daemon assumption was broken.
    """

    try:
        current = DaemonInventory.from_mapping(control.snapshot())
        assessment = assess_container_custody(plan, baseline, current)
    except (EngineContainerCustodyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return CustodySettlementResult(
            state=CustodySettlement.UNKNOWN,
            assessment=CustodyAssessment((), (), (), (), ()),
            final_inventory_digest=None,
            limitations=(f"custody_snapshot_failed:{type(exc).__name__}",),
        )

    try:
        control.remove_owned_resources(
            container_ids=assessment.owned_container_ids,
            network_ids=assessment.owned_network_ids,
            volume_ids=assessment.owned_volume_ids,
        )
        final = DaemonInventory.from_mapping(control.snapshot())
        final_assessment = assess_container_custody(plan, baseline, final)
    except (EngineContainerCustodyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return CustodySettlementResult(
            state=CustodySettlement.UNKNOWN,
            assessment=assessment,
            final_inventory_digest=None,
            limitations=(f"custody_cleanup_failed:{type(exc).__name__}",),
        )

    remaining_owned = (
        final_assessment.owned_container_ids
        + final_assessment.owned_network_ids
        + final_assessment.owned_volume_ids
    )
    limitations: tuple[str, ...]
    baseline_integrity_failed = any(
        item.startswith("baseline_") or item.startswith("expected_network_")
        for item in (*assessment.policy_violations, *final_assessment.policy_violations)
    )
    if assessment.unowned_new_ids or final_assessment.unowned_new_ids or baseline_integrity_failed:
        state = CustodySettlement.UNKNOWN
        limitations = ("dedicated_daemon_baseline_violated",)
    elif remaining_owned:
        state = CustodySettlement.RESIDUE
        limitations = ("owned_resources_remain",)
    else:
        state = CustodySettlement.VERIFIED_ABSENT
        limitations = ()
    return CustodySettlementResult(
        state=state,
        assessment=assessment,
        final_inventory_digest=final.inventory_digest,
        limitations=limitations,
    )
