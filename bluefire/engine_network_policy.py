"""Network-scope contract for one admitted external-engine attempt.

This module describes and verifies the first tenant-record lab policy.  It does
not configure a firewall, resolve DNS, or open a socket.  A separately trusted
enforcer owns those effects and returns an independently captured snapshot and
fixed probe results for validation here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence, cast
from urllib.parse import urlsplit

from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineNetworkPolicyError(ValueError):
    """Raised when a network plan or observation violates the closed contract."""


class EndpointRole(str, Enum):
    TARGET = "target"
    MODEL_GATEWAY = "model_gateway"


class ProbeOutcome(str, Enum):
    ALLOWED = "allowed"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    UNEXPECTED_REACHABLE = "unexpected_reachable"
    INCONCLUSIVE = "inconclusive"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SERVICE_NAME = re.compile(r"^bf-(?:target|model)-[0-9a-f]{12}$")
_NETWORK_NAME = re.compile(r"^bf-engine-[0-9a-f]{12}$")
_RFC1918: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_ULA = ipaddress.IPv6Network("fc00::/7")
_TARGET_PORT = 8080
_MODEL_GATEWAY_PORT = 8081
_MODEL_GATEWAY_PATH = "/v1/chat/completions"
_BLOCKED_CLASSES = (
    "controller",
    "daemon",
    "host_gateway",
    "link_local",
    "metadata",
    "other_egress",
    "public_dns",
)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineNetworkPolicyError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineNetworkPolicyError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineNetworkPolicyError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=40)
    try:
        parse_iso8601_datetime(text)
    except ValueError as exc:
        raise EngineNetworkPolicyError(f"{label} is not bounded RFC 3339") from exc
    return text


def _address(value: Any, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    text = _text(value, label, maximum=45)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise EngineNetworkPolicyError(f"{label} is not an IP literal") from exc
    if str(address) != text.lower() or (
        isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
    ):
        raise EngineNetworkPolicyError(f"{label} is not canonical")
    return address


def _private_network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    text = _text(value, "engine subnet", maximum=64)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise EngineNetworkPolicyError("engine subnet is not canonical") from exc
    if str(network) != text.lower():
        raise EngineNetworkPolicyError("engine subnet is not canonical")
    if isinstance(network, ipaddress.IPv4Network):
        if not 16 <= network.prefixlen <= 30 or not any(
            network.subnet_of(parent) for parent in _RFC1918
        ):
            raise EngineNetworkPolicyError("engine subnet must be bounded RFC 1918 space")
    else:
        if not 64 <= network.prefixlen <= 120 or not network.subnet_of(_ULA):
            raise EngineNetworkPolicyError("engine subnet must be bounded IPv6 ULA space")
        if ipaddress.IPv6Address("fd00:ec2::254") in network:
            raise EngineNetworkPolicyError("engine subnet overlaps a metadata endpoint")
    return network


def _address_in_network(
    value: Any,
    label: str,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> str:
    address = _address(value, label)
    if address.version != network.version or address not in network:
        raise EngineNetworkPolicyError(f"{label} is outside the engine subnet")
    if address == network.network_address or (
        isinstance(network, ipaddress.IPv4Network) and address == network.broadcast_address
    ):
        raise EngineNetworkPolicyError(f"{label} is not a usable engine address")
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise EngineNetworkPolicyError(f"{label} is not an admitted engine address")
    return str(address)


@dataclass(frozen=True, slots=True)
class BoundNetworkEndpoint:
    role: EndpointRole
    service_name: str
    address: str
    port: int
    path: str

    @classmethod
    def from_mapping(cls, value: Any) -> "BoundNetworkEndpoint":
        fields = frozenset(cls.__dataclass_fields__)
        row = _exact(value, fields, "network endpoint")
        try:
            role = EndpointRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise EngineNetworkPolicyError("network endpoint role is invalid") from exc
        service_name = _text(row["service_name"], "network service name", maximum=63)
        if _SERVICE_NAME.fullmatch(service_name) is None:
            raise EngineNetworkPolicyError("network service name is invalid")
        address = str(_address(row["address"], "network endpoint address"))
        port = row["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise EngineNetworkPolicyError("network endpoint port is invalid")
        path = _text(row["path"], "network endpoint path", maximum=80)
        expected_port = _TARGET_PORT if role is EndpointRole.TARGET else _MODEL_GATEWAY_PORT
        expected_path = "/" if role is EndpointRole.TARGET else _MODEL_GATEWAY_PATH
        expected_prefix = "bf-target-" if role is EndpointRole.TARGET else "bf-model-"
        if (
            port != expected_port
            or path != expected_path
            or not service_name.startswith(expected_prefix)
        ):
            raise EngineNetworkPolicyError("network endpoint does not match its fixed role")
        return cls(role=role, service_name=service_name, address=address, port=port, path=path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "service_name": self.service_name,
            "address": self.address,
            "port": self.port,
            "path": self.path,
        }

    @property
    def origin(self) -> str:
        return f"http://{self.service_name}:{self.port}"


@dataclass(frozen=True, slots=True)
class EngineNetworkPlan:
    schema_version: str
    attempt_id: str
    network_name: str
    network_identity_ref: str
    subnet: str
    target: BoundNetworkEndpoint
    model_gateway: BoundNetworkEndpoint
    host_gateway_address: str
    controller_address: str
    daemon_address: str
    created_at: str
    default_egress: str
    dns_mode: str
    redirect_mode: str
    daemon_transport: str
    network_attachment_mode: str
    loopback_scope: str

    @classmethod
    def create(
        cls,
        *,
        attempt_id: str,
        network_identity_ref: str,
        subnet: str,
        target_address: str,
        model_gateway_address: str,
        host_gateway_address: str,
        created_at: str,
    ) -> "EngineNetworkPlan":
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineNetworkPolicyError("engine attempt ID is invalid")
        network = _private_network(subnet)
        target = _address_in_network(target_address, "target address", network)
        gateway = _address_in_network(model_gateway_address, "model gateway address", network)
        host_gateway = _address_in_network(host_gateway_address, "host gateway address", network)
        if len({target, gateway, host_gateway}) != 3:
            raise EngineNetworkPolicyError("engine endpoint addresses must be distinct")
        suffix = attempt_id[-12:]
        return cls(
            schema_version="bluefire.engine-network-plan.v1",
            attempt_id=attempt_id,
            network_name=f"bf-engine-{suffix}",
            network_identity_ref=_digest(network_identity_ref, "network identity"),
            subnet=str(network),
            target=BoundNetworkEndpoint(
                role=EndpointRole.TARGET,
                service_name=f"bf-target-{suffix}",
                address=target,
                port=_TARGET_PORT,
                path="/",
            ),
            model_gateway=BoundNetworkEndpoint(
                role=EndpointRole.MODEL_GATEWAY,
                service_name=f"bf-model-{suffix}",
                address=gateway,
                port=_MODEL_GATEWAY_PORT,
                path=_MODEL_GATEWAY_PATH,
            ),
            host_gateway_address=host_gateway,
            controller_address=host_gateway,
            daemon_address=host_gateway,
            created_at=_timestamp(created_at, "network plan creation time"),
            default_egress="deny",
            dns_mode="bound_services_only",
            redirect_mode="same_target_origin_only",
            daemon_transport="unix_socket_not_mounted",
            network_attachment_mode="single_internal_network",
            loopback_scope="container_local_only_not_a_target",
        )

    @classmethod
    def from_mapping(cls, value: Any) -> "EngineNetworkPlan":
        fields = frozenset(cls.__dataclass_fields__)
        row = _exact(value, fields, "engine network plan")
        target = BoundNetworkEndpoint.from_mapping(row["target"])
        gateway = BoundNetworkEndpoint.from_mapping(row["model_gateway"])
        plan = cls.create(
            attempt_id=_text(row["attempt_id"], "engine attempt ID", maximum=47),
            network_identity_ref=row["network_identity_ref"],
            subnet=row["subnet"],
            target_address=target.address,
            model_gateway_address=gateway.address,
            host_gateway_address=row["host_gateway_address"],
            created_at=row["created_at"],
        )
        if row["schema_version"] != plan.schema_version or plan.to_dict() != json_clone(value):
            raise EngineNetworkPolicyError("engine network plan is not canonical")
        return plan

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "network_name": self.network_name,
            "network_identity_ref": self.network_identity_ref,
            "subnet": self.subnet,
            "target": self.target.to_dict(),
            "model_gateway": self.model_gateway.to_dict(),
            "host_gateway_address": self.host_gateway_address,
            "controller_address": self.controller_address,
            "daemon_address": self.daemon_address,
            "created_at": self.created_at,
            "default_egress": self.default_egress,
            "dns_mode": self.dns_mode,
            "redirect_mode": self.redirect_mode,
            "daemon_transport": self.daemon_transport,
            "network_attachment_mode": self.network_attachment_mode,
            "loopback_scope": self.loopback_scope,
        }

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class NetworkFlow:
    role: EndpointRole
    address: str
    port: int

    @classmethod
    def from_mapping(cls, value: Any) -> "NetworkFlow":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "network flow")
        try:
            role = EndpointRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise EngineNetworkPolicyError("network flow role is invalid") from exc
        address = str(_address(row["address"], "network flow address"))
        port = row["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise EngineNetworkPolicyError("network flow port is invalid")
        return cls(role=role, address=address, port=port)

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role.value, "address": self.address, "port": self.port}


@dataclass(frozen=True, slots=True)
class ResolutionBinding:
    role: EndpointRole
    service_name: str
    addresses: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "ResolutionBinding":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "resolution binding")
        try:
            role = EndpointRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise EngineNetworkPolicyError("resolution binding role is invalid") from exc
        service_name = _text(row["service_name"], "resolution service name", maximum=63)
        raw_addresses = row["addresses"]
        if not isinstance(raw_addresses, list) or len(raw_addresses) != 1:
            raise EngineNetworkPolicyError("resolution binding must contain one address")
        addresses = tuple(str(_address(item, "resolved address")) for item in raw_addresses)
        return cls(role=role, service_name=service_name, addresses=addresses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "service_name": self.service_name,
            "addresses": list(self.addresses),
        }


@dataclass(frozen=True, slots=True)
class EffectiveNetworkSnapshot:
    schema_version: str
    attempt_id: str
    policy_digest: str
    network_identity_ref: str
    network_name: str
    subnet: str
    controller_address: str
    daemon_address: str
    enforcer_ref: str
    captured_at: str
    attached_network_identity_refs: tuple[str, ...]
    allowed_flows: tuple[NetworkFlow, ...]
    resolution_bindings: tuple[ResolutionBinding, ...]
    blocked_classes: tuple[str, ...]
    default_egress_deny: bool
    public_dns_blocked: bool
    metadata_blocked: bool
    host_gateway_blocked: bool
    controller_blocked: bool
    daemon_tcp_disabled: bool
    management_socket_exposed: bool
    redirects_revalidated: bool
    single_network_attachment: bool
    host_network_disabled: bool
    overlapping_host_routes_absent: bool
    host_loopback_unreachable: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "EffectiveNetworkSnapshot":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "effective network snapshot")
        if row["schema_version"] != "bluefire.engine-network-snapshot.v1":
            raise EngineNetworkPolicyError("effective network snapshot schema is unsupported")
        attempt_id = _text(row["attempt_id"], "snapshot attempt ID", maximum=47)
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineNetworkPolicyError("snapshot attempt ID is invalid")
        network_name = _text(row["network_name"], "snapshot network name", maximum=63)
        if _NETWORK_NAME.fullmatch(network_name) is None:
            raise EngineNetworkPolicyError("snapshot network name is invalid")
        flows_value = row["allowed_flows"]
        bindings_value = row["resolution_bindings"]
        blocked_value = row["blocked_classes"]
        if not isinstance(flows_value, list) or len(flows_value) > 2:
            raise EngineNetworkPolicyError("effective allowed flows are invalid")
        if not isinstance(bindings_value, list) or len(bindings_value) > 2:
            raise EngineNetworkPolicyError("effective resolution bindings are invalid")
        if not isinstance(blocked_value, list) or len(blocked_value) > len(_BLOCKED_CLASSES):
            raise EngineNetworkPolicyError("effective blocked classes are invalid")
        boolean_fields = (
            "default_egress_deny",
            "public_dns_blocked",
            "metadata_blocked",
            "host_gateway_blocked",
            "controller_blocked",
            "daemon_tcp_disabled",
            "management_socket_exposed",
            "redirects_revalidated",
            "single_network_attachment",
            "host_network_disabled",
            "overlapping_host_routes_absent",
            "host_loopback_unreachable",
        )
        if any(not isinstance(row[field], bool) for field in boolean_fields):
            raise EngineNetworkPolicyError("effective network control is not boolean")
        blocked = tuple(_text(item, "blocked network class", maximum=40) for item in blocked_value)
        if tuple(sorted(set(blocked))) != blocked or any(
            item not in _BLOCKED_CLASSES for item in blocked
        ):
            raise EngineNetworkPolicyError("effective blocked classes are not canonical")
        attached_value = row["attached_network_identity_refs"]
        if not isinstance(attached_value, list) or not 1 <= len(attached_value) <= 8:
            raise EngineNetworkPolicyError("effective network attachment set is invalid")
        attached = tuple(_digest(item, "attached network identity") for item in attached_value)
        if tuple(sorted(set(attached))) != attached:
            raise EngineNetworkPolicyError("effective network attachment set is not canonical")
        return cls(
            schema_version="bluefire.engine-network-snapshot.v1",
            attempt_id=attempt_id,
            policy_digest=_digest(row["policy_digest"], "snapshot policy"),
            network_identity_ref=_digest(row["network_identity_ref"], "snapshot network identity"),
            network_name=network_name,
            subnet=str(_private_network(row["subnet"])),
            controller_address=str(_address(row["controller_address"], "controller address")),
            daemon_address=str(_address(row["daemon_address"], "daemon address")),
            enforcer_ref=_digest(row["enforcer_ref"], "network enforcer"),
            captured_at=_timestamp(row["captured_at"], "network snapshot time"),
            attached_network_identity_refs=attached,
            allowed_flows=tuple(NetworkFlow.from_mapping(item) for item in flows_value),
            resolution_bindings=tuple(
                ResolutionBinding.from_mapping(item) for item in bindings_value
            ),
            blocked_classes=blocked,
            default_egress_deny=cast(bool, row["default_egress_deny"]),
            public_dns_blocked=cast(bool, row["public_dns_blocked"]),
            metadata_blocked=cast(bool, row["metadata_blocked"]),
            host_gateway_blocked=cast(bool, row["host_gateway_blocked"]),
            controller_blocked=cast(bool, row["controller_blocked"]),
            daemon_tcp_disabled=cast(bool, row["daemon_tcp_disabled"]),
            management_socket_exposed=cast(bool, row["management_socket_exposed"]),
            redirects_revalidated=cast(bool, row["redirects_revalidated"]),
            single_network_attachment=cast(bool, row["single_network_attachment"]),
            host_network_disabled=cast(bool, row["host_network_disabled"]),
            overlapping_host_routes_absent=cast(bool, row["overlapping_host_routes_absent"]),
            host_loopback_unreachable=cast(bool, row["host_loopback_unreachable"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "policy_digest": self.policy_digest,
            "network_identity_ref": self.network_identity_ref,
            "network_name": self.network_name,
            "subnet": self.subnet,
            "controller_address": self.controller_address,
            "daemon_address": self.daemon_address,
            "enforcer_ref": self.enforcer_ref,
            "captured_at": self.captured_at,
            "attached_network_identity_refs": list(self.attached_network_identity_refs),
            "allowed_flows": [flow.to_dict() for flow in self.allowed_flows],
            "resolution_bindings": [binding.to_dict() for binding in self.resolution_bindings],
            "blocked_classes": list(self.blocked_classes),
            "default_egress_deny": self.default_egress_deny,
            "public_dns_blocked": self.public_dns_blocked,
            "metadata_blocked": self.metadata_blocked,
            "host_gateway_blocked": self.host_gateway_blocked,
            "controller_blocked": self.controller_blocked,
            "daemon_tcp_disabled": self.daemon_tcp_disabled,
            "management_socket_exposed": self.management_socket_exposed,
            "redirects_revalidated": self.redirects_revalidated,
            "single_network_attachment": self.single_network_attachment,
            "host_network_disabled": self.host_network_disabled,
            "overlapping_host_routes_absent": self.overlapping_host_routes_absent,
            "host_loopback_unreachable": self.host_loopback_unreachable,
        }


@dataclass(frozen=True, slots=True)
class NetworkProbeResult:
    name: str
    address: str
    port: int
    outcome: ProbeOutcome

    @classmethod
    def from_mapping(cls, value: Any) -> "NetworkProbeResult":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "network probe result")
        name = _text(row["name"], "network probe name", maximum=40)
        address = str(_address(row["address"], "network probe address"))
        port = row["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise EngineNetworkPolicyError("network probe port is invalid")
        try:
            outcome = ProbeOutcome(row["outcome"])
        except (TypeError, ValueError) as exc:
            raise EngineNetworkPolicyError("network probe outcome is invalid") from exc
        return cls(name=name, address=address, port=port, outcome=outcome)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "port": self.port,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True, slots=True)
class EngineNetworkVerification:
    schema_version: str
    attempt_id: str
    policy_digest: str
    snapshot_digest: str
    enforcer_ref: str
    checked_at: str
    state: VerificationState
    limitations: tuple[str, ...]
    probes: tuple[NetworkProbeResult, ...]

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        plan: EngineNetworkPlan,
        snapshot: EffectiveNetworkSnapshot,
    ) -> "EngineNetworkVerification":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine network verification")
        if row["schema_version"] != "bluefire.engine-network-verification.v1":
            raise EngineNetworkPolicyError("engine network verification schema is unsupported")
        attempt_id = _text(row["attempt_id"], "verification attempt ID", maximum=47)
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineNetworkPolicyError("verification attempt ID is invalid")
        try:
            state = VerificationState(row["state"])
        except (TypeError, ValueError) as exc:
            raise EngineNetworkPolicyError("network verification state is invalid") from exc
        limitations_value = row["limitations"]
        probes_value = row["probes"]
        if not isinstance(limitations_value, list) or len(limitations_value) > 32:
            raise EngineNetworkPolicyError("network verification limitations are invalid")
        if not isinstance(probes_value, list) or len(probes_value) > 16:
            raise EngineNetworkPolicyError("network verification probes are invalid")
        limitations = tuple(
            _text(item, "network verification limitation", maximum=80) for item in limitations_value
        )
        if tuple(sorted(set(limitations))) != limitations:
            raise EngineNetworkPolicyError("network verification limitations are not canonical")
        if (state is VerificationState.VERIFIED) != (not limitations):
            raise EngineNetworkPolicyError("network verification state contradicts its limitations")
        probes = tuple(NetworkProbeResult.from_mapping(item) for item in probes_value)
        if len({probe.name for probe in probes}) != len(probes):
            raise EngineNetworkPolicyError("network verification probes contain duplicate names")
        result = cls(
            schema_version="bluefire.engine-network-verification.v1",
            attempt_id=attempt_id,
            policy_digest=_digest(row["policy_digest"], "verification policy"),
            snapshot_digest=_digest(row["snapshot_digest"], "verification snapshot"),
            enforcer_ref=_digest(row["enforcer_ref"], "verification enforcer"),
            checked_at=_timestamp(row["checked_at"], "network verification time"),
            state=state,
            limitations=limitations,
            probes=probes,
        )
        if result.to_dict() != json_clone(value):
            raise EngineNetworkPolicyError("engine network verification is not canonical")
        expected = verify_effective_network(
            plan,
            snapshot,
            probes,
            checked_at=result.checked_at,
        )
        if result != expected:
            raise EngineNetworkPolicyError(
                "engine network verification does not match its plan and snapshot"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "policy_digest": self.policy_digest,
            "snapshot_digest": self.snapshot_digest,
            "enforcer_ref": self.enforcer_ref,
            "checked_at": self.checked_at,
            "state": self.state.value,
            "limitations": list(self.limitations),
            "probes": [probe.to_dict() for probe in self.probes],
        }


class EngineNetworkObserver(Protocol):
    """Trusted outer enforcer/observer used by the integration boundary."""

    def capture(self, plan: EngineNetworkPlan) -> EffectiveNetworkSnapshot:
        """Return an effective policy snapshot captured outside the engine."""

    def probe(self, plan: EngineNetworkPlan) -> Sequence[NetworkProbeResult]:
        """Run the fixed allow/deny probe matrix outside model control."""


def _expected_flows(plan: EngineNetworkPlan) -> tuple[NetworkFlow, ...]:
    return (
        NetworkFlow(EndpointRole.TARGET, plan.target.address, plan.target.port),
        NetworkFlow(
            EndpointRole.MODEL_GATEWAY,
            plan.model_gateway.address,
            plan.model_gateway.port,
        ),
    )


def _expected_bindings(plan: EngineNetworkPlan) -> tuple[ResolutionBinding, ...]:
    return (
        ResolutionBinding(
            EndpointRole.TARGET,
            plan.target.service_name,
            (plan.target.address,),
        ),
        ResolutionBinding(
            EndpointRole.MODEL_GATEWAY,
            plan.model_gateway.service_name,
            (plan.model_gateway.address,),
        ),
    )


def required_probe_matrix(
    plan: EngineNetworkPlan,
) -> tuple[tuple[str, str, int, ProbeOutcome], ...]:
    """Return the closed probe matrix for the first journey."""

    return (
        ("target", plan.target.address, plan.target.port, ProbeOutcome.ALLOWED),
        (
            "model_gateway",
            plan.model_gateway.address,
            plan.model_gateway.port,
            ProbeOutcome.ALLOWED,
        ),
        ("public_dns_v4", "1.1.1.1", 53, ProbeOutcome.BLOCKED_BY_POLICY),
        (
            "public_dns_v6",
            "2606:4700:4700::1111",
            53,
            ProbeOutcome.BLOCKED_BY_POLICY,
        ),
        ("metadata_v4", "169.254.169.254", 80, ProbeOutcome.BLOCKED_BY_POLICY),
        ("metadata_v6", "fd00:ec2::254", 80, ProbeOutcome.BLOCKED_BY_POLICY),
        (
            "host_gateway",
            plan.host_gateway_address,
            443,
            ProbeOutcome.BLOCKED_BY_POLICY,
        ),
        (
            "controller",
            plan.controller_address,
            8443,
            ProbeOutcome.BLOCKED_BY_POLICY,
        ),
        (
            "daemon_tcp",
            plan.daemon_address,
            2375,
            ProbeOutcome.BLOCKED_BY_POLICY,
        ),
        ("other_egress", "9.9.9.9", 443, ProbeOutcome.BLOCKED_BY_POLICY),
        ("rebound_target", "9.9.9.10", plan.target.port, ProbeOutcome.BLOCKED_BY_POLICY),
    )


def verify_effective_network(
    plan: EngineNetworkPlan,
    snapshot: EffectiveNetworkSnapshot,
    probes: Sequence[NetworkProbeResult],
    *,
    checked_at: str,
) -> EngineNetworkVerification:
    """Validate one trusted outer snapshot and its fixed probe results."""

    plan = EngineNetworkPlan.from_mapping(plan.to_dict())
    snapshot = EffectiveNetworkSnapshot.from_mapping(snapshot.to_dict())
    probes = tuple(NetworkProbeResult.from_mapping(probe.to_dict()) for probe in probes)
    checked = _timestamp(checked_at, "network verification time")
    limitations: list[str] = []
    mismatches: list[str] = []
    expected_flows = _expected_flows(plan)
    expected_bindings = _expected_bindings(plan)
    if snapshot.schema_version != "bluefire.engine-network-snapshot.v1":
        mismatches.append("snapshot_schema_mismatch")
    if not (
        parse_iso8601_datetime(plan.created_at)
        <= parse_iso8601_datetime(snapshot.captured_at)
        <= parse_iso8601_datetime(checked)
    ):
        mismatches.append("snapshot_time_mismatch")
    if snapshot.attempt_id != plan.attempt_id:
        mismatches.append("attempt_mismatch")
    if snapshot.policy_digest != plan.policy_digest:
        mismatches.append("policy_digest_mismatch")
    if snapshot.network_identity_ref != plan.network_identity_ref:
        mismatches.append("network_identity_mismatch")
    if snapshot.network_name != plan.network_name or snapshot.subnet != plan.subnet:
        mismatches.append("network_shape_mismatch")
    if (
        snapshot.controller_address != plan.controller_address
        or snapshot.daemon_address != plan.daemon_address
    ):
        mismatches.append("management_location_mismatch")
    if snapshot.attached_network_identity_refs != (plan.network_identity_ref,):
        mismatches.append("network_attachment_mismatch")
    if snapshot.allowed_flows != expected_flows:
        mismatches.append("allowed_flows_mismatch")
    if snapshot.resolution_bindings != expected_bindings:
        mismatches.append("resolution_binding_mismatch")
    if snapshot.blocked_classes != _BLOCKED_CLASSES:
        mismatches.append("blocked_classes_mismatch")
    expected_controls = (
        snapshot.default_egress_deny,
        snapshot.public_dns_blocked,
        snapshot.metadata_blocked,
        snapshot.host_gateway_blocked,
        snapshot.controller_blocked,
        snapshot.daemon_tcp_disabled,
        not snapshot.management_socket_exposed,
        snapshot.redirects_revalidated,
        snapshot.single_network_attachment,
        snapshot.host_network_disabled,
        snapshot.overlapping_host_routes_absent,
        snapshot.host_loopback_unreachable,
    )
    if not all(expected_controls):
        mismatches.append("effective_control_mismatch")

    expected_probes = {
        name: (address, port, outcome)
        for name, address, port, outcome in required_probe_matrix(plan)
    }
    observed: dict[str, NetworkProbeResult] = {}
    for probe in probes:
        if probe.name not in expected_probes:
            raise EngineNetworkPolicyError("network probe is outside the fixed matrix")
        if probe.name in observed:
            raise EngineNetworkPolicyError("network probe result is duplicated")
        expected_address, expected_port, expected_outcome = expected_probes[probe.name]
        if probe.address != expected_address or probe.port != expected_port:
            raise EngineNetworkPolicyError("network probe destination does not match the matrix")
        observed[probe.name] = probe
        if probe.outcome is ProbeOutcome.INCONCLUSIVE:
            limitations.append(f"{probe.name}_inconclusive")
        elif probe.outcome is not expected_outcome:
            mismatches.append(f"{probe.name}_unexpected")
    for name in expected_probes:
        if name not in observed:
            limitations.append(f"{name}_missing")

    state = (
        VerificationState.MISMATCH
        if mismatches
        else VerificationState.UNKNOWN if limitations else VerificationState.VERIFIED
    )
    details = tuple(sorted(set(mismatches + limitations)))
    return EngineNetworkVerification(
        schema_version="bluefire.engine-network-verification.v1",
        attempt_id=plan.attempt_id,
        policy_digest=plan.policy_digest,
        snapshot_digest=content_hash(snapshot.to_dict()),
        enforcer_ref=snapshot.enforcer_ref,
        checked_at=checked,
        state=state,
        limitations=details,
        probes=tuple(observed[name] for name in expected_probes if name in observed),
    )


def observe_effective_network(
    plan: EngineNetworkPlan,
    observer: EngineNetworkObserver,
    *,
    checked_at: str,
) -> EngineNetworkVerification:
    """Capture then validate through an injected, trusted outer observer."""

    return verify_effective_network(
        plan,
        observer.capture(plan),
        observer.probe(plan),
        checked_at=checked_at,
    )


def validate_target_url(plan: EngineNetworkPlan, value: str) -> str:
    """Return a same-origin target URL or reject it as out of scope."""

    return _validate_url(plan.target, value, exact_path=False)


def validate_model_gateway_url(plan: EngineNetworkPlan, value: str) -> str:
    """Return the exact attempt-local model endpoint or reject it."""

    return _validate_url(plan.model_gateway, value, exact_path=True)


def _validate_url(endpoint: BoundNetworkEndpoint, value: str, *, exact_path: bool) -> str:
    text = _text(value, "engine network URL", maximum=2048)
    if "\\" in text or any(character.isspace() for character in text):
        raise EngineNetworkPolicyError("engine network URL is not canonical")
    parsed = urlsplit(text)
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise EngineNetworkPolicyError("engine network URL is outside the admitted origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise EngineNetworkPolicyError("engine network URL port is invalid") from exc
    if port != endpoint.port:
        raise EngineNetworkPolicyError("engine network URL port is outside scope")
    hostname = parsed.hostname.lower()
    if hostname not in {endpoint.service_name, endpoint.address.lower()}:
        raise EngineNetworkPolicyError("engine network URL host is outside scope")
    literal_host = f"[{endpoint.address}]" if ":" in endpoint.address else endpoint.address
    if parsed.netloc not in {
        f"{endpoint.service_name}:{endpoint.port}",
        f"{literal_host}:{endpoint.port}",
    }:
        raise EngineNetworkPolicyError("engine network URL authority is not canonical")
    if exact_path and (parsed.path != endpoint.path or parsed.query):
        raise EngineNetworkPolicyError("model gateway URL must use its exact path")
    if not parsed.path.startswith("/"):
        raise EngineNetworkPolicyError("engine network URL path is invalid")
    return text
