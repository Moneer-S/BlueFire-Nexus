"""Exact retained-kernel and planned-input identities for Strix containment."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, cast

from .util import content_hash


class StrixWorkerContainmentError(ValueError):
    """A worker containment document is not exact or internally consistent."""


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
INPUT_KINDS = ("config", "mcp", "objective")
RELAY_PURPOSES = ("caido", "model")


def exact(value: Any, fields: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise StrixWorkerContainmentError(f"{label} fields do not match the contract")
    return value


def text(value: Any, label: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise StrixWorkerContainmentError(f"{label} is invalid")
    return value


def digest(value: Any, label: str) -> str:
    result = text(value, label, 71)
    if _DIGEST_PATTERN.fullmatch(result) is None:
        raise StrixWorkerContainmentError(f"{label} must be a sha256 digest")
    return result


def integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise StrixWorkerContainmentError(f"{label} is outside its bound")
    return int(value)


def retained_kernel_identity_digest(
    *, role: str, st_dev: int, st_ino: int, host: str | None = None, port: int | None = None
) -> str:
    """Hash retained-fd identity; controller owner/listener refs remain opaque ledger refs."""
    endpoint = host is not None or port is not None
    if endpoint and (host != "127.0.0.1" or port is None):
        raise StrixWorkerContainmentError("kernel endpoint identity is not exact loopback")
    value: dict[str, Any] = {
        "schema_version": "bluefire.retained-kernel-identity.v1",
        "role": text(role, "kernel identity role", 64),
        "st_dev": integer(st_dev, "kernel identity device", 0, 2**64 - 1),
        "st_ino": integer(st_ino, "kernel identity inode", 1, 2**64 - 1),
    }
    if endpoint:
        value.update(
            {
                "transport": "tcp",
                "host": host,
                "port": integer(port, "kernel endpoint port", 1024, 65535),
            }
        )
    return cast(str, content_hash(value))


@dataclass(frozen=True, slots=True)
class SealedInputPlan:
    kind: str
    content_digest: str
    byte_length: int
    fd_identity_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "SealedInputPlan":
        row = exact(value, set(cls.__dataclass_fields__), "sealed input plan")
        result = cls(
            kind=text(row["kind"], "sealed input kind", 16),
            content_digest=digest(row["content_digest"], "sealed input content"),
            byte_length=integer(row["byte_length"], "sealed input length", 1, 4 * 1024 * 1024),
            fd_identity_digest=digest(
                row["fd_identity_digest"], "sealed input descriptor identity"
            ),
        )
        if result.kind not in INPUT_KINDS:
            raise StrixWorkerContainmentError("sealed input kind is unsupported")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "content_digest": self.content_digest,
            "byte_length": self.byte_length,
            "fd_identity_digest": self.fd_identity_digest,
        }


@dataclass(frozen=True, slots=True)
class RelayPlan:
    purpose: str
    relay_ref: str
    owner_ref: str
    owner_process_ref: str
    listener_ref: str
    socket_identity_digest: str
    socket_st_dev: int
    socket_st_ino: int
    network_namespace_ref: str
    network_namespace_st_dev: int
    network_namespace_st_ino: int
    transport: str
    host: str
    port: int

    @classmethod
    def from_mapping(cls, value: Any) -> "RelayPlan":
        row = exact(value, set(cls.__dataclass_fields__), "worker relay plan")
        result = cls(
            purpose=text(row["purpose"], "relay purpose", 16),
            relay_ref=digest(row["relay_ref"], "relay reference"),
            owner_ref=digest(row["owner_ref"], "relay owner"),
            owner_process_ref=digest(row["owner_process_ref"], "relay owner process"),
            listener_ref=digest(row["listener_ref"], "relay listener"),
            socket_identity_digest=digest(row["socket_identity_digest"], "relay socket identity"),
            socket_st_dev=integer(row["socket_st_dev"], "relay socket device", 0, 2**64 - 1),
            socket_st_ino=integer(row["socket_st_ino"], "relay socket inode", 1, 2**64 - 1),
            network_namespace_ref=digest(row["network_namespace_ref"], "relay network namespace"),
            network_namespace_st_dev=integer(
                row["network_namespace_st_dev"], "relay namespace device", 0, 2**64 - 1
            ),
            network_namespace_st_ino=integer(
                row["network_namespace_st_ino"], "relay namespace inode", 1, 2**64 - 1
            ),
            transport=text(row["transport"], "relay transport", 8),
            host=text(row["host"], "relay host", 15),
            port=integer(row["port"], "relay port", 1024, 65535),
        )
        if (
            result.purpose not in RELAY_PURPOSES
            or result.transport != "tcp"
            or result.host != "127.0.0.1"
        ):
            raise StrixWorkerContainmentError("worker relay is not exact loopback authority")
        if result.socket_identity_digest != retained_kernel_identity_digest(
            role=f"relay-socket:{result.purpose}",
            st_dev=result.socket_st_dev,
            st_ino=result.socket_st_ino,
            host=result.host,
            port=result.port,
        ) or result.network_namespace_ref != retained_kernel_identity_digest(
            role="worker-network-namespace",
            st_dev=result.network_namespace_st_dev,
            st_ino=result.network_namespace_st_ino,
        ):
            raise StrixWorkerContainmentError("worker relay kernel identity is invalid")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}
