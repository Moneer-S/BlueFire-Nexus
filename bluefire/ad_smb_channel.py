"""Exact, separately reviewed control-plane authority for two AD host roles.

This is not the SMB/DNS/Kerberos network scope, a host attestation, or permission
to create a listener. It binds an already enrolled receiver to one address and
one profile. Ordinary runner transport remains loopback-only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .ad_smb_contract import AdSmbError, AdSmbScope, digest, exact
from .util import canonical_json_bytes, content_hash

SCHEMA = "bluefire.ad-smb-host-channel.v1"
_PRIVATE = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_FIELDS = {
    "schema_version",
    "scope_digest",
    "role",
    "host_id",
    "host_ipv4",
    "controller_ipv4",
    "port",
    "runner_id",
    "client_id",
    "profile_id",
    "profile_digest",
    "runner_binary_digest",
    "inventory_digest",
    "ca_fingerprint",
    "server_fingerprint",
    "client_fingerprint",
    "created_at",
    "expires_at",
    "policy_receipt_digest",
}


def _address(value: Any) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise AdSmbError("AD channel requires one canonical private IPv4 address") from None
    if str(address) != value or not any(address in network for network in _PRIVATE):
        raise AdSmbError("AD channel requires one canonical private IPv4 address")
    return str(address)


def _time(value: Any) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None
    ):
        raise AdSmbError("AD channel time must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise AdSmbError("AD channel time is invalid") from None


@dataclass(frozen=True)
class AdSmbHostChannel:
    _canonical: bytes

    @classmethod
    def from_mapping(cls, scope: AdSmbScope, value: Mapping[str, Any]) -> AdSmbHostChannel:
        import json

        try:
            row = json.loads(canonical_json_bytes(dict(value)))
        except (TypeError, ValueError):
            raise AdSmbError("AD channel document is invalid") from None
        exact(row, _FIELDS, "AD channel")
        if row["schema_version"] != SCHEMA or row["role"] not in {"member", "client"}:
            raise AdSmbError("AD channel schema or host role is unsupported")
        scoped = scope.to_dict()
        host = scoped["hosts"][row["role"]]
        if (
            row["scope_digest"] != scope.digest
            or row["host_id"] != host["host_id"]
            or row["host_ipv4"] != host["ipv4"]
        ):
            raise AdSmbError("AD channel does not bind the exact scope host")
        _address(row["host_ipv4"])
        controller = _address(row["controller_ipv4"])
        if controller in {item["ipv4"] for item in scoped["hosts"].values()}:
            raise AdSmbError("AD control-plane source must be a separate explicit host")
        if type(row["port"]) is not int or not 1024 <= row["port"] <= 65535:
            raise AdSmbError("AD channel port is invalid")
        for field in ("runner_id", "client_id", "profile_id"):
            if not isinstance(row[field], str) or _TOKEN.fullmatch(row[field]) is None:
                raise AdSmbError("AD channel identity is invalid")
        if row["runner_id"] == row["client_id"]:
            raise AdSmbError("AD channel peer identities must be distinct")
        for field in _FIELDS - {
            "schema_version",
            "role",
            "host_ipv4",
            "controller_ipv4",
            "port",
            "runner_id",
            "client_id",
            "profile_id",
            "created_at",
            "expires_at",
        }:
            digest(row[field])
        if (
            len(
                {row[key] for key in ("ca_fingerprint", "server_fingerprint", "client_fingerprint")}
            )
            != 3
        ):
            raise AdSmbError("AD channel certificate roles must be distinct")
        start, end = _time(row["created_at"]), _time(row["expires_at"])
        if end <= start or (end - start).total_seconds() > 86400:
            raise AdSmbError("AD channel lifetime is outside the finite enrollment bound")
        return cls(canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        import json

        return dict(json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def assert_current(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or not _time(self.to_dict()["created_at"]) <= now < _time(
            self.to_dict()["expires_at"]
        ):
            raise AdSmbError("AD channel enrollment is not currently valid")

    def address(self, value: str) -> str:
        if value != self.to_dict()["host_ipv4"]:
            raise AdSmbError("AD channel destination changed")
        return _address(value)
