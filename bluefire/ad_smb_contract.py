"""Finite AD/SMB review contracts, not enrollment or remote execution authority."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

SCHEMA = "bluefire.ad-smb-scope.v1"
MAX_DOCUMENT_BYTES = 256 * 1024
LIMIT_CEILINGS = {
    "generated_bytes": 65536,
    "returned_payload_bytes": 1048576,
    "business_attempts": 6,
    "sessions": 6,
    "session_seconds": 900,
    "business_seconds": 1800,
    "audit_seconds": 600,
    "cleanup_seconds": 900,
    "operation_seconds": 60,
    "audit_events": 1000,
    "audit_bytes": 4194304,
    "share_changes": 1,
    "rollbacks": 1,
}
# Audit rows are capped at 1,000 with fixed-schema bounded fields; reserve 1 MiB
# beyond the 4 MiB capture ceiling for their serialized projection and envelope.
MAX_AUDIT_EXECUTION_BYTES = LIMIT_CEILINGS["audit_bytes"] + 1024 * 1024
_HEX32 = re.compile(r"[0-9a-f]{32}", re.ASCII)
_VOLUME = re.compile(r"[0-9a-f]{16}", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SID = re.compile(r"S-1-([0-9]+)((?:-[0-9]+){1,15})", re.ASCII)
_PRIVATE = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class AdSmbError(ValueError):
    """Sanitized refusal of a scope or descriptor outside this finite recipe."""


def exact(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise AdSmbError(f"{label} fields do not match the closed schema")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdSmbError("duplicate JSON keys are not supported")
        result[key] = value
    return result


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise AdSmbError("nonfinite JSON numbers are not supported")
    return result


def _constant(_: str) -> Any:
    raise AdSmbError("nonfinite JSON numbers are not supported")


def document(value: Any, *, limit: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        if isinstance(value, Mapping):
            raw = canonical_json_bytes(value)
        elif isinstance(value, str):
            raw = value.encode("utf-8")
        elif type(value) is bytes:
            raw = value
        else:
            raise AdSmbError("document must be a bounded JSON object")
        if len(raw) > limit:
            raise AdSmbError("document exceeds its byte bound")
        parsed = json.loads(
            raw, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant
        )
        if not isinstance(parsed, dict):
            raise AdSmbError("document must be a JSON object")
        return parsed
    except (UnicodeError, TypeError, ValueError, RecursionError):
        raise AdSmbError("document is not supported bounded JSON") from None


def digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdSmbError("digest is invalid")
    return value


def sid(value: Any) -> str:
    match = _SID.fullmatch(value) if isinstance(value, str) and len(value) <= 184 else None
    if match is None:
        raise AdSmbError("SID is not a canonical numeric SID")
    parts = value.split("-")[2:]
    if (
        any(str(int(part)) != part for part in parts)
        or int(parts[0]) >= 2**48
        or any(int(part) >= 2**32 for part in parts[1:])
    ):
        raise AdSmbError("SID components are invalid")
    return str(value)


def timestamp(value: Any) -> datetime:
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        return parse_iso8601_datetime(value).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise AdSmbError("timestamp must be bounded and timezone aware") from None


def _dns(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 253
        or len(value.split(".")) < 2
        or any(_DNS.fullmatch(part) is None for part in value.split("."))
    ):
        raise AdSmbError("DNS name must be a canonical explicit FQDN")
    return value


def _hex32(value: Any) -> str:
    if not isinstance(value, str) or _HEX32.fullmatch(value) is None:
        raise AdSmbError("generated identity is invalid")
    return value


def volume_serial_from_native(value: Any) -> str:
    """Normalize an exact server-parsed u64, without authenticating its source."""
    if type(value) is not int or not 0 <= value < 2**64:
        raise AdSmbError("native volume serial must be an exact unsigned 64-bit integer")
    return f"{value:016x}"


def _hosts(row: dict[str, Any]) -> None:
    hosts = row["hosts"]
    exact(hosts, {"dc", "member", "client"}, "hosts")
    for role, host in hosts.items():
        exact(
            host,
            {
                "host_id",
                "fqdn",
                "ipv4",
                "os_product",
                "os_build",
                "architecture",
                "identity_receipt_digest",
            },
            "host",
        )
        digest(host["host_id"])
        digest(host["identity_receipt_digest"])
        _dns(host["fqdn"])
        if not host["fqdn"].endswith("." + row["domain"]["dns"]):
            raise AdSmbError("host does not belong to the exact domain")
        try:
            address = ipaddress.IPv4Address(host["ipv4"])
        except (ValueError, TypeError, ipaddress.AddressValueError):
            raise AdSmbError("host requires one explicit private IPv4 address") from None
        if str(address) != host["ipv4"] or not any(address in network for network in _PRIVATE):
            raise AdSmbError("host address is outside the supported private lab range")
        expected_product = "windows_client" if role == "client" else "windows_server_2022"
        if (
            host["os_product"] != expected_product
            or host["architecture"] != "x86_64"
            or not isinstance(host["os_build"], str)
            or re.fullmatch(r"10\.0\.[1-9][0-9]{3,5}\.[0-9]{1,8}", host["os_build"]) is None
        ):
            raise AdSmbError("host operating-system identity is unsupported")
        if role != "client" and not host["os_build"].startswith("10.0.20348."):
            raise AdSmbError("server build does not identify Server 2022")
    for key in ("host_id", "fqdn", "ipv4"):
        if len({host[key] for host in hosts.values()}) != 3:
            raise AdSmbError("three distinct exact hosts are required")


def _principals(row: dict[str, Any]) -> None:
    principals = row["principals"]
    exact(principals, {"controller", "probe", "legitimate"}, "principals")
    for principal in principals.values():
        exact(
            principal,
            {
                "sid",
                "kind",
                "credential_handle",
                "group_sids",
                "sid_history",
                "identity_receipt_digest",
            },
            "principal",
        )
        value = sid(principal["sid"])
        if (
            value.rsplit("-", 1)[0] != row["domain"]["sid"]
            or int(value.rsplit("-", 1)[1]) < 1000
            or principal["kind"] != "domain_user"
        ):
            raise AdSmbError("principal must be an explicit same-domain non-built-in user")
        handle = principal["credential_handle"]
        if not isinstance(handle, str) or re.fullmatch(r"credential-[0-9a-f]{32}", handle) is None:
            raise AdSmbError("only an opaque protected credential handle is accepted")
        digest(principal["identity_receipt_digest"])
        groups = principal["group_sids"]
        if (
            principal["sid_history"] != []
            or not isinstance(groups, list)
            or len(groups) > 64
            or len(set(sid(group) for group in groups)) != len(groups)
        ):
            raise AdSmbError("SID history or ambiguous group context is unsupported")
        principal["group_sids"] = sorted(groups)
    if any(
        len({principal[key] for principal in principals.values()}) != 3
        for key in ("sid", "credential_handle")
    ):
        raise AdSmbError("principals and protected handles must be distinct")
    user_sids = {principal["sid"] for principal in principals.values()}
    if any(user_sids.intersection(principal["group_sids"]) for principal in principals.values()):
        raise AdSmbError("reader/controller aliases or group routes are unsupported")
    reader_groups = {row["domain"]["sid"] + "-513", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
    if any(
        not set(principals[name]["group_sids"]).issubset(reader_groups)
        for name in ("probe", "legitimate")
    ):
        raise AdSmbError("reader group context is privileged or outside the finite recipe")


def _network(row: dict[str, Any]) -> None:
    value = row["network"]
    exact(value, {"flows", "policy_receipt_digest", "kernel_traffic_metered"}, "network")
    digest(value["policy_receipt_digest"])
    if value["kernel_traffic_metered"] is not False:
        raise AdSmbError("returned payload limits do not meter kernel network traffic")
    flows = value["flows"]
    if not isinstance(flows, list) or not 3 <= len(flows) <= 24:
        raise AdSmbError("network flows must be explicit and finite")
    keys: list[tuple[str, str, str, int, int]] = []
    for flow in flows:
        exact(
            flow,
            {"source", "destination", "transport", "port_from", "port_through"},
            "network flow",
        )
        start, end = flow["port_from"], flow["port_through"]
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
            raise AdSmbError("network port interval is invalid")
        key = (flow["source"], flow["destination"], flow["transport"], start, end)
        business = key == ("client", "member", "tcp", 445, 445)
        infrastructure = (
            flow["source"] in ("client", "member")
            and flow["destination"] == "dc"
            and (
                start == end
                and (
                    (flow["transport"] == "tcp" and start in {53, 88, 135, 389, 445, 636})
                    or (flow["transport"] == "udp" and start in {53, 88, 123, 389})
                )
                or flow["transport"] == "tcp"
                and 49152 <= start <= end
                and end - start < 256
            )
        )
        if not (business or infrastructure) or key in keys:
            raise AdSmbError("network flow is unsupported or duplicated")
        if any(key[:3] == other[:3] and start <= other[4] and end >= other[3] for other in keys):
            raise AdSmbError("network flow intervals overlap")
        keys.append(key)
    required = {
        ("client", "member", "tcp", 445, 445),
        ("client", "dc", "udp", 53, 53),
        ("client", "dc", "tcp", 88, 88),
    }
    if not required.issubset(keys):
        raise AdSmbError("exact SMB, DNS and Kerberos client flows must be declared")
    value["flows"] = [
        dict(
            zip(
                ("source", "destination", "transport", "port_from", "port_through"),
                key,
                strict=True,
            )
        )
        for key in sorted(keys)
    ]


def _resource(row: dict[str, Any]) -> None:
    share = row["share"]
    exact(
        share,
        {
            "name",
            "local_root",
            "unc",
            "identity_digest",
            "root_file_id",
            "volume_serial",
            "root_ntfs_digest",
            "baseline_descriptor_digest",
            "dfs",
            "administrative",
        },
        "share",
    )
    expected_name = "bf_" + row["scope_id"]
    expected_unc = "\\\\" + row["hosts"]["member"]["fqdn"] + "\\" + expected_name
    if (
        share["name"] != expected_name
        or share["unc"] != expected_unc
        or share["dfs"] is not False
        or share["administrative"] is not False
    ):
        raise AdSmbError("share must be the exact generated non-DFS non-administrative target")
    root = share["local_root"]
    if (
        not isinstance(root, str)
        or re.fullmatch(r"[C-Z]:\\BlueFire\\AD\\" + row["scope_id"], root) is None
    ):
        raise AdSmbError("share root must be the exact generated local directory")
    _hex32(share["root_file_id"])
    if (
        not isinstance(share["volume_serial"], str)
        or _VOLUME.fullmatch(share["volume_serial"]) is None
    ):
        raise AdSmbError("volume serial must preserve all 64 bits as canonical lowercase hex")
    for key in ("identity_digest", "root_ntfs_digest", "baseline_descriptor_digest"):
        digest(share[key])
    files = row["files"]
    if not isinstance(files, list) or len(files) != 2:
        raise AdSmbError("exactly two generated files are required")
    for entry, purpose, name in zip(
        files, ("primary", "health"), ("records.jsonl", "health.jsonl"), strict=True
    ):
        exact(
            entry,
            {
                "purpose",
                "name",
                "file_id",
                "volume_serial",
                "sha256",
                "size_bytes",
                "records",
                "ntfs_digest",
            },
            "file",
        )
        if entry["purpose"] != purpose or entry["name"] != name:
            raise AdSmbError("generated file path or purpose is invalid")
        _hex32(entry["file_id"])
        if entry["volume_serial"] != share["volume_serial"]:
            raise AdSmbError("generated files must bind the exact reviewed root volume")
        digest(entry["sha256"])
        digest(entry["ntfs_digest"])
        if (
            type(entry["size_bytes"]) is not int
            or not 1 <= entry["size_bytes"] <= row["limits"]["generated_bytes"]
            or type(entry["records"]) is not int
            or not 1 <= entry["records"] <= (32 if purpose == "primary" else 1)
        ):
            raise AdSmbError("generated content bounds are invalid")
    if (
        sum(entry["size_bytes"] for entry in files) > row["limits"]["generated_bytes"]
        or len({share["root_file_id"], *(entry["file_id"] for entry in files)}) != 3
    ):
        raise AdSmbError("generated content size or identity is ambiguous")


@dataclass(frozen=True, slots=True)
class AdSmbScope:
    _canonical: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, value: Any) -> "AdSmbScope":
        row = document(value)
        exact(
            row,
            {
                "schema_version",
                "scope_id",
                "domain",
                "hosts",
                "principals",
                "share",
                "files",
                "authentication",
                "network",
                "limits",
                "created_at",
                "expires_at",
                "ownership_receipt_digest",
                "readiness_receipt_digest",
                "exclusive_writer_receipt_digest",
                "native_parser_digest",
            },
            "AD scope",
        )
        if row["schema_version"] != SCHEMA:
            raise AdSmbError("AD scope schema is unsupported")
        _hex32(row["scope_id"])
        exact(row["domain"], {"dns", "sid"}, "domain")
        _dns(row["domain"]["dns"])
        domain_sid = sid(row["domain"]["sid"])
        if re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+", domain_sid) is None:
            raise AdSmbError("one exact AD domain SID is required")
        for key in (
            "ownership_receipt_digest",
            "readiness_receipt_digest",
            "exclusive_writer_receipt_digest",
            "native_parser_digest",
        ):
            digest(row[key])
        exact(row["limits"], set(LIMIT_CEILINGS), "limits")
        for name, ceiling in LIMIT_CEILINGS.items():
            number = row["limits"][name]
            if type(number) is not int or not 1 <= number <= ceiling:
                raise AdSmbError("scope limit exceeds the finite recipe")
        if (
            not row["limits"]["operation_seconds"]
            <= row["limits"]["session_seconds"]
            <= row["limits"]["business_seconds"]
        ):
            raise AdSmbError("operation/session limits exceed the business phase")
        created, expires = timestamp(row["created_at"]), timestamp(row["expires_at"])
        lifetime = sum(
            row["limits"][name] for name in ("business_seconds", "audit_seconds", "cleanup_seconds")
        )
        if not 0 < (expires - created).total_seconds() <= lifetime:
            raise AdSmbError("scope lifetime exceeds its explicit phase limits")
        row["created_at"], row["expires_at"] = created.isoformat(), expires.isoformat()
        _hosts(row)
        _principals(row)
        _resource(row)
        auth = row["authentication"]
        exact(
            auth,
            {
                "package",
                "spn",
                "signing_required",
                "encryption_required",
                "ntlm_fallback",
                "mutual_authentication_required",
                "hardened_unc_receipt_digest",
            },
            "authentication",
        )
        digest(auth["hardened_unc_receipt_digest"])
        if auth != {
            "package": "Kerberos",
            "spn": "cifs/" + row["hosts"]["member"]["fqdn"],
            "signing_required": True,
            "encryption_required": True,
            "ntlm_fallback": False,
            "mutual_authentication_required": True,
            "hardened_unc_receipt_digest": auth["hardened_unc_receipt_digest"],
        } or any(
            type(auth[key]) is not bool
            for key in (
                "signing_required",
                "encryption_required",
                "ntlm_fallback",
                "mutual_authentication_required",
            )
        ):
            raise AdSmbError("only exact Kerberos SMB authentication without fallback is supported")
        _network(row)
        return cls(canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        return document(self._canonical)

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def assert_current(self, clock: Callable[[], datetime]) -> None:
        row = self.from_mapping(self.to_dict()).to_dict()
        now = clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
            or not timestamp(row["created_at"]) <= now < timestamp(row["expires_at"])
        ):
            raise AdSmbError("scope is not current")


@dataclass(frozen=True, slots=True)
class AdSmbReadTarget:
    """Pure expected-target projection, not admission or an observed identity.

    The protected adapter must authenticate the member's file/volume observation,
    reader credential binding and enrolled client before constructing PreparedRead.
    NEW_CREDENTIALS local TokenUser and LUID belong only to the later native result.
    """

    _scope: AdSmbScope = field(repr=False)
    reader: str
    purpose: str

    @classmethod
    def from_scope(cls, scope: AdSmbScope, *, reader: str, purpose: str) -> "AdSmbReadTarget":
        target = cls(AdSmbScope.from_mapping(scope.to_dict()), reader, purpose)
        target.to_dict()
        return target

    def to_dict(self) -> dict[str, Any]:
        scope = AdSmbScope.from_mapping(self._scope.to_dict())
        row = scope.to_dict()
        if (
            self.reader not in ("probe", "legitimate")
            or self.purpose not in ("primary", "health")
            or (self.reader == "probe" and self.purpose == "health")
        ):
            raise AdSmbError("read target is outside the fixed reader/file recipe")
        entry = next(item for item in row["files"] if item["purpose"] == self.purpose)
        return {
            "schema_version": "bluefire.ad-smb-read-target.v1",
            "scope_digest": scope.digest,
            "scope_id": row["scope_id"],
            "reader": self.reader,
            "expected_remote_sid": row["principals"][self.reader]["sid"],
            "member_host_id": row["hosts"]["member"]["host_id"],
            "client_host_id": row["hosts"]["client"]["host_id"],
            "member_fqdn": row["hosts"]["member"]["fqdn"],
            "share_unc": row["share"]["unc"],
            "file": entry,
            "hardened_unc_receipt_digest": row["authentication"]["hardened_unc_receipt_digest"],
            "admission_verified": False,
            "authenticated_remote_reader": False,
            "effective_access_claim": False,
        }

    def native_target_arguments(self) -> tuple[str, str, str, str, int, str, int]:
        """ReadTarget::new arguments; the numeric u64 stays out of public JSON."""
        row = self.to_dict()
        entry = row["file"]
        return (
            row["member_fqdn"],
            row["scope_id"],
            entry["purpose"],
            entry["file_id"],
            int(entry["volume_serial"], 16),
            entry["sha256"],
            entry["size_bytes"],
        )
