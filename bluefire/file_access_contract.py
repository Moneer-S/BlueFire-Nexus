"""Closed Linux file-access execution projection, not client-minted authority."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .util import canonical_json_bytes, content_hash, json_clone

SCHEMA = "bluefire.file-access-execution.v1"
PROBE_ACTION = "file_access.probe.non_owner.v1"
OWNER_ACTION = "file_access.verify.owner.v1"
READ_ACTIONS = frozenset((PROBE_ACTION, OWNER_ACTION))
RESOURCE_PATH = "fixtures/transformed.jsonl"
PROBE_UID = 1002
OWNER_UID = 1000
MAX_BYTES = 1024 * 1024
MAX_REQUESTS = 64
MAX_REQUEST_MS = 5000
MAX_ENROLLMENT_MS = 900_000
MAX_REPORT_BYTES = 16 * 1024
ACL_ABSENT_DIGEST = content_hash(
    {"system.posix_acl_access": None, "system.posix_acl_default": None}
)
ANCHOR = "/run/bluefire-file-access"
ENROLLMENT_PATH = ANCHOR + "/enrollment.json"
NAMESPACE_KINDS = ("mnt", "net", "pid", "ipc")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = {
    "schema_version",
    "enrollment_id",
    "enrollment_digest",
    "expires_at_ms",
    "resource_id",
    "resource_generation",
    "control_revision",
    "mode",
    "resource",
    "worker",
}
_RESOURCE = {
    "root",
    "root_device",
    "root_inode",
    "parent_device",
    "parent_inode",
    "device",
    "inode",
    "owner_uid",
    "group_gid",
    "sha256",
    "size",
    "record_count",
    "acl_digest",
    "parent_acl_digest",
}
_WORKER = {"socket_path", "uid", "gid", "pid", "start_ticks", "launch_nonce", "namespaces"}
_OBSERVATION = {
    "schema_version",
    "reader",
    "request_hash",
    "challenge",
    "binding_digest",
    "resource_id",
    "resource_generation",
    "control_revision",
    "observed_at_ms",
    "outcome",
    "sha256",
    "size",
    "record_count",
    "mode",
    "principal",
    "resource",
    "closure",
}


class FileAccessContractError(ValueError):
    """The fixed enrolled resource or reader projection is invalid."""


def linux_attr(value: Any, name: str) -> Any:
    """Refuse missing Linux primitives instead of substituting weaker flags."""
    attribute = getattr(value, name, None)
    if attribute is None:
        raise FileAccessContractError("a required Linux file-access primitive is unavailable")
    return attribute


def exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise FileAccessContractError(f"{label} has unsupported fields")
    return value


def integer(value: Any, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise FileAccessContractError(f"{label} is outside its finite range")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FileAccessContractError(f"{label} is not a SHA-256 digest")
    return value


def identifier(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or re.fullmatch(prefix + r"-[0-9a-f]{32}", value) is None:
        raise FileAccessContractError(f"{prefix} identity is invalid")
    return value


def namespaces(value: Any) -> dict[str, str]:
    row = exact(value, set(NAMESPACE_KINDS), "namespace identity")
    for kind in NAMESPACE_KINDS:
        if (
            not isinstance(row[kind], str)
            or re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", row[kind]) is None
            or int(row[kind].split("[", 1)[1][:-1]) > 2**64 - 1
        ):
            raise FileAccessContractError("namespace identity is invalid")
    return dict(row)


def canonical_file_access_binding(value: Any) -> dict[str, Any]:
    row = exact(value, _FIELDS, "file-access binding")
    if row["schema_version"] != SCHEMA or row["mode"] not in ("0600", "0640"):
        raise FileAccessContractError("file-access binding version or mode is unsupported")
    identifier(row["enrollment_id"], "file-enrollment")
    identifier(row["resource_id"], "file-resource")
    generation = identifier(row["resource_generation"], "file-generation").rsplit("-", 1)[1]
    digest(row["enrollment_digest"], "enrollment digest")
    integer(row["expires_at_ms"], 1, 2**63 - 1, "enrollment expiry")
    integer(row["control_revision"], 1, 2**31 - 1, "control revision")
    resource = exact(row["resource"], _RESOURCE, "file-access resource")
    if resource["root"] != f"{ANCHOR}/data/{generation}":
        raise FileAccessContractError("resource is outside its fixed enrolled generation")
    for key in ("root_device", "parent_device", "device"):
        integer(resource[key], 0, 2**64 - 1, key)
    for key in ("root_inode", "parent_inode", "inode"):
        integer(resource[key], 1, 2**64 - 1, key)
    if (
        resource["root_device"] != resource["parent_device"]
        or resource["device"] != resource["root_device"]
    ):
        raise FileAccessContractError("resource crosses a filesystem boundary")
    integer(resource["owner_uid"], OWNER_UID, OWNER_UID, "resource owner")
    integer(resource["group_gid"], PROBE_UID, PROBE_UID, "resource group")
    digest(resource["sha256"], "resource content")
    if (
        resource["acl_digest"] != ACL_ABSENT_DIGEST
        or resource["parent_acl_digest"] != ACL_ABSENT_DIGEST
    ):
        raise FileAccessContractError(
            "the fixed mode-only resource must have no access or default ACL"
        )
    integer(resource["size"], 1, MAX_BYTES, "resource size")
    integer(resource["record_count"], 1, 100, "resource record count")
    worker = exact(row["worker"], _WORKER, "file-access worker")
    if worker["socket_path"] != f"{ANCHOR}/control/{generation}/probe.sock":
        raise FileAccessContractError("probe channel is outside its enrolled generation")
    integer(worker["uid"], PROBE_UID, PROBE_UID, "probe UID")
    integer(worker["gid"], PROBE_UID, PROBE_UID, "probe GID")
    integer(worker["pid"], 2, 2**31 - 1, "probe PID")
    integer(worker["start_ticks"], 1, 2**63 - 1, "probe process generation")
    if (
        not isinstance(worker["launch_nonce"], str)
        or re.fullmatch(r"[0-9a-f]{64}", worker["launch_nonce"]) is None
    ):
        raise FileAccessContractError("probe launch identity is invalid")
    namespaces(worker["namespaces"])
    return dict(json_clone(row))


class VerifiedFileAccessBinding:
    """Immutable trusted-store provenance; not an in-process security boundary."""

    __slots__ = ("_document",)
    _document: bytes

    def __init__(self) -> None:
        raise TypeError("Use the trusted stored file-access binding adapter")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Verified file-access provenance is immutable")

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self._document))


def verify_file_access_binding(
    document: Mapping[str, Any], *, expected_document_digest: str, now_ms: int
) -> VerifiedFileAccessBinding:
    """The expected digest must come from an independent durable control record.

    Call only after the controller independently checks live enrollment, resource
    generation, control revision and dependency reservation. A self-hash from a
    request is not such a record and this function does not perform those checks.
    """
    digest(expected_document_digest, "stored binding digest")
    integer(now_ms, 1, 2**63 - 1, "current time")
    value = canonical_file_access_binding(document)
    if (
        content_hash(value) != expected_document_digest
        or not 0 < value["expires_at_ms"] - now_ms <= MAX_ENROLLMENT_MS
    ):
        raise FileAccessContractError("file-access binding is changed or expired")
    verified = object.__new__(VerifiedFileAccessBinding)
    object.__setattr__(verified, "_document", canonical_json_bytes(value))
    return verified


def request_challenge(binding: Mapping[str, Any], request_hash: str) -> str:
    document = canonical_file_access_binding(binding)
    return content_hash(
        {
            "schema_version": "bluefire.file-access-challenge.v1",
            "request_hash": digest(request_hash, "request hash"),
            "binding_digest": content_hash(document),
            "launch_nonce": document["worker"]["launch_nonce"],
        }
    ).split(":", 1)[1]


def canonical_file_access_observation(value: Any) -> dict[str, Any]:
    row = exact(value, _OBSERVATION, "file-access observation")
    if (
        row["schema_version"] != "bluefire.file-access-observation.v1"
        or row["reader"] not in ("owner", "non_owner")
        or row["outcome"] not in ("allowed", "permission_denied")
        or row["mode"] not in ("0600", "0640")
    ):
        raise FileAccessContractError("file-access observation outcome is unsupported")
    for name in ("request_hash", "binding_digest"):
        digest(row[name], name)
    if (
        not isinstance(row["challenge"], str)
        or re.fullmatch(r"[0-9a-f]{64}", row["challenge"]) is None
    ):
        raise FileAccessContractError("file-access challenge is invalid")
    identifier(row["resource_id"], "file-resource")
    identifier(row["resource_generation"], "file-generation")
    integer(row["control_revision"], 1, 2**31 - 1, "control revision")
    integer(row["observed_at_ms"], 1, 2**63 - 1, "observation time")
    integer(row["size"], 1, MAX_BYTES, "observed size")
    if row["outcome"] == "allowed":
        digest(row["sha256"], "observed content")
        integer(row["record_count"], 1, 100, "observed count")
    elif row["reader"] == "owner" or row["sha256"] is not None or row["record_count"] is not None:
        raise FileAccessContractError(
            "denial cannot claim observed contents or legitimate owner success"
        )
    principal = exact(
        row["principal"], {"uid", "gid", "pid", "start_ticks", "namespaces"}, "observed principal"
    )
    uid = OWNER_UID if row["reader"] == "owner" else PROBE_UID
    integer(principal["uid"], uid, uid, "observed UID")
    integer(principal["gid"], uid, uid, "observed GID")
    integer(principal["pid"], 2, 2**31 - 1, "observed PID")
    integer(principal["start_ticks"], 1, 2**63 - 1, "observed process generation")
    namespaces(principal["namespaces"])
    resource = exact(row["resource"], (_RESOURCE - {"root"}) | {"mode"}, "observed resource")
    if resource["mode"] != row["mode"] or resource["size"] != row["size"]:
        raise FileAccessContractError("observed resource differs from read result")
    for key in ("root_device", "parent_device", "device"):
        integer(resource[key], 0, 2**64 - 1, key)
    for key in ("root_inode", "parent_inode", "inode"):
        integer(resource[key], 1, 2**64 - 1, key)
    integer(resource["owner_uid"], OWNER_UID, OWNER_UID, "observed resource owner")
    integer(resource["group_gid"], PROBE_UID, PROBE_UID, "observed resource group")
    digest(resource["sha256"], "independent resource content")
    integer(resource["record_count"], 1, 100, "independent resource count")
    if (
        resource["acl_digest"] != ACL_ABSENT_DIGEST
        or resource["parent_acl_digest"] != ACL_ABSENT_DIGEST
    ):
        raise FileAccessContractError("observed ACL policy is unsupported")
    if row["outcome"] == "allowed" and (resource["sha256"], resource["record_count"]) != (
        row["sha256"],
        row["record_count"],
    ):
        raise FileAccessContractError("successful read differs from independently observed data")
    closure = exact(
        row["closure"], {"state", "request_hash", "challenge", "principal_digest"}, "reader closure"
    )
    if closure != {
        "state": "verified_closed",
        "request_hash": row["request_hash"],
        "challenge": row["challenge"],
        "principal_digest": content_hash(principal),
    }:
        raise FileAccessContractError("reader closure is not bound to the exact request")
    return dict(json_clone(row))


def validate_file_access_observation(
    value: Any, *, binding: Mapping[str, Any], request_hash: str, reader: str
) -> dict[str, Any]:
    """Validate only after authenticated native terminal/request/profile checks."""
    document = canonical_file_access_binding(binding)
    row = canonical_file_access_observation(value)
    if (
        row["request_hash"] != digest(request_hash, "stored request hash")
        or row["challenge"] != request_challenge(document, request_hash)
        or row["reader"] != reader
        or row["binding_digest"] != content_hash(document)
        or any(
            row[key] != document[key]
            for key in ("resource_id", "resource_generation", "control_revision", "mode")
        )
        or row["observed_at_ms"] >= document["expires_at_ms"]
        or row["resource"]
        != {key: value for key, value in document["resource"].items() if key != "root"}
        | {"mode": document["mode"]}
        or row["principal"]["namespaces"] != document["worker"]["namespaces"]
    ):
        raise FileAccessContractError("observation differs from its independently bound resource")
    if reader == "non_owner" and any(
        row["principal"][key] != document["worker"][key] for key in row["principal"]
    ):
        raise FileAccessContractError("observation came from a different reader generation")
    return row


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise FileAccessContractError("duplicate probe field")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise FileAccessContractError("nonfinite probe value")
