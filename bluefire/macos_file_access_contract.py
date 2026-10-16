"""Darwin primitive documents, never serialized creator-custody authority."""

from __future__ import annotations

import json
import re
from typing import Any, cast

from .util import canonical_json_bytes, content_hash

BINDING_SCHEMA = "bluefire.macos-file-access-binding.v1"
REQUEST_SCHEMA = "bluefire.macos-file-access-request.v1"
OBSERVATION_SCHEMA = "bluefire.macos-file-access-observation.v1"
MAX_MESSAGE = 16 * 1024
MAX_BYTES = 1024 * 1024
MAX_REQUESTS = 64
MAX_OPERATION_NS = 5_000_000_000
MAX_ENROLLMENT_MS = 900_000
LEAF = "records.jsonl"
MONOTONIC_CLOCK = "darwin-mach-absolute-ns"
OPERATIONS = {"read_reader", "read_owner", "harden", "rollback", "close"}
_HEX = re.compile(r"[0-9a-f]+\Z")


class MacOSFileAccessContractError(ValueError):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise MacOSFileAccessContractError("The fixed Darwin primitive document is invalid.")


def _exact(value: Any, fields: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(fields.split()))
    return cast(dict[str, Any], value)


def _integer(value: Any, minimum: int = 0, maximum: int = 2**64 - 1) -> int:
    _require(type(value) is int and minimum <= value <= maximum)
    return cast(int, value)


def _hex(value: Any, size: int) -> None:
    _require(type(value) is str and len(value) == size and _HEX.fullmatch(value) is not None)


def _digest(value: Any) -> None:
    _require(type(value) is str and value.startswith("sha256:"))
    _hex(value[7:], 64)


def _identifier(value: Any, prefix: str) -> None:
    _require(type(value) is str and value.startswith(prefix))
    _hex(value[len(prefix) :], 32)


def validate_credentials(value: Any) -> dict[str, Any]:
    row = _exact(value, "real_uid effective_uid saved_uid real_gid effective_gid saved_gid groups")
    for field in ("real_uid", "effective_uid", "saved_uid"):
        _integer(row[field], 1, 2**32 - 2)
    for field in ("real_gid", "effective_gid", "saved_gid"):
        _integer(row[field], 1, 2**32 - 2)
    _require(row["real_uid"] == row["effective_uid"] == row["saved_uid"])
    _require(row["real_gid"] == row["effective_gid"] == row["saved_gid"])
    groups = row["groups"]
    _require(type(groups) is list and 1 <= len(groups) <= 64)
    for group in groups:
        _integer(group, 1, 2**32 - 2)
    _require(groups == sorted(set(groups)) and row["effective_gid"] in groups)
    return {**row, "groups": list(groups)}


def validate_binding(value: Any) -> dict[str, Any]:
    """Validate an inactive document; this does not authenticate its creator."""
    row = _exact(
        value,
        "schema_version enrollment_id generation custody_digest issued_at_ms expires_at_ms original_deadline_ns owner reader directory resource control_revision mode",
    )
    _require(row["schema_version"] == BINDING_SCHEMA)
    _identifier(row["enrollment_id"], "file-enrollment-")
    _identifier(row["generation"], "file-generation-")
    _digest(row["custody_digest"])
    issued = _integer(row["issued_at_ms"], 1, 2**63 - 1)
    expires = _integer(row["expires_at_ms"], issued + 1, 2**63 - 1)
    _require(expires - issued <= MAX_ENROLLMENT_MS)
    _integer(row["original_deadline_ns"], 1)
    _integer(row["control_revision"], 1, 2**31 - 1)
    _require(row["mode"] in ("0640", "0600"))
    owner, reader = (validate_credentials(row[key]) for key in ("owner", "reader"))
    _require(owner["effective_uid"] != reader["effective_uid"])
    directory = _exact(row["directory"], "device inode owner_uid group_gid mode")
    _integer(directory["device"])
    _integer(directory["inode"], 1)
    _require(type(directory["owner_uid"]) is int and directory["owner_uid"] == 0)
    _integer(directory["group_gid"], 1, 2**32 - 2)
    _require(directory["mode"] == "0550")
    _require(
        directory["group_gid"] in owner["groups"] and directory["group_gid"] in reader["groups"]
    )
    resource = _exact(
        row["resource"], "device inode owner_uid group_gid size_bytes record_count sha256"
    )
    _require(_integer(resource["device"]) == directory["device"])
    _integer(resource["inode"], 1)
    _require(resource["inode"] != directory["inode"])
    _require(type(resource["owner_uid"]) is int and resource["owner_uid"] == owner["effective_uid"])
    _integer(resource["group_gid"], 1, 2**32 - 2)
    _require(resource["group_gid"] in reader["groups"])
    _integer(resource["size_bytes"], 1, MAX_BYTES)
    _require(type(resource["record_count"]) is int and resource["record_count"] == 8)
    _digest(resource["sha256"])
    result = {
        **row,
        "owner": owner,
        "reader": reader,
        "directory": dict(directory),
        "resource": dict(resource),
    }
    _require(len(canonical_json_bytes(result)) <= MAX_MESSAGE)
    return result


def validate_request(
    value: Any, *, now_ms: int | None = None, now_ns: int | None = None
) -> dict[str, Any]:
    row = _exact(
        value,
        "schema_version binding binding_digest request_id sequence operation issued_at_ms expires_at_ms issued_monotonic_ns deadline_ns",
    )
    _require(row["schema_version"] == REQUEST_SCHEMA)
    binding = validate_binding(row["binding"])
    _require(row["binding_digest"] == content_hash(binding))
    _hex(row["request_id"], 64)
    _integer(row["sequence"], 1, MAX_REQUESTS)
    _require(type(row["operation"]) is str and row["operation"] in OPERATIONS)
    issued = _integer(row["issued_at_ms"], binding["issued_at_ms"], binding["expires_at_ms"] - 1)
    expires = _integer(row["expires_at_ms"], issued + 1, binding["expires_at_ms"])
    _require(expires - issued <= 5000)
    started = _integer(row["issued_monotonic_ns"], 1)
    deadline = _integer(row["deadline_ns"], started + 1, binding["original_deadline_ns"])
    _require(deadline - started <= MAX_OPERATION_NS)
    if now_ms is not None:
        _require(issued <= _integer(now_ms) < expires)
    if now_ns is not None:
        _require(started <= _integer(now_ns) < deadline)
    result = {**row, "binding": binding}
    _require(len(canonical_json_bytes(result)) <= MAX_MESSAGE)
    return result


def decode_request(raw: bytes, **clock: int) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_MESSAGE)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: _require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise MacOSFileAccessContractError(
            "The fixed Darwin primitive document is invalid."
        ) from None
    return validate_request(value, **clock)


def validate_observation(value: Any, request: Any) -> dict[str, Any]:
    """Join local primitive evidence, not whole-process cleanup or prevention."""
    original = validate_request(request)
    binding, operation = original["binding"], original["operation"]
    row = _exact(
        value,
        "schema_version binding_digest request_id sequence operation outcome principal fresh_read held_control request_handle_cleanup held_handle_cleanup custody prevention_proven",
    )
    _require(row["schema_version"] == OBSERVATION_SCHEMA)
    for field in ("binding_digest", "request_id", "sequence", "operation"):
        _require(type(row[field]) is type(original[field]) and row[field] == original[field])
    _require(row["custody"] == "requires_original_creator_evidence")
    _require(row["prevention_proven"] is False)
    _require(row["request_handle_cleanup"] in ("not_opened", "closed", "unknown"))
    _require(row["held_handle_cleanup"] in ("retained", "closed", "unknown"))
    _require(
        row["outcome"] in ("allowed", "denied", "mode_changed", "closed", "refused", "unknown")
    )
    principal = None if row["principal"] is None else validate_credentials(row["principal"])
    if row["outcome"] in ("allowed", "denied", "mode_changed"):
        role = "reader" if operation == "read_reader" else "owner"
        _require(principal == binding[role] and row["held_handle_cleanup"] == "retained")
    fresh, held, resource = row["fresh_read"], row["held_control"], binding["resource"]
    if row["outcome"] == "allowed":
        _require(operation in ("read_reader", "read_owner") and held is None)
        fresh = _exact(fresh, "device inode mode size_bytes record_count sha256")
        _require(fresh["mode"] == binding["mode"] and row["request_handle_cleanup"] == "closed")
        for field in ("device", "inode", "size_bytes", "record_count", "sha256"):
            _require(
                type(fresh[field]) is type(resource[field]) and fresh[field] == resource[field]
            )
    elif row["outcome"] == "mode_changed":
        _require(operation in ("harden", "rollback") and fresh is None)
        held = _exact(held, "device inode before_mode after_mode size_bytes record_count sha256")
        _require(held["before_mode"] == binding["mode"])
        _require(held["after_mode"] == ("0600" if operation == "harden" else "0640"))
        _require(held["before_mode"] != held["after_mode"])
        _require(row["request_handle_cleanup"] == "not_opened")
        for field in ("device", "inode", "size_bytes", "record_count", "sha256"):
            _require(type(held[field]) is type(resource[field]) and held[field] == resource[field])
    else:
        _require(fresh is None and held is None)
        if row["outcome"] == "denied":
            _require(operation in ("read_reader", "read_owner"))
            _require(row["request_handle_cleanup"] == "not_opened")
        elif row["outcome"] == "closed":
            _require(operation == "close" and row["held_handle_cleanup"] == "closed")
    result = {**row, "principal": principal, "fresh_read": fresh, "held_control": held}
    _require(len(canonical_json_bytes(result)) <= MAX_MESSAGE)
    return result


class OwnedMacOSAuthority:
    """Only the concrete original creator may mint this live, nonreloadable type."""

    __slots__ = ("_binding", "_producer", "_lease")
    _binding: dict[str, Any]
    _producer: object
    _lease: object

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("A live original creator custody producer is required.")

    def document(self) -> dict[str, Any]:
        return validate_binding(self._binding)

    @property
    def binding_digest(self) -> str:
        return content_hash(self.document())
