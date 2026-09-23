"""Closed handoff identity for one committed service intent; never authority.

The future runner must independently authenticate the reviewed scope, resolve the
installation digests, recheck live resource identity and reserve its own durable
effect receipt. This document cannot authorize, dispatch or replay an operation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, cast

from ..contracts import ContractError
from ..util import canonical_json_bytes, content_hash
from .service_lifecycle import OwnedUserService

SCHEMA = "bluefire.service-operation-binding.v1"
MAX_BYTES = 8192
OPERATIONS = frozenset(
    {
        "create_unit",
        "reload",
        "enable",
        "start",
        "stop",
        "disable",
        "remove_links",
        "remove_unit",
        "reload_after_cleanup",
    }
)
_FIELDS = frozenset(
    "schema_version identity identity_digest journal_request_id journal_revision "
    "journal_record_hash operation_id operation reviewed_scope_digest "
    "manager_installation_digest payload_installation_digest".split()
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")


def _fail(message: str) -> ContractError:
    return ContractError("service operation binding: " + message)


def _text(value: Any, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or len(value) > 128 or pattern.fullmatch(value) is None:
        raise _fail("invalid identifier or digest")


def _canonical(value: Any) -> bytes:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise _fail("document must contain exactly its declared fields")
    data = dict(value)
    if data["schema_version"] != SCHEMA:
        raise _fail("unsupported schema")
    identity = OwnedUserService.from_mapping(data["identity"])
    data["identity"] = identity.to_dict()
    for name in (
        "identity_digest",
        "journal_record_hash",
        "reviewed_scope_digest",
        "manager_installation_digest",
        "payload_installation_digest",
    ):
        _text(data[name], _DIGEST)
    if data["identity_digest"] != identity.digest:
        raise _fail("identity digest differs from the resource identity")
    _text(data["journal_request_id"], _REQUEST)
    _text(data["operation_id"], _OPERATION_ID)
    revision = data["journal_revision"]
    if type(revision) is not int or not 1 <= revision <= 63 or revision % 2 != 1:
        raise _fail("revision must identify one pending journal operation")
    if not isinstance(data["operation"], str) or data["operation"] not in OPERATIONS:
        raise _fail("unknown operation")
    encoded = canonical_json_bytes(data)
    if len(encoded) > MAX_BYTES:
        raise _fail("document exceeds its byte bound")
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("duplicate JSON field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class ServiceOperationBinding:
    """Immutable integrity binding, not proof of approval or effect ownership.

    The journal supplies its validated current pending record. Installation and
    reviewed-scope digests must come from separately authenticated configuration;
    valid syntax or a matching hash cannot establish that trust.
    """

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > MAX_BYTES:
            raise _fail("document must be bounded immutable bytes")
        try:
            normalized = _canonical(json.loads(self._canonical, object_pairs_hook=_unique_object))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid JSON encoding") from exc
        if normalized != self._canonical:
            raise _fail("document must use canonical encoding")

    @classmethod
    def from_mapping(cls, value: Any) -> ServiceOperationBinding:
        return cls(_canonical(value))

    @classmethod
    def from_json(cls, value: bytes) -> ServiceOperationBinding:
        if type(value) is not bytes or len(value) > MAX_BYTES:
            raise _fail("JSON must be bounded bytes")
        try:
            parsed = json.loads(value.decode("utf-8"), object_pairs_hook=_unique_object)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid JSON encoding") from exc
        return cls.from_mapping(parsed)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def canonical_bytes(self) -> bytes:
        return self._canonical
