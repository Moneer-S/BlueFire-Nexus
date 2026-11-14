"""Controller-attested V2 HTTP completion capabilities, never engine claims.

Only the private adapter issuer and protected controller retention owner may
restore these capabilities. A digest, mapping, caller boolean or public class
construction cannot establish revocation or owned-work cessation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .util import content_hash

CESSATION_SCHEMA = "bluefire.tenant-http-cessation.v2"
ADAPTER_REVOCATION_SCHEMA = "bluefire.tenant-http-adapter-revocation.v2"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_RUN = re.compile(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}")


class TenantHttpCompletionContractError(ValueError):
    """A completion proof lacks exact controller authority or identity."""


class _ControllerCessationAuthority:
    __slots__ = ()


class _ControllerAdapterAuthority:
    __slots__ = ()


_CONTROLLER_CESSATION_AUTHORITY = _ControllerCessationAuthority()
_CONTROLLER_ADAPTER_AUTHORITY = _ControllerAdapterAuthority()


def _document(value: Any, fields: frozenset[str], schema: str) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or type(value.get("schema_version")) is not str
        or value.get("schema_version") != schema
    ):
        raise TenantHttpCompletionContractError("completion receipt fields are invalid")
    return {name: value[name] for name in fields}


def _digest(value: Any) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise TenantHttpCompletionContractError("completion receipt digest is invalid")


def _integer(value: Any, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise TenantHttpCompletionContractError("completion receipt bound is invalid")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTenantHttpCessationReceipt:
    """Capability restored only after exact protected controller receipt reopen."""

    schema_version: str
    run_id: str
    attempt_id: str
    binding_digest: str
    profile_digest: str
    generation_digest: str
    target_snapshot_ref: str
    controller_trace_ref: str
    adapter_revocation_ref: str
    artifact_manifest_ref: str
    artifact_publication_ref: str
    worker_outcome_digest: str
    source_collection_seal_ref: str
    issued_ns: int
    _controller_attestation: object = field(repr=False, compare=False, init=False)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "VerifiedTenantHttpCessationReceipt":
        raise TenantHttpCompletionContractError(
            "cessation receipt requires protected controller reopen"
        )

    @classmethod
    def from_mapping(cls, _value: Any) -> "VerifiedTenantHttpCessationReceipt":
        raise TenantHttpCompletionContractError(
            "cessation receipt requires protected controller reopen"
        )

    def to_dict(self) -> dict[str, Any]:
        if getattr(self, "_controller_attestation", None) is not _CONTROLLER_CESSATION_AUTHORITY:
            raise TenantHttpCompletionContractError(
                "cessation receipt lacks controller attestation"
            )
        try:
            document = {
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if not name.startswith("_")
            }
        except AttributeError:
            raise TenantHttpCompletionContractError("cessation receipt is incomplete") from None
        recreated = _restore_controller_cessation_receipt(
            document, _authority=_CONTROLLER_CESSATION_AUTHORITY
        )
        if recreated != self:
            raise TenantHttpCompletionContractError("cessation receipt is not canonical")
        return document

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def _restore_controller_cessation_receipt(
    document: Any, *, _authority: object | None = None
) -> VerifiedTenantHttpCessationReceipt:
    if _authority is not _CONTROLLER_CESSATION_AUTHORITY:
        raise TenantHttpCompletionContractError("cessation receipt requires controller authority")
    fields = frozenset(
        name
        for name in VerifiedTenantHttpCessationReceipt.__dataclass_fields__
        if not name.startswith("_")
    )
    row = _document(document, fields, CESSATION_SCHEMA)
    if (
        type(row["run_id"]) is not str
        or _RUN.fullmatch(row["run_id"]) is None
        or type(row["attempt_id"]) is not str
        or _ATTEMPT.fullmatch(row["attempt_id"]) is None
    ):
        raise TenantHttpCompletionContractError("cessation receipt owner is invalid")
    for name in fields - {"schema_version", "run_id", "attempt_id", "issued_ns"}:
        _digest(row[name])
    _integer(row["issued_ns"], 0, 2**63 - 1)
    receipt = object.__new__(VerifiedTenantHttpCessationReceipt)
    for name, value in row.items():
        object.__setattr__(receipt, name, value)
    object.__setattr__(receipt, "_controller_attestation", _CONTROLLER_CESSATION_AUTHORITY)
    return receipt


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTenantHttpAdapterRevocation:
    """Capability issued only by the private adapter after its lock has settled."""

    schema_version: str
    profile_digest: str
    generation_digest: str
    accepted_http_calls: int
    reserved_response_bytes: int
    request_ids_digest: str
    _controller_attestation: object = field(repr=False, compare=False, init=False)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "VerifiedTenantHttpAdapterRevocation":
        raise TenantHttpCompletionContractError("adapter revocation requires controller authority")

    @classmethod
    def from_mapping(cls, _value: Any) -> "VerifiedTenantHttpAdapterRevocation":
        raise TenantHttpCompletionContractError("adapter revocation requires controller authority")

    def to_dict(self) -> dict[str, Any]:
        if getattr(self, "_controller_attestation", None) is not _CONTROLLER_ADAPTER_AUTHORITY:
            raise TenantHttpCompletionContractError(
                "adapter revocation lacks controller attestation"
            )
        try:
            document = {
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if not name.startswith("_")
            }
        except AttributeError:
            raise TenantHttpCompletionContractError("adapter revocation is incomplete") from None
        recreated = _restore_adapter_revocation(document, _authority=_CONTROLLER_ADAPTER_AUTHORITY)
        if recreated != self:
            raise TenantHttpCompletionContractError("adapter revocation is not canonical")
        return document

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def _restore_adapter_revocation(
    document: Any, *, _authority: object | None = None
) -> VerifiedTenantHttpAdapterRevocation:
    if _authority is not _CONTROLLER_ADAPTER_AUTHORITY:
        raise TenantHttpCompletionContractError("adapter revocation requires controller authority")
    fields = frozenset(
        name
        for name in VerifiedTenantHttpAdapterRevocation.__dataclass_fields__
        if not name.startswith("_")
    )
    row = _document(document, fields, ADAPTER_REVOCATION_SCHEMA)
    for name in ("profile_digest", "generation_digest", "request_ids_digest"):
        _digest(row[name])
    _integer(row["accepted_http_calls"], 0, 256)
    _integer(row["reserved_response_bytes"], 0, 256 * 65536)
    receipt = object.__new__(VerifiedTenantHttpAdapterRevocation)
    for name, value in row.items():
        object.__setattr__(receipt, name, value)
    object.__setattr__(receipt, "_controller_attestation", _CONTROLLER_ADAPTER_AUTHORITY)
    return receipt
