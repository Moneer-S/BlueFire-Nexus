"""Exact authenticated frames for the controller's private Caido connector.

This is not the worker-facing HTTP protocol. Each private stream carries one
request and one response. The attempt-local key is provisioned out of band to
the controller and its owned container connector; it never enters an HTTP
header or a frame. Authentication grants no target or model relay authority.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from .engine_caido_channel import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    EngineCaidoError,
    EngineCaidoPlan,
)

_MAGIC = b"BFCAIDO1"
# magic, direction, plan digest, connector ref, attempt ID, nonce, request digest, length
HEADER_BYTES = 8 + 1 + 32 + 32 + 47 + 32 + 32 + 4
MAC_BYTES = 32


@dataclass(frozen=True, slots=True)
class CaidoConnectorCredentials:
    """Controller-provisioned, single-attempt private connector authority."""

    plan_digest: str
    key: bytes = field(repr=False)

    def validate(self, plan: EngineCaidoPlan) -> None:
        if self.plan_digest != plan.digest or type(self.key) is not bytes or len(self.key) != 32:
            raise EngineCaidoError("connector_authority_invalid")


def frame_header(
    plan: EngineCaidoPlan,
    *,
    response: bool,
    nonce: bytes,
    request_digest: bytes,
    length: int,
) -> bytes:
    maximum = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if (
        type(nonce) is not bytes
        or len(nonce) != 32
        or type(request_digest) is not bytes
        or len(request_digest) != 32
        or type(length) is not int
        or not 1 <= length <= maximum
    ):
        raise EngineCaidoError("connector_frame_invalid")
    return (
        _MAGIC
        + (b"S" if response else b"Q")
        + bytes.fromhex(plan.digest[7:])
        + bytes.fromhex(plan.connector_ref[7:])
        + plan.attempt_id.encode("ascii")
        + nonce
        + request_digest
        + struct.pack("!I", length)
    )


def encode_frame(
    plan: EngineCaidoPlan,
    credentials: CaidoConnectorCredentials,
    payload: bytes,
    *,
    response: bool,
    nonce: bytes,
    request_digest: bytes,
) -> bytes:
    credentials.validate(plan)
    if type(payload) is not bytes:
        raise EngineCaidoError("connector_frame_invalid")
    header = frame_header(
        plan, response=response, nonce=nonce, request_digest=request_digest, length=len(payload)
    )
    return header + hmac.digest(credentials.key, header + payload, "sha256") + payload


def inspect_header(
    plan: EngineCaidoPlan, header: bytes, *, response: bool
) -> tuple[bytes, bytes, int]:
    if type(header) is not bytes or len(header) != HEADER_BYTES:
        raise EngineCaidoError("connector_frame_invalid")
    nonce, request_digest = header[-68:-36], header[-36:-4]
    length = struct.unpack("!I", header[-4:])[0]
    expected = frame_header(
        plan, response=response, nonce=nonce, request_digest=request_digest, length=length
    )
    if not hmac.compare_digest(header, expected):
        raise EngineCaidoError("connector_identity_invalid")
    return nonce, request_digest, length


def authenticate_frame(
    plan: EngineCaidoPlan,
    credentials: CaidoConnectorCredentials,
    header: bytes,
    mac: bytes,
    payload: bytes,
    *,
    response: bool,
) -> tuple[bytes, bytes]:
    credentials.validate(plan)
    nonce, request_digest, length = inspect_header(plan, header, response=response)
    if (
        type(payload) is not bytes
        or len(payload) != length
        or type(mac) is not bytes
        or len(mac) != MAC_BYTES
        or not hmac.compare_digest(mac, hmac.digest(credentials.key, header + payload, "sha256"))
        or (
            not response
            and not hmac.compare_digest(request_digest, hashlib.sha256(payload).digest())
        )
    ):
        raise EngineCaidoError("connector_authentication_refused")
    return nonce, request_digest
