"""Bounded controller-owned Caido reverse-channel core, without platform effects.

Only injected, trusted listener/connector capabilities can perform effects. This
module opens no socket, executes no process and grants no Docker authority.
Endpoint absence receipts concern this channel only, never resource cleanup.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from .util import content_hash

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_HEADER = re.compile(rb"[A-Za-z][A-Za-z0-9-]{0,63}\Z")
MAX_JSON_BYTES = 65_536
MAX_HEADER_BYTES = 8_192
MAX_REQUEST_BYTES = MAX_JSON_BYTES + MAX_HEADER_BYTES + 4
MAX_RESPONSE_BYTES = MAX_REQUEST_BYTES
MAX_RESOLUTIONS = 128


class EngineCaidoError(ValueError):
    """Stable, payload-free refusal; untrusted exception text is never retained."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Caido channel refused: " + code)


class CaidoState(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    REVOKED = "revoked"
    DRAINED = "drained"
    UNKNOWN = "unknown"


class CaidoPresence(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class CaidoRoute(str, Enum):
    HEALTH = "health"
    GRAPHQL = "graphql"


def _digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EngineCaidoError("identity_invalid")


@dataclass(frozen=True, slots=True)
class EngineCaidoPlan:
    """Protected controller input; no engine-selected address or destination.

    Digest refs bind the build, admission and all platform capabilities to one
    attempt. The reverse connector reaches only container loopback port 48080;
    the controller listener is also IPv4 loopback. No published-port, DNS,
    gateway, sidecar or arbitrary forwarding option exists in this contract.
    """

    attempt_id: str
    authorization_digest: str
    build_identity_digest: str
    daemon_ref: str
    network_ref: str
    container_ref: str
    upstream_ref: str
    listener_ref: str
    connector_ref: str
    channel_ref: str
    listener_port: int
    listener_host: str = "127.0.0.1"
    container_host: str = "127.0.0.1"
    container_port: int = 48080
    tls: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.attempt_id) is not str or _ATTEMPT.fullmatch(self.attempt_id) is None:
            raise EngineCaidoError("identity_invalid")
        for value in (
            self.authorization_digest,
            self.build_identity_digest,
            self.daemon_ref,
            self.network_ref,
            self.container_ref,
            self.upstream_ref,
            self.listener_ref,
            self.connector_ref,
            self.channel_ref,
        ):
            _digest(value)
        if (
            type(self.listener_port) is not int
            or not 1024 <= self.listener_port <= 65535
            or type(self.listener_host) is not str
            or self.listener_host != "127.0.0.1"
            or type(self.container_host) is not str
            or self.container_host != "127.0.0.1"
            or type(self.container_port) is not int
            or self.container_port != 48080
            or self.tls is not False
        ):
            raise EngineCaidoError("endpoint_invalid")

    @property
    def digest(self) -> str:
        self.validate()
        return content_hash(
            {
                "schema_version": "bluefire.engine-caido-plan.v1",
                **{name: getattr(self, name) for name in self.__dataclass_fields__},
            }
        )


@dataclass(frozen=True, slots=True)
class CaidoEndpointObservation:
    plan: EngineCaidoPlan
    presence: CaidoPresence


class CaidoListener(Protocol):
    def activate(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation: ...

    def revoke(self, plan: EngineCaidoPlan) -> None: ...

    def observe(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation: ...


class CaidoPendingExchange(Protocol):
    def finish(self) -> bytes | None: ...


class CaidoTransport(CaidoListener, Protocol):
    def start_exchange(self, plan: EngineCaidoPlan, request: bytes) -> CaidoPendingExchange:
        """Admit/start synchronously without blocking; finish may block separately.

        The controller holds the lifecycle lock for this admission operation.
        Implementations must not defer initial dispatch to ``finish``: that
        would permit new upstream work after revocation has already returned.
        Admission must not reenter channel lifecycle methods or invoke callbacks
        that do so; platform implementations remain trusted capabilities.
        """
        ...


@dataclass(frozen=True, slots=True)
class CaidoExchangeReceipt:
    channel_ref: str
    request_ref: str
    request_digest: str
    route: CaidoRoute
    status: int
    response: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class CaidoAuditReceipt:
    sequence: int
    channel_ref: str
    state: CaidoState
    outcome: str


@dataclass(frozen=True, slots=True)
class CaidoDrainReceipt:
    plan_digest: str
    listener_ref: str
    connector_ref: str
    listener_absent: bool
    connector_absent: bool
    state: CaidoState
    resource_cleanup_verified: bool = field(default=False, init=False)


def _bounded_json(body: bytes) -> None:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError

    try:
        if not body or len(body) > MAX_JSON_BYTES or body.startswith(b"\xef\xbb\xbf"):
            raise ValueError
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(value, dict):
            raise ValueError
        nodes = 0

        def visit(item: Any, depth: int) -> None:
            nonlocal nodes
            nodes += 1
            if depth > 24 or nodes > 4096:
                raise ValueError
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError
            elif isinstance(item, dict):
                for key, child in item.items():
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    visit(child, depth + 1)

        visit(value, 0)
    except (ValueError, UnicodeError, RecursionError):
        raise EngineCaidoError("json_invalid") from None


def _framing(raw: bytes, *, response: bool) -> tuple[bytes, dict[str, str], bytes]:
    maximum = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise EngineCaidoError("message_bound")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or len(head) > MAX_HEADER_BYTES:
        raise EngineCaidoError("framing_invalid")
    lines = head.split(b"\r\n")
    if any(any(byte < 32 or byte > 126 for byte in line) for line in lines):
        raise EngineCaidoError("framing_invalid")
    headers: dict[str, str] = {}
    allowed = {"content-type", "content-length"}
    if not response:
        allowed |= {"host", "accept"}
    for line in lines[1:]:
        name, separator, raw_value = line.partition(b": ")
        if not separator or _HEADER.fullmatch(name) is None or raw_value != raw_value.strip():
            raise EngineCaidoError("header_invalid")
        key = name.decode("ascii").lower()
        if key in headers or key not in allowed:
            raise EngineCaidoError("header_invalid")
        headers[key] = raw_value.decode("ascii")
    length = headers.get("content-length")
    if length is not None and length != str(len(body)):
        raise EngineCaidoError("length_invalid")
    if body and length is None:
        raise EngineCaidoError("length_invalid")
    if len(body) > MAX_JSON_BYTES:
        raise EngineCaidoError("message_bound")
    return lines[0], headers, body


def _request(raw: bytes, plan: EngineCaidoPlan) -> CaidoRoute:
    line, headers, body = _framing(raw, response=False)
    if headers.get("host") != f"127.0.0.1:{plan.listener_port}":
        raise EngineCaidoError("host_invalid")
    if headers.get("accept", "application/json") != "application/json":
        raise EngineCaidoError("header_invalid")
    if line == b"GET /health HTTP/1.1":
        if body or "content-type" in headers:
            raise EngineCaidoError("health_body")
        return CaidoRoute.HEALTH
    if line != b"POST /graphql HTTP/1.1":
        raise EngineCaidoError("route_invalid")
    if headers.get("content-type") != "application/json":
        raise EngineCaidoError("content_type_invalid")
    _bounded_json(body)
    return CaidoRoute.GRAPHQL


def _response(raw: bytes) -> int:
    line, headers, body = _framing(raw, response=True)
    match = re.fullmatch(rb"HTTP/1\.1 ([2-5][0-9]{2}) [A-Za-z][A-Za-z ]{0,63}", line)
    if match is None or int(match[1]) in {204, 205} or 300 <= int(match[1]) < 400:
        raise EngineCaidoError("response_status_invalid")
    if headers.get("content-type") != "application/json" or "content-length" not in headers:
        raise EngineCaidoError("response_headers_invalid")
    _bounded_json(body)
    return int(match[1])


class EngineCaidoChannel:
    """Attempt-local, bounded exact resolution with fail-closed revocation.

    Fakes/capabilities are trusted controller dependencies. Unknown exchanges
    are never replayed. A concurrent revoke discards every in-flight result;
    verified drain requires both independently observed endpoint absences.
    """

    def __init__(
        self, plan: EngineCaidoPlan, listener: CaidoListener, transport: CaidoTransport
    ) -> None:
        if type(plan) is not EngineCaidoPlan:
            raise EngineCaidoError("identity_invalid")
        plan.validate()
        self._plan = plan
        self._plan_digest = plan.digest
        self._listener = listener
        self._transport = transport
        self._state = CaidoState.NEW
        self._lock = threading.RLock()
        self._pending: dict[str, str] = {}
        self._resolved: dict[str, CaidoExchangeReceipt] = {}
        self._audits: deque[CaidoAuditReceipt] = deque(maxlen=512)
        self._sequence = 0

    @property
    def state(self) -> CaidoState:
        with self._lock:
            return self._state

    @property
    def audits(self) -> tuple[CaidoAuditReceipt, ...]:
        with self._lock:
            return tuple(self._audits)

    def _audit(self, outcome: str) -> None:
        self._sequence += 1
        self._audits.append(
            CaidoAuditReceipt(self._sequence, self._plan.channel_ref, self._state, outcome)
        )

    def _identity(self) -> None:
        try:
            matches = self._plan.digest == self._plan_digest
        except EngineCaidoError:
            matches = False
        if not matches:
            self._state = CaidoState.UNKNOWN
            raise EngineCaidoError("identity_changed")

    def _observed(self, observation: CaidoEndpointObservation, presence: CaidoPresence) -> bool:
        return (
            type(observation) is CaidoEndpointObservation
            and type(observation.plan) is EngineCaidoPlan
            and observation.plan == self._plan
            and observation.plan.digest == self._plan_digest
            and observation.presence is presence
        )

    def activate(self) -> None:
        with self._lock:
            self._identity()
            if self._state is not CaidoState.NEW:
                raise EngineCaidoError("state_refused")
            try:
                listener = self._listener.activate(self._plan)
                if self._state is not CaidoState.NEW:
                    raise EngineCaidoError("state_refused")
                connector = self._transport.activate(self._plan)
                if self._state is not CaidoState.NEW:
                    raise EngineCaidoError("state_refused")
                if not self._observed(listener, CaidoPresence.PRESENT) or not self._observed(
                    connector, CaidoPresence.PRESENT
                ):
                    raise EngineCaidoError("binding_unverified")
            except Exception:
                self._state = CaidoState.UNKNOWN
                self._audit("activation_unknown")
                raise EngineCaidoError("activation_unknown") from None
            self._state = CaidoState.ACTIVE
            self._audit("activated")

    def resolve(self, request_ref: str, request: bytes) -> CaidoExchangeReceipt:
        with self._lock:
            self._identity()
            if self._state is not CaidoState.ACTIVE:
                raise EngineCaidoError("state_refused")
            _digest(request_ref)
            try:
                route = _request(request, self._plan)
            except EngineCaidoError:
                self._audit("request_refused")
                raise
            digest = "sha256:" + hashlib.sha256(request).hexdigest()
            previous = self._resolved.get(request_ref)
            if previous is not None:
                if previous.request_digest != digest:
                    raise EngineCaidoError("resolution_conflict")
                return previous
            if request_ref in self._pending:
                if self._pending[request_ref] != digest:
                    raise EngineCaidoError("resolution_conflict")
                raise EngineCaidoError("resolution_pending")
            if len(self._pending) + len(self._resolved) >= MAX_RESOLUTIONS:
                raise EngineCaidoError("resolution_bound")
            self._pending[request_ref] = digest
            try:
                exchange = self._transport.start_exchange(self._plan, request)
                if self._state is not CaidoState.ACTIVE:
                    raise EngineCaidoError("state_refused")
            except Exception:
                self._pending.pop(request_ref, None)
                if self._state is CaidoState.ACTIVE:
                    self._state = CaidoState.UNKNOWN
                self._audit("exchange_unknown")
                raise EngineCaidoError("exchange_unknown") from None
        try:
            response = exchange.finish()
            if response is None:
                raise EngineCaidoError("exchange_unknown")
            status = _response(response)
        except Exception:
            with self._lock:
                self._pending.pop(request_ref, None)
                if self._state is CaidoState.ACTIVE:
                    self._state = CaidoState.UNKNOWN
                self._audit("exchange_unknown")
            raise EngineCaidoError("exchange_unknown") from None
        with self._lock:
            self._pending.pop(request_ref, None)
            self._identity()
            if self._state is not CaidoState.ACTIVE:
                self._audit("exchange_revoked")
                raise EngineCaidoError("state_refused")
            receipt = CaidoExchangeReceipt(
                self._plan.channel_ref, request_ref, digest, route, status, response
            )
            self._resolved[request_ref] = receipt
            self._audit("resolved")
            return receipt

    def revoke(self) -> None:
        """Cancel admission before asking both endpoints to revoke; retry is safe."""
        with self._lock:
            self._identity()
            if self._state is CaidoState.DRAINED:
                return
            self._state = CaidoState.REVOKED
            failed = False
            for endpoint in (self._listener, self._transport):
                try:
                    endpoint.revoke(self._plan)
                except Exception:
                    failed = True
            if failed:
                self._state = CaidoState.UNKNOWN
            self._audit("revocation_unknown" if failed else "revoked")

    def cancel(self) -> None:
        self.revoke()

    def drain(self) -> CaidoDrainReceipt:
        with self._lock:
            self._identity()
            if self._state not in {CaidoState.REVOKED, CaidoState.UNKNOWN, CaidoState.DRAINED}:
                raise EngineCaidoError("state_refused")
            if self._pending:
                raise EngineCaidoError("drain_pending")
            absent: list[bool] = []
            for endpoint in (self._listener, self._transport):
                try:
                    absent.append(
                        self._observed(endpoint.observe(self._plan), CaidoPresence.ABSENT)
                    )
                except Exception:
                    absent.append(False)
            self._state = CaidoState.DRAINED if all(absent) else CaidoState.UNKNOWN
            self._audit("drained" if all(absent) else "drain_unknown")
            return CaidoDrainReceipt(
                self._plan_digest,
                self._plan.listener_ref,
                self._plan.connector_ref,
                absent[0],
                absent[1],
                self._state,
            )
