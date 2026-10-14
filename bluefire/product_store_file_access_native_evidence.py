"""Historical public wire evidence for already durable private Windows claims.

The original claim is independently loaded from the store. expected_binding must
be the independently retained trusted ORIGINAL admission binding, never fresh
resource state or caller data authenticated merely by matching hashes. No Windows
preparation, enrollment, task admission, execution or credential authority is
created here. The supplied aware historical clock only bounds retained observed
timestamps; it never replaces the original immutable execution interval.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Literal, cast

from . import windows_file_access_native_wire as wire
from ._windows_file_access_cleanup_proof import (
    MAX_RECEIPT_BYTES,
    OwnedCleanupReceipt,
    validate_retained_cleanup,
)
from ._windows_file_access_native_contract import _digest
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash

_PublicEvidenceSink = Callable[
    [Literal["packet", "ready", "terminal"], bytes, int | None, datetime], None
]

_SCHEMA = "bluefire.windows-file-task-evidence.v1"
_STAGES = ("packet", "ready", "terminal")
_MAXIMUM = {"packet": wire.PUBLIC_MAX, "ready": wire.READY_MAX, "terminal": wire.TERMINAL_MAX}
_ROW_MAX = 4 * wire.PUBLIC_MAX
_CLAIM_MAX = 2 * wire.PUBLIC_MAX
_FIELDS = {
    "schema_version",
    "task_id",
    "transport_request_hash",
    "claim_digest",
    "stage",
    "packet_digest",
    "previous_digest",
    "payload_utf8",
    "actual_returncode",
}
_ERROR = "The retained native file-access evidence is unavailable or invalid."
_FAILURES = (
    ProductStoreError,
    wire.NativeWireError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    RecursionError,
    OverflowError,
    sqlite3.DatabaseError,
)


class _Protocol(Enum):
    READER_V1 = "reader_v1"
    PAIR_V2 = "pair_v2"

    @property
    def schema(self) -> str:
        return (
            _SCHEMA
            if self is _Protocol.READER_V1
            else "bluefire.windows-file-pair-task-evidence.v2"
        )


class NativeEvidenceStoreMixin:
    def record_file_access_native_packet(
        self, task_id, *, transport_request_hash, expected_binding, public_bytes, clock
    ):
        from .product_store_file_access_native_evidence import record

        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "packet",
            public_bytes,
            None,
            clock,
        )

    def record_file_access_native_ready(
        self, task_id, *, transport_request_hash, expected_binding, ready_bytes, clock
    ):
        from .product_store_file_access_native_evidence import record

        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "ready",
            ready_bytes,
            None,
            clock,
        )

    def record_file_access_native_terminal(
        self,
        task_id,
        *,
        transport_request_hash,
        expected_binding,
        terminal_bytes,
        actual_returncode,
        clock,
    ):
        from .product_store_file_access_native_evidence import record

        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "terminal",
            terminal_bytes,
            actual_returncode,
            clock,
        )

    def file_access_native_evidence(
        self, task_id, *, transport_request_hash, expected_binding, clock
    ):
        from .product_store_file_access_native_evidence import query

        return query(self, task_id, transport_request_hash, expected_binding, clock)

    def record_file_access_native_pair_packet(
        self, task_id, *, transport_request_hash, expected_binding, public_bytes, clock
    ):
        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "packet",
            public_bytes,
            None,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )

    def record_file_access_native_pair_ready(
        self, task_id, *, transport_request_hash, expected_binding, ready_bytes, clock
    ):
        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "ready",
            ready_bytes,
            None,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )

    def record_file_access_native_pair_terminal(
        self,
        task_id,
        *,
        transport_request_hash,
        expected_binding,
        terminal_bytes,
        actual_returncode,
        clock,
    ):
        return record(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            "terminal",
            terminal_bytes,
            actual_returncode,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )

    def file_access_native_pair_evidence(
        self, task_id, *, transport_request_hash, expected_binding, clock
    ):
        return query(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )

    def record_file_access_native_cleanup(
        self, task_id, *, transport_request_hash, expected_binding, receipt, clock
    ):
        return record_cleanup(
            self, task_id, transport_request_hash, expected_binding, receipt, clock
        )

    def record_file_access_native_pair_cleanup(
        self, task_id, *, transport_request_hash, expected_binding, receipt, clock
    ):
        return record_cleanup(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            receipt,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )

    def file_access_native_cleanup_evidence(
        self, task_id, *, transport_request_hash, expected_binding, clock
    ):
        return query_cleanup(self, task_id, transport_request_hash, expected_binding, clock)

    def file_access_native_pair_cleanup_evidence(
        self, task_id, *, transport_request_hash, expected_binding, clock
    ):
        return query_cleanup(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            clock,
            _protocol=_Protocol.PAIR_V2,
        )


def native_evidence_sink(
    store: Any,
    task_id: str,
    *,
    transport_request_hash: str,
    expected_binding: object,
) -> _PublicEvidenceSink:
    """Capture trusted ORIGINAL binding for public persistence, never admission.

    Construct this before transferring suspended resources to the supervisor.
    The caller must independently retain the original trusted binding; matching
    hashes do not authenticate it. This adapter creates no execution deadline.
    """
    return _sink(store, task_id, transport_request_hash, expected_binding, _Protocol.READER_V1)


def native_pair_evidence_sink(
    store: Any, task_id: str, *, transport_request_hash: str, expected_binding: object
) -> _PublicEvidenceSink:
    """Capture only an independently admitted ORIGINAL pair-v2 claim and binding.

    This is not a pair admission path or a v1 upgrade. No deadline, credential,
    owned-Job closure or settlement is created by constructing this callback.
    """
    return _sink(store, task_id, transport_request_hash, expected_binding, _Protocol.PAIR_V2)


def _sink(
    store: Any,
    task_id: str,
    transport_request_hash: str,
    expected_binding: object,
    protocol: _Protocol,
) -> _PublicEvidenceSink:
    try:
        context = _context(
            store, task_id, transport_request_hash, expected_binding, _protocol=protocol
        )
        captured_binding = context.original._expected
        _require(type(captured_binding) is bytes and 0 < len(captured_binding) <= wire.PUBLIC_MAX)
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None

    def sink(
        stage: Literal["packet", "ready", "terminal"],
        public_bytes: bytes,
        actual_returncode: int | None,
        clock: datetime,
    ) -> None:
        try:
            binding = wire._document(captured_binding, wire.PUBLIC_MAX)
            if protocol is _Protocol.READER_V1:
                record(
                    store,
                    task_id,
                    transport_request_hash,
                    binding,
                    stage,
                    public_bytes,
                    actual_returncode,
                    clock,
                )
            else:
                record(
                    store,
                    task_id,
                    transport_request_hash,
                    binding,
                    stage,
                    public_bytes,
                    actual_returncode,
                    clock,
                    _protocol=protocol,
                )
        except _FAILURES:
            raise ProductStoreError(_ERROR) from None
        return None

    return sink


@dataclass(frozen=True, slots=True)
class NativeTaskEvidence:
    task_id: str
    transport_request_hash: str
    claim_digest: str
    packet_bytes: bytes | None = field(repr=False)
    ready_bytes: bytes | None = field(repr=False)
    terminal_bytes: bytes | None = field(repr=False)
    actual_returncode: int | None
    projection: wire.NativeProjection | None = field(repr=False)
    settled: bool = field(default=False, init=False)
    owned_job_cleanup: str = field(default="unverified", init=False)

    def __post_init__(self) -> None:
        _snapshot(self)
        if self.terminal_bytes is not None:
            _require(type(self.projection) is wire.NativeProjection)


@dataclass(frozen=True, slots=True)
class PairNativeTaskEvidence(NativeTaskEvidence):
    """Historical pair phases only; never admission or supervised Job closure."""

    projection: wire.PairNativeProjection | None = field(repr=False)

    def __post_init__(self) -> None:
        _snapshot(self)
        if self.terminal_bytes is not None:
            _require(type(self.projection) is wire.PairNativeProjection)


def _snapshot(value: NativeTaskEvidence) -> None:
    _digest(value.transport_request_hash)
    _digest(value.claim_digest)
    _require(value.task_id == "execute-" + value.transport_request_hash[7:])
    for stage, data in zip(
        _STAGES, (value.packet_bytes, value.ready_bytes, value.terminal_bytes), strict=True
    ):
        if data is not None:
            _payload(data, stage)
    _require(value.packet_bytes is not None or value.ready_bytes is value.terminal_bytes is None)
    _require(value.ready_bytes is not None or value.terminal_bytes is None)
    if value.terminal_bytes is None:
        _require(value.actual_returncode is None and value.projection is None)
    else:
        _require(type(value.actual_returncode) is int and value.actual_returncode in (0, 4))


@dataclass(frozen=True, slots=True)
class _Context:
    task_id: str
    transport_hash: str
    claim_digest: str
    claim_bytes: bytes
    original: wire.OriginalReservation
    protocol: _Protocol = _Protocol.READER_V1


def _require(valid: bool) -> None:
    if not valid:
        raise ValueError("native evidence")


def _text_bytes(value: Any, maximum: int) -> bytes:
    _require(type(value) is str and 0 < len(value) <= maximum)
    data = cast(str, value).encode("utf-8", "strict")
    _require(len(data) <= maximum)
    return data


def _row_document(row: Any, maximum: int) -> dict[str, Any]:
    _require(row is not None)
    data = _text_bytes(row["document_json"], maximum)
    document = wire._document(data, maximum)
    _require(content_hash(document) == row["document_digest"])
    return document


def _context(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    *,
    _protocol: _Protocol = _Protocol.READER_V1,
) -> _Context:
    _require(type(_protocol) is _Protocol)
    _require(type(task_id) is str and bool(task_id) and type(transport_hash) is str)
    _digest(transport_hash)
    # This sole historical read gates bytes before decoding. Do not follow it
    # with an unbounded reread through the general task-record API.
    with store._connection() as connection:
        row = connection.execute(
            "SELECT task_id,job_id,step_id,request_hash,document_digest, "
            "CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
            "THEN document_json ELSE NULL END AS document_json "
            "FROM file_access_task_claims WHERE task_id=?",
            (_CLAIM_MAX, task_id),
        ).fetchone()
        claim = _row_document(row, _CLAIM_MAX)
    _require(
        set(claim)
        == {
            "job_id",
            "task_id",
            "step_id",
            "request_hash",
            "transport_request_hash",
            "manifest",
            "runner_profile",
        }
    )
    _require(row["task_id"] == claim["task_id"] == task_id)
    _require(row["job_id"] == claim["job_id"])
    _require(row["step_id"] == claim["step_id"])
    _require(row["request_hash"] == claim["request_hash"])
    _require(claim["transport_request_hash"] == transport_hash)
    pair = _protocol is _Protocol.PAIR_V2
    _require(claim["manifest"]["action_id"] == (wire.PAIR_ACTION if pair else wire.ACTION))
    validator = (
        wire.validate_pair_original_reservation if pair else wire.validate_original_reservation
    )
    original = validator(
        {
            "manifest": claim["manifest"],
            "profile": claim["runner_profile"],
            "task_id": claim["task_id"],
            "transport_request_hash": claim["transport_request_hash"],
        },
        expected_binding=expected_binding,
    )
    operation = claim["manifest"]["params"]["windows_file_read_request"]
    _require(claim["request_hash"] == claim["manifest"]["request_hash"])
    _require(claim["step_id"] == claim["manifest"]["step_id"])
    _require(claim["job_id"] == operation["operation_job_id"] == claim["manifest"]["run_id"])
    _require(claim["step_id"] == ("read_generated_pair" if pair else "read_generated"))
    return _Context(
        task_id,
        transport_hash,
        row["document_digest"],
        canonical_json(claim).encode("utf-8"),
        original,
        _protocol,
    )


def _packet(context: _Context, data: bytes) -> wire.RetainedPacket:
    validator = (
        wire.validate_pair_retained_packet
        if context.protocol is _Protocol.PAIR_V2
        else wire.validate_retained_packet
    )
    return validator(context.original, data)


def _ready(context: _Context, packet: wire.RetainedPacket, data: bytes) -> None:
    validator = (
        wire.validate_pair_ready if context.protocol is _Protocol.PAIR_V2 else wire.validate_ready
    )
    validator(packet, data)


def _terminal(
    context: _Context,
    packet: wire.RetainedPacket,
    ready: bytes,
    data: bytes,
    clock: datetime,
    code: int,
) -> wire.NativeProjection:
    validator = (
        wire.validate_pair_terminal
        if context.protocol is _Protocol.PAIR_V2
        else wire.validate_terminal
    )
    return validator(context.original, packet, ready, data, clock=clock, returncode=code)


def _limits(context: _Context) -> dict[str, Any]:
    protocol = wire._PAIR if context.protocol is _Protocol.PAIR_V2 else wire._V1
    return cast(dict[str, Any], wire._reservation(context.original, protocol)["manifest"]["limits"])


def _recheck(connection: Any, context: _Context) -> None:
    row = connection.execute(
        "SELECT task_id,job_id,step_id,request_hash,document_digest, "
        "CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json "
        "FROM file_access_task_claims WHERE task_id=?",
        (_CLAIM_MAX, context.task_id),
    ).fetchone()
    document = _row_document(row, _CLAIM_MAX)
    _require(row["document_digest"] == context.claim_digest)
    _require(canonical_json(document).encode("utf-8") == context.claim_bytes)
    _require(row["task_id"] == document["task_id"] == context.task_id)
    _require(row["job_id"] == document["job_id"])
    _require(row["step_id"] == document["step_id"])
    _require(row["request_hash"] == document["request_hash"])


def _payload(data: Any, stage: str) -> str:
    _require(type(data) is bytes and 0 < len(data) <= _MAXIMUM[stage])
    _require(cast(bytes, data).lstrip().startswith(b"{"))
    text = cast(bytes, data).decode("utf-8", "strict")
    _require(not text.startswith("\ufeff"))
    return text


def _load(
    connection: Any, context: _Context, clock: datetime
) -> tuple[NativeTaskEvidence, dict[str, Any]]:
    wire._clock(clock)
    rows = connection.execute(
        "SELECT task_id,stage,document_digest, "
        "CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json "
        "FROM file_access_task_evidence WHERE task_id=? LIMIT 4",
        (_ROW_MAX, context.task_id),
    ).fetchall()
    _require(len(rows) <= 3)
    documents: dict[str, Any] = {}
    previous: str | None = None
    payloads: dict[str, bytes] = {}
    packet = None
    projection = None
    returncode = None
    for row in rows:
        _require(type(row["stage"]) is str and row["stage"] in _STAGES)
        _require(row["stage"] not in documents)
        documents[row["stage"]] = (row, _row_document(row, _ROW_MAX))
    seen_gap = False
    for stage in _STAGES:
        if stage not in documents:
            seen_gap = True
            continue
        _require(not seen_gap)
        row, document = documents[stage]
        _require(set(document) == _FIELDS and document["schema_version"] == context.protocol.schema)
        _require(
            document["stage"] == stage and row["task_id"] == document["task_id"] == context.task_id
        )
        _require(document["transport_request_hash"] == context.transport_hash)
        _require(document["claim_digest"] == context.claim_digest)
        _require(document["previous_digest"] == previous)
        data = _text_bytes(document["payload_utf8"], _MAXIMUM[stage])
        _payload(data, stage)
        payloads[stage] = data
        if stage == "packet":
            _require(document["actual_returncode"] is None)
            packet = _packet(context, data)
        elif stage == "ready":
            _require(document["actual_returncode"] is None and packet is not None)
            _ready(context, cast(wire.RetainedPacket, packet), data)
            limits = _limits(context)
            _require(len(data) + 4 <= limits["max_stdout_bytes"])
        else:
            _require(
                type(document["actual_returncode"]) is int
                and document["actual_returncode"] in (0, 4)
            )
            returncode = document["actual_returncode"]
            _require(packet is not None)
            projection = _terminal(
                context,
                cast(wire.RetainedPacket, packet),
                payloads["ready"],
                data,
                clock,
                returncode,
            )
        _require(
            packet is not None
            and document["packet_digest"]
            == wire._binding(cast(wire.RetainedPacket, packet))["packet_digest"]
        )
        previous = row["document_digest"]
    arguments = (
        context.task_id,
        context.transport_hash,
        context.claim_digest,
        payloads.get("packet"),
        payloads.get("ready"),
        payloads.get("terminal"),
        returncode,
    )
    snapshot: NativeTaskEvidence
    if context.protocol is _Protocol.PAIR_V2:
        _require(projection is None or type(projection) is wire.PairNativeProjection)
        snapshot = PairNativeTaskEvidence(
            *arguments, cast(wire.PairNativeProjection | None, projection)
        )
    else:
        snapshot = NativeTaskEvidence(*arguments, projection)
    return snapshot, documents


def record(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    stage: str,
    data: bytes,
    returncode: int | None,
    clock: datetime,
    *,
    _protocol: _Protocol = _Protocol.READER_V1,
) -> NativeTaskEvidence:
    """Append public bytes only; clock is historical validation, not new admission."""
    try:
        context = _context(store, task_id, transport_hash, expected_binding, _protocol=_protocol)
        with store._connection(write=True) as connection:
            return _record_at(connection, context, stage, data, returncode, clock)
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None


def _record_at(
    connection: Any,
    context: _Context,
    stage: str,
    data: bytes,
    returncode: int | None,
    clock: datetime,
) -> NativeTaskEvidence:
    """Append under a caller-owned write transaction; never grant dispatch."""
    _require(connection.in_transaction and stage in _STAGES)
    text = _payload(data, stage)
    _recheck(connection, context)
    snapshot, documents = _load(connection, context, clock)
    index = _STAGES.index(stage)
    _require(stage in documents or index == len(documents))
    previous = documents[_STAGES[index - 1]][0]["document_digest"] if index else None
    packet_bytes = data if stage == "packet" else snapshot.packet_bytes
    _require(packet_bytes is not None)
    packet = _packet(context, cast(bytes, packet_bytes))
    if stage == "ready":
        _require(returncode is None)
        _ready(context, packet, data)
        _require(len(data) + 4 <= _limits(context)["max_stdout_bytes"])
    elif stage == "terminal":
        _require(
            type(returncode) is int and returncode in (0, 4) and snapshot.ready_bytes is not None
        )
        _terminal(
            context, packet, cast(bytes, snapshot.ready_bytes), data, clock, cast(int, returncode)
        )
    else:
        _require(returncode is None)
    document = {
        "schema_version": context.protocol.schema,
        "task_id": context.task_id,
        "transport_request_hash": context.transport_hash,
        "claim_digest": context.claim_digest,
        "stage": stage,
        "packet_digest": wire._binding(packet)["packet_digest"],
        "previous_digest": previous,
        "payload_utf8": text,
        "actual_returncode": returncode,
    }
    if stage in documents:
        _require(documents[stage][1] == document)
        _cleanup_load(connection, context, clock, snapshot)
        return snapshot
    serialized = canonical_json(document)
    _text_bytes(serialized, _ROW_MAX)
    connection.execute(
        "INSERT INTO file_access_task_evidence VALUES(?,?,?,?)",
        (context.task_id, stage, serialized, content_hash(document)),
    )
    snapshot = _load(connection, context, clock)[0]
    _cleanup_load(connection, context, clock, snapshot)
    return snapshot


def query(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    clock: datetime,
    *,
    _protocol: _Protocol = _Protocol.READER_V1,
) -> NativeTaskEvidence:
    """Return a revalidated partial/full original trail, never replay permission."""
    try:
        context = _context(store, task_id, transport_hash, expected_binding, _protocol=_protocol)
        with store._connection() as connection:
            _recheck(connection, context)
            return _load(connection, context, clock)[0]
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None


_CLEANUP_SCHEMA = "bluefire.windows-file-owned-cleanup-evidence.v1"
_CLEANUP_FIELDS = {
    "schema_version",
    "protocol",
    "task_id",
    "transport_request_hash",
    "claim_digest",
    "packet_digest",
    "receipt_utf8",
    "private_packet_utf8",
}


@dataclass(frozen=True, slots=True)
class NativeCleanupEvidence:
    """Explicit historical join; physical closure never settles a read outcome.

    Native-only snapshots stay Job-unverified. Missing public stages remain
    missing even when the privately retained packet binds positive closure.
    """

    native_evidence: NativeTaskEvidence
    receipt_bytes: bytes | None = field(repr=False)
    private_packet_bytes: bytes | None = field(repr=False)
    settled: bool = field(default=False, init=False)
    independent_observation: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _require(type(self.native_evidence) in (NativeTaskEvidence, PairNativeTaskEvidence))
        _require((self.receipt_bytes is None) == (self.private_packet_bytes is None))
        if self.receipt_bytes is None:
            return
        _require(type(self.private_packet_bytes) is bytes)
        proof = validate_retained_cleanup(
            self.receipt_bytes, cast(bytes, self.private_packet_bytes)
        )
        trail = self.native_evidence
        protocol = "pair_v2" if type(trail) is PairNativeTaskEvidence else "reader_v1"
        _require(proof["protocol"] == protocol and proof["task_id"] == trail.task_id)
        _require(proof["transport_request_hash"] == trail.transport_request_hash)
        if trail.packet_bytes is not None:
            _require(trail.packet_bytes == self.private_packet_bytes)
        if trail.terminal_bytes is not None:
            _require(proof["child_generation_captured"] and proof["begin_attempted"])
            _require(proof["supported_terminal_returncode"] == trail.actual_returncode)

    @property
    def owned_job_cleanup(self) -> Literal["unverified", "verified"]:
        return "verified" if self.receipt_bytes is not None else "unverified"


def _cleanup_validate(
    context: _Context,
    receipt: bytes,
    packet_bytes: bytes,
    clock: datetime,
    trail: NativeTaskEvidence,
) -> dict[str, Any]:
    proof = validate_retained_cleanup(receipt, packet_bytes)
    _require(proof["protocol"] == context.protocol.value)
    _require(proof["task_id"] == context.task_id)
    _require(proof["transport_request_hash"] == context.transport_hash)
    _require(wire._time(proof["observed_at"], canonical=True) <= wire._clock(clock))
    packet = _packet(context, packet_bytes)
    _require(proof["packet_digest"] == wire._binding(packet)["packet_digest"])
    if trail.packet_bytes is not None:
        _require(trail.packet_bytes == packet_bytes)
    if trail.terminal_bytes is not None:
        _require(proof["child_generation_captured"] and proof["begin_attempted"])
        _require(proof["supported_terminal_returncode"] == trail.actual_returncode)
    return proof


def _cleanup_load(
    connection: Any,
    context: _Context,
    clock: datetime,
    trail: NativeTaskEvidence,
) -> tuple[NativeCleanupEvidence, dict[str, Any] | None]:
    row = connection.execute(
        "SELECT task_id,document_digest, CASE WHEN length(CAST(document_json AS BLOB)) "
        "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
        "FROM file_access_owned_process_closures WHERE task_id=?",
        (_ROW_MAX, context.task_id),
    ).fetchone()
    if row is None:
        return NativeCleanupEvidence(trail, None, None), None
    document = _row_document(row, _ROW_MAX)
    _require(set(document) == _CLEANUP_FIELDS and document["schema_version"] == _CLEANUP_SCHEMA)
    _require(row["task_id"] == document["task_id"] == context.task_id)
    _require(document["protocol"] == context.protocol.value)
    _require(document["transport_request_hash"] == context.transport_hash)
    _require(document["claim_digest"] == context.claim_digest)
    receipt = _text_bytes(document["receipt_utf8"], MAX_RECEIPT_BYTES)
    packet = _text_bytes(document["private_packet_utf8"], wire.PUBLIC_MAX)
    proof = _cleanup_validate(context, receipt, packet, clock, trail)
    _require(document["packet_digest"] == proof["packet_digest"])
    return NativeCleanupEvidence(trail, receipt, packet), document


def record_cleanup(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    receipt: OwnedCleanupReceipt,
    clock: datetime,
    *,
    _protocol: _Protocol = _Protocol.READER_V1,
) -> NativeCleanupEvidence:
    """Persist a trusted supervisor receipt only, never caller cleanup assertions.

    Matching hashes are consistency checks, not producer authentication. The
    trusted local controller owns this exact producer handoff. No native closure
    or dispatch is performed on persistence failure or an idempotent retry.
    """
    try:
        _require(type(receipt) is OwnedCleanupReceipt)
        receipt.document()
        context = _context(store, task_id, transport_hash, expected_binding, _protocol=_protocol)
        with store._connection(write=True) as connection:
            _recheck(connection, context)
            trail = _load(connection, context, clock)[0]
            snapshot, previous = _cleanup_load(connection, context, clock, trail)
            proof = _cleanup_validate(context, receipt._raw, receipt._packet, clock, trail)
            document = {
                "schema_version": _CLEANUP_SCHEMA,
                "protocol": context.protocol.value,
                "task_id": task_id,
                "transport_request_hash": transport_hash,
                "claim_digest": context.claim_digest,
                "packet_digest": proof["packet_digest"],
                "receipt_utf8": receipt._raw.decode("utf-8", "strict"),
                "private_packet_utf8": _payload(receipt._packet, "packet"),
            }
            if previous is not None:
                _require(previous == document)
                return snapshot
            serialized = canonical_json(document)
            _text_bytes(serialized, _ROW_MAX)
            connection.execute(
                "INSERT INTO file_access_owned_process_closures VALUES(?,?,?)",
                (task_id, serialized, content_hash(document)),
            )
            return _cleanup_load(connection, context, clock, trail)[0]
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None


def query_cleanup(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    clock: datetime,
    *,
    _protocol: _Protocol = _Protocol.READER_V1,
) -> NativeCleanupEvidence:
    """Validate retained closure separately; never mint a producer receipt or replay."""
    try:
        context = _context(store, task_id, transport_hash, expected_binding, _protocol=_protocol)
        with store._connection() as connection:
            _recheck(connection, context)
            trail = _load(connection, context, clock)[0]
            return _cleanup_load(connection, context, clock, trail)[0]
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None
