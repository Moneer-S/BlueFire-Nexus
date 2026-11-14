"""Private controller receipt custody for installed Strix attempts.

This ledger records authenticated native packets and bounded controller call
metadata. It does not turn a model-visible response into execution proof: the
caller must still join Docker dispatch, target observation, model, and retained
artifact sources before publishing a run result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, cast

from . import product_store_strix_v2_authority as authority
from . import product_store_strix_v2_resources as resources
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import utc_now
from .strix_controlled_backend import ControlledExecReceipt, ControlledExecRequest
from .strix_controlled_worker_channel import (
    METHODS,
    ControlledWorkerBinding,
    ControllerSettledCall,
)
from .util import canonical_json_bytes, content_hash, json_clone, parse_iso8601_datetime

if TYPE_CHECKING:
    from .product_store import ProductStore


RECORD_SCHEMA = "bluefire.strix-controller-receipt-record.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_NATIVE = ("observed", "qualified", "terminal")
_MAX_DOCUMENT = 256 * 1024


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Any, context: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{context} is not a digest")
    return value


def _canonical(value: Mapping[str, Any]) -> str:
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("Strix controller receipt is not canonical JSON") from exc
    if not 0 < len(encoded) <= _MAX_DOCUMENT:
        raise ProductStoreError("Strix controller receipt exceeds private limit")
    return encoded.decode("utf-8")


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Register with ProductStore's one owning migration transaction."""
    if not connection.in_transaction:
        raise ProductStoreError("Strix controller receipts require one owning migration")
    connection.execute("""CREATE TABLE IF NOT EXISTS strix_controller_receipts (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id TEXT NOT NULL
          REFERENCES strix_composition_prelaunch_records(attempt_id),
        attempt_sequence INTEGER NOT NULL CHECK(attempt_sequence BETWEEN 1 AND 2048),
        claim_ref TEXT NOT NULL,
        prelaunch_ref TEXT NOT NULL,
        transaction_ref TEXT NOT NULL
          REFERENCES strix_composition_resource_transactions(transaction_ref),
        activation_ref TEXT,
        kind TEXT NOT NULL CHECK(kind IN
          ('native_observed','native_qualified','native_terminal','controller_call')),
        source_ref TEXT NOT NULL,
        previous_ref TEXT,
        record_schema TEXT NOT NULL,
        record_json TEXT NOT NULL CHECK(json_valid(record_json))
          CHECK(length(CAST(record_json AS BLOB)) BETWEEN 1 AND 262144),
        record_ref TEXT NOT NULL UNIQUE,
        recorded_at TEXT NOT NULL,
        UNIQUE(attempt_id,attempt_sequence),
        UNIQUE(attempt_id,kind,source_ref),
        CHECK((attempt_sequence=1 AND previous_ref IS NULL)
          OR (attempt_sequence>1 AND previous_ref IS NOT NULL))
    )""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_controller_receipts_no_update
        BEFORE UPDATE ON strix_controller_receipts
        BEGIN SELECT RAISE(ABORT,'Strix controller receipts are immutable'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_controller_receipts_no_delete
        BEFORE DELETE ON strix_controller_receipts
        BEGIN SELECT RAISE(ABORT,'Strix controller receipts cannot be deleted'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_controller_receipts_no_replace
        BEFORE INSERT ON strix_controller_receipts
        WHEN EXISTS (
          SELECT 1 FROM strix_controller_receipts prior
          WHERE prior.attempt_id=NEW.attempt_id AND (
            prior.attempt_sequence=NEW.attempt_sequence
            OR (prior.kind=NEW.kind AND prior.source_ref=NEW.source_ref)
          ) OR prior.record_ref=NEW.record_ref)
        BEGIN SELECT RAISE(ABORT,'Strix controller receipts cannot be replaced'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_controller_receipts_chain
        BEFORE INSERT ON strix_controller_receipts
        WHEN NEW.attempt_sequence>1 AND NOT EXISTS (
          SELECT 1 FROM strix_controller_receipts prior
          WHERE prior.attempt_id=NEW.attempt_id
            AND prior.attempt_sequence=NEW.attempt_sequence-1
            AND prior.record_ref=NEW.previous_ref)
        BEGIN SELECT RAISE(ABORT,'invalid Strix controller receipt chain'); END""")


@dataclass(frozen=True, slots=True)
class RetainedStrixControllerReceipt:
    kind: str
    source_ref: str
    record_ref: str
    recorded_at: str
    document: Mapping[str, Any]


def _context(connection: sqlite3.Connection, attempt_id: str, transaction_ref: str):
    _digest(transaction_ref, "Strix controller transaction")
    prelaunch_row, (prelaunch, snapshot) = authority._read_prelaunch_at(connection, attempt_id)
    transaction, replay = resources._read_at(connection, transaction_ref)
    if (
        transaction["attempt_id"] != attempt_id
        or transaction["authority_ref"] != snapshot.prelaunch_ref
        or transaction["action"] != "execution"
    ):
        raise ResourceConflictError("Strix controller receipt has another resource intent")
    activated = connection.execute(
        "SELECT * FROM strix_composition_authority_records WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()
    activation = None
    if activated is not None:
        authority_row, (document, _snapshot, _identity) = authority._read_authority_at(
            connection, attempt_id
        )
        if authority_row["resource_transaction_ref"] != transaction_ref:
            raise ResourceConflictError("Strix controller receipt has another activation")
        activation = document["activation"]
    return prelaunch_row, prelaunch, snapshot, transaction, replay, activation


def _native_packet(
    packet: Mapping[str, Any],
    *,
    phase: str,
    attempt_id: str,
    claim_ref: str,
    plan_ref: str,
    observed_ref: str | None,
    qualified_ref: str | None,
) -> tuple[str, dict[str, Any]]:
    if (
        type(packet) is not dict
        or set(packet) != {"phase", "sequence", "packet_digest", "helper_pid", "document"}
        or phase not in _NATIVE
        or packet["phase"] != phase
        or packet["sequence"] != _NATIVE.index(phase) + 1
        or type(packet["helper_pid"]) is not int
        or packet["helper_pid"] <= 1
        or type(packet["document"]) is not dict
    ):
        raise ProductStoreError("native Strix receipt source is invalid")
    _digest(packet["packet_digest"], "native Strix packet")
    document = json_clone(packet["document"])
    packet_body = {
        "schema_version": "bluefire.strix-worker-runtime-ipc.v1",
        "kind": phase,
        phase: document,
    }
    if _sha256(canonical_json_bytes(packet_body)) != packet["packet_digest"]:
        raise ProductStoreError("native Strix packet digest changed")
    ref_field = "observation_ref" if phase == "observed" else "receipt_ref"
    source_ref = _digest(document.get(ref_field), "native Strix source")
    if source_ref != content_hash(
        {key: value for key, value in document.items() if key != ref_field}
    ):
        raise ProductStoreError("native Strix source hash changed")
    expected_schema = {
        "observed": "bluefire.strix-worker-runtime-observation.v1",
        "qualified": "bluefire.strix-linux-fixed-exec-receipt.v1",
        "terminal": "bluefire.strix-worker-runtime-terminal.v1",
    }[phase]
    if (
        document.get("schema_version") != expected_schema
        or document.get("attempt_id") != attempt_id
        or document.get("plan_ref") != plan_ref
        or phase != "observed"
        and document.get("resource_claim_ref") != claim_ref
        or phase == "qualified"
        and document.get("native_observation_ref") != observed_ref
        or phase == "terminal"
        and (
            document.get("observation_ref") != observed_ref
            or document.get("qualified_receipt_ref") != qualified_ref
            or document.get("verified_absent") is not True
        )
    ):
        raise ProductStoreError("native Strix source differs from retained intent")
    return source_ref, {
        "packet_digest": packet["packet_digest"],
        "helper_pid": packet["helper_pid"],
        "sequence": packet["sequence"],
        "document": document,
    }


def _decode_row(row: sqlite3.Row) -> RetainedStrixControllerReceipt:
    try:
        document = json.loads(row["record_json"])
        if (
            type(document) is not dict
            or set(document)
            != {
                "schema_version",
                "kind",
                "attempt_id",
                "claim_ref",
                "prelaunch_ref",
                "transaction_ref",
                "activation_ref",
                "source_ref",
                "source",
                "previous_ref",
                "recorded_at",
            }
            or document["schema_version"] != RECORD_SCHEMA
            or row["record_schema"] != RECORD_SCHEMA
            or _canonical(document) != row["record_json"]
            or content_hash(document) != row["record_ref"]
            or any(
                row[field] != document[field]
                for field in (
                    "kind",
                    "attempt_id",
                    "claim_ref",
                    "prelaunch_ref",
                    "transaction_ref",
                    "activation_ref",
                    "source_ref",
                    "previous_ref",
                    "recorded_at",
                )
            )
        ):
            raise ProductStoreError("Strix controller receipt integrity changed")
        parse_iso8601_datetime(document["recorded_at"])
        return RetainedStrixControllerReceipt(
            row["kind"], row["source_ref"], row["record_ref"], row["recorded_at"], document
        )
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("Strix controller receipt cannot be decoded") from exc


def _require_call_binding(
    binding: ControlledWorkerBinding,
    prelaunch: Mapping[str, Any],
    activation: Mapping[str, Any],
    worker_plan_digest: str,
) -> None:
    profile = prelaunch["admission"]["execution_identity"]["controlled_runtime_profile"]
    if (
        binding.attempt_id != prelaunch["binding"]["attempt_id"]
        or binding.claim_digest != prelaunch["accepted"]["claim_ref"]
        or binding.plan_digest != worker_plan_digest
        or binding.profile_digest != activation["controlled_profile_ref"]
        or binding.profile_digest != profile["profile_digest"]
        or binding.identity_digest != profile["identity_digest"]
        or binding.controller_fence != activation["controller_fence"]
    ):
        raise ResourceConflictError("Strix controller call has another activated binding")


class ProductStoreStrixControllerReceiptJournal:
    """ProductStore-bound source; no runtime response is trusted on its own."""

    def __init__(self, *, product_store: ProductStore) -> None:
        if product_store is None:
            raise ProductStoreError("Strix controller receipt store is unavailable")
        self._store = product_store

    def _append(
        self,
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        claim_ref: str,
        prelaunch_ref: str,
        transaction_ref: str,
        activation_ref: str | None,
        kind: str,
        source_ref: str,
        source: Mapping[str, Any],
    ) -> RetainedStrixControllerReceipt:
        existing = connection.execute(
            "SELECT * FROM strix_controller_receipts "
            "WHERE attempt_id=? AND kind=? AND source_ref=?",
            (attempt_id, kind, source_ref),
        ).fetchone()
        if existing is not None:
            retained = _decode_row(existing)
            if (
                retained.document["source"] != source
                or retained.document["claim_ref"] != claim_ref
                or retained.document["prelaunch_ref"] != prelaunch_ref
                or retained.document["transaction_ref"] != transaction_ref
                or retained.document["activation_ref"] != activation_ref
            ):
                raise ResourceConflictError("Strix controller source identity was reused")
            return retained
        head = connection.execute(
            "SELECT * FROM strix_controller_receipts "
            "WHERE attempt_id=? ORDER BY attempt_sequence DESC LIMIT 1",
            (attempt_id,),
        ).fetchone()
        position, previous = (
            (0, None) if head is None else (head["attempt_sequence"], _decode_row(head).record_ref)
        )
        if type(position) is not int or not 0 <= position < 2048:
            raise ResourceConflictError("Strix controller receipt budget exhausted")
        timestamp = utc_now()
        parse_iso8601_datetime(timestamp)
        document = {
            "schema_version": RECORD_SCHEMA,
            "kind": kind,
            "attempt_id": attempt_id,
            "claim_ref": claim_ref,
            "prelaunch_ref": prelaunch_ref,
            "transaction_ref": transaction_ref,
            "activation_ref": activation_ref,
            "source_ref": source_ref,
            "source": dict(source),
            "previous_ref": previous,
            "recorded_at": timestamp,
        }
        encoded = _canonical(document)
        record_ref = content_hash(document)
        connection.execute(
            "INSERT INTO strix_controller_receipts "
            "(attempt_id,attempt_sequence,claim_ref,prelaunch_ref,transaction_ref,"
            "activation_ref,kind,source_ref,previous_ref,record_schema,record_json,"
            "record_ref,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attempt_id,
                position + 1,
                claim_ref,
                prelaunch_ref,
                transaction_ref,
                activation_ref,
                kind,
                source_ref,
                previous,
                RECORD_SCHEMA,
                encoded,
                record_ref,
                timestamp,
            ),
        )
        return RetainedStrixControllerReceipt(kind, source_ref, record_ref, timestamp, document)

    def retain_native(
        self,
        *,
        worker: object,
        closure: object,
        attempt_id: str,
        transaction_ref: str,
    ) -> tuple[RetainedStrixControllerReceipt, ...]:
        """Copy the exact accepted native packet prefix from its OS custody owner.

        This is deliberately callable before activation, after the immutable
        prelaunch and resource transaction exist. A preactivation record is
        historical source evidence, not permission to dispatch an effect.
        """
        try:
            from .strix_linux_native_worker import InstalledStrixLinuxWorkerController
            from .strix_linux_runtime_closure import PinnedStrixRuntimeClosure
        except ImportError as exc:
            raise ProductStoreError("installed native worker source is unavailable") from exc
        if (
            type(worker) is not InstalledStrixLinuxWorkerController
            or type(closure) is not PinnedStrixRuntimeClosure
        ):
            raise ProductStoreError("native Strix receipt lacks protected source owners")
        native_worker = cast(InstalledStrixLinuxWorkerController, worker)
        pinned_closure = cast(PinnedStrixRuntimeClosure, closure)
        plan_ref = _digest(pinned_closure.plan.plan_ref, "pinned native closure plan")
        packets = json_clone(native_worker.accepted_native_documents())
        if type(packets) is not list or not 1 <= len(packets) <= 3:
            raise ProductStoreError("native Strix source has no accepted packet")
        with self._store._connection(write=True) as connection:
            _row, prelaunch, snapshot, transaction, _replay, activation = _context(
                connection, attempt_id, transaction_ref
            )
            if transaction["state"] not in {
                "allocating",
                "allocated",
                "committing",
                "active",
                "stopping",
                "closed",
                "cleanup_unknown",
            }:
                raise ResourceConflictError("native Strix source has no allocated intent")
            claim_ref = prelaunch["accepted"]["claim_ref"]
            if activation is not None and activation["runtime_closure_plan_ref"] != plan_ref:
                raise ProductStoreError("native closure differs from activated identity")
            retained_native = {
                (row["kind"], row["source_ref"])
                for row in connection.execute(
                    "SELECT kind,source_ref FROM strix_controller_receipts "
                    "WHERE attempt_id=? AND kind IN ('native_observed','native_qualified')",
                    (attempt_id,),
                ).fetchall()
            }
            observed_ref = qualified_ref = None
            helper_pid = None
            closure_checked = False
            retained = []
            for index, packet in enumerate(packets):
                phase = packet.get("phase") if type(packet) is dict else None
                if (
                    phase not in _NATIVE
                    or index == 0
                    and phase != "observed"
                    or index > 0
                    and phase == "observed"
                    or index == 2
                    and phase != "terminal"
                    or phase == "qualified"
                    and qualified_ref is not None
                    or phase == "terminal"
                    and index != len(packets) - 1
                ):
                    raise ProductStoreError("native Strix packet order changed")
                source_ref, source = _native_packet(
                    packet,
                    phase=phase,
                    attempt_id=attempt_id,
                    claim_ref=claim_ref,
                    plan_ref=plan_ref,
                    observed_ref=observed_ref,
                    qualified_ref=qualified_ref,
                )
                if (
                    phase in {"observed", "qualified"}
                    and ("native_" + phase, source_ref) not in retained_native
                    and not closure_checked
                ):
                    try:
                        pinned_closure.verify()
                    except Exception as exc:
                        raise ProductStoreError("pinned native closure is no longer live") from exc
                    closure_checked = True
                if helper_pid is None:
                    helper_pid = source["helper_pid"]
                elif helper_pid != source["helper_pid"]:
                    raise ProductStoreError("native Strix packet helper changed")
                if phase == "observed":
                    observed_ref = source_ref
                elif phase == "qualified":
                    qualified_ref = source_ref
                    if (
                        activation is not None
                        and activation["fixed_exec_receipt_ref"] != qualified_ref
                    ):
                        raise ProductStoreError("native qualification differs from activation")
                retained.append(
                    self._append(
                        connection,
                        attempt_id=attempt_id,
                        claim_ref=claim_ref,
                        prelaunch_ref=snapshot.prelaunch_ref,
                        transaction_ref=transaction_ref,
                        activation_ref=activation["receipt_ref"]
                        if phase == "terminal" and activation
                        else None,
                        kind="native_" + phase,
                        source_ref=source_ref,
                        source=source,
                    )
                )
            return tuple(retained)

    def retain_settled_call(
        self,
        call: ControllerSettledCall,
        *,
        transaction_ref: str,
        worker_plan_digest: str,
    ) -> RetainedStrixControllerReceipt:
        """Retain bounded metadata from the server's post-validation sink.

        The plan digest argument must come from a separately retained worker
        invocation. This method alone does not authenticate a dispatch or
        attest guest receipt delivery.
        """
        if type(call) is not ControllerSettledCall:
            raise ProductStoreError("Strix controller call lacks a validated source")
        _digest(worker_plan_digest, "Strix worker invocation plan")
        binding = call.binding
        if type(binding) is not ControlledWorkerBinding or call.method not in METHODS:
            raise ProductStoreError("Strix controller call binding is invalid")
        request = call.request
        receipt = call.receipt
        if (
            type(request) is not METHODS[call.method].request_type
            or type(receipt) is not METHODS[call.method].receipt_type
            or type(call.response_frame) is not bytes
            or not 0 < len(call.response_frame) <= 48 * 1024 * 1024
        ):
            raise ProductStoreError("Strix controller call type changed")
        execution = None
        argv_digest = None
        if call.method == "exec_exact":
            if (
                type(request) is not ControlledExecRequest
                or type(receipt) is not ControlledExecReceipt
            ):
                raise ProductStoreError("Strix exec source type changed")
            argv_digest = content_hash(list(request.argv))
            execution = {
                "exit_code": receipt.exit_code,
                "stdout_digest": receipt.stdout_digest,
                "stderr_digest": receipt.stderr_digest,
                "stdout_size": len(receipt.stdout),
                "stderr_size": len(receipt.stderr),
                "complete": receipt.complete,
                "resource_digest": receipt.resource_digest,
            }
            if (
                _sha256(receipt.stdout) != receipt.stdout_digest
                or _sha256(receipt.stderr) != receipt.stderr_digest
                or receipt.complete is not True
            ):
                raise ProductStoreError("Strix exec bytes changed after validation")
        source = {
            "binding": binding.wire(),
            "method": call.method,
            "request_id": call.request_id,
            "request_digest": request.request_digest,
            "operation_id": getattr(request, "operation_id", None),
            "argv_digest": argv_digest,
            "receipt_schema": receipt.schema_version,
            "response_frame_digest": _sha256(call.response_frame),
            "response_frame_size": len(call.response_frame),
            "receipt": execution,
            "responded_ns": call.responded_ns,
            "delivery_state": "controller_validated_not_acknowledged",
        }
        source_ref = content_hash(source)
        _validate_call_source(source, source_ref)
        with self._store._connection(write=True) as connection:
            _row, prelaunch, snapshot, transaction, replay, activation = _context(
                connection, binding.attempt_id, transaction_ref
            )
            if (
                activation is None
                # A dispatch may settle while cancellation closes the resource
                # transaction. Retention records that historical response; it
                # does not authorize a new effect or assert guest delivery.
                or transaction["state"] not in {"active", "stopping", "closed", "cleanup_unknown"}
                or replay.activation_ref != activation["receipt_ref"]
            ):
                raise ResourceConflictError("Strix controller call lacks activated authority")
            _require_call_binding(binding, prelaunch, activation, worker_plan_digest)
            return self._append(
                connection,
                attempt_id=binding.attempt_id,
                claim_ref=prelaunch["accepted"]["claim_ref"],
                prelaunch_ref=snapshot.prelaunch_ref,
                transaction_ref=transaction_ref,
                activation_ref=activation["receipt_ref"],
                kind="controller_call",
                source_ref=source_ref,
                source=source,
            )

    async def retain_settled_call_async(
        self,
        call: ControllerSettledCall,
        *,
        transaction_ref: str,
        worker_plan_digest: str,
    ) -> None:
        """Run private SQLite custody off the controller RPC event loop."""
        await asyncio.to_thread(
            self.retain_settled_call,
            call,
            transaction_ref=transaction_ref,
            worker_plan_digest=worker_plan_digest,
        )

    def reopen(
        self,
        *,
        attempt_id: str,
        claim_ref: str,
        prelaunch_ref: str,
        transaction_ref: str,
        closure_plan_ref: str,
        worker_plan_digest: str,
    ) -> tuple[RetainedStrixControllerReceipt, ...]:
        """Reopen exact history using an independently sourced worker plan.

        The returned call rows are controller response metadata, not complete
        proof of upstream tool execution or guest receipt delivery.
        """
        _digest(closure_plan_ref, "Strix native closure plan")
        _digest(worker_plan_digest, "Strix worker invocation plan")
        with self._store._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            _row, prelaunch, snapshot, _tx, _replay, activation = _context(
                connection, attempt_id, transaction_ref
            )
            if (
                prelaunch["accepted"]["claim_ref"] != claim_ref
                or snapshot.prelaunch_ref != prelaunch_ref
            ):
                raise ResourceConflictError("Strix controller receipt authority changed")
            if (
                activation is not None
                and activation["runtime_closure_plan_ref"] != closure_plan_ref
            ):
                raise ProductStoreError("Strix native closure plan differs from activation")
            rows = connection.execute(
                "SELECT * FROM strix_controller_receipts WHERE attempt_id=? ORDER BY attempt_sequence",
                (attempt_id,),
            ).fetchall()
            if len(rows) > 2048:
                raise ProductStoreError("Strix controller receipt chain exceeds limit")
            result = []
            previous = observed_ref = qualified_ref = None
            native_terminal_seen = False
            native_helper_pid = None
            for position, row in enumerate(rows, start=1):
                retained = _decode_row(row)
                document = retained.document
                if (
                    row["attempt_sequence"] != position
                    or document["previous_ref"] != previous
                    or document["attempt_id"] != attempt_id
                    or document["claim_ref"] != claim_ref
                    or document["prelaunch_ref"] != prelaunch_ref
                    or document["transaction_ref"] != transaction_ref
                ):
                    raise ProductStoreError("Strix controller receipt chain or authority changed")
                previous = retained.record_ref
                if retained.kind.startswith("native_"):
                    phase = retained.kind.removeprefix("native_")
                    packet = {"phase": phase, **document["source"]}
                    source_ref, source = _native_packet(
                        packet,
                        phase=phase,
                        attempt_id=attempt_id,
                        claim_ref=claim_ref,
                        plan_ref=closure_plan_ref,
                        observed_ref=observed_ref,
                        qualified_ref=qualified_ref,
                    )
                    if source_ref != retained.source_ref or source != document["source"]:
                        raise ProductStoreError("native Strix retained source changed")
                    if native_helper_pid is None:
                        native_helper_pid = source["helper_pid"]
                    elif native_helper_pid != source["helper_pid"]:
                        raise ProductStoreError("native Strix helper identity changed")
                    if phase == "observed":
                        if observed_ref is not None or document["activation_ref"] is not None:
                            raise ProductStoreError(
                                "native observation was duplicated or preactivated"
                            )
                        observed_ref = source_ref
                    elif phase == "qualified":
                        if (
                            observed_ref is None
                            or qualified_ref is not None
                            or native_terminal_seen
                            or document["activation_ref"] is not None
                        ):
                            raise ProductStoreError("native qualification order changed")
                        qualified_ref = source_ref
                    elif observed_ref is None or native_terminal_seen:
                        raise ProductStoreError(
                            "native terminal lacks observation or is duplicated"
                        )
                    else:
                        native_terminal_seen = True
                        if document["activation_ref"] != (
                            activation["receipt_ref"] if activation else None
                        ):
                            raise ProductStoreError("native terminal activation changed")
                    if (
                        phase == "qualified"
                        and activation is not None
                        and activation["fixed_exec_receipt_ref"] != source_ref
                    ):
                        raise ProductStoreError("activation differs from native qualification")
                elif retained.kind == "controller_call":
                    if (
                        activation is None
                        or document["activation_ref"] != activation["receipt_ref"]
                    ):
                        raise ProductStoreError("controller call lacks activated authority")
                    _validate_call_source(document["source"], retained.source_ref)
                    try:
                        _require_call_binding(
                            ControlledWorkerBinding(**document["source"]["binding"]),
                            prelaunch,
                            activation,
                            worker_plan_digest,
                        )
                    except (TypeError, ValueError) as exc:
                        raise ProductStoreError(
                            "controller call binding cannot be decoded"
                        ) from exc
                else:
                    raise ProductStoreError("unknown Strix controller receipt kind")
                result.append(retained)
            return tuple(result)


def _validate_call_source(source: Any, source_ref: str) -> None:
    if (
        type(source) is not dict
        or set(source)
        != {
            "binding",
            "method",
            "request_id",
            "request_digest",
            "operation_id",
            "argv_digest",
            "receipt_schema",
            "response_frame_digest",
            "response_frame_size",
            "receipt",
            "responded_ns",
            "delivery_state",
        }
        or source_ref != content_hash(source)
        or type(source["method"]) is not str
        or source["method"] not in METHODS
        or type(source["binding"]) is not dict
        or type(source["request_id"]) is not str
        or _HEX32.fullmatch(source["request_id"]) is None
        or source["receipt_schema"]
        != f"bluefire.strix-controlled-{METHODS[source['method']].kind}-receipt.v1"
        or type(source["responded_ns"]) is not int
        or source["responded_ns"] <= 0
        or source["delivery_state"] != "controller_validated_not_acknowledged"
        or type(source["response_frame_size"]) is not int
        or not 0 < source["response_frame_size"] <= 48 * 1024 * 1024
    ):
        raise ProductStoreError("Strix controller call metadata changed")
    for name in ("request_digest", "response_frame_digest"):
        _digest(source[name], f"Strix controller {name}")
    if source["operation_id"] is not None and (
        type(source["operation_id"]) is not str
        or re.fullmatch(r"operation-[0-9a-f]{32}", source["operation_id"]) is None
    ):
        raise ProductStoreError("Strix controller operation identity changed")
    if source["argv_digest"] is not None:
        _digest(source["argv_digest"], "Strix controller argv")
    if source["method"] == "exec_exact":
        receipt = source["receipt"]
        if (
            source["argv_digest"] is None
            or source["operation_id"] is None
            or type(receipt) is not dict
            or set(receipt)
            != {
                "exit_code",
                "stdout_digest",
                "stderr_digest",
                "stdout_size",
                "stderr_size",
                "complete",
                "resource_digest",
            }
            or type(receipt["exit_code"]) is not int
            or type(receipt["stdout_size"]) is not int
            or type(receipt["stderr_size"]) is not int
            or not 0 <= receipt["stdout_size"] <= 32 * 1024 * 1024
            or not 0 <= receipt["stderr_size"] <= 32 * 1024 * 1024
            or receipt["complete"] is not True
        ):
            raise ProductStoreError("Strix controller exec terminal metadata changed")
        for name in ("stdout_digest", "stderr_digest", "resource_digest"):
            _digest(receipt[name], f"Strix controller exec {name}")
    elif source["argv_digest"] is not None or source["receipt"] is not None:
        raise ProductStoreError("Strix non-exec call contains exec metadata")


__all__ = [
    "ProductStoreStrixControllerReceiptJournal",
    "RetainedStrixControllerReceipt",
    "initialize_schema",
]
