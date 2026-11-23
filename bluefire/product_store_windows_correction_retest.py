"""One new correction retest claim and Ready; historical evidence grants no replay."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, cast

from . import product_store_file_access_native_evidence as native
from . import product_store_file_access_ready as ready_store
from . import product_store_windows_correction as journal
from . import product_store_windows_file_access as windows
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_correction_contract as observation
from . import windows_file_access_native_wire as wire
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import canonical_json_bytes, content_hash


def successful_control(connection: Any, job_id: str, prepared: dict) -> dict:
    events = journal._events(connection, job_id, prepared)
    wire._require(set(events) == {"dispatch", "closure"})
    payload = events["closure"]["payload"]
    wire._require(
        payload["dispatch"] == "attempted"
        and payload["process_cleanup"] == "verified"
        and payload["terminal"] is not None
        and payload["terminal"]["result"] is not None
    )
    return cast(dict, payload["terminal"]["result"])


def register_retest(
    store: Any,
    job_id: str,
    *,
    checked: observation.VerifiedWindowsCorrectionPostimage,
    original: dict,
    expected_binding: dict,
    now_ms: int,
    revalidate: Callable[[], None],
) -> None:
    """Consume a newly observed postimage only after physical setter-child closure."""
    try:
        record, receipt, binding = observation.checked_provenance(checked)
        with store._connection(write=True) as connection:
            operation, prepared, imported, _ = journal.original_at(store, connection, job_id)
            journal._live(store, connection, job_id, prepared, now_ms)
            result = successful_control(connection, job_id, prepared)
            dispatch = journal._events(connection, job_id, prepared)["dispatch"]["payload"]
            wire._require(now_ms >= dispatch["dispatched_at_ms"])
            wire._require(
                record == imported["enrollment"]
                and receipt == imported["setup_receipt"]
                and binding == prepared["binding"]
                and checked._descriptor_sha256 == result["after_descriptor_sha256"]
            )
            wanted, expected = admission._build_retest_original(
                binding, record, receipt, now_ms, operation["submitted_request"]["reviewed_by"]
            )
            wire._require(original == wanted and expected_binding == expected)
            wire._require(
                not connection.execute(
                    "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1", (job_id,)
                ).fetchone()
            )
            revalidate()
            manifest = wanted["manifest"]
            claim = {
                "job_id": job_id,
                "task_id": wanted["task_id"],
                "step_id": manifest["step_id"],
                "request_hash": manifest["request_hash"],
                "transport_request_hash": wanted["transport_request_hash"],
                "manifest": manifest,
                "runner_profile": wanted["profile"],
            }
            connection.execute(
                "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                (
                    wanted["task_id"],
                    job_id,
                    manifest["step_id"],
                    manifest["request_hash"],
                    canonical_json(claim),
                    content_hash(claim),
                ),
            )
    except native._FAILURES:
        raise ProductStoreError(journal._ERROR) from None


def retained_context(store: Any, connection: Any, context: native._Context) -> tuple[dict, dict]:
    """Rejoin exact original control effect and one v3 task without observation calls."""
    wire._require(context.protocol is native._Protocol.CORRECTION_V3)
    original = wire._document(context.original._raw)
    manifest = original["manifest"]
    job_id = manifest["run_id"]
    operation, prepared, imported, _ = journal.original_at(store, connection, job_id)
    result = successful_control(connection, job_id, prepared)
    issued = wire._time(manifest["requested_at"])
    issued_ms = int(issued.timestamp() * 1000)
    dispatch = journal._events(connection, job_id, prepared)["dispatch"]["payload"]
    wire._require(issued_ms >= dispatch["dispatched_at_ms"])
    wanted, expected = admission._build_retest_original(
        prepared["binding"],
        imported["enrollment"],
        imported["setup_receipt"],
        issued_ms,
        operation["submitted_request"]["reviewed_by"],
    )
    wire._require(
        original == wanted and context.original._expected == canonical_json_bytes(expected)
    )
    claims = connection.execute(
        "SELECT task_id FROM file_access_task_claims WHERE job_id=? LIMIT 2", (job_id,)
    ).fetchall()
    wire._require(len(claims) == 1 and claims[0]["task_id"] == wanted["task_id"])
    native._recheck(connection, context)
    return prepared, result


def live_context(store: Any, connection: Any, context: native._Context, clock: datetime) -> None:
    prepared, _ = retained_context(store, connection, context)
    journal._live(store, connection, prepared["job_id"], prepared, int(clock.timestamp() * 1000))


def consume_ready(
    store: Any,
    task_id: str,
    *,
    transport_request_hash: str,
    expected_binding: dict,
    prepared_packet: wire.PreparedPacket,
    ready_bytes: bytes,
    clock: datetime,
    monotonic_now: float,
) -> Callable[[datetime, float], None]:
    try:
        frame, retained, validate_ready = ready_store._pair_wire(native._Protocol.CORRECTION_V3)
        context = native._context(
            store,
            task_id,
            transport_request_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        wire._require(
            type(prepared_packet) is wire.PreparedPacket
            and prepared_packet._original == context.original
        )
        frame(prepared_packet, clock=clock, monotonic_now=monotonic_now)
        validate_ready(retained(context.original, prepared_packet._raw), ready_bytes)
        with store._connection(write=True) as connection:
            native._recheck(connection, context)
            live_context(store, connection, context, clock)
            ready_store._record_ready_at(connection, context, prepared_packet, ready_bytes, clock)
    except native._FAILURES:
        raise ProductStoreError(windows._ERROR) from None

    def validate(current_clock: datetime, current_monotonic: float) -> None:
        try:
            frame(prepared_packet, clock=current_clock, monotonic_now=current_monotonic)
            with store._connection() as connection:
                native._recheck(connection, context)
                live_context(store, connection, context, current_clock)
                ready_store._allowance_at(
                    connection, context, prepared_packet, ready_bytes, current_clock
                )
        except native._FAILURES:
            raise ProductStoreError(windows._ERROR) from None

    return validate


def revalidate_original(
    store: Any,
    task_id: str,
    *,
    transport_request_hash: str,
    expected_binding: dict,
    prepared_packet: wire.PreparedPacket,
    clock: datetime,
    monotonic_now: float,
) -> None:
    try:
        frame, _, _ = ready_store._pair_wire(native._Protocol.CORRECTION_V3)
        context = native._context(
            store,
            task_id,
            transport_request_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        wire._require(
            type(prepared_packet) is wire.PreparedPacket
            and prepared_packet._original == context.original
        )
        frame(prepared_packet, clock=clock, monotonic_now=monotonic_now)
        with store._connection() as connection:
            native._recheck(connection, context)
            live_context(store, connection, context, clock)
            ready_store._unfinished_at(connection, context, prepared_packet, clock)
    except native._FAILURES:
        raise ProductStoreError(windows._ERROR) from None
