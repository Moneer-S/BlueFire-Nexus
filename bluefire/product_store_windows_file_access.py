"""Original Windows setup, once-only Ready and retained baseline transactions.

An import alone has no execution or cleanup claim. Pair publication derives
only from separately retained native and owned-process evidence, never dispatch.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Callable, cast

from . import product_store_file_access_native_evidence as native
from . import product_store_file_access_ready as ready_store
from . import windows_file_access_admission as admission
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as pair_admission
from .file_access_contract import FileAccessContractError
from .product_store_errors import ProductStoreError
from .product_store_file_access_ready import _pair_wire as _pair_wire
from .product_store_serialization import canonical_json
from .util import canonical_json_bytes, content_hash


class WindowsSetupStoreMixin:
    def windows_file_access_setup_projection(self, owner_id):
        return public_projection(self, owner_id)

    def get_windows_file_access_import(self, selection):
        return lookup(self, selection)

    def get_windows_file_access_pair_import(self, selection):
        return lookup(self, selection, _pair=True)

    def import_windows_file_access_setup(self, checked, *, selection, now_ms):
        return save(self, checked, selection=selection, now_ms=now_ms)

    def import_windows_file_access_pair_setup(self, checked, *, selection, now_ms):
        return save(self, checked, selection=selection, now_ms=now_ms, _pair=True)

    def consume_windows_file_access_pair_ready(
        self,
        task_id,
        *,
        transport_request_hash,
        expected_binding,
        prepared_packet,
        ready_bytes,
        clock,
        monotonic_now,
    ):
        return consume_pair_ready(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            prepared_packet,
            ready_bytes,
            clock,
            monotonic_now,
        )

    def revalidate_windows_file_access_pair_original(
        self,
        task_id,
        *,
        transport_request_hash,
        expected_binding,
        prepared_packet,
        clock,
        monotonic_now,
    ):
        revalidate_pair_original(
            self,
            task_id,
            transport_request_hash,
            expected_binding,
            prepared_packet,
            clock,
            monotonic_now,
        )

    def publish_windows_file_access_baseline(self, job_id, *, clock, expected_outcome_digest=None):
        return publish_baseline(
            self, job_id, clock=clock, expected_outcome_digest=expected_outcome_digest
        )

    def windows_file_access_pair_control_projection(self, owner_id, *, clock):
        return pair_control_projection(self, owner_id, clock=clock)

    def recover_windows_file_access_baseline(self, job_id, *, expected_outcome_digest, clock):
        return publish_baseline(
            self, job_id, clock=clock, expected_outcome_digest=expected_outcome_digest
        )


CONTROL_RECORD_SCHEMA = "bluefire.windows-file-access-control-record.v2"
_ERROR = "The original Windows baseline remains unavailable or unresolved."
_FAILURES = native._FAILURES


def _contract(schema: Any, *, preparation: bool = False):
    for module in (admission, pair_admission):
        expected = module.PREPARATION_SCHEMA if preparation else module.IMPORT_SCHEMA
        if schema == expected:
            return module
    raise ValueError("unsupported Windows provenance")


def is_windows_control(value: Any) -> bool:
    return isinstance(value, dict) and value.get("schema_version") in (
        admission.IMPORT_SCHEMA,
        pair_admission.IMPORT_SCHEMA,
        CONTROL_RECORD_SCHEMA,
        "bluefire.windows-file-access-control-record.v3",
    )


def is_preparation(value: Any) -> bool:
    return isinstance(value, dict) and value.get("schema_version") in (
        admission.PREPARATION_SCHEMA,
        pair_admission.PREPARATION_SCHEMA,
    )


def permitted_operations(
    store: Any, connection: Any, control: dict, review_context: dict, *, now_ms: int
) -> list[str]:
    if control.get("schema_version") in (
        CONTROL_RECORD_SCHEMA,
        "bluefire.windows-file-access-control-record.v3",
    ):
        return []
    module = _contract(control.get("schema_version"))
    if review_context != module.baseline_context(control):
        raise ProductStoreError("The original Windows baseline context changed.")
    if (
        module is pair_admission
        and connection.execute(
            "SELECT 1 FROM file_access_operations WHERE control_owner_id=? LIMIT 1",
            (control["control_owner_id"],),
        ).fetchone()
    ):
        return []
    return ["baseline"]


def validate_preparation(value: Any, original: dict, imported: dict, *, now_ms: int):
    return _contract(value.get("schema_version"), preparation=True).validate_preparation(
        value, original, imported, now_ms=now_ms
    )


def document(row: Any) -> dict:
    try:
        if row is None or not isinstance(row["document_json"], str):
            raise ValueError("missing")
        parsed = wire._document(
            native._text_bytes(row["document_json"], wire.PUBLIC_MAX), wire.PUBLIC_MAX
        )
        saved = _contract(parsed.get("schema_version")).validate_import(parsed)
        wire._require(type(saved) is dict)
        saved = cast(dict, saved)
        if (
            content_hash(saved) != row["document_digest"]
            or saved["control_owner_id"] != row["control_owner_id"]
            or saved["enrollment_id"] != row["enrollment_id"]
            or saved["generation"] != row["generation"]
        ):
            raise ValueError("binding")
        return saved
    except (ValueError, TypeError, KeyError):
        raise ProductStoreError("The saved Windows setup provenance is unavailable.") from None


def at(connection: Any, *, owner_id: str | None = None, enrollment_id: str | None = None):
    if owner_id is not None:
        query = (
            "SELECT control_owner_id,enrollment_id,generation,document_digest,"
            "CASE WHEN length(CAST(document_json AS BLOB))<=65536 THEN document_json END AS document_json "
            "FROM file_access_setup_imports WHERE control_owner_id=?"
        )
        value: str | None = owner_id
    else:
        query = (
            "SELECT control_owner_id,enrollment_id,generation,document_digest,"
            "CASE WHEN length(CAST(document_json AS BLOB))<=65536 THEN document_json END AS document_json "
            "FROM file_access_setup_imports WHERE enrollment_id=?"
        )
        value = enrollment_id
    return connection.execute(query, (value,)).fetchone()


def lookup(store: Any, selection: Any, *, _pair: bool = False) -> dict | None:
    try:
        selected = admission.selected(selection)
        with store._connection() as connection:
            row = at(connection, enrollment_id=selected["enrollment_id"])
            if row is None:
                return None
            saved = document(row)
            if saved["schema_version"] != (
                pair_admission.IMPORT_SCHEMA if _pair else admission.IMPORT_SCHEMA
            ):
                raise ValueError("protocol")
            if content_hash(saved["enrollment"]) != selected["enrollment_digest"]:
                raise ValueError("selection")
            return saved
    except (ValueError, TypeError, KeyError):
        raise ProductStoreError(
            "The selected protected setup differs from saved provenance."
        ) from None


def public_projection(store: Any, owner_id: str) -> dict:
    from .product_store_capability_grants import control_usages_settled

    with store._connection() as connection:
        saved = document(at(connection, owner_id=owner_id))
        if connection.execute(
            "SELECT 1 FROM file_access_operations WHERE control_owner_id=?", (owner_id,)
        ).fetchone() or not control_usages_settled(store, connection, owner_id):
            raise FileAccessContractError(
                "Windows setup has an unsupported operation obligation; the setup-only view is unavailable."
            )
        return admission.projection(saved)


def save(store: Any, checked: Any, *, selection: Any, now_ms: int, _pair: bool = False) -> dict:
    try:
        module = pair_admission if _pair else admission
        selected = admission.selected(selection)
        record, receipt = module.checked_provenance(checked)
        if selected != {
            "enrollment_id": record["enrollment_id"],
            "enrollment_digest": content_hash(record),
        }:
            raise ValueError("selection")
        with store._connection(write=True) as connection:
            previous = at(connection, enrollment_id=record["enrollment_id"])
            if previous is not None:
                saved = document(previous)
                if saved["enrollment"] != record or saved["setup_receipt"] != receipt:
                    raise ValueError("conflict")
                return saved
            saved = module.import_document(checked, now_ms=now_ms)
            wire._require(type(saved) is dict)
            saved = cast(dict, saved)
            # Reuse the enrollment table, but never its digest as first-import authority.
            existing = connection.execute(
                "SELECT document_json,document_digest FROM file_access_enrollments WHERE enrollment_id=?",
                (record["enrollment_id"],),
            ).fetchone()
            if existing is not None:
                if existing["document_json"] != canonical_json(record) or existing[
                    "document_digest"
                ] != content_hash(record):
                    raise ValueError("enrollment conflict")
            else:
                connection.execute(
                    "INSERT INTO file_access_enrollments VALUES(?,?,?)",
                    (record["enrollment_id"], canonical_json(record), content_hash(record)),
                )
            connection.execute(
                "INSERT INTO file_access_setup_imports VALUES(?,?,?,?,?)",
                (
                    saved["control_owner_id"],
                    saved["enrollment_id"],
                    saved["generation"],
                    canonical_json(saved),
                    content_hash(saved),
                ),
            )
            return saved
    except (ValueError, TypeError, KeyError, sqlite3.IntegrityError):
        raise ProductStoreError(
            "Verified protected setup is required for this exact import."
        ) from None


def register_task(
    connection: Any,
    *,
    operation: Any,
    original: dict,
    prepared: dict,
    control_document: dict,
    usage_settled: bool,
    task_id: str,
    step_id: str,
    manifest: dict,
    profile: dict,
    now_ms: int,
    validate_context: Any,
) -> None:
    module = _contract(prepared.get("schema_version"), preparation=True)
    module.validate_preparation(prepared, original, control_document, now_ms=now_ms)
    pair = prepared["original"]
    if (
        operation["operation"] != "baseline"
        or step_id != ("read_generated_pair" if module is pair_admission else "read_generated")
        or pair["task_id"] != task_id
        or manifest != pair["manifest"]
        or profile != pair["profile"]
        or usage_settled is not True
        or connection.execute(
            "SELECT 1 FROM file_access_task_claims WHERE job_id=?", (operation["job_id"],)
        ).fetchone()
    ):
        raise ProductStoreError("The original private Windows task differs or is already claimed.")
    validate_context()
    record = {
        "job_id": operation["job_id"],
        "task_id": task_id,
        "step_id": step_id,
        "request_hash": manifest["request_hash"],
        "transport_request_hash": pair["transport_request_hash"],
        "manifest": manifest,
        "runner_profile": profile,
    }
    connection.execute(
        "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
        (
            task_id,
            operation["job_id"],
            step_id,
            manifest["request_hash"],
            canonical_json(record),
            content_hash(record),
        ),
    )


def consume_pair_ready(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    prepared: wire.PreparedPacket,
    ready: bytes,
    clock: datetime,
    monotonic_now: float,
    *,
    _protocol: native._Protocol = native._Protocol.PAIR_V2,
) -> Callable[[datetime, float], None]:
    """Persist a conservative once lock before any credential resolution.

    Ready does not prove a password was decrypted or delivered. Any existing
    Ready permanently refuses a new allowance, including after controller crash.
    The returned private predicate is retained by one trusted one-use producer;
    it checks the captured original and cannot mint another allowance.
    """
    try:
        wire._require(_protocol is native._Protocol.PAIR_V2)
        frame, retained, validate_ready = _pair_wire(_protocol)
        context = native._context(
            store, task_id, transport_hash, expected_binding, _protocol=_protocol
        )
        wire._require(
            type(prepared) is wire.PreparedPacket and prepared._original == context.original
        )
        frame(prepared, clock=clock, monotonic_now=monotonic_now)
        validate_ready(retained(context.original, prepared._raw), ready)
        with store._connection(write=True) as connection:
            native._recheck(connection, context)
            _live(store, connection, context, clock=clock)
            ready_store._record_ready_at(connection, context, prepared, ready, clock)
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None

    def validate(current_clock: datetime, current_monotonic: float) -> None:
        try:
            frame(prepared, clock=current_clock, monotonic_now=current_monotonic)
            with store._connection() as connection:
                native._recheck(connection, context)
                _live(store, connection, context, clock=current_clock)
                ready_store._allowance_at(connection, context, prepared, ready, current_clock)
        except _FAILURES:
            raise ProductStoreError(_ERROR) from None

    return validate


def revalidate_pair_original(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    prepared: wire.PreparedPacket,
    clock: datetime,
    monotonic_now: float,
    *,
    _protocol: native._Protocol = native._Protocol.PAIR_V2,
) -> None:
    """Check current original admission without creating or renewing an allowance."""
    try:
        wire._require(_protocol is native._Protocol.PAIR_V2)
        frame, _, _ = _pair_wire(_protocol)
        context = native._context(
            store, task_id, transport_hash, expected_binding, _protocol=_protocol
        )
        wire._require(
            type(prepared) is wire.PreparedPacket and prepared._original == context.original
        )
        frame(prepared, clock=clock, monotonic_now=monotonic_now)
        with store._connection() as connection:
            native._recheck(connection, context)
            _live(store, connection, context, clock=clock)
            ready_store._unfinished_at(connection, context, prepared, clock)
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None


def _live(store: Any, connection: Any, context: native._Context, *, clock: datetime) -> None:
    wire._require(context.protocol is native._Protocol.PAIR_V2)
    job_id = wire._document(context.original._raw, wire.PUBLIC_MAX)["manifest"]["run_id"]
    job = store._job_from_row(
        connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    )
    wire._require(
        job["state"] in ("queued", "running")
        and not job["progress"].get("stopped")
        and _outcome_at(connection, job_id)[0] is None
    )


_BOUNDED_QUERIES = {
    ("file_access_operations", "job_id"): (
        "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json FROM file_access_operations WHERE job_id=?"
    ),
    ("file_access_preparations", "job_id"): (
        "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json FROM file_access_preparations WHERE job_id=?"
    ),
    ("file_access_revisions", "job_id"): (
        "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json FROM file_access_revisions WHERE job_id=?"
    ),
}


def _bounded(connection: Any, table: str, column: str, value: str, maximum: int):
    wire._require(type(table) is str and type(column) is str)
    query = _BOUNDED_QUERIES.get((table, column))
    wire._require(query is not None)
    row = connection.execute(query, (maximum, value)).fetchone()
    return native._row_document(row, maximum), row["document_digest"]


def _original_pair_at(connection: Any, job_id: str):
    operation, operation_digest = _bounded(
        connection, "file_access_operations", "job_id", job_id, wire.PUBLIC_MAX
    )
    preparation, preparation_digest = _bounded(
        connection, "file_access_preparations", "job_id", job_id, native._CLAIM_MAX
    )
    imported = document(at(connection, owner_id=preparation["control_owner_id"]))
    wire._require(imported["schema_version"] == pair_admission.IMPORT_SCHEMA)
    checked = pair_admission.validate_retained_preparation(preparation, operation, imported)
    rows = connection.execute(
        "SELECT task_id FROM file_access_task_claims WHERE job_id=? LIMIT 2", (job_id,)
    ).fetchall()
    wire._require(len(rows) == 1 and rows[0]["task_id"] == checked["original"]["task_id"])
    row = connection.execute(
        "SELECT operation,control_owner_id,enrollment_id FROM file_access_operations WHERE job_id=?",
        (job_id,),
    ).fetchone()
    wire._require(
        row["operation"] == "baseline"
        and row["control_owner_id"] == imported["control_owner_id"]
        and row["enrollment_id"] == imported["enrollment_id"]
    )
    return operation, operation_digest, checked, preparation_digest, imported


def _pair_baseline(
    connection: Any,
    context: native._Context,
    prepared: dict,
    prep_digest: str,
    imported: dict,
    clock: datetime,
):
    native._recheck(connection, context)
    wire._require(context.original._raw == canonical_json_bytes(prepared["original"]))
    trail, stages = native._load(connection, context, clock)
    closure, cleanup_document = native._cleanup_load(connection, context, clock, trail)
    projection = trail.projection
    wire._require(
        type(trail) is native.PairNativeTaskEvidence
        and type(projection) is wire.PairNativeProjection
    )
    projection = cast(wire.PairNativeProjection, projection)
    wire._require(
        trail.actual_returncode == 0
        and projection.observation_complete
        and projection.outcome == projection.reader_outcome == projection.owner_outcome == "allowed"
        and projection.local_cleanup == "verified"
        and closure.owned_job_cleanup == "verified"
    )
    wire._require(set(stages) == {"packet", "ready", "terminal"} and cleanup_document is not None)
    resource = prepared["expected_binding"]["resource"]
    terminal = wire._document(cast(bytes, trail.terminal_bytes), wire.TERMINAL_MAX)
    digest = content_hash(
        {
            "claim_digest": context.claim_digest,
            "preparation_digest": prep_digest,
            "import_digest": content_hash(imported),
            "wire_stage_digests": {name: row[0]["document_digest"] for name, row in stages.items()},
            "cleanup_digest": content_hash(cleanup_document),
        }
    )
    return {
        "schema_version": "bluefire.windows-file-readable-baseline.v2",
        "non_owner": "allowed",
        "owner": "allowed",
        "size_bytes": resource["size_bytes"],
        "sha256": resource["sha256"],
        "resource_generation": prepared["expected_binding"]["generation"],
        "observed_at": terminal["observed_at"],
        "native_cleanup": "verified",
        "owned_job_cleanup": "verified",
        "independent_observation": False,
        "baseline_digest": digest,
    }


def _outcome_at(connection: Any, job_id: str):
    row = connection.execute(
        "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
        "THEN document_json ELSE NULL END AS document_json FROM file_access_outcomes "
        "WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
        (wire.PUBLIC_MAX, job_id),
    ).fetchone()
    return (
        (native._row_document(row, wire.PUBLIC_MAX), row["document_digest"])
        if row is not None
        else (None, None)
    )


def _revision(
    imported: dict, prepared: dict, context: native._Context, baseline: dict, job_id: str
) -> dict:
    return {
        "schema_version": CONTROL_RECORD_SCHEMA,
        "control_owner_id": imported["control_owner_id"],
        "enrollment_id": imported["enrollment_id"],
        "generation": imported["generation"],
        "revision": imported["revision"] + 1,
        "status": "baseline_verified",
        "original_import_digest": content_hash(imported),
        "operation_job_id": job_id,
        "task_id": context.task_id,
        "transport_request_hash": context.transport_hash,
        "resource": prepared["expected_binding"]["resource"],
        "baseline": baseline,
    }


def publish_baseline(
    store: Any, job_id: str, *, clock: datetime, expected_outcome_digest: str | None = None
) -> dict:
    """Atomically derive one original readable baseline; no native or credential call.

    Late retained evidence is validated historically, not reprepared. Denial,
    unknown, missing evidence or uncertain closure never publishes a revision.
    """
    try:
        wire._clock(clock)
        if expected_outcome_digest is not None:
            native._digest(expected_outcome_digest)
        with store._connection() as connection:
            original = _original_pair_at(connection, job_id)
        prepared = original[2]
        context = native._context(
            store,
            prepared["original"]["task_id"],
            prepared["original"]["transport_request_hash"],
            prepared["expected_binding"],
            _protocol=native._Protocol.PAIR_V2,
        )
        with store._connection(write=True) as connection:
            current = _original_pair_at(connection, job_id)
            wire._require(current == original)
            operation, _, prepared, prep_digest, imported = current
            baseline = _pair_baseline(connection, context, prepared, prep_digest, imported, clock)
            revision = _revision(imported, prepared, context, baseline, job_id)
            outcome = {
                "state": "complete",
                "evidence_digest": baseline["baseline_digest"],
                "control_digest": content_hash(revision),
                "native_baseline": baseline,
            }
            prior, prior_digest = _outcome_at(connection, job_id)
            committed = connection.execute(
                "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
                "THEN document_json END AS document_json FROM file_access_revisions WHERE job_id=?",
                (wire.PUBLIC_MAX, job_id),
            ).fetchone()
            if prior is not None and prior["state"] == "complete":
                wire._require(
                    prior == outcome
                    and committed is not None
                    and native._row_document(committed, wire.PUBLIC_MAX) == revision
                )
                if expected_outcome_digest is not None:
                    uncertain = connection.execute(
                        "SELECT document_digest, CASE WHEN length(CAST(document_json AS BLOB)) BETWEEN 1 AND ? "
                        "THEN document_json END AS document_json FROM file_access_outcomes "
                        "WHERE job_id=? AND document_digest=? LIMIT 1",
                        (wire.PUBLIC_MAX, job_id, expected_outcome_digest),
                    ).fetchone()
                    wire._require(
                        native._row_document(uncertain, wire.PUBLIC_MAX)["state"] == "unknown"
                    )
                return revision
            wire._require(
                (prior is None and expected_outcome_digest is None)
                or (
                    prior is not None
                    and prior["state"] == "unknown"
                    and prior_digest == expected_outcome_digest
                )
            )
            wire._require(committed is None)
            wire._require(operation["review"]["control_digest"] == content_hash(imported))
            wire._require(
                not connection.execute(
                    "SELECT 1 FROM file_access_revisions WHERE control_owner_id=? LIMIT 1",
                    (imported["control_owner_id"],),
                ).fetchone()
            )
            from .product_store_capability_grants import control_usages_settled

            wire._require(control_usages_settled(store, connection, imported["control_owner_id"]))
            others = connection.execute(
                "SELECT job_id FROM file_access_operations WHERE control_owner_id=? AND job_id<>?",
                (imported["control_owner_id"], job_id),
            ).fetchall()
            for other in others:
                state, _ = _outcome_at(connection, other["job_id"])
                wire._require(
                    state is not None and state["state"] in ("complete", "refused_no_effect")
                )
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                (
                    revision["control_owner_id"],
                    revision["revision"],
                    job_id,
                    canonical_json(revision),
                    content_hash(revision),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (job_id, canonical_json(outcome), content_hash(outcome)),
            )
            return revision
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None


def _pair_attempt_unused(connection: Any, job_id: str) -> bool:
    job = connection.execute("SELECT state FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    claimed = connection.execute(
        "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1", (job_id,)
    ).fetchone()
    outcome, _ = _outcome_at(connection, job_id)
    return (
        job is not None
        and job["state"] in ("failed", "cancelled", "interrupted")
        and claimed is None
        and outcome
        == {
            "state": "refused_no_effect",
            "evidence_digest": content_hash([]),
            "control_digest": None,
        }
    )


def pair_control_projection(store: Any, owner_id: str, *, clock: datetime) -> dict:
    """Read the committed original observation without refreshing enrollment or replay."""
    try:
        wire._clock(clock)
        with store._connection() as connection:
            imported = document(at(connection, owner_id=owner_id))
            wire._require(imported["schema_version"] == pair_admission.IMPORT_SCHEMA)
            row = connection.execute(
                "SELECT job_id FROM file_access_revisions WHERE control_owner_id=? ORDER BY revision DESC LIMIT 1",
                (owner_id,),
            ).fetchone()
            if row is None:
                projected = pair_admission.projection(imported)
                attempts = connection.execute(
                    "SELECT job_id FROM file_access_operations WHERE control_owner_id=?",
                    (owner_id,),
                ).fetchall()
                projected["task_usage_state"] = (
                    "none"
                    if all(
                        _pair_attempt_unused(connection, attempt["job_id"]) for attempt in attempts
                    )
                    else "unresolved"
                )
                return projected
            original = _original_pair_at(connection, row["job_id"])
            _, _, prepared, prep_digest, same_import = original
        context = native._context(
            store,
            prepared["original"]["task_id"],
            prepared["original"]["transport_request_hash"],
            prepared["expected_binding"],
            _protocol=native._Protocol.PAIR_V2,
        )
        with store._connection() as connection:
            wire._require(
                _original_pair_at(connection, row["job_id"]) == original and same_import == imported
            )
            baseline = _pair_baseline(connection, context, prepared, prep_digest, imported, clock)
            saved, saved_digest = _bounded(
                connection, "file_access_revisions", "job_id", row["job_id"], wire.PUBLIC_MAX
            )
            outcome, _ = _outcome_at(connection, row["job_id"])
            wire._require(
                saved == _revision(imported, prepared, context, baseline, row["job_id"])
                and outcome is not None
                and outcome
                == {
                    "state": "complete",
                    "evidence_digest": baseline["baseline_digest"],
                    "control_digest": saved_digest,
                    "native_baseline": baseline,
                }
            )
            projected = pair_admission.projection(imported)
            projected.update(
                control_digest=saved_digest,
                revision=2,
                status="baseline_verified",
                baseline=baseline,
                task_usage_state="settled",
                allowed_operations=[],
            )
            return projected
    except _FAILURES:
        raise ProductStoreError(_ERROR) from None
