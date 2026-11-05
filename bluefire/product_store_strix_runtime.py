"""Controller-private operations over Strix runtime authority and admission records.

SQL record validation lives below this store mixin so issuance and runtime
operations can share it without depending on one another's coordinators.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .product_store_strix_runtime_records import (
    _ADMISSION_DIGEST_FIELDS as _ADMISSION_DIGEST_FIELDS,
)
from .product_store_strix_runtime_records import (
    _ADMISSION_FIELDS as _ADMISSION_FIELDS,
)
from .product_store_strix_runtime_records import (
    _ADMISSION_STATES as _ADMISSION_STATES,
)
from .product_store_strix_runtime_records import (
    _ADMISSION_TRANSITIONS as _ADMISSION_TRANSITIONS,
)
from .product_store_strix_runtime_records import (
    _ARTIFACT_KEY as _ARTIFACT_KEY,
)
from .product_store_strix_runtime_records import (
    _ATTEMPT as _ATTEMPT,
)
from .product_store_strix_runtime_records import (
    _AUTHORITY_FIELDS as _AUTHORITY_FIELDS,
)
from .product_store_strix_runtime_records import (
    _AUTHORITY_STATES as _AUTHORITY_STATES,
)
from .product_store_strix_runtime_records import (
    _DIGEST as _DIGEST,
)
from .product_store_strix_runtime_records import (
    _EXPERIMENT as _EXPERIMENT,
)
from .product_store_strix_runtime_records import (
    _OPAQUE_DIGEST_FIELDS as _OPAQUE_DIGEST_FIELDS,
)
from .product_store_strix_runtime_records import (
    _RESERVATION_FIELDS as _RESERVATION_FIELDS,
)
from .product_store_strix_runtime_records import (
    _REVISION as _REVISION,
)
from .product_store_strix_runtime_records import (
    ADMISSION_EVENT_SCHEMA as ADMISSION_EVENT_SCHEMA,
)
from .product_store_strix_runtime_records import (
    ADMISSION_RECORD_SCHEMA as ADMISSION_RECORD_SCHEMA,
)
from .product_store_strix_runtime_records import (
    ADMISSION_RESERVATION_SCHEMA as ADMISSION_RESERVATION_SCHEMA,
)
from .product_store_strix_runtime_records import (
    AUTHORITY_EVENT_SCHEMA as AUTHORITY_EVENT_SCHEMA,
)
from .product_store_strix_runtime_records import (
    MAX_ADMISSION_EVENTS as MAX_ADMISSION_EVENTS,
)
from .product_store_strix_runtime_records import (
    MAX_AUTHORITY_EVENTS as MAX_AUTHORITY_EVENTS,
)
from .product_store_strix_runtime_records import (
    MAX_DOCUMENT_BYTES as MAX_DOCUMENT_BYTES,
)
from .product_store_strix_runtime_records import (
    StrixRuntimeStore as StrixRuntimeStore,
)
from .product_store_strix_runtime_records import (
    _admission as _admission,
)
from .product_store_strix_runtime_records import (
    _append_strix_runtime_admission_event_at as _append_strix_runtime_admission_event_at,
)
from .product_store_strix_runtime_records import (
    _authority as _authority,
)
from .product_store_strix_runtime_records import (
    _authority_event_document as _authority_event_document,
)
from .product_store_strix_runtime_records import (
    _bounded_document as _bounded_document,
)
from .product_store_strix_runtime_records import (
    _canonical_row as _canonical_row,
)
from .product_store_strix_runtime_records import (
    _digest as _digest,
)
from .product_store_strix_runtime_records import (
    _event_document as _event_document,
)
from .product_store_strix_runtime_records import (
    _issuer_owned as _issuer_owned,
)
from .product_store_strix_runtime_records import (
    _issuer_preparing_event as _issuer_preparing_event,
)
from .product_store_strix_runtime_records import (
    _positive_int as _positive_int,
)
from .product_store_strix_runtime_records import (
    _read_admission as _read_admission,
)
from .product_store_strix_runtime_records import (
    _read_admission_chain as _read_admission_chain,
)
from .product_store_strix_runtime_records import (
    _read_authority_chain as _read_authority_chain,
)
from .product_store_strix_runtime_records import (
    _read_reservation as _read_reservation,
)
from .product_store_strix_runtime_records import (
    _read_strix_runtime_admission_state as _read_strix_runtime_admission_state,
)
from .product_store_strix_runtime_records import (
    _refuse_issuer_owned as _refuse_issuer_owned,
)
from .product_store_strix_runtime_records import (
    _reservation as _reservation,
)
from .product_store_strix_runtime_records import (
    _reserve_strix_runtime_admission_at as _reserve_strix_runtime_admission_at,
)
from .product_store_strix_runtime_records import (
    _retain_verified_strix_runtime_admission_at as _retain_verified_strix_runtime_admission_at,
)
from .product_store_strix_runtime_records import (
    _timestamp as _timestamp,
)
from .product_store_strix_runtime_records import (
    initialize_schema as initialize_schema,
)
from .util import content_hash


class StrixRuntimeStoreMixin:
    """Controller-private exact reads and append-only writes."""

    def _append_strix_runtime_authority(
        self: StrixRuntimeStore,
        *,
        authority_ref: str,
        authority: Mapping[str, Any],
        authority_basis_ref: str,
        expected_previous_event_digest: str | None,
    ) -> Mapping[str, Any]:
        checked = _authority(authority)
        with self._connection(write=True) as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if checked["generation"] <= len(chain):
                existing = chain[checked["generation"] - 1]
                expected = _authority_event_document(
                    authority_ref=authority_ref,
                    authority=checked,
                    authority_basis_ref=authority_basis_ref,
                    previous_event_digest=expected_previous_event_digest,
                )
                if existing["document"] == expected:
                    return cast(Mapping[str, Any], existing)
                raise ResourceConflictError("Strix runtime authority event conflicts")
            previous = chain[-1] if chain else None
            if (previous is None) != (expected_previous_event_digest is None) or (
                previous is not None and previous["event_digest"] != expected_previous_event_digest
            ):
                raise ResourceConflictError("Strix runtime authority head changed")
            if checked["generation"] != len(chain) + 1:
                raise ResourceConflictError("Strix runtime authority generation changed")
            document = _authority_event_document(
                authority_ref=authority_ref,
                authority=checked,
                authority_basis_ref=authority_basis_ref,
                previous_event_digest=expected_previous_event_digest,
            )
            if previous is not None:
                prior = previous["authority"]
                if checked["state"] == prior["state"]:
                    raise ResourceConflictError("Strix runtime authority transition is invalid")
                if authority_basis_ref == previous["authority_basis_ref"]:
                    raise ResourceConflictError("Strix runtime authority requires a fresh basis")
                if checked["state"] == "revoked" and any(
                    checked[name] != prior[name]
                    for name in (
                        "qualification_manifest_ref",
                        "protected_artifact_key",
                        "installed_bluefire_revision",
                        "strix_build_digest",
                        "threat_review_ref",
                    )
                ):
                    raise ResourceConflictError(
                        "Strix runtime revocation changed candidate anchors"
                    )
            record_digest = document["authority_record_digest"]
            event_digest = content_hash(document)
            connection.execute(
                """INSERT INTO strix_runtime_authority_events VALUES(?,?,?,?,?,?,?,?)""",
                (
                    authority_ref,
                    checked["generation"],
                    canonical_json(document),
                    record_digest,
                    event_digest,
                    authority_basis_ref,
                    expected_previous_event_digest,
                    checked["recorded_at"],
                ),
            )
            if previous is None:
                connection.execute(
                    "INSERT INTO strix_runtime_authority_heads VALUES(?,?,?,?,?)",
                    (
                        authority_ref,
                        checked["generation"],
                        record_digest,
                        event_digest,
                        authority_basis_ref,
                    ),
                )
            else:
                updated = connection.execute(
                    """UPDATE strix_runtime_authority_heads SET active_generation=?,
                    active_record_digest=?,active_event_digest=?,authority_basis_ref=?
                    WHERE authority_ref=? AND active_generation=? AND active_event_digest=?""",
                    (
                        checked["generation"],
                        record_digest,
                        event_digest,
                        authority_basis_ref,
                        authority_ref,
                        previous["authority"]["generation"],
                        previous["event_digest"],
                    ),
                )
                if updated.rowcount != 1:
                    raise ResourceConflictError("Strix runtime authority head changed")
            return cast(Mapping[str, Any], _read_authority_chain(connection, authority_ref)[-1])

    def _read_current_strix_runtime_authority(
        self: StrixRuntimeStore, authority_ref: str
    ) -> Mapping[str, Any] | None:
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            return None if not chain else chain[-1]

    def _read_strix_runtime_authority_event(
        self: StrixRuntimeStore, authority_ref: str, generation: int, record_digest: str
    ) -> Mapping[str, Any] | None:
        _positive_int(generation, "Strix authority generation", maximum=MAX_AUTHORITY_EVENTS)
        _digest(record_digest, "Strix authority record digest")
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if generation > len(chain):
                return None
            record = chain[generation - 1]
            return record if record["authority_record_digest"] == record_digest else None

    def _is_strix_runtime_authority_descendant(
        self: StrixRuntimeStore,
        *,
        authority_ref: str,
        ancestor_generation: int,
        ancestor_record_digest: str,
        descendant_generation: int,
        descendant_record_digest: str,
    ) -> bool:
        _positive_int(
            ancestor_generation, "ancestor Strix authority generation", maximum=MAX_AUTHORITY_EVENTS
        )
        _positive_int(
            descendant_generation,
            "descendant Strix authority generation",
            maximum=MAX_AUTHORITY_EVENTS,
        )
        _digest(ancestor_record_digest, "ancestor Strix authority digest")
        _digest(descendant_record_digest, "descendant Strix authority digest")
        with self._connection() as connection:
            chain = _read_authority_chain(connection, authority_ref)
            if ancestor_generation > descendant_generation or descendant_generation > len(chain):
                return False
            return bool(
                chain[ancestor_generation - 1]["authority_record_digest"] == ancestor_record_digest
                and chain[descendant_generation - 1]["authority_record_digest"]
                == descendant_record_digest
            )

    def _reserve_strix_runtime_admission(
        self: StrixRuntimeStore, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        checked = _reservation(document)
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, checked["attempt_id"])
            return _reserve_strix_runtime_admission_at(connection, checked)

    def _append_strix_runtime_admission_event(
        self: StrixRuntimeStore,
        *,
        attempt_id: str,
        state: str,
        lifecycle_basis_ref: str,
        recorded_at: str,
        expected_head_digest: str,
    ) -> Mapping[str, Any]:
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, attempt_id)
            _append_strix_runtime_admission_event_at(
                connection,
                attempt_id=attempt_id,
                state=state,
                lifecycle_basis_ref=lifecycle_basis_ref,
                recorded_at=recorded_at,
                expected_head_digest=expected_head_digest,
            )
            return cast(Mapping[str, Any], _read_admission_chain(connection, attempt_id)[-1])

    def _retain_verified_strix_runtime_admission(
        self: StrixRuntimeStore,
        *,
        document: Mapping[str, Any],
        lifecycle_basis_ref: str,
        recorded_at: str,
        expected_head_digest: str,
    ) -> Mapping[str, Any]:
        checked = _admission(document)
        with self._connection(write=True) as connection:
            _refuse_issuer_owned(connection, checked["attempt_id"])
            return _retain_verified_strix_runtime_admission_at(
                connection,
                document=checked,
                lifecycle_basis_ref=lifecycle_basis_ref,
                recorded_at=recorded_at,
                expected_head_digest=expected_head_digest,
            )

    def _read_strix_runtime_admission_envelope(
        self: StrixRuntimeStore, attempt_id: str
    ) -> Mapping[str, Any] | None:
        if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
            raise ProductStoreError("Strix admission attempt is invalid")
        with self._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            if _read_reservation(connection, attempt_id) is None:
                return None
            if _issuer_owned(connection, attempt_id):
                from .product_store_strix_admission_issuer import _read_at

                _read_at(connection, attempt_id)
            return _read_strix_runtime_admission_state(connection, attempt_id)
