"""Controller-owned presentation metadata for external-engine experiments.

The canonical :class:`~bluefire.engine_experiment.EngineExperiment` remains
the source of truth for execution state.  This module stores only immutable,
public display/setup metadata that the experiment contract deliberately does
not own, then derives one revision-exact workspace presentation at read time.

There is no public authoring surface here.  Trusted controller/bootstrap code
preprovisions the immutable profile and initial target, and controller code
registers later target/defense display metadata against an exact saved
experiment revision and digest.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol, cast

from .engine_experiment import EngineExperiment, EngineExperimentError
from .engine_experiment_workspace import (
    EngineExperimentWorkspaceError,
    _checked_presentation,
    _public_text,
    _text,
    _timestamp,
)
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, json_clone, parse_iso8601_datetime

_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROFILE_SCHEMA = "bluefire.engine-experiment-presentation-profile.v1"
_TARGET_SCHEMA = "bluefire.engine-experiment-target-presentation.v1"
_DEFENSE_SCHEMA = "bluefire.engine-experiment-defense-presentation.v1"
_MAX_PROFILE_BYTES = 64 * 1024
_MAX_DETAIL_BYTES = 8 * 1024
_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "objective",
        "environment",
        "initial_target_snapshot_ref",
        "engine_setup",
        "authorization",
        "limitations",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "snapshot_ref",
        "display_name",
        "captured_at",
    }
)
_DEFENSE_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "change_id",
        "kind",
        "summary",
    }
)
_DEFENSE_KINDS = frozenset(
    {"configuration", "permission", "identity", "prevention", "visibility", "detection"}
)


class EngineExperimentPresentationStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    def get_engine_experiment(
        self, experiment_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create append-only presentation registries in the product database."""

    if not connection.in_transaction:
        raise ProductStoreError("Engine presentation migration requires one transaction.")
    statements = (
        """CREATE TABLE IF NOT EXISTS engine_experiment_presentation_profiles (
            experiment_id TEXT PRIMARY KEY,
            initial_target_snapshot_ref TEXT NOT NULL
                CHECK (
                    length(initial_target_snapshot_ref) = 71 AND
                    substr(initial_target_snapshot_ref, 1, 7) = 'sha256:'
                ),
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 65536),
            document_digest TEXT NOT NULL
                CHECK (
                    length(document_digest) = 71 AND
                    substr(document_digest, 1, 7) = 'sha256:'
                ),
            registered_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS engine_experiment_target_presentations (
            experiment_id TEXT NOT NULL,
            snapshot_ref TEXT NOT NULL
                CHECK (length(snapshot_ref) = 71 AND substr(snapshot_ref, 1, 7) = 'sha256:'),
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 8192),
            document_digest TEXT NOT NULL
                CHECK (
                    length(document_digest) = 71 AND
                    substr(document_digest, 1, 7) = 'sha256:'
                ),
            record_digest TEXT NOT NULL PRIMARY KEY
                CHECK (
                    length(record_digest) = 71 AND
                    substr(record_digest, 1, 7) = 'sha256:'
                ),
            registered_revision INTEGER CHECK (registered_revision > 0),
            registered_experiment_digest TEXT
                CHECK (
                    registered_experiment_digest IS NULL OR
                    (
                        length(registered_experiment_digest) = 71 AND
                        substr(registered_experiment_digest, 1, 7) = 'sha256:'
                    )
                ),
            registered_prior_digest TEXT
                CHECK (
                    registered_prior_digest IS NULL OR
                    (
                        length(registered_prior_digest) = 71 AND
                        substr(registered_prior_digest, 1, 7) = 'sha256:'
                    )
                ),
            registered_at TEXT NOT NULL,
            FOREIGN KEY (experiment_id)
                REFERENCES engine_experiment_presentation_profiles(experiment_id),
            CHECK (
                (
                    registered_revision IS NULL AND
                    registered_experiment_digest IS NULL AND
                    registered_prior_digest IS NULL
                ) OR (
                    registered_revision IS NOT NULL AND
                    registered_experiment_digest IS NOT NULL AND
                    registered_prior_digest IS NOT NULL
                )
            )
        )""",
        """CREATE TABLE IF NOT EXISTS engine_experiment_defense_presentations (
            experiment_id TEXT NOT NULL,
            change_id TEXT NOT NULL,
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 8192),
            document_digest TEXT NOT NULL
                CHECK (
                    length(document_digest) = 71 AND
                    substr(document_digest, 1, 7) = 'sha256:'
                ),
            record_digest TEXT NOT NULL PRIMARY KEY
                CHECK (
                    length(record_digest) = 71 AND
                    substr(record_digest, 1, 7) = 'sha256:'
                ),
            registered_revision INTEGER NOT NULL CHECK (registered_revision > 0),
            registered_experiment_digest TEXT NOT NULL
                CHECK (
                    length(registered_experiment_digest) = 71 AND
                    substr(registered_experiment_digest, 1, 7) = 'sha256:'
                ),
            registered_prior_digest TEXT NOT NULL
                CHECK (
                    length(registered_prior_digest) = 71 AND
                    substr(registered_prior_digest, 1, 7) = 'sha256:'
                ),
            registered_at TEXT NOT NULL,
            FOREIGN KEY (experiment_id)
                REFERENCES engine_experiment_presentation_profiles(experiment_id)
        )""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_profiles_no_update
        BEFORE UPDATE ON engine_experiment_presentation_profiles
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment presentation profiles are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_profiles_no_delete
        BEFORE DELETE ON engine_experiment_presentation_profiles
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment presentation profiles are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_targets_valid_insert
        BEFORE INSERT ON engine_experiment_target_presentations
        BEGIN
            SELECT CASE
                WHEN NEW.registered_revision IS NULL AND NOT EXISTS (
                    SELECT 1 FROM engine_experiment_presentation_profiles AS profile
                    WHERE profile.experiment_id = NEW.experiment_id
                      AND profile.initial_target_snapshot_ref = NEW.snapshot_ref
                )
                THEN RAISE(ABORT, 'unanchored target is not the provisioned initial target')
                WHEN NEW.registered_revision IS NOT NULL AND NOT (
                    EXISTS (
                        SELECT 1 FROM engine_experiment_versions AS version
                        WHERE version.experiment_id = NEW.experiment_id
                          AND version.revision = NEW.registered_revision
                          AND version.digest = NEW.registered_experiment_digest
                          AND version.prior_digest = NEW.registered_prior_digest
                    ) OR EXISTS (
                        SELECT 1 FROM engine_experiment_versions AS prior
                        WHERE prior.experiment_id = NEW.experiment_id
                          AND prior.revision = NEW.registered_revision - 1
                          AND prior.digest = NEW.registered_prior_digest
                    )
                )
                THEN RAISE(ABORT, 'target presentation experiment anchor is invalid')
            END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_targets_no_update
        BEFORE UPDATE ON engine_experiment_target_presentations
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment target presentations are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_targets_no_delete
        BEFORE DELETE ON engine_experiment_target_presentations
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment target presentations are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_defenses_valid_insert
        BEFORE INSERT ON engine_experiment_defense_presentations
        BEGIN
            SELECT CASE WHEN NOT (
                EXISTS (
                    SELECT 1 FROM engine_experiment_versions AS version
                    WHERE version.experiment_id = NEW.experiment_id
                      AND version.revision = NEW.registered_revision
                      AND version.digest = NEW.registered_experiment_digest
                      AND version.prior_digest = NEW.registered_prior_digest
                ) OR EXISTS (
                    SELECT 1 FROM engine_experiment_versions AS prior
                    WHERE prior.experiment_id = NEW.experiment_id
                      AND prior.revision = NEW.registered_revision - 1
                      AND prior.digest = NEW.registered_prior_digest
                )
            ) THEN RAISE(ABORT, 'defense presentation experiment anchor is invalid') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_defenses_no_update
        BEFORE UPDATE ON engine_experiment_defense_presentations
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment defense presentations are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_defenses_no_delete
        BEFORE DELETE ON engine_experiment_defense_presentations
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment defense presentations are immutable');
        END""",
        """CREATE INDEX IF NOT EXISTS engine_experiment_targets_identity_idx
            ON engine_experiment_target_presentations(experiment_id, snapshot_ref)""",
        """CREATE INDEX IF NOT EXISTS engine_experiment_defenses_identity_idx
            ON engine_experiment_defense_presentations(experiment_id, change_id)""",
    )
    for statement in statements:
        connection.execute(statement)


def _experiment_id(value: Any) -> str:
    if not isinstance(value, str) or _EXPERIMENT_ID.fullmatch(value) is None:
        raise ProductStoreError("engine experiment presentation identity is invalid")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{context} must be an exact sha256 digest")
    return value


def _revision(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProductStoreError(f"{context} must be a positive integer")
    return int(value)


def _exact(value: Any, fields: frozenset[str], context: str) -> dict[str, Any]:
    try:
        document = json_clone(value)
        if not isinstance(document, dict):
            raise ProductStoreError(f"{context} must be a JSON object")
        if fields == _PROFILE_FIELDS:
            scrubbed = json_clone(document)
            authorization = scrubbed.pop("authorization", None)
            safe_document(scrubbed, context=context)
            safe_document(authorization, context=f"{context}.limits")
        else:
            safe_document(document, context=context)
    except ProductStoreError:
        raise
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"{context} must contain only safe JSON values") from exc
    if not isinstance(document, dict) or set(document) != fields:
        raise ProductStoreError(f"{context} fields changed")
    return document


def _canonical_document(
    value: Any,
    fields: frozenset[str],
    context: str,
    *,
    maximum_bytes: int,
) -> tuple[dict[str, Any], str, str]:
    document = _exact(value, fields, context)
    try:
        encoded = canonical_json(document)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"{context} is not canonical JSON") from exc
    if not encoded or len(encoded.encode("utf-8")) > maximum_bytes:
        raise ProductStoreError(f"{context} exceeds its canonical JSON bound")
    return document, encoded, content_hash(document)


def _registry_record_digest(
    *,
    kind: str,
    experiment_id: str,
    item_id: str,
    document_digest: str,
    revision: int | None,
    experiment_digest: str | None,
    prior_digest: str | None,
) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.engine-experiment-presentation-registry-record.v1",
            "kind": kind,
            "experiment_id": experiment_id,
            "item_id": item_id,
            "document_digest": document_digest,
            "registered_revision": revision,
            "registered_experiment_digest": experiment_digest,
            "registered_prior_digest": prior_digest,
        }
    )


def _assert_registry_record_digest(
    row: sqlite3.Row,
    *,
    kind: str,
    item_column: str,
    context: str,
) -> None:
    expected = _registry_record_digest(
        kind=kind,
        experiment_id=str(row["experiment_id"]),
        item_id=str(row[item_column]),
        document_digest=str(row["document_digest"]),
        revision=(None if row["registered_revision"] is None else int(row["registered_revision"])),
        experiment_digest=(
            None
            if row["registered_experiment_digest"] is None
            else str(row["registered_experiment_digest"])
        ),
        prior_digest=(
            None if row["registered_prior_digest"] is None else str(row["registered_prior_digest"])
        ),
    )
    if row["record_digest"] != expected:
        raise ProductStoreError(f"saved {context} registry integrity check failed")


def _target_document(value: Any) -> tuple[dict[str, Any], str, str]:
    document, encoded, document_digest = _canonical_document(
        value,
        _TARGET_FIELDS,
        "engine experiment target presentation",
        maximum_bytes=_MAX_DETAIL_BYTES,
    )
    if document["schema_version"] != _TARGET_SCHEMA:
        raise ProductStoreError("engine experiment target presentation is unsupported")
    _experiment_id(document["experiment_id"])
    _digest(document["snapshot_ref"], "target snapshot reference")
    try:
        _public_text(document["display_name"], "current target display name", maximum=200)
        _timestamp(document["captured_at"], "current target capture time")
    except EngineExperimentWorkspaceError as exc:
        raise ProductStoreError("engine experiment target presentation is invalid") from exc
    return document, encoded, document_digest


def _defense_document(value: Any) -> tuple[dict[str, Any], str, str]:
    document, encoded, document_digest = _canonical_document(
        value,
        _DEFENSE_FIELDS,
        "engine experiment defense presentation",
        maximum_bytes=_MAX_DETAIL_BYTES,
    )
    if document["schema_version"] != _DEFENSE_SCHEMA:
        raise ProductStoreError("engine experiment defense presentation is unsupported")
    _experiment_id(document["experiment_id"])
    if document["kind"] not in _DEFENSE_KINDS:
        raise ProductStoreError("engine experiment defense presentation kind is invalid")
    try:
        _text(document["change_id"], "defensive change identity", maximum=80)
        _public_text(document["summary"], "defensive change summary", maximum=1000)
    except EngineExperimentWorkspaceError as exc:
        raise ProductStoreError("engine experiment defense presentation is invalid") from exc
    return document, encoded, document_digest


def _presentation(
    profile: Mapping[str, Any],
    experiment: EngineExperiment,
    target: Mapping[str, Any] | None,
    defense: Mapping[str, Any] | None,
) -> dict[str, Any]:
    change = experiment.defense_change
    defensive_change = None
    if change is not None:
        if defense is None:
            raise ProductStoreError("engine experiment defense presentation is missing")
        defensive_change = {
            "change_id": defense["change_id"],
            "state": change.state.value,
            "kind": defense["kind"],
            "summary": defense["summary"],
            "mechanism_ref": change.mechanism_ref,
            "before_target_snapshot_ref": change.before_target_snapshot_ref,
            "after_target_snapshot_ref": change.after_target_snapshot_ref,
            "rollback_digest": change.rollback_digest,
            "applied_at": change.applied_at,
        }
    current_target = None
    if experiment.current_target_snapshot_ref is not None:
        if target is None:
            raise ProductStoreError("engine experiment current target presentation is missing")
        current_target = {
            "snapshot_ref": target["snapshot_ref"],
            "display_name": target["display_name"],
            "captured_at": target["captured_at"],
        }
    return {
        "schema_version": "bluefire.engine-experiment-presentation.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "objective": json_clone(profile["objective"]),
        "environment": json_clone(profile["environment"]),
        "current_target": current_target,
        "engine_setup": json_clone(profile["engine_setup"]),
        "authorization": json_clone(profile["authorization"]),
        "defensive_change": defensive_change,
        "selection": None,
        "limitations": json_clone(profile["limitations"]),
    }


def _validate_complete_presentation(
    profile: Mapping[str, Any],
    experiment: EngineExperiment,
    target: Mapping[str, Any] | None,
    defense: Mapping[str, Any] | None,
) -> dict[str, Any]:
    result = _presentation(profile, experiment, target, defense)
    try:
        _checked_presentation(result, experiment)
    except EngineExperimentWorkspaceError as exc:
        raise ProductStoreError(
            "engine experiment presentation failed contract validation"
        ) from exc
    return result


def _profile_and_initial_documents(
    experiment_id: str,
    profile_value: Any,
    target_value: Any,
) -> tuple[dict[str, Any], str, str, dict[str, Any], str, str]:
    identity = _experiment_id(experiment_id)
    profile, profile_json, profile_digest = _canonical_document(
        profile_value,
        _PROFILE_FIELDS,
        "engine experiment presentation profile",
        maximum_bytes=_MAX_PROFILE_BYTES,
    )
    target, target_json, target_digest = _target_document(target_value)
    if profile["schema_version"] != _PROFILE_SCHEMA:
        raise ProductStoreError("engine experiment presentation profile is unsupported")
    if profile["experiment_id"] != identity or target["experiment_id"] != identity:
        raise ProductStoreError("engine experiment presentation identity is mismatched")
    initial_ref = _digest(
        profile["initial_target_snapshot_ref"], "initial target snapshot reference"
    )
    if target["snapshot_ref"] != initial_ref:
        raise ProductStoreError("initial target presentation identity is mismatched")
    try:
        synthetic = EngineExperiment.create(
            experiment_id=identity,
            objective_ref=cast(Mapping[str, Any], profile["objective"])["objective_ref"],
            environment_ref=cast(Mapping[str, Any], profile["environment"])["environment_ref"],
            scope_ref=cast(Mapping[str, Any], profile["authorization"])["scope_ref"],
            scope_version=cast(Mapping[str, Any], profile["authorization"])["scope_version"],
            target_snapshot_ref=initial_ref,
            created_at=target["captured_at"],
        )
        _validate_complete_presentation(profile, synthetic, target, None)
    except (EngineExperimentError, KeyError, TypeError) as exc:
        raise ProductStoreError("engine experiment presentation profile is invalid") from exc
    return profile, profile_json, profile_digest, target, target_json, target_digest


def _saved_document(
    row: sqlite3.Row,
    *,
    context: str,
    fields: frozenset[str],
    maximum_bytes: int,
) -> dict[str, Any]:
    try:
        value = json.loads(str(row["document_json"]))
        document, encoded, digest = _canonical_document(
            value,
            fields,
            context,
            maximum_bytes=maximum_bytes,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProductStoreError(f"saved {context} JSON is invalid") from exc
    if encoded != row["document_json"] or digest != row["document_digest"]:
        raise ProductStoreError(f"saved {context} integrity check failed")
    return document


def _load_profile(connection: sqlite3.Connection, experiment_id: str) -> dict[str, Any]:
    row = connection.execute(
        """SELECT * FROM engine_experiment_presentation_profiles
           WHERE experiment_id = ?""",
        (experiment_id,),
    ).fetchone()
    if row is None:
        raise ProductStoreError("engine experiment presentation profile is missing")
    profile = _saved_document(
        row,
        context="engine experiment presentation profile",
        fields=_PROFILE_FIELDS,
        maximum_bytes=_MAX_PROFILE_BYTES,
    )
    if (
        profile.get("schema_version") != _PROFILE_SCHEMA
        or profile.get("experiment_id") != row["experiment_id"]
        or profile.get("initial_target_snapshot_ref") != row["initial_target_snapshot_ref"]
    ):
        raise ProductStoreError("saved engine experiment presentation profile identity changed")
    return profile


def _load_target(
    connection: sqlite3.Connection,
    experiment_id: str,
    snapshot_ref: str,
) -> dict[str, Any]:
    rows = connection.execute(
        """SELECT * FROM engine_experiment_target_presentations
           WHERE experiment_id = ? AND snapshot_ref = ?""",
        (experiment_id, snapshot_ref),
    ).fetchall()
    if not rows:
        raise ProductStoreError("engine experiment current target presentation is missing")
    documents: list[dict[str, Any]] = []
    for row in rows:
        _assert_registry_record_digest(
            row,
            kind="target",
            item_column="snapshot_ref",
            context="engine experiment target presentation",
        )
        target = _saved_document(
            row,
            context="engine experiment target presentation",
            fields=_TARGET_FIELDS,
            maximum_bytes=_MAX_DETAIL_BYTES,
        )
        if (
            target.get("schema_version") != _TARGET_SCHEMA
            or target.get("experiment_id") != row["experiment_id"]
            or target.get("snapshot_ref") != row["snapshot_ref"]
        ):
            raise ProductStoreError("saved engine experiment target presentation identity changed")
        documents.append(target)
    if any(document != documents[0] for document in documents[1:]):
        raise ProductStoreError("saved engine experiment target presentation metadata conflicts")
    return documents[0]


def _load_defense(
    connection: sqlite3.Connection,
    experiment_id: str,
    change_id: str,
) -> dict[str, Any]:
    rows = connection.execute(
        """SELECT * FROM engine_experiment_defense_presentations
           WHERE experiment_id = ? AND change_id = ?""",
        (experiment_id, change_id),
    ).fetchall()
    if not rows:
        raise ProductStoreError("engine experiment defense presentation is missing")
    documents: list[dict[str, Any]] = []
    for row in rows:
        _assert_registry_record_digest(
            row,
            kind="defense",
            item_column="change_id",
            context="engine experiment defense presentation",
        )
        defense = _saved_document(
            row,
            context="engine experiment defense presentation",
            fields=_DEFENSE_FIELDS,
            maximum_bytes=_MAX_DETAIL_BYTES,
        )
        if (
            defense.get("schema_version") != _DEFENSE_SCHEMA
            or defense.get("experiment_id") != row["experiment_id"]
            or defense.get("change_id") != row["change_id"]
            or defense.get("kind") not in _DEFENSE_KINDS
        ):
            raise ProductStoreError("saved engine experiment defense presentation identity changed")
        documents.append(defense)
    if any(document != documents[0] for document in documents[1:]):
        raise ProductStoreError("saved engine experiment defense presentation metadata conflicts")
    return documents[0]


def _registry_anchor(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    experiment: EngineExperiment,
    *,
    context: str,
) -> tuple[bool, EngineExperiment | None]:
    revision = row["registered_revision"]
    digest = row["registered_experiment_digest"]
    prior_digest = row["registered_prior_digest"]
    if revision is None or digest is None or prior_digest is None:
        if revision is None and digest is None and prior_digest is None:
            return True, None
        raise ProductStoreError(f"saved {context} anchor is incomplete")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision <= 0
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or not isinstance(prior_digest, str)
        or _DIGEST.fullmatch(prior_digest) is None
    ):
        raise ProductStoreError(f"saved {context} anchor is invalid")
    if revision > experiment.revision:
        return False, None
    if revision == experiment.revision:
        if digest != experiment.digest or prior_digest != experiment.previous_revision_digest:
            return False, None
        return True, experiment
    version = connection.execute(
        """SELECT * FROM engine_experiment_versions
           WHERE experiment_id = ? AND revision = ?""",
        (experiment.experiment_id, revision),
    ).fetchone()
    if version is None:
        return False, None
    try:
        document = json.loads(str(version["document_json"]))
        if (
            canonical_json(document) != version["document_json"]
            or content_hash(document) != version["digest"]
        ):
            raise ProductStoreError(f"saved {context} anchor integrity check failed")
        anchored = EngineExperiment._from_controller_mapping(document)
    except ProductStoreError:
        raise
    except (EngineExperimentError, TypeError, ValueError) as exc:
        raise ProductStoreError(f"saved {context} anchor is invalid") from exc
    if anchored.revision != revision or anchored.digest != digest:
        return False, None
    if version["digest"] != digest or version["prior_digest"] != prior_digest:
        return False, None
    return True, anchored


def _assert_target_anchor(
    connection: sqlite3.Connection,
    experiment: EngineExperiment,
    snapshot_ref: str,
) -> None:
    rows = connection.execute(
        """SELECT *
           FROM engine_experiment_target_presentations
           WHERE experiment_id = ? AND snapshot_ref = ?""",
        (experiment.experiment_id, snapshot_ref),
    ).fetchall()
    if not rows:
        raise ProductStoreError("engine experiment current target presentation is missing")
    for row in rows:
        _assert_registry_record_digest(
            row,
            kind="target",
            item_column="snapshot_ref",
            context="engine experiment target presentation",
        )
        reachable, anchor = _registry_anchor(
            connection,
            row,
            experiment,
            context="engine experiment target presentation",
        )
        if not reachable:
            continue
        if anchor is None:
            if snapshot_ref == experiment.initial_target_snapshot_ref:
                return
        elif snapshot_ref in _referenced_snapshots(anchor):
            return
    raise ProductStoreError("target presentation has no reachable experiment anchor")


def _assert_defense_anchor(
    connection: sqlite3.Connection,
    experiment: EngineExperiment,
    change_id: str,
) -> None:
    rows = connection.execute(
        """SELECT *
           FROM engine_experiment_defense_presentations
           WHERE experiment_id = ? AND change_id = ?""",
        (experiment.experiment_id, change_id),
    ).fetchall()
    if not rows:
        raise ProductStoreError("engine experiment defense presentation is missing")
    for row in rows:
        _assert_registry_record_digest(
            row,
            kind="defense",
            item_column="change_id",
            context="engine experiment defense presentation",
        )
        reachable, anchor = _registry_anchor(
            connection,
            row,
            experiment,
            context="engine experiment defense presentation",
        )
        if (
            reachable
            and anchor is not None
            and anchor.defense_change is not None
            and anchor.defense_change.change_id == change_id
        ):
            return
    raise ProductStoreError("defense presentation has no reachable experiment anchor")


def _has_exact_registry_anchor(
    connection: sqlite3.Connection,
    *,
    kind: str,
    experiment_id: str,
    item_id: str,
    revision: int,
    experiment_digest: str,
    prior_digest: str,
) -> bool:
    if kind == "target":
        table = "engine_experiment_target_presentations"
        item_column = "snapshot_ref"
    elif kind == "defense":
        table = "engine_experiment_defense_presentations"
        item_column = "change_id"
    else:  # pragma: no cover - internal closed call sites
        raise ProductStoreError("engine experiment presentation registry kind is invalid")
    row = connection.execute(
        f"""SELECT 1 FROM {table}
            WHERE experiment_id = ? AND {item_column} = ?
              AND registered_revision = ?
              AND registered_experiment_digest = ?
              AND registered_prior_digest = ?""",
        (experiment_id, item_id, revision, experiment_digest, prior_digest),
    ).fetchone()
    return row is not None


def _experiment_from_record(
    record: Mapping[str, Any],
    *,
    expected_revision: int,
    expected_digest: str,
) -> EngineExperiment:
    if record.get("revision") != expected_revision or record.get("digest") != expected_digest:
        raise ResourceConflictError("engine experiment presentation anchor changed")
    try:
        experiment = EngineExperiment._from_controller_mapping(record["document"])
    except (EngineExperimentError, KeyError, TypeError) as exc:
        raise ProductStoreError("saved engine experiment contract is invalid") from exc
    if experiment.revision != expected_revision or experiment.digest != expected_digest:
        raise ProductStoreError("saved engine experiment digest differs from its contract")
    return experiment


def _profile_matches_experiment(profile: Mapping[str, Any], experiment: EngineExperiment) -> None:
    try:
        objective = cast(Mapping[str, Any], profile["objective"])
        environment = cast(Mapping[str, Any], profile["environment"])
        setup = cast(Mapping[str, Any], profile["engine_setup"])
        engine = cast(Mapping[str, Any], setup["engine"])
        model = cast(Mapping[str, Any], setup["model"])
        authorization = cast(Mapping[str, Any], profile["authorization"])
        if (
            objective["objective_ref"] != experiment.objective_ref
            or environment["environment_ref"] != experiment.environment_ref
            or profile["initial_target_snapshot_ref"] != experiment.initial_target_snapshot_ref
            or authorization["scope_ref"] != experiment.scope_ref
            or authorization["scope_version"] != experiment.scope_version
        ):
            raise ProductStoreError("engine experiment presentation references changed")
        visible_engine = {
            key: engine[key] for key in ("id", "version", "revision", "package_digest")
        }
        visible_model = {
            key: model[key]
            for key in ("provider", "id", "data_destination", "authorization_digest")
        }
        visible_limits = {
            key: authorization[key]
            for key in (
                "wall_clock_seconds",
                "action_limit",
                "artifact_byte_limit",
                "cost_limit_microunits",
            )
        }
    except (KeyError, TypeError) as exc:
        raise ProductStoreError("engine experiment presentation profile is invalid") from exc
    for entry in experiment.attempts:
        binding = entry.record.binding
        if (
            visible_engine
            != {
                "id": binding.engine_id,
                "version": binding.engine_version,
                "revision": binding.engine_revision,
                "package_digest": binding.engine_package_digest,
            }
            or visible_model
            != {
                "provider": binding.model_provider,
                "id": binding.model_id,
                "data_destination": binding.model_data_destination,
                "authorization_digest": binding.model_authorization_ref,
            }
            or visible_limits
            != {
                "wall_clock_seconds": binding.wall_clock_seconds,
                "action_limit": binding.action_limit,
                "artifact_byte_limit": binding.artifact_byte_limit,
                "cost_limit_microunits": binding.cost_limit_microunits,
            }
        ):
            raise ProductStoreError("engine experiment attempt setup changed")


def _referenced_snapshots(experiment: EngineExperiment) -> frozenset[str]:
    snapshots = {
        experiment.initial_target_snapshot_ref,
        *(entry.record.binding.target_snapshot_ref for entry in experiment.attempts),
        *(check.target_snapshot_ref for check in experiment.checks),
        *(observation.target_snapshot_ref for observation in experiment.independent_observations),
    }
    if experiment.current_target_snapshot_ref is not None:
        snapshots.add(experiment.current_target_snapshot_ref)
    if experiment.defense_change is not None:
        snapshots.add(experiment.defense_change.before_target_snapshot_ref)
        snapshots.add(experiment.defense_change.after_target_snapshot_ref)
    return frozenset(snapshots)


def _validate_transition(current: EngineExperiment, successor: EngineExperiment) -> None:
    if not isinstance(current, EngineExperiment) or not isinstance(successor, EngineExperiment):
        raise ProductStoreError("engine experiment presentation transition is invalid")
    try:
        current.validate()
        successor.validate()
    except EngineExperimentError as exc:
        raise ProductStoreError("engine experiment presentation transition is invalid") from exc
    if (
        successor.experiment_id != current.experiment_id
        or successor.revision != current.revision + 1
        or successor.previous_revision_digest != current.digest
        or successor.objective_ref != current.objective_ref
        or successor.environment_ref != current.environment_ref
        or successor.scope_ref != current.scope_ref
        or successor.scope_version != current.scope_version
        or successor.initial_target_snapshot_ref != current.initial_target_snapshot_ref
        or successor.created_at != current.created_at
    ):
        raise ProductStoreError("engine experiment presentation transition changed identity")


def _presentation_parts(
    connection: sqlite3.Connection,
    experiment: EngineExperiment,
    profile: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    target = (
        None
        if experiment.current_target_snapshot_ref is None
        else _load_target(
            connection,
            experiment.experiment_id,
            experiment.current_target_snapshot_ref,
        )
    )
    if experiment.current_target_snapshot_ref is not None:
        _assert_target_anchor(
            connection,
            experiment,
            experiment.current_target_snapshot_ref,
        )
    defense = (
        None
        if experiment.defense_change is None
        else _load_defense(
            connection,
            experiment.experiment_id,
            experiment.defense_change.change_id,
        )
    )
    if experiment.defense_change is not None:
        _assert_defense_anchor(
            connection,
            experiment,
            experiment.defense_change.change_id,
        )
    _profile_matches_experiment(profile, experiment)
    _validate_complete_presentation(profile, experiment, target, defense)
    return target, defense


class EngineExperimentPresentationStoreMixin:
    """ProductStore methods for immutable, controller-owned presentation data."""

    def provision_engine_experiment_presentation(
        self: EngineExperimentPresentationStore,
        experiment_id: str,
        profile: Mapping[str, Any],
        initial_target: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Preprovision one immutable profile and its exact initial target."""

        (
            checked_profile,
            profile_json,
            profile_digest,
            checked_target,
            target_json,
            target_digest,
        ) = _profile_and_initial_documents(experiment_id, profile, initial_target)
        identity = _experiment_id(experiment_id)
        initial_record_digest = _registry_record_digest(
            kind="target",
            experiment_id=identity,
            item_id=cast(str, checked_target["snapshot_ref"]),
            document_digest=target_digest,
            revision=None,
            experiment_digest=None,
            prior_digest=None,
        )
        now = utc_now()
        with self._connection(write=True) as connection:
            existing_profile = connection.execute(
                """SELECT * FROM engine_experiment_presentation_profiles
                   WHERE experiment_id = ?""",
                (identity,),
            ).fetchone()
            existing_target = connection.execute(
                """SELECT * FROM engine_experiment_target_presentations
                   WHERE experiment_id = ? AND snapshot_ref = ?""",
                (identity, checked_target["snapshot_ref"]),
            ).fetchone()
            if existing_profile is not None or existing_target is not None:
                if existing_profile is None or existing_target is None:
                    raise ProductStoreError(
                        "engine experiment presentation provisioning is incomplete"
                    )
                saved_profile = _load_profile(connection, identity)
                saved_target = _load_target(
                    connection, identity, cast(str, checked_target["snapshot_ref"])
                )
                if saved_profile != checked_profile or saved_target != checked_target:
                    raise ResourceConflictError(
                        "engine experiment presentation identity already has different metadata"
                    )
                return {
                    "profile": json_clone(saved_profile),
                    "initial_target": json_clone(saved_target),
                }
            try:
                connection.execute(
                    """INSERT INTO engine_experiment_presentation_profiles(
                           experiment_id, initial_target_snapshot_ref, document_json,
                           document_digest, registered_at
                       ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        identity,
                        checked_profile["initial_target_snapshot_ref"],
                        profile_json,
                        profile_digest,
                        now,
                    ),
                )
                connection.execute(
                    """INSERT INTO engine_experiment_target_presentations(
                           experiment_id, snapshot_ref, document_json, document_digest,
                           record_digest,
                           registered_revision, registered_experiment_digest,
                           registered_prior_digest, registered_at
                       ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?)""",
                    (
                        identity,
                        checked_target["snapshot_ref"],
                        target_json,
                        target_digest,
                        initial_record_digest,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError(
                    "engine experiment presentation provisioning lost a race"
                ) from exc
        return {
            "profile": json_clone(checked_profile),
            "initial_target": json_clone(checked_target),
        }

    def assert_engine_experiment_presentation_create_ready(
        self: EngineExperimentPresentationStore,
        experiment: EngineExperiment,
    ) -> None:
        """Fail before history mutation unless exact revision-one metadata is ready."""

        if not isinstance(experiment, EngineExperiment):
            raise ProductStoreError("engine experiment presentation preflight is invalid")
        try:
            experiment.validate()
        except EngineExperimentError as exc:
            raise ProductStoreError("engine experiment presentation preflight is invalid") from exc
        if (
            experiment.revision != 1
            or experiment.previous_revision_digest is not None
            or experiment.current_target_snapshot_ref != experiment.initial_target_snapshot_ref
            or experiment.attempts
            or experiment.checks
            or experiment.independent_observations
            or experiment.defense_change is not None
        ):
            raise ProductStoreError(
                "engine experiment presentation preflight requires a new experiment"
            )
        with self._connection() as connection:
            profile = _load_profile(connection, experiment.experiment_id)
            target = _load_target(
                connection,
                experiment.experiment_id,
                experiment.initial_target_snapshot_ref,
            )
            _assert_target_anchor(
                connection,
                experiment,
                experiment.initial_target_snapshot_ref,
            )
        _profile_matches_experiment(profile, experiment)
        _validate_complete_presentation(profile, experiment, target, None)

    def provision_engine_experiment_transition_presentation(
        self: EngineExperimentPresentationStore,
        current: EngineExperiment,
        successor: EngineExperiment,
        *,
        target_presentation: Mapping[str, Any] | None = None,
        defense_presentation: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Preprovision display metadata for one exact not-yet-saved successor.

        Trusted controller code calls this before the history compare-and-swap.
        A failed history CAS can leave only unreachable immutable metadata; it
        cannot make that metadata current or visible for another revision.
        """

        _validate_transition(current, successor)
        current_record = self.get_engine_experiment(
            current.experiment_id, revision=current.revision
        )
        saved = _experiment_from_record(
            current_record,
            expected_revision=current.revision,
            expected_digest=current.digest,
        )
        if (
            current_record.get("active") is not True
            or current_record.get("active_revision") != current.revision
            or saved.to_dict() != current.to_dict()
        ):
            raise ResourceConflictError("engine experiment presentation transition changed")

        checked_target: dict[str, Any] | None = None
        target_json: str | None = None
        target_digest: str | None = None
        if target_presentation is not None:
            checked_target, target_json, target_digest = _target_document(target_presentation)
            if checked_target["experiment_id"] != successor.experiment_id:
                raise ProductStoreError(
                    "engine experiment target presentation identity is mismatched"
                )
            snapshot_ref = cast(str, checked_target["snapshot_ref"])
            if snapshot_ref not in _referenced_snapshots(successor):
                raise ProductStoreError("target snapshot is not referenced by the successor")
            captured = parse_iso8601_datetime(cast(str, checked_target["captured_at"]))
            if captured > parse_iso8601_datetime(successor.updated_at) or (
                snapshot_ref != successor.initial_target_snapshot_ref
                and captured < parse_iso8601_datetime(successor.created_at)
            ):
                raise ProductStoreError("target presentation capture time changed")

        checked_defense: dict[str, Any] | None = None
        defense_json: str | None = None
        defense_digest: str | None = None
        if defense_presentation is not None:
            checked_defense, defense_json, defense_digest = _defense_document(defense_presentation)
            change = successor.defense_change
            if (
                checked_defense["experiment_id"] != successor.experiment_id
                or change is None
                or checked_defense["change_id"] != change.change_id
            ):
                raise ProductStoreError("defense presentation is not referenced by the successor")

        now = utc_now()
        with self._connection(write=True) as connection:
            profile = _load_profile(connection, current.experiment_id)
            initial_target = _load_target(
                connection,
                current.experiment_id,
                cast(str, profile["initial_target_snapshot_ref"]),
            )
            _profile_and_initial_documents(current.experiment_id, profile, initial_target)
            _presentation_parts(connection, current, profile)

            successor_target = None
            if successor.current_target_snapshot_ref is not None:
                if (
                    checked_target is not None
                    and checked_target["snapshot_ref"] == successor.current_target_snapshot_ref
                ):
                    successor_target = checked_target
                else:
                    successor_target = _load_target(
                        connection,
                        successor.experiment_id,
                        successor.current_target_snapshot_ref,
                    )
            successor_defense = None
            if successor.defense_change is not None:
                if (
                    checked_defense is not None
                    and checked_defense["change_id"] == successor.defense_change.change_id
                ):
                    successor_defense = checked_defense
                else:
                    successor_defense = _load_defense(
                        connection,
                        successor.experiment_id,
                        successor.defense_change.change_id,
                    )
            _profile_matches_experiment(profile, successor)
            _validate_complete_presentation(
                profile,
                successor,
                successor_target,
                successor_defense,
            )

            if checked_target is not None:
                snapshot_ref = cast(str, checked_target["snapshot_ref"])
                existing = connection.execute(
                    """SELECT * FROM engine_experiment_target_presentations
                       WHERE experiment_id = ? AND snapshot_ref = ?""",
                    (successor.experiment_id, snapshot_ref),
                ).fetchone()
                needs_insert = existing is None
                if existing is not None:
                    if (
                        _load_target(connection, successor.experiment_id, snapshot_ref)
                        != checked_target
                    ):
                        raise ResourceConflictError(
                            "engine experiment target presentation already has different metadata"
                        )
                    needs_insert = not _has_exact_registry_anchor(
                        connection,
                        kind="target",
                        experiment_id=successor.experiment_id,
                        item_id=snapshot_ref,
                        revision=successor.revision,
                        experiment_digest=successor.digest,
                        prior_digest=current.digest,
                    )
                if needs_insert:
                    target_record_digest = _registry_record_digest(
                        kind="target",
                        experiment_id=successor.experiment_id,
                        item_id=snapshot_ref,
                        document_digest=cast(str, target_digest),
                        revision=successor.revision,
                        experiment_digest=successor.digest,
                        prior_digest=current.digest,
                    )
                    connection.execute(
                        """INSERT INTO engine_experiment_target_presentations(
                               experiment_id, snapshot_ref, document_json, document_digest,
                               record_digest,
                               registered_revision, registered_experiment_digest,
                               registered_prior_digest, registered_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            successor.experiment_id,
                            snapshot_ref,
                            target_json,
                            target_digest,
                            target_record_digest,
                            successor.revision,
                            successor.digest,
                            current.digest,
                            now,
                        ),
                    )
            if checked_defense is not None:
                change_id = cast(str, checked_defense["change_id"])
                existing = connection.execute(
                    """SELECT * FROM engine_experiment_defense_presentations
                       WHERE experiment_id = ? AND change_id = ?""",
                    (successor.experiment_id, change_id),
                ).fetchone()
                needs_insert = existing is None
                if existing is not None:
                    if (
                        _load_defense(connection, successor.experiment_id, change_id)
                        != checked_defense
                    ):
                        raise ResourceConflictError(
                            "engine experiment defense presentation already has different metadata"
                        )
                    needs_insert = not _has_exact_registry_anchor(
                        connection,
                        kind="defense",
                        experiment_id=successor.experiment_id,
                        item_id=change_id,
                        revision=successor.revision,
                        experiment_digest=successor.digest,
                        prior_digest=current.digest,
                    )
                if needs_insert:
                    defense_record_digest = _registry_record_digest(
                        kind="defense",
                        experiment_id=successor.experiment_id,
                        item_id=change_id,
                        document_digest=cast(str, defense_digest),
                        revision=successor.revision,
                        experiment_digest=successor.digest,
                        prior_digest=current.digest,
                    )
                    connection.execute(
                        """INSERT INTO engine_experiment_defense_presentations(
                               experiment_id, change_id, document_json, document_digest,
                               record_digest,
                               registered_revision, registered_experiment_digest,
                               registered_prior_digest, registered_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            successor.experiment_id,
                            change_id,
                            defense_json,
                            defense_digest,
                            defense_record_digest,
                            successor.revision,
                            successor.digest,
                            current.digest,
                            now,
                        ),
                    )
        return {
            "schema_version": "bluefire.engine-experiment-transition-presentation.v1",
            "experiment_id": successor.experiment_id,
            "revision": successor.revision,
            "experiment_digest": successor.digest,
            "target_registered": checked_target is not None,
            "defense_registered": checked_defense is not None,
        }

    def assert_engine_experiment_presentation_transition_ready(
        self: EngineExperimentPresentationStore,
        current: EngineExperiment,
        successor: EngineExperiment,
    ) -> None:
        """Fail before history CAS unless the exact successor can be presented."""

        _validate_transition(current, successor)
        current_record = self.get_engine_experiment(
            current.experiment_id, revision=current.revision
        )
        saved = _experiment_from_record(
            current_record,
            expected_revision=current.revision,
            expected_digest=current.digest,
        )
        if (
            current_record.get("active") is not True
            or current_record.get("active_revision") != current.revision
            or saved.to_dict() != current.to_dict()
        ):
            raise ResourceConflictError("engine experiment presentation transition changed")
        with self._connection() as connection:
            profile = _load_profile(connection, current.experiment_id)
            initial_target = _load_target(
                connection,
                current.experiment_id,
                cast(str, profile["initial_target_snapshot_ref"]),
            )
            _profile_and_initial_documents(current.experiment_id, profile, initial_target)
            _presentation_parts(connection, current, profile)
            _presentation_parts(connection, successor, profile)

    def register_engine_experiment_target_presentation(
        self: EngineExperimentPresentationStore,
        experiment_id: str,
        target: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Register immutable display metadata for one referenced target snapshot."""

        identity = _experiment_id(experiment_id)
        revision = _revision(expected_revision, "expected engine experiment revision")
        digest = _digest(expected_experiment_digest, "expected engine experiment digest")
        checked_target, target_json, target_digest = _target_document(target)
        if checked_target["experiment_id"] != identity:
            raise ProductStoreError("engine experiment target presentation identity is mismatched")
        snapshot_ref = _digest(checked_target["snapshot_ref"], "target snapshot reference")
        record = self.get_engine_experiment(identity, revision=revision)
        experiment = _experiment_from_record(
            record, expected_revision=revision, expected_digest=digest
        )
        prior_digest = experiment.previous_revision_digest
        if snapshot_ref not in _referenced_snapshots(experiment):
            raise ProductStoreError("target snapshot is not referenced by the experiment")
        try:
            captured = parse_iso8601_datetime(cast(str, checked_target["captured_at"]))
        except (TypeError, ValueError) as exc:
            raise ProductStoreError("target presentation capture time is invalid") from exc
        created = parse_iso8601_datetime(experiment.created_at)
        updated = parse_iso8601_datetime(experiment.updated_at)
        if snapshot_ref == experiment.current_target_snapshot_ref:
            if captured > updated or (
                snapshot_ref != experiment.initial_target_snapshot_ref and captured < created
            ):
                raise ProductStoreError("target presentation capture time changed")
        elif captured < created:
            raise ProductStoreError("target presentation capture time changed")
        now = utc_now()
        with self._connection(write=True) as connection:
            profile = _load_profile(connection, identity)
            initial_target = _load_target(
                connection,
                identity,
                cast(str, profile["initial_target_snapshot_ref"]),
            )
            _profile_and_initial_documents(identity, profile, initial_target)
            _profile_matches_experiment(profile, experiment)
            existing = connection.execute(
                """SELECT * FROM engine_experiment_target_presentations
                   WHERE experiment_id = ? AND snapshot_ref = ?""",
                (identity, snapshot_ref),
            ).fetchone()
            needs_insert = existing is None
            if existing is not None:
                saved = _load_target(connection, identity, snapshot_ref)
                if saved != checked_target:
                    raise ResourceConflictError(
                        "engine experiment target presentation already has different metadata"
                    )
                if prior_digest is None:
                    _assert_target_anchor(connection, experiment, snapshot_ref)
                    return cast(Mapping[str, Any], json_clone(saved))
                needs_insert = not _has_exact_registry_anchor(
                    connection,
                    kind="target",
                    experiment_id=identity,
                    item_id=snapshot_ref,
                    revision=revision,
                    experiment_digest=digest,
                    prior_digest=prior_digest,
                )
                if not needs_insert:
                    return cast(Mapping[str, Any], json_clone(saved))
            if prior_digest is None:
                raise ProductStoreError("target presentation successor anchor is unavailable")
            try:
                record_digest = _registry_record_digest(
                    kind="target",
                    experiment_id=identity,
                    item_id=snapshot_ref,
                    document_digest=target_digest,
                    revision=revision,
                    experiment_digest=digest,
                    prior_digest=prior_digest,
                )
                connection.execute(
                    """INSERT INTO engine_experiment_target_presentations(
                           experiment_id, snapshot_ref, document_json, document_digest,
                           record_digest,
                           registered_revision, registered_experiment_digest,
                           registered_prior_digest, registered_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        identity,
                        snapshot_ref,
                        target_json,
                        target_digest,
                        record_digest,
                        revision,
                        digest,
                        prior_digest,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError(
                    "engine experiment target presentation registration lost a race"
                ) from exc
        return cast(Mapping[str, Any], json_clone(checked_target))

    def register_engine_experiment_defense_presentation(
        self: EngineExperimentPresentationStore,
        experiment_id: str,
        defense: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Register immutable display metadata for one reviewed defensive change."""

        identity = _experiment_id(experiment_id)
        revision = _revision(expected_revision, "expected engine experiment revision")
        digest = _digest(expected_experiment_digest, "expected engine experiment digest")
        checked_defense, defense_json, defense_digest = _defense_document(defense)
        if checked_defense["experiment_id"] != identity:
            raise ProductStoreError("engine experiment defense presentation identity is mismatched")
        record = self.get_engine_experiment(identity, revision=revision)
        experiment = _experiment_from_record(
            record, expected_revision=revision, expected_digest=digest
        )
        prior_digest = experiment.previous_revision_digest
        if prior_digest is None:
            raise ProductStoreError("defense presentation successor anchor is unavailable")
        change = experiment.defense_change
        if change is None or checked_defense["change_id"] != change.change_id:
            raise ProductStoreError("defense presentation is not referenced by the experiment")
        now = utc_now()
        with self._connection(write=True) as connection:
            profile = _load_profile(connection, identity)
            initial_target = _load_target(
                connection,
                identity,
                cast(str, profile["initial_target_snapshot_ref"]),
            )
            _profile_and_initial_documents(identity, profile, initial_target)
            _profile_matches_experiment(profile, experiment)
            existing = connection.execute(
                """SELECT * FROM engine_experiment_defense_presentations
                   WHERE experiment_id = ? AND change_id = ?""",
                (identity, change.change_id),
            ).fetchone()
            needs_insert = existing is None
            if existing is not None:
                saved = _load_defense(connection, identity, change.change_id)
                if saved != checked_defense:
                    raise ResourceConflictError(
                        "engine experiment defense presentation already has different metadata"
                    )
                needs_insert = not _has_exact_registry_anchor(
                    connection,
                    kind="defense",
                    experiment_id=identity,
                    item_id=change.change_id,
                    revision=revision,
                    experiment_digest=digest,
                    prior_digest=prior_digest,
                )
                if not needs_insert:
                    return cast(Mapping[str, Any], json_clone(saved))
            try:
                record_digest = _registry_record_digest(
                    kind="defense",
                    experiment_id=identity,
                    item_id=change.change_id,
                    document_digest=defense_digest,
                    revision=revision,
                    experiment_digest=digest,
                    prior_digest=prior_digest,
                )
                connection.execute(
                    """INSERT INTO engine_experiment_defense_presentations(
                           experiment_id, change_id, document_json, document_digest,
                           record_digest,
                           registered_revision, registered_experiment_digest,
                           registered_prior_digest, registered_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        identity,
                        change.change_id,
                        defense_json,
                        defense_digest,
                        record_digest,
                        revision,
                        digest,
                        prior_digest,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError(
                    "engine experiment defense presentation registration lost a race"
                ) from exc
        return cast(Mapping[str, Any], json_clone(checked_defense))

    def get_engine_experiment_presentation(
        self: EngineExperimentPresentationStore,
        experiment_id: str,
        *,
        revision: int,
        experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Derive one exact immutable revision's public workspace presentation."""

        identity = _experiment_id(experiment_id)
        exact_revision = _revision(revision, "engine experiment presentation revision")
        exact_digest = _digest(experiment_digest, "engine experiment presentation digest")
        record = self.get_engine_experiment(identity, revision=exact_revision)
        experiment = _experiment_from_record(
            record,
            expected_revision=exact_revision,
            expected_digest=exact_digest,
        )
        with self._connection() as connection:
            profile = _load_profile(connection, identity)
            initial_target = _load_target(
                connection,
                identity,
                cast(str, profile["initial_target_snapshot_ref"]),
            )
            _profile_and_initial_documents(identity, profile, initial_target)
            target, defense = _presentation_parts(connection, experiment, profile)
        return cast(
            Mapping[str, Any],
            json_clone(_validate_complete_presentation(profile, experiment, target, defense)),
        )


__all__ = [
    "EngineExperimentPresentationStore",
    "EngineExperimentPresentationStoreMixin",
    "initialize_schema",
]
