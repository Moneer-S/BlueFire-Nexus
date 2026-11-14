from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire.engine_artifact_store import (
    _CONTROLLER_SOURCE_AUTHORITY,
    EngineArtifactPublicationBinding,
    EngineArtifactStore,
    SourceCollectionSeal,
    source_collection_tree_digest,
)
from bluefire.engine_execution_proof_writer import (
    EngineExecutionProofWriterError,
    _artifact_index,
    reopen_controller_artifact_index,
)
from bluefire.engine_artifact_review import review_retained_engine_artifact
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "1" * 32


@pytest.fixture(autouse=True)
def protected_test_root(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        # The Windows test container cannot reopen an owner-only DACL. Other
        # tests cover the real production ACL verifier and publication path.
        monkeypatch.setattr(
            EngineArtifactStore,
            "_prepare_root",
            staticmethod(lambda path: path.mkdir(mode=0o700, parents=True, exist_ok=True)),
        )
        monkeypatch.setattr(
            EngineArtifactStore, "_verify_protected_root", staticmethod(lambda _path: None)
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_protected_root_descriptor",
            staticmethod(lambda _descriptor: None),
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_harden_private",
            staticmethod(lambda _path, *, directory: None),
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_private_entry",
            staticmethod(lambda _path, *, directory: None),
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_private_descriptor",
            staticmethod(lambda _descriptor, *, directory: None),
        )


def _binding(*, worker: str = "7") -> EngineArtifactPublicationBinding:
    return EngineArtifactPublicationBinding(
        attempt_id=ATTEMPT,
        binding_digest="sha256:" + "1" * 64,
        delegation_digest="sha256:" + "2" * 64,
        launch_digest="sha256:" + "3" * 64,
        runtime_resolution_ref="sha256:" + "4" * 64,
        execution_claim_ref="sha256:" + "5" * 64,
        worker_outcome_digest="sha256:" + worker * 64,
    )


def _store(tmp_path: Path) -> tuple[EngineArtifactStore, EngineArtifactPublicationBinding]:
    source = tmp_path / "source"
    (source / "reports").mkdir(parents=True)
    (source / "reports" / "run.json").write_bytes(b'{"status":"complete"}\n')
    (source / "run.log").write_bytes(b"generated test log\n")
    details = source.lstat()
    seal = SourceCollectionSeal.from_mapping(
        {
            "schema_version": "bluefire.engine-source-collection-seal.v1",
            "attempt_id": ATTEMPT,
            "source_root_device": details.st_dev,
            "source_root_inode": details.st_ino,
            "source_root_mtime_ns": details.st_mtime_ns,
            "source_tree_digest": source_collection_tree_digest(source),
            "worker_state": "stopped",
            "write_access_revoked": True,
            "controller_receipt_digest": content_hash({"kind": "controller-stopped"}),
        },
        _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
    )
    store = EngineArtifactStore(tmp_path / "owned")
    binding = _binding()
    store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=seal,
        allowed_names=("reports/run.json", "run.log"),
        publication_binding=binding,
    )
    return store, binding


def test_reopens_exact_private_artifact_index(tmp_path: Path) -> None:
    store, binding = _store(tmp_path)
    reopened = store.reopen_attempt(ATTEMPT)

    index = reopen_controller_artifact_index(
        store, publication_binding=binding, artifact_byte_limit=4096
    )

    assert index.manifest_ref == reopened.manifest_ref
    assert {row.name for row in index.artifacts} == {
        "reports › run.json",
        "run.log",
    }
    assert all(row.attempt_id == ATTEMPT for row in index.artifacts)
    assert all(row.access == "private" for row in index.artifacts)
    assert {row.media_type for row in index.artifacts} == {
        "application/json",
        "text/plain",
    }
    assert all(row.artifact_id.startswith("artifact-") for row in index.artifacts)
    assert all(row.to_dict()["sha256"] == row.sha256 for row in index.artifacts)


def _review_setup(tmp_path: Path):
    store, publication = _store(tmp_path)
    index = reopen_controller_artifact_index(
        store, publication_binding=publication, artifact_byte_limit=4096
    )
    rows = [item.to_dict() for item in index.artifacts]
    saved_binding = SimpleNamespace(
        attempt_id=ATTEMPT,
        binding_digest=publication.binding_digest,
        artifact_byte_limit=4096,
    )
    entry = SimpleNamespace(
        record=SimpleNamespace(binding=saved_binding),
        delegation_digest=publication.delegation_digest,
        artifact_manifest_ref=index.manifest_ref,
    )
    return store, entry, rows


def test_private_review_reopens_bytes_but_releases_only_structure(tmp_path: Path) -> None:
    store, entry, rows = _review_setup(tmp_path)
    selected = next(row for row in rows if row["media_type"] == "application/json")

    result = review_retained_engine_artifact(
        store, experiment_id="experiment-" + "9" * 32,
        entry=entry, saved_artifacts=rows, selected_artifact=selected,
    )

    assert result["availability"] == "retained"
    assert result["access"] == "private"
    assert result["summary"] == {
        "kind": "json", "line_count": 1, "root": "object",
        "field_count": 1, "recognized_fields": ["status"], "item_count": None,
    }
    assert result["text"] is None
    assert "complete" not in str(result)


def test_private_review_fails_closed_for_missing_reader_or_changed_source(tmp_path: Path) -> None:
    store, entry, rows = _review_setup(tmp_path)
    selected = rows[0]
    arguments = dict(
        experiment_id="experiment-" + "9" * 32,
        entry=entry, saved_artifacts=rows, selected_artifact=selected,
    )
    assert review_retained_engine_artifact(None, **arguments)["reason"] == "reader_not_configured"
    assert review_retained_engine_artifact(
        store, **{**arguments, "saved_artifacts": rows[:1]}
    )["availability"] == "unavailable"
    assert review_retained_engine_artifact(
        store, **{**arguments, "entry": SimpleNamespace(
            record=SimpleNamespace(binding=SimpleNamespace(
                attempt_id=ATTEMPT, binding_digest="sha256:" + "0" * 64,
                artifact_byte_limit=4096,
            )),
            delegation_digest=entry.delegation_digest,
            artifact_manifest_ref=entry.artifact_manifest_ref,
        )}
    )["availability"] == "unavailable"
    (store.root / ATTEMPT / "raw" / "run.log").write_bytes(b"tampered")
    result = review_retained_engine_artifact(store, **arguments)
    assert result["availability"] == "unavailable"
    assert result["summary"] is None and result["text"] is None


def test_private_proof_cannot_be_promoted_to_reviewable_at_read_time(tmp_path: Path) -> None:
    store, entry, rows = _review_setup(tmp_path)
    promoted = [{**row, "access": "reviewable"} if row is rows[0] else row for row in rows]
    result = review_retained_engine_artifact(
        store, experiment_id="experiment-" + "9" * 32,
        entry=entry, saved_artifacts=promoted, selected_artifact=promoted[0],
    )
    assert result["availability"] == "unavailable"
    assert result["text"] is None


def test_long_valid_artifact_name_gets_bounded_distinct_label(tmp_path: Path) -> None:
    store, binding = _store(tmp_path)
    retained = store.reopen_attempt(ATTEMPT)
    long_name = "a" * 197 + ".json"
    changed_artifact = replace(retained.artifacts[0], name=long_name)
    changed = replace(retained, artifacts=(changed_artifact, *retained.artifacts[1:]))
    changed = replace(changed, manifest_ref=content_hash(changed.to_manifest()))

    index = _artifact_index(changed, publication_binding=binding, artifact_byte_limit=4096)

    assert len(index.artifacts[0].name) <= 200
    assert index.artifacts[0].name.endswith(
        hashlib.sha256(long_name.encode("utf-8")).hexdigest()[:12]
    )
    assert index.artifacts[0].name != long_name


def test_rejects_other_worker_outcome_or_byte_limit(tmp_path: Path) -> None:
    store, binding = _store(tmp_path)

    with pytest.raises(EngineExecutionProofWriterError, match="binding changed"):
        reopen_controller_artifact_index(
            store, publication_binding=_binding(worker="8"), artifact_byte_limit=4096
        )
    with pytest.raises(EngineExecutionProofWriterError, match="binding changed"):
        reopen_controller_artifact_index(store, publication_binding=binding, artifact_byte_limit=1)


def test_rejects_tampered_retained_payload(tmp_path: Path) -> None:
    store, binding = _store(tmp_path)
    (store.root / ATTEMPT / "raw" / "run.log").write_bytes(b"changed after publication")

    with pytest.raises(EngineExecutionProofWriterError, match="could not be reopened"):
        reopen_controller_artifact_index(
            store, publication_binding=binding, artifact_byte_limit=4096
        )
