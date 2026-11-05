from __future__ import annotations

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from bluefire.engine_artifact_store import (
    _CONTROLLER_SOURCE_AUTHORITY,
    MAX_SOURCE_TREE_ENTRIES,
    EngineArtifactPublicationBinding,
    EngineArtifactPublicationUnknown,
    EngineArtifactStore,
    EngineArtifactStoreError,
    ReopenedEngineArtifactAttempt,
    SourceCollectionSeal,
    normalized_finding_id,
    source_collection_tree_digest,
)
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_owner_acl import _windows_extended_path

ATTEMPT = "engine-attempt-" + "1" * 32
_PRODUCTION_PREPARE_ROOT = EngineArtifactStore._prepare_root


@pytest.fixture(autouse=True)
def protected_test_root(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pytest runs in an AppContainer on the Windows development host. Rewriting
    # a temporary directory to the product owner-only DACL would remove that
    # container capability. Product integration uses the real verifier.
    if os.name == "nt":
        monkeypatch.setattr(
            EngineArtifactStore,
            "_prepare_root",
            staticmethod(lambda path: path.mkdir(mode=0o700, parents=True, exist_ok=True)),
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_protected_root",
            staticmethod(lambda _path: None),
        )
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_protected_root_descriptor",
            staticmethod(lambda _descriptor: None),
        )


def seal(
    source: Path,
    *,
    attempt_id: str = ATTEMPT,
    receipt: str = "sha256:" + "a" * 64,
) -> SourceCollectionSeal:
    details = source.lstat()
    return SourceCollectionSeal.from_mapping(
        {
            "schema_version": "bluefire.engine-source-collection-seal.v1",
            "attempt_id": attempt_id,
            "source_root_device": details.st_dev,
            "source_root_inode": details.st_ino,
            "source_root_mtime_ns": details.st_mtime_ns,
            "source_tree_digest": source_collection_tree_digest(source),
            "worker_state": "stopped",
            "write_access_revoked": True,
            "controller_receipt_digest": receipt,
        },
        _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
    )


def publication_binding(
    *, attempt_id: str = ATTEMPT, worker: str = "7"
) -> EngineArtifactPublicationBinding:
    return EngineArtifactPublicationBinding(
        attempt_id=attempt_id,
        binding_digest="sha256:" + "1" * 64,
        delegation_digest="sha256:" + "2" * 64,
        launch_digest="sha256:" + "3" * 64,
        runtime_resolution_ref="sha256:" + "4" * 64,
        execution_claim_ref="sha256:" + "5" * 64,
        worker_outcome_digest="sha256:" + worker * 64,
    )


def publish_v2(
    tmp_path: Path,
    *,
    payloads: tuple[tuple[str, bytes], ...] = (("run.json", b"retained"),),
) -> tuple[
    EngineArtifactStore,
    Path,
    SourceCollectionSeal,
    EngineArtifactPublicationBinding,
    ReopenedEngineArtifactAttempt,
]:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    for name, payload in payloads:
        target = source.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")
    reopened = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=tuple(name for name, _payload in payloads),
        publication_binding=binding,
    )
    return store, source, frozen, binding, reopened


def test_import_preserves_exact_raw_bytes_hashes_and_relative_names(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "findings").mkdir(parents=True)
    run = b'{"run_id":"upstream-one","status":"completed"}\n'
    finding = b'{"title":"generated fixture finding"}\n'
    (source / "run.json").write_bytes(run)
    (source / "findings" / "finding-1.json").write_bytes(finding)
    store = EngineArtifactStore(tmp_path / "owned")

    manifest = store.import_attempt(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=seal(source),
        allowed_names=("run.json", "findings/finding-1.json"),
    )

    assert (store.root / ATTEMPT / "raw" / "run.json").read_bytes() == run
    assert (store.root / ATTEMPT / "raw" / "findings" / "finding-1.json").read_bytes() == finding
    assert manifest["total_bytes"] == len(run) + len(finding)
    assert manifest["artifacts"][0]["sha256"] == "sha256:" + hashlib.sha256(run).hexdigest()
    assert manifest["storage_boundary"] == "contained_exclusive_protected_root"
    assert manifest["source_collection_receipt"] == "sha256:" + "a" * 64
    assert (store.root / ATTEMPT / "manifest.json").is_file()


def test_v2_import_reopen_is_canonical_immutable_and_source_independent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "findings").mkdir(parents=True)
    run = b'{"status":"complete"}\n'
    finding = b'{"title":"retained"}\n'
    (source / "run.json").write_bytes(run)
    (source / "findings" / "one.json").write_bytes(finding)
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")

    imported = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json", "findings/one.json"),
        publication_binding=binding,
    )
    manifest_path = store.root / ATTEMPT / "manifest.json"
    before_manifest = manifest_path.read_bytes()
    before_mtime = manifest_path.stat().st_mtime_ns

    assert isinstance(imported, ReopenedEngineArtifactAttempt)
    assert imported.recovery_eligible is True
    assert imported.schema_version == "bluefire.engine-artifacts.v2"
    assert imported.publication_binding == binding
    assert imported.source_tree_digest == frozen.source_tree_digest
    assert imported.source_collection_seal_ref == content_hash(frozen.to_dict())
    assert imported.source_collection_seal == frozen
    assert imported.to_manifest()["source_collection_seal"] == frozen.to_dict()
    assert [item.name for item in imported.artifacts] == [
        "findings/one.json",
        "run.json",
    ]
    assert [item.payload for item in imported.artifacts] == [finding, run]
    assert before_manifest == canonical_json_bytes(imported.to_manifest()) + b"\n"
    assert imported.manifest_ref == content_hash(imported.to_manifest())
    assert imported.artifact_publication_ref is not None
    publication_seal = imported.publication_seal()
    assert publication_seal["artifact_publication_ref"] == imported.artifact_publication_ref
    assert publication_seal["source_tree_digest"] == frozen.source_tree_digest
    assert run.decode().strip() not in repr(imported)
    with pytest.raises(FrozenInstanceError):
        imported.total_bytes = 0  # type: ignore[misc]

    moved = tmp_path / "source-removed"
    source.rename(moved)
    reopened = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("findings/one.json", "run.json"),
        publication_binding=binding,
    )

    assert reopened == imported
    assert store.reopen_attempt(ATTEMPT) == imported
    assert manifest_path.read_bytes() == before_manifest
    assert manifest_path.stat().st_mtime_ns == before_mtime


def test_v2_lost_ack_exact_retry_reopens_without_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b'{"status":"complete"}\n')
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")
    original_sync = store._sync_directory

    def fail_root_sync(path: Path) -> None:
        if path == store.root:
            raise EngineArtifactStoreError("injected lost acknowledgement")
        original_sync(path)

    monkeypatch.setattr(store, "_sync_directory", fail_root_sync)
    with pytest.raises(EngineArtifactPublicationUnknown, match="published.*unknown"):
        store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )
    monkeypatch.setattr(store, "_sync_directory", original_sync)
    source.rename(tmp_path / "source-gone")

    reopened = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
        publication_binding=binding,
    )

    assert reopened.recovery_eligible
    assert reopened.artifacts[0].payload == b'{"status":"complete"}\n'
    assert not (store.root / (".pending-" + ATTEMPT)).exists()


def test_v2_publish_boundary_interrupt_reopens_exactly_without_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"retained")
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")
    original_publish = store._publish_staging

    def publish_then_interrupt(staging: Path, final: Path) -> None:
        original_publish(staging, final)
        raise KeyboardInterrupt

    monkeypatch.setattr(store, "_publish_staging", publish_then_interrupt)
    with pytest.raises(EngineArtifactPublicationUnknown, match="reconciliation"):
        store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )
    monkeypatch.setattr(store, "_publish_staging", original_publish)
    source.rename(tmp_path / "source-gone")

    reopened = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
        publication_binding=binding,
    )

    assert reopened.artifacts[0].payload == b"retained"
    assert reopened.publication_seal() == store.reopen_attempt(ATTEMPT).publication_seal()


def test_v2_existing_publication_requires_exact_binding_seal_and_selection(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"run")
    (source / "other.json").write_bytes(b"other")
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")
    original = store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
        publication_binding=binding,
    )
    manifest_path = store.root / ATTEMPT / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest_mtime = manifest_path.stat().st_mtime_ns

    wrong_values = [
        (frozen, publication_binding(worker="8"), ("run.json",)),
        (seal(source, receipt="sha256:" + "b" * 64), binding, ("run.json",)),
        (frozen, binding, ("other.json",)),
    ]
    for wrong_seal, wrong_binding, names in wrong_values:
        with pytest.raises(EngineArtifactStoreError, match="exact retry"):
            store.import_or_reopen(
                attempt_id=ATTEMPT,
                source_run_dir=source,
                source_seal=wrong_seal,
                allowed_names=names,
                publication_binding=wrong_binding,
            )

    assert store.reopen_attempt(ATTEMPT) == original
    assert manifest_path.read_bytes() == manifest_bytes
    assert manifest_path.stat().st_mtime_ns == manifest_mtime


def test_legacy_reopen_is_display_only_and_never_auto_upgraded(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"legacy")
    frozen = seal(source)
    store = EngineArtifactStore(tmp_path / "owned")
    store.import_attempt(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
    )
    manifest_path = store.root / ATTEMPT / "manifest.json"
    original = manifest_path.read_bytes()

    reopened = store.reopen_attempt(ATTEMPT)

    assert reopened.schema_version == "bluefire.engine-artifacts.v1"
    assert reopened.recovery_eligible is False
    assert reopened.artifact_publication_ref is None
    assert reopened.artifacts[0].payload == b"legacy"
    with pytest.raises(EngineArtifactStoreError, match="no recovery seal"):
        reopened.publication_seal()
    with pytest.raises(EngineArtifactStoreError, match="exact retry"):
        store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=publication_binding(),
        )
    assert manifest_path.read_bytes() == original


@pytest.mark.parametrize(
    "variant",
    [
        "duplicate_field",
        "noncanonical",
        "extra_field",
        "wrong_reference",
        "source_seal",
        "boolean_count",
        "unsorted_rows",
    ],
)
def test_reopen_rejects_noncanonical_or_tampered_v2_manifest(tmp_path: Path, variant: str) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(
        tmp_path,
        payloads=(("a.json", b"a"), ("b.json", b"b")),
    )
    manifest_path = store.root / ATTEMPT / "manifest.json"
    value = json.loads(manifest_path.read_bytes())
    if variant == "duplicate_field":
        payload = manifest_path.read_bytes().replace(
            b'{"artifact_count":', b'{"artifact_count":2,"artifact_count":', 1
        )
    elif variant == "noncanonical":
        payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    else:
        if variant == "extra_field":
            value["unexpected"] = True
        elif variant == "wrong_reference":
            value["artifact_publication_ref"] = "sha256:" + "f" * 64
        elif variant == "source_seal":
            value["source_collection_seal"]["source_root_inode"] += 1
        elif variant == "boolean_count":
            value["artifact_count"] = True
        elif variant == "unsorted_rows":
            value["artifacts"].reverse()
        payload = canonical_json_bytes(value) + b"\n"
    manifest_path.write_bytes(payload)

    with pytest.raises(EngineArtifactStoreError) as raised:
        store.reopen_attempt(ATTEMPT)

    assert str(tmp_path) not in str(raised.value)


def test_reopen_rejects_payload_tamper_extra_and_missing(
    tmp_path: Path,
) -> None:
    cases = ("tamper", "extra", "missing")
    for index, case in enumerate(cases):
        case_root = tmp_path / str(index)
        store, _source, _seal, _binding, _reopened = publish_v2(case_root)
        raw = store.root / ATTEMPT / "raw"
        payload = raw / "run.json"
        if case == "tamper":
            payload.write_bytes(b"replaced")
        elif case == "extra":
            (raw / "extra.json").write_bytes(b"extra")
        elif case == "missing":
            payload.unlink()
        with pytest.raises(EngineArtifactStoreError):
            store.reopen_attempt(ATTEMPT)


def test_reopen_rejects_hardlinked_payload_when_available(tmp_path: Path) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path)
    payload = store.root / ATTEMPT / "raw" / "run.json"
    outside = tmp_path / "retained-hardlink"
    try:
        os.link(payload, outside)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(EngineArtifactStoreError, match="unsafe"):
        store.reopen_attempt(ATTEMPT)


def test_reopen_rejects_linked_payload_when_links_are_available(tmp_path: Path) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path)
    payload = store.root / ATTEMPT / "raw" / "run.json"
    original = tmp_path / "original"
    original.write_bytes(b"retained")
    payload.unlink()
    try:
        payload.symlink_to(original)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links unavailable: {exc}")

    with pytest.raises(EngineArtifactStoreError, match="unsafe|inventory"):
        store.reopen_attempt(ATTEMPT)


def test_reopen_rejects_extra_top_level_and_portable_alias(
    tmp_path: Path,
) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path / "top")
    (store.root / ATTEMPT / "extra").mkdir()
    with pytest.raises(EngineArtifactStoreError, match="not exact"):
        store.reopen_attempt(ATTEMPT)

    if os.name == "nt":
        return
    alias_store, _source, _seal, _binding, _reopened = publish_v2(tmp_path / "alias")
    raw = alias_store.root / ATTEMPT / "raw"
    canonical = raw / "run.json"
    alias = raw / "Run.json"
    if alias.exists() and alias.samefile(canonical):
        # A case-insensitive filesystem cannot materialize the portable alias
        # as a second entry. The exact case-fold collision remains exercised
        # on case-sensitive POSIX filesystems.
        return
    alias.write_bytes(b"retained")
    os.chmod(alias, 0o600)
    with pytest.raises(EngineArtifactStoreError, match="not exact"):
        alias_store.reopen_attempt(ATTEMPT)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes only")
@pytest.mark.parametrize(
    ("relative", "mode"),
    [("raw", 0o755), ("raw/run.json", 0o640), ("manifest.json", 0o644)],
)
def test_reopen_requires_exact_posix_modes(tmp_path: Path, relative: str, mode: int) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path)
    path = store.root / ATTEMPT
    for part in relative.split("/"):
        path = path / part
    os.chmod(path, mode)

    with pytest.raises(EngineArtifactStoreError, match="permissions"):
        store.reopen_attempt(ATTEMPT)


def test_partial_and_conflicting_pending_publications_remain_untouched(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"retained")
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")
    pending = store.root / (".pending-" + ATTEMPT)
    pending.mkdir()
    sentinel = pending / "sentinel"
    sentinel.write_bytes(b"partial")

    with pytest.raises(EngineArtifactPublicationUnknown, match="incomplete|recovery"):
        store.reopen_attempt(ATTEMPT)
    with pytest.raises(EngineArtifactPublicationUnknown, match="incomplete|recovery"):
        store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )
    assert sentinel.read_bytes() == b"partial"

    sentinel.unlink()
    pending.rmdir()
    store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
        publication_binding=binding,
    )
    pending.mkdir()
    sentinel.write_bytes(b"ambiguous")
    with pytest.raises(EngineArtifactPublicationUnknown, match="incomplete|recovery"):
        store.reopen_attempt(ATTEMPT)
    assert sentinel.read_bytes() == b"ambiguous"
    assert (store.root / ATTEMPT / "manifest.json").is_file()


def test_exact_concurrent_imports_converge_and_conflicts_fail_closed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"retained")
    frozen = seal(source)
    binding = publication_binding()
    store = EngineArtifactStore(tmp_path / "owned")

    def exact() -> ReopenedEngineArtifactAttempt:
        return store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = tuple(workers.map(lambda _index: exact(), range(2)))
    assert first == second
    assert not (store.root / (".pending-" + ATTEMPT)).exists()

    with pytest.raises(EngineArtifactStoreError, match="exact retry"):
        store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=publication_binding(worker="8"),
        )
    assert store.reopen_attempt(ATTEMPT) == first


def test_two_store_pending_race_is_sanitized_and_exact_retry_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"retained")
    frozen = seal(source)
    binding = publication_binding()
    first_store = EngineArtifactStore(tmp_path / "owned")
    second_store = EngineArtifactStore(tmp_path / "owned")
    pending_created = threading.Event()
    finish_first = threading.Event()
    original_write = first_store._write_exclusive
    paused = False

    def pause_with_owned_pending(path: Path, payload: bytes) -> None:
        nonlocal paused
        original_write(path, payload)
        if not paused:
            paused = True
            pending_created.set()
            assert finish_first.wait(5)

    monkeypatch.setattr(first_store, "_write_exclusive", pause_with_owned_pending)

    def publish_first() -> ReopenedEngineArtifactAttempt:
        return first_store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )

    with ThreadPoolExecutor(max_workers=1) as worker:
        future = worker.submit(publish_first)
        assert pending_created.wait(5)
        pending = first_store.root / (".pending-" + ATTEMPT)
        before = tuple(sorted(path.name for path in pending.iterdir()))
        with pytest.raises(EngineArtifactPublicationUnknown) as raised:
            second_store.import_or_reopen(
                attempt_id=ATTEMPT,
                source_run_dir=source,
                source_seal=frozen,
                allowed_names=("run.json",),
                publication_binding=binding,
            )
        assert str(tmp_path) not in str(raised.value)
        assert tuple(sorted(path.name for path in pending.iterdir())) == before
        finish_first.set()
        published = future.result(timeout=10)

    retried = second_store.import_or_reopen(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
        publication_binding=binding,
    )
    assert retried == published


def test_two_store_post_rename_staging_race_reopens_without_stranding_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"retained")
    frozen = seal(source)
    binding = publication_binding()
    first_store = EngineArtifactStore(tmp_path / "owned")
    second_store = EngineArtifactStore(tmp_path / "owned")
    second_prechecked_final = threading.Event()
    first_published = threading.Event()
    original_exists = second_store._entry_exists
    final = second_store.root / ATTEMPT
    final_checks = 0

    def pause_third_final_check(path: Path) -> bool:
        nonlocal final_checks
        if path == final:
            final_checks += 1
            if final_checks == 3:
                second_prechecked_final.set()
                assert first_published.wait(5)
                return False
        return original_exists(path)

    monkeypatch.setattr(second_store, "_entry_exists", pause_third_final_check)

    def import_with_second_store() -> ReopenedEngineArtifactAttempt:
        return second_store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )

    with ThreadPoolExecutor(max_workers=1) as worker:
        second_future = worker.submit(import_with_second_store)
        assert second_prechecked_final.wait(5)
        first = first_store.import_or_reopen(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
            publication_binding=binding,
        )
        first_published.set()
        second = second_future.result(timeout=10)

    assert second == first
    assert not (first_store.root / (".pending-" + ATTEMPT)).exists()
    assert first_store.reopen_attempt(ATTEMPT) == first


def test_staging_created_after_precheck_returns_sanitized_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EngineArtifactStore(tmp_path / "owned")
    pending = store.root / (".pending-" + ATTEMPT)
    pending.mkdir()
    sentinel = pending / "sentinel"
    sentinel.write_bytes(b"foreign partial")
    original_exists = store._entry_exists
    hidden = False

    def raced_exists(path: Path) -> bool:
        nonlocal hidden
        if path == pending and not hidden:
            hidden = True
            return False
        return original_exists(path)

    monkeypatch.setattr(store, "_entry_exists", raced_exists)
    with pytest.raises(EngineArtifactPublicationUnknown) as raised:
        store._publish_payloads_locked(ATTEMPT, (), {})

    assert str(tmp_path) not in str(raised.value)
    assert sentinel.read_bytes() == b"foreign partial"


def test_descriptor_permission_verification_closes_path_check_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path)
    original_open = store._open_directory_descriptor
    original_verify = store._verify_private_descriptor
    raced = False

    def race_open(path: Path) -> int:
        nonlocal raced
        descriptor = original_open(path)
        if path.name == ATTEMPT and not raced:
            raced = True
            if os.name != "nt":
                os.chmod(path, 0o755)
        return descriptor

    def verify_descriptor(descriptor: int, *, directory: bool) -> None:
        if os.name == "nt" and directory and raced:
            raise EngineArtifactStoreError("artifact publication permissions are unsafe")
        original_verify(descriptor, directory=directory)

    monkeypatch.setattr(store, "_open_directory_descriptor", race_open)
    monkeypatch.setattr(store, "_verify_private_descriptor", verify_descriptor)
    with pytest.raises(EngineArtifactStoreError, match="permissions"):
        store.reopen_attempt(ATTEMPT)


def test_pinned_root_descriptor_permissions_are_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(tmp_path)

    def refuse_root(_descriptor: int) -> None:
        raise EngineArtifactStoreError("artifact publication permissions are unsafe")

    monkeypatch.setattr(store, "_verify_protected_root_descriptor", refuse_root)
    with pytest.raises(EngineArtifactStoreError, match="permissions"):
        store.reopen_attempt(ATTEMPT)


def test_kernel_no_replace_never_overwrites_existing_final_directory(
    tmp_path: Path,
) -> None:
    store = EngineArtifactStore(tmp_path / "owned")
    staging = store.root / (".pending-" + ATTEMPT)
    final = store.root / ATTEMPT
    staging.mkdir()
    final.mkdir()
    store._harden_private(staging, directory=True)
    staged = staging / "staged"
    retained = final / "retained"
    staged.write_bytes(b"new")
    retained.write_bytes(b"old")

    with pytest.raises(EngineArtifactStoreError, match="already exists"):
        store._publish_staging(staging, final)

    assert retained.read_bytes() == b"old"
    assert staged.read_bytes() == b"new"


def test_reopen_enforces_current_store_bounds_before_payload_read(tmp_path: Path) -> None:
    store, _source, _seal, _binding, _reopened = publish_v2(
        tmp_path,
        payloads=(("run.json", b"12345"),),
    )
    bounded = EngineArtifactStore(store.root, max_file_bytes=4, max_total_bytes=4)

    with pytest.raises(EngineArtifactStoreError, match="row|bound"):
        bounded.reopen_attempt(ATTEMPT)


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/absolute",
        "bad\\path",
        "a/../b",
        "a//b",
        "CON",
        "con.txt",
        "dir/PRN.log",
        "trailing.",
    ],
)
def test_import_rejects_unsafe_ambiguous_or_reserved_names(tmp_path: Path, name: str) -> None:
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(EngineArtifactStoreError, match="name|namespace"):
        EngineArtifactStore(tmp_path / "owned").import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=(name,),
        )


@pytest.mark.parametrize(
    "names",
    [
        ("run.json", "run.json"),
        ("Run.json", "run.json"),
        ("findings", "findings/one.json"),
        ("Findings", "findings/one.json"),
    ],
)
def test_import_rejects_portable_aliases_and_file_directory_conflicts(
    tmp_path: Path, names: tuple[str, str]
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    store = EngineArtifactStore(tmp_path / "owned")

    with pytest.raises(EngineArtifactStoreError, match="aliases|conflict"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=names,
        )
    assert not (tmp_path / "owned" / ATTEMPT).exists()


def test_import_rejects_unbounded_or_scalar_name_collections(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    store = EngineArtifactStore(tmp_path / "owned", max_files=1)

    with pytest.raises(EngineArtifactStoreError, match="finite name collection"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names="run.json",
        )
    with pytest.raises(EngineArtifactStoreError, match="selection count"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("one.json", "two.json"),
        )


def test_source_tree_snapshot_stops_enumeration_at_entry_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()

    class OversizedScan:
        consumed = 0

        def __enter__(self) -> "OversizedScan":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> "OversizedScan":
            return self

        def __next__(self) -> object:
            self.consumed += 1
            return object()

    scan = OversizedScan()
    monkeypatch.setattr(os, "scandir", lambda _path: scan)

    with pytest.raises(EngineArtifactStoreError, match="entry bound"):
        source_collection_tree_digest(source)
    assert scan.consumed == MAX_SOURCE_TREE_ENTRIES + 1


def test_import_requires_stopped_write_revoked_source_seal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"{}")
    valid = seal(source)
    invalid = {
        field: getattr(valid, field)
        for field in valid.__dataclass_fields__
        if not field.startswith("_")
    }
    invalid["worker_state"] = "running"

    with pytest.raises(EngineArtifactStoreError, match="controller authority"):
        SourceCollectionSeal.from_mapping(invalid)
    with pytest.raises(EngineArtifactStoreError, match="stopped snapshot"):
        SourceCollectionSeal.from_mapping(
            invalid, _controller_authority=_CONTROLLER_SOURCE_AUTHORITY
        )

    tampered = seal(source)
    object.__setattr__(tampered, "write_access_revoked", False)
    with pytest.raises(EngineArtifactStoreError, match="stopped snapshot"):
        EngineArtifactStore(tmp_path / "tampered-owned").import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=tampered,
            allowed_names=("run.json",),
        )


def test_direct_source_seal_constructor_cannot_bypass_controller_authority(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    details = source.lstat()

    with pytest.raises(TypeError):
        SourceCollectionSeal(  # type: ignore[call-arg]
            schema_version="bluefire.engine-source-collection-seal.v1",
            attempt_id=ATTEMPT,
            source_root_device=details.st_dev,
            source_root_inode=details.st_ino,
            source_root_mtime_ns=details.st_mtime_ns,
            source_tree_digest=source_collection_tree_digest(source),
            worker_state="stopped",
            write_access_revoked=True,
            controller_receipt_digest="sha256:" + "a" * 64,
        )

    unattested = seal(source)
    object.__setattr__(unattested, "_controller_attestation", None)
    with pytest.raises(EngineArtifactStoreError, match="controller authority"):
        unattested.to_dict()


def test_import_rejects_source_changed_after_collection_seal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"{}")
    frozen = seal(source)
    (source / "later.json").write_bytes(b"change")
    current = source.lstat()
    os.utime(
        source,
        ns=(current.st_atime_ns, frozen.source_root_mtime_ns),
    )

    assert source.lstat().st_mtime_ns == frozen.source_root_mtime_ns
    assert source_collection_tree_digest(source) != frozen.source_tree_digest

    with pytest.raises(EngineArtifactStoreError, match="unsafe"):
        EngineArtifactStore(tmp_path / "owned").import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
        )


def test_import_rejects_source_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"private")
    linked = source / "run.json"
    try:
        linked.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file links unavailable: {exc}")

    with pytest.raises(EngineArtifactStoreError, match="unsafe"):
        EngineArtifactStore(tmp_path / "owned").import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )


def test_import_rejects_special_file_when_supported(tmp_path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "mkfifo"):
        pytest.skip("named pipes unavailable")
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "run.json")

    with pytest.raises(EngineArtifactStoreError, match="unsafe"):
        EngineArtifactStore(tmp_path / "owned").import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )


def test_import_rejects_per_file_and_aggregate_bounds(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one").write_bytes(b"12345")
    (source / "two").write_bytes(b"67890")
    store = EngineArtifactStore(tmp_path / "owned", max_file_bytes=5, max_total_bytes=8)

    with pytest.raises(EngineArtifactStoreError, match="aggregate"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("one", "two"),
        )
    assert not (tmp_path / "owned" / ATTEMPT).exists()


def test_attempt_destination_is_exclusive_and_cannot_overwrite_evidence(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"{}")
    frozen = seal(source)
    store = EngineArtifactStore(tmp_path / "owned")
    store.import_attempt(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=frozen,
        allowed_names=("run.json",),
    )
    original = (tmp_path / "owned" / ATTEMPT / "raw" / "run.json").read_bytes()

    with pytest.raises(EngineArtifactStoreError, match="already exists"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=frozen,
            allowed_names=("run.json",),
        )
    assert (tmp_path / "owned" / ATTEMPT / "raw" / "run.json").read_bytes() == original


def test_failed_manifest_retains_exact_partial_for_guarded_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b"{}")
    store = EngineArtifactStore(tmp_path / "owned")
    original = store._write_exclusive
    calls = 0

    def fail_manifest(path: Path, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if path.name == "manifest.json":
            raise EngineArtifactStoreError("injected manifest failure")
        original(path, payload)

    monkeypatch.setattr(store, "_write_exclusive", fail_manifest)
    with pytest.raises(EngineArtifactPublicationUnknown, match="guarded recovery"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )

    assert calls == 2
    assert not (tmp_path / "owned" / ATTEMPT).exists()
    pending = tmp_path / "owned" / (".pending-" + ATTEMPT)
    assert (pending / "raw" / "run.json").read_bytes() == b"{}"
    assert not (pending / "manifest.json").exists()
    with pytest.raises(EngineArtifactPublicationUnknown, match="recovery"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )
    assert (pending / "raw" / "run.json").read_bytes() == b"{}"


def test_root_sync_failure_is_commit_unknown_with_complete_reconcilable_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b'{"status":"complete"}\n')
    store = EngineArtifactStore(tmp_path / "owned")
    original_sync = store._sync_directory

    def fail_root_sync(path: Path) -> None:
        if path == store.root:
            raise EngineArtifactStoreError("injected root sync failure")
        original_sync(path)

    monkeypatch.setattr(store, "_sync_directory", fail_root_sync)
    with pytest.raises(EngineArtifactPublicationUnknown, match="published.*unknown"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )

    final = store.root / ATTEMPT
    assert (final / "manifest.json").is_file()
    assert (final / "raw" / "run.json").read_bytes() == b'{"status":"complete"}\n'
    assert not (store.root / (".pending-" + ATTEMPT)).exists()
    with pytest.raises(EngineArtifactStoreError, match="already exists"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )


def test_post_publish_interrupt_is_commit_unknown_without_deleting_final_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b'{"status":"complete"}\n')
    store = EngineArtifactStore(tmp_path / "owned")
    original_sync = store._sync_directory

    def interrupt_root_sync(path: Path) -> None:
        if path == store.root:
            raise KeyboardInterrupt
        original_sync(path)

    monkeypatch.setattr(store, "_sync_directory", interrupt_root_sync)
    with pytest.raises(EngineArtifactPublicationUnknown, match="published.*unknown"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )

    final = store.root / ATTEMPT
    assert (final / "manifest.json").is_file()
    assert (final / "raw" / "run.json").read_bytes() == b'{"status":"complete"}\n'
    assert not (store.root / (".pending-" + ATTEMPT)).exists()


def test_interrupt_at_atomic_promotion_boundary_preserves_final_for_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.json").write_bytes(b'{"status":"complete"}\n')
    store = EngineArtifactStore(tmp_path / "owned")
    original_publish = store._publish_staging

    def publish_then_interrupt(staging: Path, final: Path) -> None:
        original_publish(staging, final)
        raise KeyboardInterrupt

    monkeypatch.setattr(store, "_publish_staging", publish_then_interrupt)
    with pytest.raises(EngineArtifactPublicationUnknown, match="requires manifest reconciliation"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )

    final = store.root / ATTEMPT
    assert (final / "manifest.json").is_file()
    assert (final / "raw" / "run.json").read_bytes() == b'{"status":"complete"}\n'
    assert not (store.root / (".pending-" + ATTEMPT)).exists()


def test_protected_root_is_verified_before_source_or_destination_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(
        EngineArtifactStore,
        "_verify_protected_root",
        staticmethod(lambda path: calls.append(path)),
    )
    store = EngineArtifactStore(tmp_path / "owned")

    assert calls == [store.root]
    assert not any(store.root.iterdir())


def test_windows_root_requires_product_store_provisioning(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows ProductStore precondition only")

    with pytest.raises(EngineArtifactStoreError, match="provisioned by ProductStore"):
        _PRODUCTION_PREPARE_ROOT(tmp_path / "not-provisioned")


def test_windows_extended_root_supports_nested_artifact_publication(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows extended path regression only")
    extended_temp = _windows_extended_path(tmp_path)
    long_root = extended_temp
    while len(os.fspath(long_root)) < 300:
        long_root = long_root / ("artifact-segment-" + "x" * 24)
    source = long_root / "source"
    source.mkdir(parents=True)
    (source / "nested").mkdir()
    (source / "nested" / "result.json").write_bytes(b'{"result":"retained"}\n')
    owned = long_root / "owned"
    owned.mkdir()
    store = EngineArtifactStore(owned)

    store.import_attempt(
        attempt_id=ATTEMPT,
        source_run_dir=source,
        source_seal=seal(source),
        allowed_names=("nested/result.json",),
    )

    assert (
        store.root / ATTEMPT / "raw" / "nested" / "result.json"
    ).read_bytes() == b'{"result":"retained"}\n'


def test_normalized_finding_identity_uses_attempt_source_hash_and_ordinal() -> None:
    source = "sha256:" + "a" * 64
    first = normalized_finding_id(ATTEMPT, source, 0)

    assert first == normalized_finding_id(ATTEMPT, source, 0)
    assert first != normalized_finding_id(ATTEMPT, source, 1)
    assert first.startswith("engine-finding-")
