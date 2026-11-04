from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from bluefire.engine_artifact_store import (
    _CONTROLLER_SOURCE_AUTHORITY,
    MAX_SOURCE_TREE_ENTRIES,
    EngineArtifactPublicationUnknown,
    EngineArtifactStore,
    EngineArtifactStoreError,
    SourceCollectionSeal,
    normalized_finding_id,
    source_collection_tree_digest,
)
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


def seal(source: Path, *, attempt_id: str = ATTEMPT) -> SourceCollectionSeal:
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
            "controller_receipt_digest": "sha256:" + "a" * 64,
        },
        _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
    )


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


def test_failed_manifest_never_publishes_partial_attempt(
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
    with pytest.raises(EngineArtifactStoreError, match="injected"):
        store.import_attempt(
            attempt_id=ATTEMPT,
            source_run_dir=source,
            source_seal=seal(source),
            allowed_names=("run.json",),
        )

    assert calls == 2
    assert not (tmp_path / "owned" / ATTEMPT).exists()
    assert not (tmp_path / "owned" / (".pending-" + ATTEMPT)).exists()


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
