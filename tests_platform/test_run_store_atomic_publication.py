from __future__ import annotations

import multiprocessing
import os
import threading
from functools import partial
from pathlib import Path
from typing import Any

import pytest

import bluefire.run_store as run_store_module
from bluefire.run_store import RunStore, RunStoreError
from bluefire.windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl_path

RUN_ID = "run-20261104T120000Z-1111111111111111"
CREATED = "2026-11-04T12:00:00Z"
FINALIZED = "2026-11-04T12:00:09Z"


def _store(path: Path) -> RunStore:
    store = RunStore(path)
    if run_store_module.os.name == "nt":
        apply_owner_private_acl_path(store.root, directory=True)
    else:
        store.root.chmod(0o700)
    return store


def _values(*, outcome: str = "observed") -> dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "created_at": CREATED,
        "finalized_at": FINALIZED,
        "scenario": {
            "schema_version": "bluefire.scenario.v1",
            "id": "engine-attempt-observation",
        },
        "plan": {"schema_version": "bluefire.plan.v1", "steps": []},
        "policy": {"schema_version": "bluefire.policy.v1", "effect": "observation"},
        "profile": None,
        "result": {"schema_version": "bluefire.run-result.v1", "status": "completed"},
        "evidence": [
            {
                "schema_version": "bluefire.evidence.v1",
                "evidence_id": "engine-evidence-111111111111111111111111",
                "outcome": outcome,
            }
        ],
        "detections": [],
        "replay": {"kind": "controller_observation"},
    }


def _publish(store: RunStore, **changes: Any):
    values = _values()
    values.update(changes)
    run_id = values.pop("run_id")
    return store.publish_finalized_run(run_id, **values)


def _bundle_bytes(store: RunStore) -> dict[str, bytes]:
    directory = store.root / RUN_ID
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def _staging(store: RunStore) -> list[str]:
    return sorted(path.name for path in store.root.glob(".run-publish-tmp-*"))


def _process_publish(root: str, outcome: str, start, results) -> None:
    store = RunStore(root)
    values = _values(outcome=outcome)
    run_id = values.pop("run_id")
    start.wait(10)
    try:
        manifest = store.publish_finalized_run(run_id, **values)
    except Exception as exc:
        results.put(("error", type(exc).__name__))
    else:
        results.put(("published", str(manifest["bundle_hash"])))


def _process_create(root: str, start, results) -> None:
    store = RunStore(root)
    start.wait(10)
    try:
        store.create_run(
            scenario=_values()["scenario"],
            plan=_values()["plan"],
            policy=_values()["policy"],
            profile=None,
            replay=_values()["replay"],
            _reserved_run_id=RUN_ID,
        )
    except Exception as exc:
        results.put(("error", type(exc).__name__))
    else:
        results.put(("created", RUN_ID))


def test_atomic_publication_exposes_only_one_complete_finalized_bundle(tmp_path: Path) -> None:
    store = _store(tmp_path / "runs")
    manifest = _publish(store)

    assert manifest == store.validate_bundle(RUN_ID)["manifest"]
    assert store.validate_bundle(RUN_ID)["valid"] is True
    run = store.get_run(RUN_ID, require_finalized=True)
    assert run["run_id"] == RUN_ID
    assert run["created_at"] == CREATED
    assert run["finalized_at"] == FINALIZED
    assert [event["event_type"] for event in run["events"]] == [
        "run.created",
        "run.finalized",
    ]
    assert [event["timestamp"] for event in run["events"]] == [CREATED, FINALIZED]
    assert run["evidence"]["records"] == _values()["evidence"]
    assert _staging(store) == []
    assert str(store.root).encode() not in b"".join(_bundle_bytes(store).values())


def test_exact_retry_reopens_without_rewriting_any_byte(tmp_path: Path) -> None:
    first = _store(tmp_path / "runs")
    expected = _publish(first)
    before = _bundle_bytes(first)
    before_times = {path.name: path.stat().st_mtime_ns for path in (first.root / RUN_ID).iterdir()}

    second = RunStore(first.root)
    assert _publish(second) == expected
    assert _bundle_bytes(second) == before
    assert {
        path.name: path.stat().st_mtime_ns for path in (second.root / RUN_ID).iterdir()
    } == before_times
    assert _staging(second) == []


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"evidence": _values(outcome="changed")["evidence"]}, "byte-identical"),
        ({"finalized_at": "2026-11-04T12:00:10Z"}, "byte-identical"),
    ],
)
def test_conflicting_retry_preserves_original_evidence(
    tmp_path: Path, changes: dict[str, Any], match: str
) -> None:
    store = _store(tmp_path / "runs")
    _publish(store)
    before = _bundle_bytes(store)

    with pytest.raises(RunStoreError, match=match):
        _publish(RunStore(store.root), **changes)

    assert _bundle_bytes(store) == before
    assert store.validate_bundle(RUN_ID)["valid"] is True
    assert _staging(store) == []


@pytest.mark.parametrize("partial", [False, True])
def test_preexisting_unsealed_directory_is_never_replaced_or_deleted(
    tmp_path: Path, partial: bool
) -> None:
    store = _store(tmp_path / "runs")
    existing = store.root / RUN_ID
    existing.mkdir()
    if partial:
        (existing / "partial.json").write_text('{"retained":true}\n', encoding="utf-8")
    before = {path.name: path.read_bytes() for path in existing.iterdir()}

    with pytest.raises(RunStoreError, match="byte-identical"):
        _publish(store)

    assert existing.is_dir()
    assert {path.name: path.read_bytes() for path in existing.iterdir()} == before
    assert _staging(store) == []


def test_extra_unmanifested_file_and_same_root_alias_are_refused(tmp_path: Path) -> None:
    store = _store(tmp_path / "runs")
    _publish(store)
    bundle = store.root / RUN_ID
    extra = bundle / "untrusted.txt"
    extra.write_text("not evidence", encoding="utf-8")
    with pytest.raises(RunStoreError, match="byte-identical"):
        _publish(store)
    assert extra.read_text(encoding="utf-8") == "not evidence"

    other_id = "run-20261104T120001Z-2222222222222222"
    other = store.root / other_id
    try:
        other.symlink_to(bundle, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable to this test account")
    values = _values()
    values["run_id"] = other_id
    with pytest.raises(RunStoreError, match="unsafe"):
        store.publish_finalized_run(other_id, **{k: v for k, v in values.items() if k != "run_id"})
    assert other.is_symlink()


@pytest.mark.parametrize("failure", ["payload", "mkdir", "write", "rename"])
def test_failed_publication_cleans_only_owned_staging_and_sanitizes_os_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store = _store(tmp_path / "private-secret-root" / "runs")
    retained = store.root / "operator-evidence.txt"
    retained.write_text("keep", encoding="utf-8")
    secret = "private-secret-root"
    publish = partial(_publish, store)
    if failure == "payload":
        values = _values()

        def broken_evidence():
            yield {"first": True}
            raise OSError(f"{secret}:payload")

        values["evidence"] = broken_evidence()
        publish = partial(
            store.publish_finalized_run,
            RUN_ID,
            **{key: value for key, value in values.items() if key != "run_id"},
        )
    elif failure == "mkdir":
        monkeypatch.setattr(
            run_store_module.tempfile,
            "mkdtemp",
            lambda **_values: (_ for _ in ()).throw(OSError(f"{secret}:mkdir")),
        )
    elif failure == "write":
        original = store._atomic_write
        calls = 0

        def fail_write(target: Path, payload: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError(f"{secret}:{target}")
            original(target, payload)

        monkeypatch.setattr(store, "_atomic_write", fail_write)
    else:
        monkeypatch.setattr(
            store,
            "_publish_directory_no_replace",
            lambda *_args, **_values: (_ for _ in ()).throw(OSError(f"{secret}:rename")),
        )

    with pytest.raises(RunStoreError) as caught:
        publish()

    assert secret not in str(caught.value)
    assert str(store.root) not in str(caught.value)
    assert retained.read_text(encoding="utf-8") == "keep"
    assert not (store.root / RUN_ID).exists()
    assert _staging(store) == []


def test_arbitrary_iterable_failure_is_sanitized_before_staging(tmp_path: Path) -> None:
    store = _store(tmp_path / "private-generator-detail" / "runs")

    class PrivateGeneratorFailure(Exception):
        pass

    def broken_evidence():
        raise PrivateGeneratorFailure("private-generator-detail")
        yield  # pragma: no cover - makes this an iterable without producing data

    values = _values()
    values["evidence"] = broken_evidence()
    with pytest.raises(RunStoreError) as caught:
        store.publish_finalized_run(
            RUN_ID, **{key: value for key, value in values.items() if key != "run_id"}
        )
    assert "private-generator-detail" not in str(caught.value)
    assert not (store.root / RUN_ID).exists()
    assert _staging(store) == []


def test_staging_directory_fsync_failure_leaves_no_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "private-fsync-stage" / "runs")
    original = store._fsync_publication_directory

    def fail_staging(path: Path, identity: tuple[int, int, int]) -> None:
        if path.name.startswith(run_store_module._PUBLICATION_TEMP_PREFIX):
            raise OSError("private-fsync-stage")
        original(path, identity)

    monkeypatch.setattr(store, "_fsync_publication_directory", fail_staging)
    with pytest.raises(RunStoreError, match="failed safely") as caught:
        _publish(store)
    assert "private-fsync-stage" not in str(caught.value)
    assert not (store.root / RUN_ID).exists()
    assert _staging(store) == []


def test_root_directory_fsync_failure_retains_valid_bundle_for_exact_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "private-fsync-root" / "runs")
    original = store._fsync_publication_directory

    def fail_root(path: Path, identity: tuple[int, int, int]) -> None:
        if path == store.root:
            raise OSError("private-fsync-root")
        original(path, identity)

    monkeypatch.setattr(store, "_fsync_publication_directory", fail_root)
    with pytest.raises(RunStoreError, match="failed safely") as caught:
        _publish(store)
    assert "private-fsync-root" not in str(caught.value)
    assert store.validate_bundle(RUN_ID)["valid"] is True
    monkeypatch.setattr(store, "_fsync_publication_directory", original)
    assert _publish(RunStore(store.root)) == store.validate_bundle(RUN_ID)["manifest"]
    assert _staging(store) == []


def test_no_replace_refuses_a_raced_empty_destination(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path / "runs")
    original = store._publish_directory_no_replace
    raced = store.root / RUN_ID

    def collide(*args, **values):
        raced.mkdir()
        return original(*args, **values)

    monkeypatch.setattr(store, "_publish_directory_no_replace", collide)
    with pytest.raises(RunStoreError, match="byte-identical"):
        _publish(store)
    assert raced.is_dir()
    assert list(raced.iterdir()) == []
    assert _staging(store) == []


def test_cleanup_refuses_rebound_staging_identity(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path / "runs")
    rebound: list[Path] = []

    def replace_staging(temporary: Path, *_args, **_values):
        retained = temporary.with_name(temporary.name + "-original")
        temporary.rename(retained)
        temporary.mkdir()
        (temporary / "foreign.txt").write_text("foreign", encoding="utf-8")
        rebound.extend((temporary, retained))
        raise OSError("refuse after rebound")

    monkeypatch.setattr(store, "_publish_directory_no_replace", replace_staging)
    with pytest.raises(RunStoreError, match="failed safely"):
        _publish(store)
    replacement, original = rebound
    assert (replacement / "foreign.txt").read_text(encoding="utf-8") == "foreign"
    assert original.is_dir()
    # Test-owned cleanup; production correctly leaves both unverified identities alone.
    (replacement / "foreign.txt").unlink()
    replacement.rmdir()
    for child in original.iterdir():
        child.unlink()
    original.rmdir()


def test_cleanup_refuses_rebound_child_identity(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path / "runs")
    rebound: list[Path] = []
    armed = False
    if run_store_module.os.name == "nt":
        original_windows_open = run_store_module._windows_open_descriptor

        def rebind_windows(path: Path, *, directory: bool, **values):
            if armed and not directory and not rebound:
                retained = path.with_name(path.name + ".owned")
                path.rename(retained)
                path.write_bytes(b"foreign")
                rebound.extend((path, retained))
            return original_windows_open(path, directory=directory, **values)

        monkeypatch.setattr(run_store_module, "_windows_open_descriptor", rebind_windows)
    else:
        original_posix_open = run_store_module.os.open

        def rebind_posix(path, flags, *args, **values):
            if (
                values.get("dir_fd") is not None
                and isinstance(path, str)
                and not path.startswith(run_store_module._PUBLICATION_TEMP_PREFIX)
                and armed
                and not rebound
            ):
                staging = next(store.root.glob(".run-publish-tmp-*"))
                child = staging / path
                retained = staging / (path + ".owned")
                child.rename(retained)
                child.write_bytes(b"foreign")
                rebound.extend((child, retained))
            return original_posix_open(path, flags, *args, **values)

        monkeypatch.setattr(run_store_module.os, "open", rebind_posix)

    def refuse_publication(*_args, **_values):
        nonlocal armed
        armed = True
        raise OSError("refuse publication")

    monkeypatch.setattr(store, "_publish_directory_no_replace", refuse_publication)

    with pytest.raises(RunStoreError, match="failed safely"):
        _publish(store)
    if run_store_module.os.name == "nt" and not rebound:
        assert rebound == []
        staging = next(store.root.glob(".run-publish-tmp-*"))
        assert any(staging.iterdir())
        for child in staging.iterdir():
            child.unlink()
        staging.rmdir()
        return
    foreign, retained = rebound
    assert foreign.read_bytes() == b"foreign"
    assert retained.is_file()
    # Test-owned cleanup of the deliberately rebound staging directory.
    staging = foreign.parent
    for child in staging.iterdir():
        child.unlink()
    staging.rmdir()


@pytest.mark.parametrize("kind", ["records", "record_bytes", "bytes"])
def test_publication_bounds_refuse_before_allocating_staging(tmp_path: Path, kind: str) -> None:
    store = _store(tmp_path / "runs")
    values = _values()
    if kind == "records":
        values["evidence"] = [
            {"record": index} for index in range(run_store_module._MAX_PUBLICATION_RECORDS + 1)
        ]
        match = "count"
    elif kind == "record_bytes":
        values["evidence"] = [{"oversized": "x" * run_store_module._MAX_PUBLICATION_RECORD_BYTES}]
        match = "byte bound"
    else:
        values["scenario"] = {
            "schema_version": "bluefire.scenario.v1",
            "oversized": "x" * run_store_module._MAX_PUBLICATION_FILE_BYTES,
        }
        match = "byte bound"
    with pytest.raises(RunStoreError, match=match):
        store.publish_finalized_run(
            RUN_ID, **{key: value for key, value in values.items() if key != "run_id"}
        )
    assert not (store.root / RUN_ID).exists()
    assert _staging(store) == []


@pytest.mark.skipif(run_store_module.os.name == "nt", reason="POSIX mode invariant")
def test_publication_refuses_group_or_world_writable_root(tmp_path: Path) -> None:
    store = _store(tmp_path / "runs")
    store.root.chmod(0o777)
    try:
        with pytest.raises(RunStoreError, match="owner-private"):
            _publish(store)
        assert not (store.root / RUN_ID).exists()
        assert _staging(store) == []
    finally:
        store.root.chmod(0o700)


@pytest.mark.skipif(run_store_module.os.name == "nt", reason="POSIX ancestor invariant")
def test_publication_refuses_replaceable_nonsticky_ancestor(tmp_path: Path) -> None:
    unsafe_parent = tmp_path / "replaceable"
    unsafe_parent.mkdir(mode=0o700)
    store = RunStore(unsafe_parent / "runs")
    unsafe_parent.chmod(0o777)
    try:
        with pytest.raises(RunStoreError, match="ancestor chain permits replacement"):
            _publish(store)
        assert not (store.root / RUN_ID).exists()
        assert _staging(store) == []
    finally:
        unsafe_parent.chmod(0o700)


@pytest.mark.skipif(run_store_module.os.name == "nt", reason="POSIX ancestor-owner invariant")
def test_publication_refuses_foreign_owned_private_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign_parent = tmp_path / "foreign-owner"
    foreign_parent.mkdir(mode=0o700)
    store = RunStore(foreign_parent / "runs")
    actual = foreign_parent.lstat()
    fields = list(actual)
    fields[4] = int(os.geteuid()) + 1
    projected = os.stat_result(fields)
    original_lstat = Path.lstat

    def projected_lstat(path: Path):
        if path == foreign_parent:
            return projected
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", projected_lstat)
    with pytest.raises(RunStoreError, match="ancestor owner is untrusted"):
        _publish(store)


@pytest.mark.skipif(run_store_module.os.name != "nt", reason="Windows DACL invariant")
def test_publication_refuses_preexisting_root_without_private_dacl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runs"
    root.mkdir()
    store = RunStore(root)

    def refuse_private_acl(_descriptor: int, *, directory: bool) -> None:
        assert directory is True
        raise WindowsOwnerAclError("untrusted inherited principal")

    monkeypatch.setattr(run_store_module, "verify_owner_private_acl", refuse_private_acl)
    with pytest.raises(RunStoreError, match="owner-private DACL") as caught:
        _publish(store)
    assert "untrusted inherited principal" not in str(caught.value)
    assert not (root / RUN_ID).exists()
    assert _staging(store) == []


def test_two_store_instances_serialize_exact_and_conflicting_publications(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    stores = [_store(root), RunStore(root)]
    gate = threading.Barrier(2)
    exact_results: list[object] = []

    def exact(store: RunStore) -> None:
        gate.wait(timeout=5)
        try:
            exact_results.append(_publish(store))
        except Exception as exc:  # pragma: no cover - asserted below
            exact_results.append(exc)

    threads = [threading.Thread(target=exact, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert len(exact_results) == 2
    assert all(isinstance(item, dict) for item in exact_results)
    assert stores[0].validate_bundle(RUN_ID)["valid"] is True

    other_id = "run-20261104T120002Z-3333333333333333"
    gate = threading.Barrier(2)
    conflict_results: list[object] = []

    def conflict(store: RunStore, outcome: str) -> None:
        values = _values(outcome=outcome)
        values["run_id"] = other_id
        gate.wait(timeout=5)
        try:
            conflict_results.append(
                store.publish_finalized_run(
                    other_id, **{key: value for key, value in values.items() if key != "run_id"}
                )
            )
        except Exception as exc:
            conflict_results.append(exc)

    threads = [
        threading.Thread(target=conflict, args=(stores[0], "first")),
        threading.Thread(target=conflict, args=(stores[1], "second")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert sum(isinstance(item, dict) for item in conflict_results) == 1
    assert sum(isinstance(item, RunStoreError) for item in conflict_results) == 1
    assert RunStore(root).validate_bundle(other_id)["valid"] is True
    assert _staging(stores[0]) == []


def test_foreign_staging_entry_is_never_published(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path / "runs")
    original = store._publish_directory_no_replace

    def inject_foreign(temporary: Path, *args, **values):
        (temporary / "foreign.txt").write_text("foreign", encoding="utf-8")
        return original(temporary, *args, **values)

    monkeypatch.setattr(store, "_publish_directory_no_replace", inject_foreign)
    with pytest.raises(RunStoreError, match="byte-identical|inventory"):
        _publish(store)
    assert not (store.root / RUN_ID).exists()
    staging = next(store.root.glob(".run-publish-tmp-*"))
    assert (staging / "foreign.txt").read_text(encoding="utf-8") == "foreign"
    for child in staging.iterdir():
        child.unlink()
    staging.rmdir()


def test_existing_oversized_entry_is_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "runs")
    _publish(store)
    evidence = store.root / RUN_ID / "evidence.json"
    evidence.write_bytes(b"x" * (run_store_module._MAX_PUBLICATION_FILE_BYTES + 1))
    if run_store_module.os.name == "nt":
        apply_owner_private_acl_path(evidence, directory=False)
    else:
        evidence.chmod(0o600)
    original = store._read_exact_publication_entry

    def refuse_oversized(path: Path, **values):
        assert path != evidence
        return original(path, **values)

    monkeypatch.setattr(store, "_read_exact_publication_entry", refuse_oversized)
    with pytest.raises(RunStoreError, match="byte-identical"):
        _publish(store)


def test_record_count_bound_is_shared_across_evidence_and_detections(tmp_path: Path) -> None:
    store = _store(tmp_path / "runs")
    values = _values()
    half = run_store_module._MAX_PUBLICATION_RECORDS // 2
    values["evidence"] = [{"evidence": index} for index in range(half + 1)]
    values["detections"] = [{"detection": index} for index in range(half)]
    with pytest.raises(RunStoreError, match="count"):
        store.publish_finalized_run(
            RUN_ID,
            **{key: value for key, value in values.items() if key != "run_id"},
        )
    assert not (store.root / RUN_ID).exists()
    assert _staging(store) == []


def test_exact_retry_requires_root_fsync(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path / "runs")
    _publish(store)
    original = store._fsync_publication_directory

    def fail_root(path: Path, identity: tuple[int, int, int]) -> None:
        if path == store.root:
            raise OSError("private exact retry fsync")
        original(path, identity)

    monkeypatch.setattr(store, "_fsync_publication_directory", fail_root)
    with pytest.raises(RunStoreError, match="failed safely") as caught:
        _publish(store)
    assert "private exact retry fsync" not in str(caught.value)
    assert store.validate_bundle(RUN_ID)["valid"] is True


def test_new_root_replacement_is_refused_before_hardening_or_staging(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    original = store.root.with_name("runs-original")
    store.root.rename(original)
    replacement = Path(str(store.root))
    replacement.mkdir(mode=0o700)
    with pytest.raises(RunStoreError, match="root changed"):
        _publish(store)
    assert not (replacement / RUN_ID).exists()
    assert list(replacement.glob(".run-publish-tmp-*")) == []


def test_create_run_and_atomic_publisher_never_overwrite_each_other(tmp_path: Path) -> None:
    root = _store(tmp_path / "runs").root
    gate = threading.Barrier(2)
    outcomes: list[str] = []

    def create() -> None:
        gate.wait(timeout=5)
        try:
            RunStore(root).create_run(
                scenario=_values()["scenario"],
                plan=_values()["plan"],
                policy=_values()["policy"],
                profile=None,
                replay=_values()["replay"],
                _reserved_run_id=RUN_ID,
            )
        except RunStoreError:
            outcomes.append("create-refused")
        else:
            outcomes.append("created")

    def publish() -> None:
        gate.wait(timeout=5)
        try:
            _publish(RunStore(root))
        except RunStoreError:
            outcomes.append("publish-refused")
        else:
            outcomes.append("published")

    threads = [threading.Thread(target=create), threading.Thread(target=publish)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert len(outcomes) == 2
    assert sum(value in {"created", "published"} for value in outcomes) == 1
    if "published" in outcomes:
        assert RunStore(root).validate_bundle(RUN_ID)["valid"] is True
    else:
        result = RunStore(root).read_json(RUN_ID, "result.json")
        assert result["status"] == "created"
        assert not (root / RUN_ID / "manifest.json").exists()


def test_separate_process_conflicting_publishers_have_one_winner(tmp_path: Path) -> None:
    root = _store(tmp_path / "runs").root
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=_process_publish, args=(str(root), outcome, start, results))
        for outcome in ("first", "second")
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=30)
        assert not process.is_alive()
        assert process.exitcode == 0
    observed = [results.get(timeout=5) for _ in processes]
    assert sum(kind == "published" for kind, _value in observed) == 1
    assert sum(kind == "error" for kind, _value in observed) == 1
    assert RunStore(root).validate_bundle(RUN_ID)["valid"] is True


def test_separate_process_create_and_publish_never_overwrite(tmp_path: Path) -> None:
    root = _store(tmp_path / "runs").root
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=_process_create, args=(str(root), start, results)),
        context.Process(
            target=_process_publish,
            args=(str(root), "observed", start, results),
        ),
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=30)
        assert not process.is_alive()
        assert process.exitcode == 0
    observed = [results.get(timeout=5) for _ in processes]
    assert sum(kind in {"created", "published"} for kind, _value in observed) == 1
    assert sum(kind == "error" for kind, _value in observed) == 1
    if any(kind == "published" for kind, _value in observed):
        assert RunStore(root).validate_bundle(RUN_ID)["valid"] is True
    else:
        result = RunStore(root).read_json(RUN_ID, "result.json")
        assert result["status"] == "created"
        assert not (root / RUN_ID / "manifest.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX root rebind invariant")
def test_root_rebind_before_staging_writes_no_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "runs")
    original_root = store.root.with_name("runs-original")
    replacement = store.root
    original_mkdtemp = run_store_module.tempfile.mkdtemp

    def rebind_root(**values):
        replacement.rename(original_root)
        replacement.mkdir(mode=0o700)
        return original_mkdtemp(**values)

    monkeypatch.setattr(run_store_module.tempfile, "mkdtemp", rebind_root)
    with pytest.raises(RunStoreError, match="root changed"):
        _publish(store)
    staging = list(replacement.glob(".run-publish-tmp-*"))
    assert len(staging) == 1
    assert list(staging[0].iterdir()) == []
