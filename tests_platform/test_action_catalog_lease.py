from __future__ import annotations

import multiprocessing
import os
import sqlite3
import stat
import subprocess  # nosec B404 - fixed interpreter test child
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import bluefire.local_lock as local_lock_module
import bluefire.product_store as product_store_module
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.runner_client import (
    InventoryBoundRunner,
    canonical_runner_inventory,
    runner_transport_identity,
)
from bluefire.util import content_hash
from tests_platform.test_action_package_lifecycle import (
    PACKAGE_ID,
    _enroll,
    _runner_inventory,
    _verified,
)


def _active_catalog(database: Path) -> tuple[ProductStore, Mapping[str, Any]]:
    store = ProductStore(database)
    key = Ed25519PrivateKey.generate()
    _enroll(store, key)
    package = store.install_action_package(
        _verified(store, key),
        installed_by="lease-test",
    )
    activation = store.prepare_action_package_activation(
        PACKAGE_ID,
        "1.2.3",
        runner_inventory=_runner_inventory(),
        runner_identity_digest="sha256:" + "9" * 64,
    )
    store.activate_action_package(
        activation,
        activated_by="lease-test",
        reason="prove dispatch serialization",
    )
    snapshot = store.get_action_package_catalog_snapshot()
    return store, {
        "package_digest": package["package_digest"],
        "generation": snapshot["generation"],
        "catalog_digest": snapshot["catalog_digest"],
    }


def _hard_link_or_skip(source: Path, target: Path) -> None:
    try:
        os.link(source, target)
    except OSError:
        pytest.skip("hard links are unavailable on this platform")
    if source.stat().st_nlink == 1:
        target.unlink()
        pytest.skip("filesystem does not expose hard-link counts")


def test_catalog_lease_does_not_relabel_an_effect_body_os_error(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "body-error.sqlite3")

    with pytest.raises(FileNotFoundError, match="effect-owned missing file"):
        with store.action_package_catalog_lease():
            raise FileNotFoundError("effect-owned missing file")


class _BlockingRunner:
    def __init__(self, started: threading.Event, release: threading.Event) -> None:
        self.started = started
        self.release = release
        self.execute_calls = 0

    def inventory(self) -> Mapping[str, Any]:
        return _runner_inventory()

    def _effect(self) -> Mapping[str, Any]:
        self.execute_calls += 1
        self.started.set()
        if not self.release.wait(5):
            raise AssertionError("lease test did not release the native effect")
        return {"status": "success"}

    def execute(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self._effect()

    def execute_task(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        assert task_id == "lease-task"
        assert not cancel_event.is_set()
        assert Path(durable_result_path).is_absolute()
        return self._effect()


@pytest.mark.parametrize("task_aware", [False, True])
def test_dispatch_lease_blocks_second_store_lifecycle_until_effect_returns(
    tmp_path: Path,
    task_aware: bool,
) -> None:
    database = tmp_path / "dispatch-ordering.sqlite3"
    dispatch_store, authority = _active_catalog(database)
    writer_store = ProductStore(database)
    started = threading.Event()
    release = threading.Event()
    writer_attempted = threading.Event()
    writer_done = threading.Event()
    runner = _BlockingRunner(started, release)
    inventory = runner.inventory()
    bound = InventoryBoundRunner(
        runner,
        expected_inventory_digest=content_hash(canonical_runner_inventory(inventory)),
        expected_identity_digest=content_hash(runner_transport_identity(runner, inventory)),
        recovery_identity={},
        dispatch_lease=lambda: dispatch_store.action_package_catalog_dispatch_lease(
            int(authority["generation"]),
            str(authority["catalog_digest"]),
        ),
    )
    dispatch_error: list[BaseException] = []
    writer_error: list[BaseException] = []

    def dispatch() -> None:
        try:
            if task_aware:
                bound.execute_task(
                    {},
                    {},
                    task_id="lease-task",
                    cancel_event=threading.Event(),
                    durable_result_path=tmp_path / "durable.json",
                )
            else:
                bound.execute({}, {})
        except BaseException as exc:
            dispatch_error.append(exc)

    def deactivate() -> None:
        writer_attempted.set()
        try:
            writer_store.deactivate_action_package(
                PACKAGE_ID,
                "1.2.3",
                str(authority["package_digest"]),
                expected_catalog_generation=int(authority["generation"]),
                expected_catalog_digest=str(authority["catalog_digest"]),
                deactivated_by="lease-writer",
                reason="prove lifecycle waits for effect completion",
            )
        except BaseException as exc:
            writer_error.append(exc)
        finally:
            writer_done.set()

    dispatch_thread = threading.Thread(target=dispatch, daemon=True)
    dispatch_thread.start()
    assert started.wait(5)
    writer_thread = threading.Thread(target=deactivate, daemon=True)
    writer_thread.start()
    assert writer_attempted.wait(5)
    assert not writer_done.wait(0.2)
    assert dispatch_store.get_action_package_catalog_snapshot()["generation"] == 1

    release.set()
    dispatch_thread.join(timeout=5)
    writer_thread.join(timeout=5)
    assert not dispatch_thread.is_alive()
    assert not writer_thread.is_alive()
    assert dispatch_error == []
    assert writer_error == []
    assert writer_done.is_set()
    assert dispatch_store.get_action_package_catalog_snapshot()["generation"] == 2


def test_subprocess_lifecycle_waits_for_exact_dispatch_lease(tmp_path: Path) -> None:
    database = tmp_path / "subprocess-ordering.sqlite3"
    store, authority = _active_catalog(database)
    child_code = """
import sys
from bluefire.product_store import ProductStore
print("attempt", flush=True)
store = ProductStore(sys.argv[1])
store.deactivate_action_package(
    sys.argv[2], sys.argv[3], sys.argv[4],
    expected_catalog_generation=int(sys.argv[5]),
    expected_catalog_digest=sys.argv[6],
    deactivated_by="subprocess-writer",
    reason="prove cross-process dispatch ordering",
)
print("completed", flush=True)
"""
    process: subprocess.Popen[str] | None = None
    try:
        with store.action_package_catalog_dispatch_lease(
            int(authority["generation"]),
            str(authority["catalog_digest"]),
        ):
            process = subprocess.Popen(  # nosec B603 - fixed interpreter and test script
                [
                    sys.executable,
                    "-c",
                    child_code,
                    str(database),
                    PACKAGE_ID,
                    "1.2.3",
                    str(authority["package_digest"]),
                    str(authority["generation"]),
                    str(authority["catalog_digest"]),
                ],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdout is not None
            assert process.stdout.readline().strip() == "attempt"
            time.sleep(0.2)
            assert process.poll() is None
            assert store.get_action_package_catalog_snapshot()["generation"] == 1
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        assert stdout.strip() == "completed"
        assert store.get_action_package_catalog_snapshot()["generation"] == 2
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_catalog_lease_is_inode_reentrant_owner_private_and_refuses_links(
    tmp_path: Path,
) -> None:
    database = tmp_path / "lock-safety.sqlite3"
    first = ProductStore(database)
    second = ProductStore(database)
    with first.action_package_catalog_lease():
        with second.action_package_catalog_lease():
            assert first.path == second.path

    details = database.stat()
    assert details.st_nlink == 1
    if os.name != "nt":
        assert stat.S_IMODE(details.st_mode) == 0o600

    database.unlink()
    target = tmp_path / "attacker-controlled.sqlite3"
    ProductStore(target)
    try:
        database.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")
    with pytest.raises(ProductStoreError, match="catalog lease is unavailable"):
        with first.action_package_catalog_lease():
            pass


def test_product_store_refuses_existing_database_hard_link_alias(tmp_path: Path) -> None:
    database = tmp_path / "canonical.sqlite3"
    ProductStore(database)
    alias = tmp_path / "alias.sqlite3"
    _hard_link_or_skip(database, alias)

    with pytest.raises(ProductStoreError, match="single-link regular file"):
        ProductStore(alias)


def test_catalog_lease_refuses_hard_link_added_after_construction(tmp_path: Path) -> None:
    database = tmp_path / "pinned.sqlite3"
    store = ProductStore(database)
    alias = tmp_path / "late-alias.sqlite3"
    _hard_link_or_skip(database, alias)

    with pytest.raises(ProductStoreError, match="single-link regular file"):
        with store.action_package_catalog_lease():
            pass

    alias.unlink()
    with store.action_package_catalog_lease():
        pass


def test_database_inode_lease_survives_cross_directory_move(tmp_path: Path) -> None:
    database = tmp_path / "source" / "catalog.sqlite3"
    database.parent.mkdir()
    first = ProductStore(database)
    moved = tmp_path / "destination" / "renamed.sqlite3"
    moved.parent.mkdir()
    original_identity = database.stat().st_dev, database.stat().st_ino
    attempted = threading.Event()
    done = threading.Event()
    errors: list[BaseException] = []
    moved_while_locked = False

    def construct_moved_store() -> None:
        attempted.set()
        try:
            ProductStore(moved)
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    thread: threading.Thread | None = None
    with first.action_package_catalog_lease():
        try:
            database.replace(moved)
        except OSError:
            # A Windows no-delete handle is the stronger safe outcome.
            assert database.is_file()
            assert not moved.exists()
        else:
            moved_while_locked = True
            assert (moved.stat().st_dev, moved.stat().st_ino) == original_identity
            thread = threading.Thread(target=construct_moved_store, daemon=True)
            thread.start()
            assert attempted.wait(5)
            assert not done.wait(0.2)

    if not moved_while_locked:
        database.replace(moved)
        ProductStore(moved)
    else:
        assert thread is not None
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert done.is_set()
        assert errors == []
    assert not database.exists()


@pytest.mark.parametrize("attack", ["hardlink", "replacement"])
def test_pre_migration_victim_swap_is_refused_without_mutating_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    victim = tmp_path / "victim.sqlite3"
    connection = sqlite3.connect(victim)
    connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
    connection.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
    connection.commit()
    connection.close()
    victim_bytes = victim.read_bytes()
    database = tmp_path / "candidate.sqlite3"
    real_prepare = product_store_module.prepare_owner_private_database_file
    observed_victim = victim

    def inject_swap(path: str | Path) -> tuple[Path, tuple[int, int]]:
        nonlocal observed_victim
        canonical, identity = real_prepare(path)
        canonical.unlink()
        if attack == "hardlink":
            os.link(victim, canonical)
        else:
            victim.replace(canonical)
            observed_victim = canonical
        return canonical, identity

    monkeypatch.setattr(
        product_store_module,
        "prepare_owner_private_database_file",
        inject_swap,
    )

    with pytest.raises(ProductStoreError, match="catalog lease is unavailable"):
        ProductStore(database)

    assert observed_victim.read_bytes() == victim_bytes


@pytest.mark.skipif(
    not callable(getattr(os, "register_at_fork", None))
    or "fork" not in multiprocessing.get_all_start_methods(),
    reason="requires POSIX fork callbacks",
)
def test_forked_lifecycle_writer_waits_for_parent_inode_lease(tmp_path: Path) -> None:
    database = tmp_path / "forked-writer.sqlite3"
    store, authority = _active_catalog(database)
    context: Any = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)

    def child_writer() -> None:
        sender.send(("attempt", ""))
        try:
            child_store = ProductStore(database)
            child_store.deactivate_action_package(
                PACKAGE_ID,
                "1.2.3",
                str(authority["package_digest"]),
                expected_catalog_generation=int(authority["generation"]),
                expected_catalog_digest=str(authority["catalog_digest"]),
                deactivated_by="forked-writer",
                reason="prove fork cannot inherit catalog authority",
            )
        except BaseException as exc:
            sender.send(("error", f"{type(exc).__name__}: {exc}"))
            raise
        else:
            sender.send(("completed", ""))
        finally:
            sender.close()

    process: multiprocessing.Process | None = None
    try:
        with store.action_package_catalog_lease():
            process = context.Process(target=child_writer)
            process.start()
            sender.close()
            assert receiver.poll(5)
            assert receiver.recv() == ("attempt", "")
            assert not receiver.poll(0.25)

        assert receiver.poll(10)
        assert receiver.recv() == ("completed", "")
        process.join(timeout=10)
        assert not process.is_alive()
        assert process.exitcode == 0
        assert store.get_action_package_catalog_snapshot()["generation"] == 2
    finally:
        receiver.close()
        if process is not None and process.is_alive():
            process.kill()
            process.join(timeout=5)


@pytest.mark.skipif(
    not callable(getattr(os, "register_at_fork", None)) or not callable(getattr(os, "fork", None)),
    reason="requires direct POSIX fork callbacks",
)
def test_direct_fork_stale_context_cannot_close_reused_child_descriptor(
    tmp_path: Path,
) -> None:
    fcntl: Any = __import__("fcntl")

    parent_store = ProductStore(tmp_path / "parent.sqlite3")
    child_store = ProductStore(tmp_path / "child.sqlite3")
    receiver, sender = os.pipe()
    outer = parent_store.action_package_catalog_lease()
    outer.__enter__()
    inherited_descriptors = set(local_lock_module._DATABASE_DESCRIPTORS)
    assert len(inherited_descriptors) == 1
    inherited_descriptor = next(iter(inherited_descriptors))

    fork: Any = os.__dict__["fork"]
    child_pid = fork()
    if child_pid == 0:
        os.close(receiver)
        inner = child_store.action_package_catalog_lease()
        try:
            inner.__enter__()
            child_descriptors = set(local_lock_module._DATABASE_DESCRIPTORS)
            assert child_descriptors == {inherited_descriptor}

            # Unwind the context copied from the parent only after the child has
            # reused its descriptor number for a different database lease.
            outer.__exit__(None, None, None)
            assert child_descriptors == set(local_lock_module._DATABASE_DESCRIPTORS)
            os.fstat(inherited_descriptor)

            probe = os.open(child_store.path, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
        except BaseException as exc:
            os.write(sender, f"error:{type(exc).__name__}:{exc}".encode("utf-8"))
            os._exit(1)
        else:
            inner.__exit__(None, None, None)
            os.write(sender, b"ok")
            os._exit(0)

    os.close(sender)
    try:
        outer.__exit__(None, None, None)
        _, status = os.waitpid(child_pid, 0)
        report = os.read(receiver, 4096).decode("utf-8")
        assert os.waitstatus_to_exitcode(status) == 0, report
        assert report == "ok"
    finally:
        os.close(receiver)
