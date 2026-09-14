"""Deterministic remount projections; no runner, WSL or native effect is executed."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.runner_history_documents as documents
import bluefire.runner_history_identity as identity
import bluefire.runner_history_preservation as preservation
import bluefire.runner_history_upgrade as upgrade
import bluefire.runner_lifecycle as lifecycle_module
from bluefire.runner_history_identity import DurableIdentityUnavailable
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
from tests_platform.test_runner_history_upgrade import (
    PROFILE_ID,
    _HistoryFixture,
    _preserved_bytes,
    _StagedBootstrap,
)
from tests_platform.test_runner_history_upgrade import (
    history as history,
)


@pytest.fixture(autouse=True)
def portable_preservation_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Software state-machine cases also run on filesystems without native durable IDs."""
    actual = preservation.durable_descriptor_identity

    def authored_when_unavailable(descriptor: int, *, directory: bool = False) -> dict[str, Any]:
        try:
            return actual(descriptor, directory=directory)
        except DurableIdentityUnavailable:
            details = os.fstat(descriptor)
            return {
                "format": "authored-descriptor-test-fixture.v1",
                "device": str(details.st_dev),
                "inode": str(details.st_ino),
            }

    monkeypatch.setattr(preservation, "durable_descriptor_identity", authored_when_unavailable)


@pytest.fixture
def session_identity(history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Change only the inspected kernel device/mount projection, never actual storage."""
    epoch = [0]
    snapshot = upgrade._file_snapshot

    def projected(directory: Any, name: str, maximum: int, **kwargs: Any) -> dict[str, Any]:
        result = snapshot(directory, name, maximum, **kwargs)
        if directory.path / name in {
            history.lifecycle.ledger_path,
            *history.factory.binaries.values(),
        }:
            result["identity"] = [result["identity"][0] + epoch[0], result["identity"][1]]
        return result

    monkeypatch.setattr(upgrade, "_file_snapshot", projected)
    monkeypatch.setattr(documents, "_descriptor_mount_identity", lambda _fd: 100 + epoch[0])
    return epoch


def _interrupt(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    review: Mapping[str, Any],
    boundary: str,
) -> None:
    write = lifecycle_module._write_private_json

    def interrupted(path: Path, value: Mapping[str, Any], **kwargs: Any) -> None:
        if boundary == "missing" and path == history.lifecycle.bootstrap_record_path:
            raise OSError("fixture interruption before selection")
        write(path, value, **kwargs)
        if (
            boundary == "approved"
            and path.name == "upgrade-pending.json"
            or boundary == "selected"
            and path == history.lifecycle.bootstrap_record_path
            or boundary == "committed"
            and path.name.startswith("upgrade-")
            and path.name != "upgrade-pending.json"
            or boundary == "continuation"
            and path.name.startswith("history-upgrade-continuation-")
            or boundary == "origin"
            and path.name.startswith("history-upgrade-origin-")
        ):
            raise OSError("fixture interruption after publication")

    with monkeypatch.context() as patch:
        patch.setattr(lifecycle_module, "_write_private_json", interrupted)
        with pytest.raises(RunnerLifecycleError):
            history.apply(review)


def _pending(history: _HistoryFixture) -> bytes:
    return (history.lifecycle.control_root / "upgrade-pending.json").read_bytes()


def _assert_authenticated(history: _HistoryFixture, value: dict[str, Any]) -> None:
    enrollment = history.lifecycle._load_enrollment(require_active=True)
    payload = {key: item for key, item in value.items() if key != "authentication"}
    assert value == upgrade._authenticated(enrollment, payload)


@pytest.mark.parametrize("boundary", ["approved", "origin", "missing", "selected", "committed"])
def test_fresh_review_recovers_each_remounted_phase_without_reusing_authority(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    session_identity: list[int],
    boundary: str,
) -> None:
    preserved = _preserved_bytes(history)
    original = history.review()
    assert original["recovery_scope"] == "durable_objects"
    _interrupt(history, monkeypatch, original, boundary)
    pending = _pending(history)
    assert json.loads(pending)["schema_version"] == upgrade.JOURNAL_SCHEMA
    session_identity[0] += 1

    with pytest.raises(RunnerLifecycleError):
        history.apply(original)
    for operation in (history.lifecycle.start, history.lifecycle.stop):
        with pytest.raises(RunnerLifecycleError, match="interrupted"):
            operation(profile_id=PROFILE_ID)
    assert _pending(history) == pending
    refreshed = history.review()
    assert refreshed["recovery_scope"] == "durable_objects"
    assert refreshed["recovery_required"] is True
    assert refreshed["review_digest"] != original["review_digest"]
    assert refreshed["history"]["history_digest"] != original["history"]["history_digest"]
    assert refreshed["history"]["completed_executions"] == 1
    assert refreshed["staging"]["execution_started"] is False
    assert _pending(history) == pending
    result = history.apply(refreshed)

    assert result["state"] == "stopped"
    assert _preserved_bytes(history) == preserved
    assert not (history.lifecycle.control_root / "upgrade-pending.json").exists()
    origins = list(history.lifecycle.control_root.glob("history-upgrade-origin-*.json"))
    assert len(origins) == 1 and origins[0].read_bytes() == pending
    continuations = list(history.lifecycle.control_root.glob("history-upgrade-continuation-*.json"))
    assert len(continuations) == 1
    record = json.loads(continuations[0].read_bytes())
    _assert_authenticated(history, record)
    assert record["original_pending_digest"] == content_hash(json.loads(pending))
    assert record["review_digest"] == refreshed["review_digest"]
    assert record["review"]["continuation"]["previous_review_digest"] == original["review_digest"]


def test_repeated_interruption_preserves_each_review_and_original_pending(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch, session_identity: list[int]
) -> None:
    preserved = _preserved_bytes(history)
    original = history.review()
    _interrupt(history, monkeypatch, original, "approved")
    pending = _pending(history)
    session_identity[0] += 1
    second = history.review()
    _interrupt(history, monkeypatch, second, "continuation")
    assert _pending(history) == pending
    first_records = {
        path: path.read_bytes()
        for path in history.lifecycle.control_root.glob("history-upgrade-*.json")
    }
    session_identity[0] += 1
    with pytest.raises(RunnerLifecycleError):
        history.apply(second)
    third = history.review()
    assert len({original["review_digest"], second["review_digest"], third["review_digest"]}) == 3
    history.apply(third)
    assert all(path.read_bytes() == value for path, value in first_records.items())
    assert (
        len(list(history.lifecycle.control_root.glob("history-upgrade-continuation-*.json"))) == 2
    )
    assert _preserved_bytes(history) == preserved


@pytest.mark.parametrize("boundary", ["origin", "continuation", "missing", "selected", "committed"])
def test_continuation_publication_boundaries_preserve_original_and_require_current_review(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    session_identity: list[int],
    boundary: str,
) -> None:
    preserved = _preserved_bytes(history)
    original = history.review()
    _interrupt(history, monkeypatch, original, "approved")
    original_pending = _pending(history)
    session_identity[0] += 1
    second = history.review()
    _interrupt(history, monkeypatch, second, boundary)
    assert _pending(history) == original_pending
    session_identity[0] += 1
    with pytest.raises(RunnerLifecycleError):
        history.apply(second)
    history.apply(history.review())
    assert _preserved_bytes(history) == preserved
    assert (
        next(history.lifecycle.control_root.glob("history-upgrade-origin-*.json")).read_bytes()
        == original_pending
    )


@pytest.mark.parametrize("swapped", [False, True])
def test_empty_history_binds_real_enrolled_sandbox_for_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped: bool
) -> None:
    factory = _StagedBootstrap()
    lifecycle = ManagedRunnerLifecycle(
        tmp_path / "empty", secret_provider=ProcessTestSecretProvider(), bootstrap_factory=factory
    )
    lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,))
    factory.version = "2.0.0"
    fixture = _HistoryFixture(lifecycle, factory, {}, {}, tmp_path / "unused-result")
    epoch = [1]
    monkeypatch.setattr(documents, "_descriptor_mount_identity", lambda _fd: epoch[0])
    review = fixture.review()
    assert review["history"]["ledger_generation"] is None
    assert review["history"]["total_rows"] == review["history"]["durable_results"] == 0
    _interrupt(fixture, monkeypatch, review, "approved")
    pending = _pending(fixture)
    epoch[0] += 1
    if swapped:
        sandbox = lifecycle.runtime_root / "sandbox"
        sandbox.rename(sandbox.with_name("retained-sandbox"))
        sandbox.mkdir()
        with pytest.raises(RunnerLifecycleError):
            fixture.review()
        assert _pending(fixture) == pending
        return
    with pytest.raises(RunnerLifecycleError):
        fixture.apply(review)
    refreshed = fixture.review()
    assert refreshed["review_digest"] != review["review_digest"]
    assert fixture.apply(refreshed)["state"] == "stopped"
    assert not lifecycle.ledger_path.exists()
    assert (
        next(lifecycle.control_root.glob("history-upgrade-origin-*.json")).read_bytes() == pending
    )


@pytest.mark.parametrize(
    "changed", ["ledger", "result_bytes", "workspace", "old_binary", "receipt", "profile"]
)
def test_changed_preservation_never_gains_fresh_continuation(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    session_identity: list[int],
    changed: str,
) -> None:
    review = history.review()
    _interrupt(history, monkeypatch, review, "approved")
    original_pending = _pending(history)
    session_identity[0] += 1
    if changed == "ledger":
        with sqlite3.connect(history.lifecycle.ledger_path) as connection:
            connection.execute("UPDATE transport_tasks SET updated_at=updated_at+1")
    elif changed == "result_bytes":
        history.result_path.write_bytes(history.result_path.read_bytes() + b" \n")
    elif changed in {"workspace", "old_binary"}:
        target = (
            Path(history.profile["sandbox_root"]) if changed == "workspace" else history.old_binary
        )
        previous = target.with_name(target.name + "-retained")
        target.rename(previous)
        if changed == "workspace":
            target.mkdir()
        else:
            target.write_bytes(previous.read_bytes())
    elif changed == "receipt":
        target = Path(history.profile["sandbox_root"]) / ".bluefire" / "receipts"
        target.mkdir(parents=True, exist_ok=True)
        (target / "unresolved.json").write_bytes(b"{}\n")
    else:
        with pytest.raises(RunnerLifecycleError):
            history.lifecycle.review_upgrade(
                allowed_profile_ids=(PROFILE_ID,), profile_binding="sha256:" + "a" * 64
            )
        assert _pending(history) == original_pending
        return
    changed_bytes = _preserved_bytes(history)
    with pytest.raises(RunnerLifecycleError):
        history.review()
    with pytest.raises(RunnerLifecycleError):
        history.apply(review)
    assert _pending(history) == original_pending
    assert _preserved_bytes(history) == changed_bytes


def test_unknown_durable_identity_keeps_same_session_upgrade_but_refuses_remount(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch, session_identity: list[int]
) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise DurableIdentityUnavailable("unsupported fixture storage")

    monkeypatch.setattr(preservation, "durable_descriptor_identity", unavailable)
    review = history.review()
    assert review["recovery_scope"] == "current_filesystem_session"
    _interrupt(history, monkeypatch, review, "approved")
    original = _pending(history)
    assert history.review()["review_digest"] == review["review_digest"]
    session_identity[0] += 1
    with pytest.raises(RunnerLifecycleError):
        history.review()
    assert _pending(history) == original
    session_identity[0] -= 1
    assert history.apply(history.review())["state"] == "stopped"


def test_v1_pending_record_retains_exact_comparison_and_original_bytes(
    history: _HistoryFixture, session_identity: list[int]
) -> None:
    history.review()  # Stage only the known fixture candidate.
    lifecycle = history.lifecycle
    enrollment = lifecycle._load_enrollment(require_active=True)
    old = upgrade._bootstrap_record_payload(lifecycle._load_bootstrap(enrollment))
    new = lifecycle._validated_bootstrap_payload(
        history.factory(managed_root=lifecycle.runtime_root)
    )
    bound = upgrade._bound_review(
        lifecycle, enrollment, old, new, None, schema=upgrade.LEGACY_JOURNAL_SCHEMA
    )
    assert set(bound) == {
        "schema_version",
        "old",
        "new",
        "enrollment",
        "profiles",
        "profile_binding",
        "history",
    }
    assert set(bound["history"]) == {
        "total_rows",
        "execute_rows",
        "completed_executions",
        "undispatched_executions",
        "durable_results",
        "ledger_generation",
        "history_digest",
    }
    record = upgrade._authenticated(
        enrollment,
        {
            "schema_version": upgrade.LEGACY_JOURNAL_SCHEMA,
            "state": "approved",
            "review_digest": content_hash(bound),
            "review": bound,
        },
    )
    lifecycle._upgrade_io().write(
        lifecycle.control_root / "upgrade-pending.json",
        record,
        maximum=upgrade.MAX_RECORD_BYTES,
        replace=False,
    )
    original = _pending(history)
    public = history.review()
    assert public["review_digest"] == content_hash(bound)
    assert public["recovery_scope"] == "current_filesystem_session"
    session_identity[0] += 1
    with pytest.raises(RunnerLifecycleError):
        history.review()
    with pytest.raises(RunnerLifecycleError):
        history.apply({"review_digest": content_hash(bound)})
    assert _pending(history) == original == canonical_json_bytes(record)


def test_raced_origin_bytes_are_preserved_and_stop_activation(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch, session_identity: list[int]
) -> None:
    original = history.review()
    _interrupt(history, monkeypatch, original, "approved")
    pending = _pending(history)
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    session_identity[0] += 1
    refreshed = history.review()
    write = lifecycle_module._write_private_json
    raced = {}

    def alter_origin(path: Path, value: Mapping[str, Any], **kwargs: Any) -> None:
        write(path, value, **kwargs)
        if path.name.startswith("history-upgrade-origin-"):
            payload = path.read_bytes() + b" \n"
            path.write_bytes(payload)
            raced[path] = payload

    monkeypatch.setattr(lifecycle_module, "_write_private_json", alter_origin)
    with pytest.raises(RunnerLifecycleError):
        history.apply(refreshed)
    assert raced and all(path.read_bytes() == payload for path, payload in raced.items())
    assert _pending(history) == pending
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows FileIdInfo assertion")
def test_actual_windows_durable_identity_is_read_only_and_distinguishes_same_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "owned.bin"
    path.write_bytes(b"owned identity fixture\n")
    before = path.stat()
    descriptor = os.open(path, os.O_RDONLY)
    try:
        first = identity.durable_descriptor_identity(descriptor)
        assert identity.durable_descriptor_identity(descriptor) == first
    finally:
        os.close(descriptor)
    after = path.stat()
    assert (before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_mode,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    assert first["format"] == "windows-file-id-info.v1"
    assert len(first["volume_serial_number"]) == 16 and len(first["file_id"]) == 32
    retained = path.with_name("retained.bin")
    path.rename(retained)
    path.write_bytes(retained.read_bytes())
    descriptor = os.open(path, os.O_RDONLY)
    try:
        second = identity.durable_descriptor_identity(descriptor)
    finally:
        os.close(descriptor)
    assert second["volume_serial_number"] == first["volume_serial_number"]
    assert second["file_id"] != first["file_id"]
    assert path.read_bytes() == retained.read_bytes()
