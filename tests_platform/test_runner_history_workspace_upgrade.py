"""History review binds and checks only the workspaces of authenticated rows."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from bluefire import runner_history_upgrade as upgrade
from bluefire.runner_contracts import seal_manifest, seal_profile
from bluefire.runner_lifecycle import RunnerLifecycleError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_authenticated_runner_transport import _result
from tests_platform.test_runner_history_upgrade import _HistoryFixture, _preserved_bytes
from tests_platform.test_runner_history_upgrade import history as history


def _append_workspace_execution(history: _HistoryFixture, index: int, workspace: Path) -> Path:
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = seal_profile({**history.profile, "sandbox_root": str(workspace)})
    manifest = seal_manifest(
        {
            **history.manifest,
            "run_id": "run-20260825T120000Z-" + f"{index:016x}",
            "policy_digest": profile["policy_digest"],
            "approval": {
                "approved_by": "history fixture reviewer",
                "approved_at": history.manifest["requested_at"],
                "expires_at": history.manifest["expires_at"],
                "request_hash": "",
            },
        }
    )
    payload = {"manifest": manifest, "profile": profile}
    request_hash = content_hash(payload)
    task_id = "execute-" + request_hash.removeprefix("sha256:")
    result = _result(manifest, profile)
    with sqlite3.connect(history.lifecycle.ledger_path) as connection:
        connection.row_factory = sqlite3.Row
        row = dict(connection.execute("SELECT * FROM transport_tasks LIMIT 1").fetchone())
        row.update(
            task_id=task_id,
            nonce=f"{index + 10001:064x}",
            request_hash=request_hash,
            execute_payload_json=canonical_json_bytes(payload),
            result_json=canonical_json_bytes({"result": result}),
        )
        columns = list(row)
        connection.execute(
            "INSERT INTO transport_tasks ("
            + ",".join(columns)
            + ") VALUES ("
            + ",".join("?" for _ in columns)
            + ")",
            tuple(row.values()),
        )
    filename = hashlib.sha256(task_id.encode()).hexdigest()[:40] + ".json"
    result_path = history.result_path.with_name(filename)
    result_path.write_bytes(canonical_json_bytes(result))
    return result_path


def _workspace(history: _HistoryFixture, index: int) -> Path:
    return (
        history.lifecycle.runtime_root
        / "sandbox"
        / ".bluefire-executions"
        / ("approval-" + f"{index:032x}")
    )


def test_review_rechecks_each_distinct_workspace_and_keeps_paths_private(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = _workspace(history, 1), _workspace(history, 2)
    paths = [
        _append_workspace_execution(history, 1, first),
        _append_workspace_execution(history, 2, second),
        _append_workspace_execution(history, 3, first),
    ]
    before = {**_preserved_bytes(history), **{path: path.read_bytes() for path in paths}}
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    inspect = history.lifecycle._require_no_receipt_obligations
    checked = []

    def observed(path: Path) -> None:
        checked.append(path)
        inspect(path)

    monkeypatch.setattr(history.lifecycle, "_require_no_receipt_obligations", observed)
    review = history.review()

    assert checked.count(first) == checked.count(second) == 2
    assert review["history"]["completed_executions"] == 4
    assert review["history"]["durable_results"] == 4
    assert all(str(path) not in json.dumps(review) for path in (first, second))
    assert "workspaces" not in review["history"]
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("namespace", ["receipts", "receipt-commits"])
def test_isolated_workspace_cleanup_obligation_blocks_review_without_removal(
    history: _HistoryFixture, namespace: str
) -> None:
    workspace = _workspace(history, 1)
    _append_workspace_execution(history, 1, workspace)
    marker = workspace / ".bluefire" / namespace / "retained.json"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b'{"fixture":"unresolved cleanup"}')
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    before = _preserved_bytes(history)

    with pytest.raises(RunnerLifecycleError):
        history.review()

    assert marker.read_bytes() == b'{"fixture":"unresolved cleanup"}'
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == before


def test_receipt_arriving_in_an_existing_nested_directory_blocks_final_review(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(history, 1)
    _append_workspace_execution(history, 1, workspace)
    marker = workspace / ".bluefire" / "receipts" / "late.json"
    marker.parent.mkdir(parents=True)
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    decode = upgrade._decode_durable_json_object
    calls = []

    def arrival(raw: bytes) -> dict[str, Any]:
        if not calls:
            marker.write_bytes(b"late cleanup obligation")
            calls.append(True)
        return decode(raw)

    monkeypatch.setattr(upgrade, "_decode_durable_json_object", arrival)
    with pytest.raises(RunnerLifecycleError):
        history.review()

    assert calls == [True]
    assert marker.read_bytes() == b"late cleanup obligation"
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert not (history.lifecycle.control_root / "upgrade-pending.json").exists()


def test_workspace_replacement_invalidates_the_reviewed_transition(
    history: _HistoryFixture,
) -> None:
    workspace = _workspace(history, 1)
    _append_workspace_execution(history, 1, workspace)
    review = history.review()
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    before = _preserved_bytes(history)
    preserved = workspace.with_name(workspace.name + "-preserved")
    workspace.rename(preserved)
    workspace.mkdir(mode=0o700)

    with pytest.raises(RunnerLifecycleError):
        history.apply(review)

    assert preserved.is_dir() and workspace.is_dir()
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == before


def test_workspace_changed_during_receipt_inspection_is_refused(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(history, 1)
    _append_workspace_execution(history, 1, workspace)
    inspect = history.lifecycle._require_no_receipt_obligations
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    preserved = workspace.with_name(workspace.name + "-preserved")
    changed = []

    def raced(path: Path) -> None:
        inspect(path)
        if path == workspace and not changed:
            workspace.rename(preserved)
            workspace.mkdir(mode=0o700)
            changed.append(True)

    monkeypatch.setattr(history.lifecycle, "_require_no_receipt_obligations", raced)
    with pytest.raises(RunnerLifecycleError):
        history.review()

    assert changed == [True] and preserved.is_dir()
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap


def test_reviewed_workspace_upgrade_preserves_history_and_completed_results(
    history: _HistoryFixture,
) -> None:
    workspace = _workspace(history, 1)
    result_path = _append_workspace_execution(history, 1, workspace)
    before = {**_preserved_bytes(history), result_path: result_path.read_bytes()}
    result = history.apply(history.review())
    assert result["runner"]["runner_version"] == "2.0.0"
    assert all(path.read_bytes() == raw for path, raw in before.items())
