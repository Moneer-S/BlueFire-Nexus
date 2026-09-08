from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.service import BlueFireService


def service_at(root: Path, database: str = "product.sqlite") -> BlueFireService:
    # Real storage and synchronization, without constructing runner/provider services.
    service = BlueFireService.__new__(BlueFireService)
    service.store = RunStore(root / "runs")
    service.product_store = ProductStore(root / database)
    return service


def recorded(service: BlueFireService, mode: str = "simulate") -> str:
    handle = service.store.create_run(
        scenario={"id": "index-fixture.v1", "title": "Index fixture"},
        plan={},
        policy={},
        profile={},
    )
    service.store.finalize(
        handle.run_id,
        result={
            "scenario_id": "index-fixture.v1",
            "mode": mode,
            "status": "completed",
            "steps": [],
            # Synthetic conflicting claims must never become digest authority.
            "bundle_digest": "sha256:" + "0" * 64,
            "manifest": {"bundle_hash": "sha256:" + "1" * 64},
        },
        evidence=[],
        detections=[],
    )
    return handle.run_id


def exact_files(service: BlueFireService, run_id: str) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in (service.store.root / run_id).iterdir()
        if path.is_file()
    }


def assert_index_digest(service: BlueFireService, run_id: str, digest: str | None) -> None:
    rows = service.product_store.list_runs()
    row = next(item for item in rows if item["run_id"] == run_id)
    assert row.get("bundle_digest") == digest
    with sqlite3.connect(service.product_store.path) as connection:
        sql_digest, summary = connection.execute(
            "SELECT bundle_digest, summary_json FROM run_index WHERE run_id = ?", (run_id,)
        ).fetchone()
    assert sql_digest == digest
    assert json.loads(summary) == row


@pytest.mark.parametrize("mode", ["simulate", "execute"])
def test_restart_and_empty_index_rebuild_preserve_validated_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service, mode)
    result = service.store.get_run(run_id)
    digest = result["manifest"]["bundle_hash"]
    service._index_run(result)
    assert_index_digest(service, run_id, digest)
    before = exact_files(service, run_id)

    def no_event_hydration(*args: object, **kwargs: object) -> None:
        pytest.fail("index synchronization must not hydrate event streams or full run details")

    for database in ("product.sqlite", "rebuilt.sqlite"):
        reopened = service_at(tmp_path, database)
        monkeypatch.setattr(reopened.store, "get_run", no_event_hydration)
        monkeypatch.setattr(reopened.store, "read_events", no_event_hydration)
        summary = reopened.store.list_runs()[0]
        assert summary["bundle_digest"] == digest
        assert "manifest" not in summary
        reopened._synchronize_run_index()
        assert_index_digest(reopened, run_id, digest)
        assert exact_files(reopened, run_id) == before


@pytest.mark.parametrize("damage", ["corrupt-result", "corrupt-manifest", "unsealed"])
def test_invalid_finalization_cannot_seed_a_digest_claim(tmp_path: Path, damage: str) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service)
    directory = service.store.root / run_id
    if damage == "corrupt-result":
        result = dict(service.store.read_json(run_id, "result.json"))
        result["status"] = "failed"
        (directory / "result.json").write_text(json.dumps(result), encoding="utf-8")
    elif damage == "corrupt-manifest":
        manifest = dict(service.store.read_json(run_id, "manifest.json"))
        manifest["bundle_hash"] = "sha256:" + "2" * 64
        (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    else:
        (directory / "manifest.json").unlink()
    before = exact_files(service, run_id)

    summary = service.store.list_runs()[0]
    assert summary["status"] == ("interrupted" if damage == "unsealed" else "corrupted")
    assert "bundle_digest" not in summary
    assert "manifest" not in summary
    service._synchronize_run_index()
    assert service.product_store.list_runs() == []
    assert exact_files(service, run_id) == before


@pytest.mark.parametrize("status", ["created", "interrupted"])
def test_legacy_unsealed_summaries_keep_nullable_digest_without_trusting_claims(
    tmp_path: Path, status: str
) -> None:
    service = service_at(tmp_path)
    handle = service.store.create_run(scenario={"id": "legacy.v1"}, plan={}, policy={}, profile={})
    result = dict(service.store.read_json(handle.run_id, "result.json"))
    result.update(
        scenario_id="legacy.v1",
        mode="simulate",
        status=status,
        bundle_digest="sha256:" + "3" * 64,
        manifest={"bundle_hash": "sha256:" + "4" * 64},
    )
    service.store.write_json(handle.run_id, "result.json", result)
    before = exact_files(service, handle.run_id)

    summary = service.store.list_runs()[0]
    assert summary["status"] == status
    assert "bundle_digest" not in summary
    assert "manifest" not in summary
    service._synchronize_run_index()
    assert_index_digest(service, handle.run_id, None)
    assert exact_files(service, handle.run_id) == before


def test_full_manifest_remains_authoritative_over_summary_digest(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service)
    result = service.store.get_run(run_id)
    service._index_run(result, validated_bundle_digest="sha256:" + "5" * 64)
    assert_index_digest(service, run_id, result["manifest"]["bundle_hash"])
