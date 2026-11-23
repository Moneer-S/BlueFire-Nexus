from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

import bluefire.run_bundle_export as exporter
from bluefire.run_store import RunStore, RunStoreError
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash, file_hash
from tests_platform.test_api import StubService, request, running_server


def finalized(tmp_path: Path) -> tuple[RunStore, str]:
    store = RunStore(tmp_path / "runs")
    handle = store.create_run(scenario={}, plan={}, policy={}, profile={})
    store.finalize(
        handle.run_id,
        result={"mode": "simulate", "status": "cancelled"},
        evidence=[],
        detections=[],
    )
    return store, handle.run_id


def test_exact_bytes_all_events_and_recovery_roundtrip(tmp_path):
    store, run_id = finalized(tmp_path)
    # Build a valid large chain directly; append_event would reread it on each append.
    previous = None
    rows = []
    for sequence in range(1, 10_005):
        body = {
            "schema_version": "1.0",
            "sequence": sequence,
            "previous_event_hash": previous,
            "event_type": "test.event",
            "data": {},
            "timestamp": "2026-09-06T00:00:00Z",
        }
        previous = content_hash(body)
        rows.append(canonical_json_bytes({**body, "event_hash": previous}) + b"\n")
    events = store.root / run_id / "events.jsonl"
    events.write_bytes(b"".join(rows))
    manifest = dict(store.read_json(run_id, "manifest.json"))
    manifest["files"]["events.jsonl"] = {
        "hash": file_hash(events),
        "size_bytes": events.stat().st_size,
    }
    manifest["bundle_hash"] = content_hash(manifest["files"])
    store.write_json(run_id, "manifest.json", manifest)
    recovery = store.append_recovery_record(
        run_id, {"success": True, "outstanding_receipt_count": 0}
    )
    assert len(store.get_run(run_id)["events"]) == 10_000
    blob = exporter.export_run_bundle(store, run_id)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        expected = {
            f"{run_id}/{path.relative_to(store.root / run_id).as_posix()}": path.read_bytes()
            for path in (store.root / run_id).rglob("*")
            if path.is_file()
        }
        assert set(archive.namelist()) == set(expected)
        assert all(archive.read(name) == payload for name, payload in expected.items())
        assert archive.read(f"{run_id}/events.jsonl") == b"".join(rows)
        archive.extractall(tmp_path / "imported")
    imported = RunStore(tmp_path / "imported")
    assert imported.validate_bundle(run_id)["valid"]
    assert imported.read_recovery_records(run_id) == [recovery]


@pytest.mark.parametrize(
    "mutation",
    ["tamper", "path", "staging", "unsealed", "unfinished", "recovery", "oversize", "hardlink"],
)
def test_refuses_unsafe_or_incomplete_snapshot(tmp_path, monkeypatch, mutation):
    store, run_id = finalized(tmp_path)
    root = store.root / run_id
    if mutation == "tamper":
        (root / "scenario.json").write_bytes(b'{"changed":true}\n')
    elif mutation == "path":
        manifest = dict(store.read_json(run_id, "manifest.json"))
        manifest["files"]["../outside.json"] = manifest["files"].pop("scenario.json")
        manifest["bundle_hash"] = content_hash(manifest["files"])
        store.write_json(run_id, "manifest.json", manifest)
    elif mutation == "staging":
        (root / ".recovery-tmp-private").mkdir()
    elif mutation == "unsealed":
        (root / "manifest.json").unlink()
    elif mutation == "unfinished":
        store, handle = RunStore(tmp_path / "unfinished"), None
        handle = store.create_run(scenario={}, plan={}, policy={}, profile={})
        run_id = handle.run_id
    elif mutation == "recovery":
        record = store.append_recovery_record(run_id, {"success": False})
        (root / record["recovery_id"] / "record.json").write_text("{}")
    elif mutation == "oversize":
        monkeypatch.setattr(exporter, "MAX_FILE_BYTES", 8)
    elif mutation == "hardlink":
        os.link(root / "scenario.json", tmp_path / "linked")
    with pytest.raises(RunStoreError):
        exporter.export_run_bundle(store, run_id)


def test_snapshot_change_during_read_refuses(tmp_path, monkeypatch):
    store, run_id = finalized(tmp_path)
    original = exporter._read

    def change(path, expected):
        result = original(path, expected)
        if path.name == "scenario.json":
            path.write_bytes(b"{} ")
        return result

    monkeypatch.setattr(exporter, "_read", change)
    with pytest.raises(RunStoreError, match="changed"):
        exporter.export_run_bundle(store, run_id)


def test_actual_captured_bytes_are_hashed(tmp_path, monkeypatch):
    store, run_id = finalized(tmp_path)
    original = exporter._read
    monkeypatch.setattr(
        exporter,
        "_read",
        lambda path, expected: (
            b"[]\n" if path.name == "scenario.json" else original(path, expected)
        ),
    )
    with pytest.raises(RunStoreError, match="integrity"):
        exporter.export_run_bundle(store, run_id)


def test_bundle_api_guards_and_binary_response(tmp_path):
    store, run_id = finalized(tmp_path)

    class Service(StubService):
        def run_bundle(self, requested):
            self.calls.append(("run_bundle", requested))
            return BlueFireService.run_bundle(self, requested)

    service = Service()
    service.store = store
    path = f"/api/v1/runs/{run_id}/bundle"
    with running_server(service) as (server, _):
        status, headers, payload = request(server, "GET", path)
        assert status == 200 and headers["Content-Type"] == "application/zip"
        assert headers["Content-Disposition"] == f'attachment; filename="{run_id}.zip"'
        assert headers["Cache-Control"] == "no-store"
        assert zipfile.is_zipfile(io.BytesIO(payload))
        assert len(service.calls) == 1
        for method in ("POST", "HEAD", "PUT", "DELETE", "OPTIONS"):
            assert request(server, method, path, body={} if method == "POST" else None)[0] == 405
        assert request(server, "GET", path, authenticated=False)[0] == 401
        assert request(server, "GET", path + "?output=/tmp/result.zip")[0] == 400
        assert request(server, "GET", "/api/v1/runs/invalid/bundle")[0] == 400
        assert request(server, "POST", path, body={}, origin="http://evil.test")[0] == 403
        assert len(service.calls) == 1


def test_bounded_total_and_count(tmp_path, monkeypatch):
    store, run_id = finalized(tmp_path)
    monkeypatch.setattr(exporter, "MAX_TOTAL_BYTES", 10)
    with pytest.raises(RunStoreError, match="limit"):
        exporter.export_run_bundle(store, run_id)
    monkeypatch.setattr(exporter, "MAX_TOTAL_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(exporter, "MAX_FILES", 8)
    with pytest.raises(RunStoreError, match="limit"):
        exporter.export_run_bundle(store, run_id)


def test_links_and_reparse_points_are_refused(tmp_path, monkeypatch):
    store, run_id = finalized(tmp_path)
    original = Path.lstat
    from types import SimpleNamespace

    def reparse(path):
        value = original(path)
        if path.name == "scenario.json":
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
        return value

    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(RunStoreError, match="unsafe"):
        exporter.export_run_bundle(store, run_id)


def test_unavailable_bundle_has_typed_http_error(tmp_path):
    store, run_id = finalized(tmp_path)
    (store.root / run_id / "manifest.json").unlink()

    class Service(StubService):
        run_bundle = BlueFireService.run_bundle

    service = Service()
    service.store = store
    with running_server(service) as (server, _):
        status, _, payload = request(server, "GET", f"/api/v1/runs/{run_id}/bundle")
        assert status == 409
        assert b'"code":"run_bundle_unavailable"' in payload
        assert str(tmp_path).encode() not in payload
