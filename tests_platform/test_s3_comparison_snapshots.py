"""Durable saved snapshots for the bounded run-comparison API."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from bluefire import run_store
from bluefire import service as service_module
from bluefire.application_errors import APIError
from bluefire.product_store_errors import ProductStoreError
from tests_platform.test_api import json_body, request, running_server
from tests_platform.test_s3_comparison import (
    comparison_service,
    generic_run,
    journey,
)
from tests_platform.test_s3_comparison import (
    stable_identities as stable_identities,
)


def test_api_creates_and_reopens_immutable_snapshot(tmp_path, stable_identities):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)
        with running_server(app) as (server, _):
            status, _, raw = request(
                server, "POST", "/api/v1/comparisons", body={"run_ids": run_ids}
            )
            assert status == 200
            created = json_body(raw)
            metadata = created["saved_snapshot"]
            assert set(metadata) == {"snapshot_id", "digest", "created_at"}

            status, _, raw = request(server, "GET", "/api/v1/comparison-snapshots")
            assert status == 200
            listing = json_body(raw)["snapshots"]
            assert listing == [
                {
                    **metadata,
                    "run_ids": run_ids,
                    "baseline_run_id": run_ids[0],
                }
            ]

            status, _, raw = request(
                server,
                "GET",
                f"/api/v1/comparison-snapshots/{metadata['snapshot_id']}",
            )
            assert status == 200
            reopened = json_body(raw)
            assert reopened["comparison"] == {
                key: value for key, value in created.items() if key != "saved_snapshot"
            }
            assert reopened["source_integrity"] == {
                "status": "verified",
                "runs": [{"run_id": run_id, "status": "verified"} for run_id in run_ids],
            }
            assert [row["run_id"] for row in reopened["source_bindings"]] == run_ids


def test_snapshot_creation_is_idempotent_and_generic_resource_write_is_refused(
    tmp_path, stable_identities
):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)
        first = app.compare({"run_ids": run_ids})
        second = app.compare({"run_ids": run_ids})
        assert first["saved_snapshot"] == second["saved_snapshot"]
        assert len(app.comparison_snapshots()["snapshots"]) == 1
        assert app.product_store.list_resources("comparison") == []
        with pytest.raises(ProductStoreError, match="immutable"):
            app.product_store.save_resource(
                "comparison",
                first["saved_snapshot"]["snapshot_id"],
                {"schema_version": "bluefire.saved-run-comparison.v1"},
            )
        with pytest.raises(ProductStoreError, match="immutable"):
            app.product_store.save_resource(
                "comparison",
                "forged-comparison",
                {"schema_version": "bluefire.saved-run-comparison.v1"},
            )


def test_non_s3_simulated_comparison_snapshot_reopens_idempotently_without_mutating_runs(
    tmp_path, stable_identities
):
    with comparison_service(tmp_path) as (app, _executor):
        run_ids = [generic_run(app.store), generic_run(app.store)]
        original_runs = [deepcopy(app.store.get_run(run_id)) for run_id in run_ids]

        first = app.compare({"run_ids": run_ids})
        saved = first["saved_snapshot"]
        assert "s3_access" not in first

        reopened = app.comparison_snapshot(saved["snapshot_id"])
        second = app.compare({"run_ids": run_ids})

        assert second["saved_snapshot"] == saved
        assert len(app.comparison_snapshots()["snapshots"]) == 1
        assert reopened["comparison"] == {
            key: value for key, value in first.items() if key != "saved_snapshot"
        }
        assert "s3_access" not in reopened["comparison"]
        assert reopened["source_integrity"]["status"] == "verified"
        assert [app.store.get_run(run_id) for run_id in run_ids] == original_runs


@pytest.mark.parametrize("source_state,expected", [("changed", "changed"), ("missing", "missing")])
def test_reopen_preserves_snapshot_and_reports_unavailable_source(
    tmp_path, stable_identities, monkeypatch, source_state, expected
):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)
        created = app.compare({"run_ids": run_ids})["saved_snapshot"]
        original = app.store.validate_bundle
        target = run_ids[0]

        def unavailable(run_id):
            if run_id == target and source_state == "missing":
                raise run_store.RunStoreError(f"unknown run: {run_id}")
            integrity = original(run_id)
            if run_id == target and source_state == "changed":
                manifest = dict(integrity["manifest"], bundle_hash="sha256:" + "a" * 64)
                return {**integrity, "manifest": manifest}
            return integrity

        monkeypatch.setattr(app.store, "validate_bundle", unavailable)
        reopened = app.comparison_snapshot(created["snapshot_id"])
        assert reopened["source_integrity"]["status"] == "unavailable"
        assert reopened["source_integrity"]["runs"] == [
            {"run_id": run_id, "status": expected if run_id == target else "verified"}
            for run_id in run_ids
        ]
        assert reopened["comparison"]["run_ids"] == run_ids


@pytest.mark.parametrize("corruption", ["baseline", "nan", "surrogate"])
def test_tampered_saved_comparison_is_rejected(tmp_path, stable_identities, corruption):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)
        saved = app.compare({"run_ids": run_ids})["saved_snapshot"]
        resource = app.product_store.get_resource("comparison", saved["snapshot_id"])
        document = deepcopy(resource["document"])
        if corruption == "baseline":
            document["comparison"]["baseline_run_id"] = run_ids[1]
        elif corruption == "nan":
            document["comparison"]["summaries"][0]["duration_ms"] = float("nan")
        else:
            document["comparison"]["summaries"][0]["first_blocked_step"] = "\ud800"
        with app.product_store._connection(write=True) as connection:
            connection.execute(
                "UPDATE resources SET document_json = ? WHERE kind = 'comparison' AND resource_id = ?",
                (json.dumps(document), saved["snapshot_id"]),
            )
        with pytest.raises(APIError) as error:
            app.comparison_snapshot(saved["snapshot_id"])
        assert error.value.code == "comparison_snapshot_invalid"


def test_source_bundle_change_during_capture_refuses_snapshot(
    tmp_path, stable_identities, monkeypatch
):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)
        original_compare = service_module.compare_runs
        original_validate = app.store.validate_bundle

        def change_after_compare(store, selected, *, s3_access=None):
            comparison = original_compare(store, selected, s3_access=s3_access)

            def changed(run_id):
                integrity = original_validate(run_id)
                if run_id == run_ids[0]:
                    manifest = dict(integrity["manifest"], bundle_hash="sha256:" + "b" * 64)
                    return {**integrity, "manifest": manifest}
                return integrity

            monkeypatch.setattr(store, "validate_bundle", changed)
            return comparison

        monkeypatch.setattr(service_module, "compare_runs", change_after_compare)
        with pytest.raises(APIError) as error:
            app.compare({"run_ids": run_ids})
        assert error.value.code == "comparison_source_changed"
        assert app.comparison_snapshots()["snapshots"] == []


def test_bundle_read_race_is_reported_as_comparison_error(tmp_path, stable_identities, monkeypatch):
    with comparison_service(tmp_path) as (app, executor):
        _, _, run_ids = journey(app, executor)

        def unreadable(_run_id):
            raise OSError("private filesystem detail")

        monkeypatch.setattr(app.store, "validate_bundle", unreadable)
        with pytest.raises(APIError) as error:
            app.compare({"run_ids": run_ids})
        assert error.value.code == "comparison_invalid"
        assert app.comparison_snapshots()["snapshots"] == []
