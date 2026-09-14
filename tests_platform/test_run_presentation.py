from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from bluefire.application_errors import APIError
from bluefire.product_store import ProductStore
from bluefire.product_store_run_presentation import KIND, presentation
from bluefire.run_store import RunStore
from bluefire.service import BlueFireService
from tests_platform.test_api import request, running_server


def service_at(root: Path) -> BlueFireService:
    # Exercise real read/management methods without constructing any runner/provider.
    service = BlueFireService.__new__(BlueFireService)
    service.store = RunStore(root / "runs")
    service.product_store = ProductStore(root / "product.sqlite")
    return service


def recorded(service: BlueFireService, title: str = "File collection") -> str:
    scenario = {"id": "collection.v1", "title": title}
    handle = service.store.create_run(scenario=scenario, plan={}, policy={}, profile={})
    service.store.finalize(
        handle.run_id,
        result={
            "scenario_id": scenario["id"],
            "mode": "simulate",
            "status": "cancelled",
            "steps": [],
        },
        evidence=[],
        detections=[],
    )
    return handle.run_id


def bundle_files(service: BlueFireService, run_id: str) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(service.run_bundle(run_id))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_rename_reset_and_restart_preserve_exact_canonical_bundle(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service)
    before = service.store.get_run(run_id)
    files = bundle_files(service, run_id)
    assert service.detail(run_id)["presentation"]["default_name"] == "File collection"
    renamed = service.rename_run(run_id, {"display_name": "  Collection check — café  "})
    assert renamed["display_name"] == "Collection check — café"
    assert renamed["run_id"] == run_id
    assert renamed["updated_at"]
    assert service.list()["runs"][0]["presentation"] == renamed

    reopened = service_at(tmp_path)
    reopened._synchronize_run_index()
    assert reopened.detail(run_id)["presentation"] == renamed
    assert reopened.store.get_run(run_id) == before
    assert bundle_files(reopened, run_id) == files
    reset = reopened.rename_run(run_id, {"display_name": None})
    assert reset["display_name"] is None
    assert reset["default_name"] == "File collection"
    assert service_at(tmp_path).list()["runs"][0]["presentation"] == reset
    assert bundle_files(reopened, run_id) == files
    assert reopened.store.validate_bundle(run_id)["valid"] is True


def test_duplicate_names_do_not_merge_runs_or_invent_roles(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    first, second = recorded(service), recorded(service)
    for identifier in (first, second):
        service.rename_run(identifier, {"display_name": "Same name"})
    names = {run["run_id"]: run["presentation"] for run in service.list()["runs"]}
    assert set(names) == {first, second}
    assert all(item["default_name"] == "File collection" for item in names.values())
    assert all(item["display_name"] == "Same name" for item in names.values())


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "x" * 121,
        "line\nname",
        "\tname",
        "name\x00",
        "name\x7f",
        "a\u202eb",
        3,
        True,
        [],
        {},
    ],
)
def test_invalid_names_never_write_presentation(tmp_path: Path, value: object) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service)
    with pytest.raises(APIError) as failure:
        service.rename_run(run_id, {"display_name": value})
    assert failure.value.code == "run_name_invalid"
    assert service.product_store.list_resources(KIND) == []


def test_unknown_run_and_sensitive_or_extra_fields_cannot_create_metadata(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    with pytest.raises(APIError, match="Run was not found"):
        service.rename_run("run-20260908T120000Z-0123456789abcdef", {"display_name": "Missing"})
    run_id = recorded(service)
    for payload in (
        {},
        {"display_name": "Okay", "status": "completed"},
        # Synthetic credential shape exercises the real sensitive-value refusal.
        {"display_name": "sk-" + "0" * 36},
    ):
        with pytest.raises(APIError):
            service.rename_run(run_id, payload)
    assert service.product_store.list_resources(KIND) == []
    assert service.rename_run(run_id, {"display_name": "a" * 120})["display_name"] == "a" * 120


def test_names_use_frozen_procedure_and_missing_provenance_is_neutral() -> None:
    assert (
        presentation({"run_id": "id", "scenario_title": "Original procedure"})["default_name"]
        == "Original procedure"
    )
    assert (
        presentation({"run_id": "id", "status": "completed", "scenario_id": "internal.v1"})[
            "default_name"
        ]
        == "Run"
    )
    assert (
        presentation({"run_id": "id", "objective": "Collect selected files\n" * 30})["default_name"]
        == "Run"
    )


def test_http_rename_preserves_browser_authorization_and_run_binding(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    run_id = recorded(service)
    with running_server(service) as (server, _):
        path = f"/api/v1/runs/{run_id}/presentation"
        for kwargs in ({"authenticated": False}, {"origin": "https://unrelated.invalid"}):
            status, _, _ = request(server, "POST", path, body={"display_name": "Refused"}, **kwargs)
            assert status in {401, 403}
        assert service.product_store.list_resources(KIND) == []
        status, _, body = request(
            server, "POST", path, body={"display_name": "Reviewed collection"}
        )
        assert status == 200
        expected = json.loads(body)
        for endpoint in (f"/api/v1/runs/{run_id}", "/api/v1/runs"):
            status, _, body = request(server, "GET", endpoint)
            assert status == 200
            result = json.loads(body)
            assert (result.get("runs", [result])[0])["presentation"] == expected
        status, _, _ = request(
            server, "POST", path + "?unexpected=1", body={"display_name": "Refused"}
        )
        assert status == 400
        status, _, _ = request(
            server, "POST", "/api/v1/runs/invalid/presentation", body={"display_name": "Refused"}
        )
        assert status == 400
        assert service.detail(run_id)["presentation"] == expected
