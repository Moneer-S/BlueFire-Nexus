"""Generated-run checks for separately verified composition objectives."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import comparison_snapshot_store, composition_comparison
from bluefire import service as service_module
from bluefire.application_errors import APIError
from bluefire.capability_grant import objective_result
from bluefire.capability_packs import RECEIVER_PACK
from bluefire.comparison import ComparisonError, compare_runs
from bluefire.composition_comparison import projections
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore
from bluefire.util import content_hash
from tests_platform.test_capability_composition import state as state
from tests_platform.test_product_store_capability_grants import reserve, unused
from tests_platform.test_product_store_capability_grants import saved as saved

_PROJECTION_SCHEMA = "bluefire.composition-objective-projection.v1"
_PREDICATE = content_hash(
    {
        "kind": "redacted_delivery_preserves_records",
        "record_count": 8,
        "data_class": "generated_public_jsonl",
    }
)
_OTHER_PREDICATE = content_hash(
    {
        "kind": "redacted_delivery_preserves_records",
        "record_count": 7,
        "data_class": "generated_public_jsonl",
    }
)


def _run(store: RunStore, *, graph_reached: bool) -> str:
    """Finalize only generated run evidence; no runner or target is contacted."""
    handle = store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "scenario.composed-test.v1"},
        plan={"schema_version": "bluefire.plan.v1", "steps": []},
        policy={"schema_version": "bluefire.run-policy.v1"},
        profile=None,
    )
    store.finalize(
        handle.run_id,
        result={
            "schema_version": "bluefire.run-result.v1",
            "status": "completed" if graph_reached else "incomplete",
            "mode": "execute",
            "scenario_id": "scenario.composed-test.v1",
            "objective_reached": graph_reached,
            "autonomy": "off",
            "steps": [
                {
                    "step_id": "clean",
                    "status": "success",
                    "policy": {"status": "allowed"},
                }
            ],
        },
        evidence=[],
        detections=[],
    )
    return handle.run_id


def _projection(
    run_id: str,
    number: int,
    *,
    established: bool | None,
    state: str = "verified",
    objective_digest: str = _PREDICATE,
) -> dict[str, object]:
    return {
        "schema_version": _PROJECTION_SCHEMA,
        "run_id": run_id,
        "attempt_id": f"attempt-{number:032x}",
        "state": state,
        "objective_digest": objective_digest,
        "established": established,
        "result_digest": (
            content_hash({"run_id": run_id, "established": established})
            if state == "verified"
            else None
        ),
    }


def test_verified_composition_result_overrides_graph_completion_without_erasing_it(
    tmp_path: Path,
    state,
) -> None:
    store = RunStore(tmp_path / "runs")
    refused = _run(store, graph_reached=True)
    accepted = _run(store, graph_reached=True)
    receiver_result = {
        "receiver_verified": True,
        "policy_digest": state["grant"]["environment"]["policy_digest"],
        "data_class": "generated_public_jsonl",
        "record_count": 8,
        "redacted_record_count": 0,
        "retained_record_count": 8,
        "empty_record_count": 0,
        "decision": "policy_refused",
        "run_cleanup": "complete",
        "receiver_cleanup": "verified_closed",
    }
    refused_objective = objective_result(state["grant"], receiver_result)
    accepted_objective = objective_result(
        state["grant"],
        {
            **receiver_result,
            "redacted_record_count": 8,
            "retained_record_count": 0,
            "decision": "accepted",
        },
    )
    assert refused_objective["established"] is False
    assert accepted_objective["established"] is True

    comparison = compare_runs(
        store,
        [refused, accepted],
        capability_objectives={
            refused: _projection(refused, 1, established=refused_objective["established"]),
            accepted: _projection(accepted, 2, established=accepted_objective["established"]),
        },
    )

    assert [item["graph_objective_reached"] for item in comparison["summaries"]] == [
        True,
        True,
    ]
    assert [item["objective_reached"] for item in comparison["summaries"]] == [False, True]
    assert "objective_recovered" in comparison["deltas"][0]["signals"]
    assert "objective_regressed" not in comparison["deltas"][0]["signals"]
    assert comparison["deltas"][0]["objective_changed"] is True


def test_verified_same_predicate_regression_uses_composition_result(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    accepted = _run(store, graph_reached=True)
    refused = _run(store, graph_reached=True)

    comparison = compare_runs(
        store,
        [accepted, refused],
        capability_objectives={
            accepted: _projection(accepted, 1, established=True),
            refused: _projection(refused, 2, established=False),
        },
    )

    assert [item["objective_reached"] for item in comparison["summaries"]] == [True, False]
    assert "objective_regressed" in comparison["deltas"][0]["signals"]
    assert "objective_recovered" not in comparison["deltas"][0]["signals"]


@pytest.mark.parametrize("comparison_kind", ["mixed", "different_predicate", "unverified"])
def test_noncomparable_capability_results_do_not_claim_objective_change(
    tmp_path: Path, comparison_kind: str
) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(store, graph_reached=False)
    candidate = _run(store, graph_reached=True)
    projections = {baseline: _projection(baseline, 1, established=False)}
    if comparison_kind == "different_predicate":
        projections[candidate] = _projection(
            candidate, 2, established=True, objective_digest=_OTHER_PREDICATE
        )
    elif comparison_kind == "unverified":
        projections[candidate] = _projection(candidate, 2, established=None, state="unverified")

    comparison = compare_runs(
        store,
        [baseline, candidate],
        capability_objectives=projections,
    )
    delta = comparison["deltas"][0]

    assert [item["graph_objective_reached"] for item in comparison["summaries"]] == [
        False,
        True,
    ]
    if comparison_kind == "unverified":
        assert comparison["summaries"][1]["objective_reached"] is None
    assert "objective_recovered" not in delta["signals"]
    assert "objective_regressed" not in delta["signals"]
    assert delta["objective_changed"] is False


def test_ordinary_run_objective_comparison_remains_unchanged(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(store, graph_reached=False)
    candidate = _run(store, graph_reached=True)

    comparison = compare_runs(store, [baseline, candidate])
    empty_projection = compare_runs(store, [baseline, candidate], capability_objectives={})

    assert [item["objective_reached"] for item in comparison["summaries"]] == [False, True]
    assert [item["objective_reached"] for item in empty_projection["summaries"]] == [
        False,
        True,
    ]
    assert comparison["deltas"][0]["objective_changed"] is True
    assert empty_projection["deltas"][0]["objective_changed"] is True
    assert "objective_recovered" in comparison["deltas"][0]["signals"]
    assert "objective_recovered" in empty_projection["deltas"][0]["signals"]


def test_projection_must_bind_the_requested_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    baseline = _run(store, graph_reached=True)
    candidate = _run(store, graph_reached=True)
    forged = _projection("run-another", 1, established=True)

    with pytest.raises(ComparisonError):
        compare_runs(
            store,
            [baseline, candidate],
            capability_objectives={baseline: forged},
        )


def test_persisted_attempt_lookup_uses_exact_unique_run(saved) -> None:
    store, _, _, _ = saved
    lease = reserve(saved)

    selected = store.get_capability_attempt_for_run(lease["run_id"])

    assert selected is not None
    assert selected["attempt_id"] == lease["attempt_id"]
    assert selected["lease"]["run_id"] == lease["run_id"]
    assert selected["state"] == "reserved"
    assert store.get_capability_attempt_for_run("run-absent") is None
    with pytest.raises(ProductStoreError):
        store.get_capability_attempt_for_run("../another-run")


def test_settled_attempt_projects_only_its_verified_objective(saved) -> None:
    store, state, _, _ = saved
    lease = reserve(saved)
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    verified = {
        "run_id": lease["run_id"],
        "source_binding": {"manifest_digest": content_hash("manifest")},
        "objective": {"established": False, "checks": {"accepted": False}},
    }
    calls = []

    class Composition:
        def clock(self):
            return state["now_ms"]

        def _verified_result(self, attempt):
            calls.append(attempt["lease"]["attempt_id"])
            return verified

    service = SimpleNamespace(product_store=store, composition=Composition())
    selected = projections(service, [lease["run_id"]])
    row = selected[lease["run_id"]]

    assert calls == [lease["attempt_id"]]
    assert row == {
        "schema_version": _PROJECTION_SCHEMA,
        "run_id": lease["run_id"],
        "attempt_id": lease["attempt_id"],
        "state": "verified",
        "objective_digest": content_hash(
            {"pack": RECEIVER_PACK, "predicate": state["grant"]["objective"]["predicate"]}
        ),
        "established": False,
        "result_digest": content_hash(verified),
    }


@pytest.mark.parametrize("proof", ["pending", "invalid"])
def test_pending_or_unavailable_composition_proof_remains_unknown(saved, proof: str) -> None:
    store, state, _, _ = saved
    lease = reserve(saved)
    if proof == "invalid":
        store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    calls = []

    class Composition:
        def clock(self):
            return state["now_ms"]

        def _verified_result(self, attempt):
            calls.append(attempt["lease"]["attempt_id"])
            raise ProductStoreError("Source proof could not be verified.")

    service = SimpleNamespace(product_store=store, composition=Composition())
    row = projections(service, [lease["run_id"]])[lease["run_id"]]

    assert calls == ([] if proof == "pending" else [lease["attempt_id"]])
    assert row["state"] == "unverified"
    assert row["established"] is None
    assert row["result_digest"] is None


@pytest.mark.parametrize("swapped", ["run_id", "grant_digest"])
def test_composition_projection_refuses_swapped_run_or_grant_binding(
    saved, monkeypatch, swapped: str
) -> None:
    store, state, _, _ = saved
    lease = reserve(saved)
    original_lookup = store.get_capability_attempt_for_run

    def lookup(run_id):
        attempt = deepcopy(original_lookup(run_id))
        assert attempt is not None
        attempt["lease"][swapped] = (
            "run-another" if swapped == "run_id" else content_hash("another grant")
        )
        return attempt

    monkeypatch.setattr(store, "get_capability_attempt_for_run", lookup)
    service = SimpleNamespace(
        product_store=store,
        composition=SimpleNamespace(clock=lambda: state["now_ms"]),
    )

    with pytest.raises(ProductStoreError, match="binding changed"):
        projections(service, [lease["run_id"]])


def test_service_compare_refuses_objective_proof_change_before_snapshot(
    monkeypatch,
) -> None:
    run_ids = ["run-baseline", "run-candidate"]
    before = {run_ids[0]: _projection(run_ids[0], 1, established=None, state="unverified")}
    after = {run_ids[0]: _projection(run_ids[0], 1, established=False)}
    observed = iter((before, after))
    saved = []
    monkeypatch.setattr(composition_comparison, "projections", lambda *_: next(observed))
    monkeypatch.setattr(service_module, "compare_runs", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        comparison_snapshot_store,
        "save",
        lambda *_args: saved.append(True),
    )
    service = SimpleNamespace(
        store=object(),
        product_store=object(),
        s3_access=None,
        _comparison_source_bindings=lambda _run_ids: [
            {"run_id": run_id, "bundle_hash": content_hash(run_id)} for run_id in run_ids
        ],
    )

    with pytest.raises(APIError) as error:
        service_module.BlueFireService.compare(service, {"run_ids": run_ids})

    assert error.value.code == "comparison_source_changed"
    assert saved == []


def test_saved_comparison_binds_capability_proof_without_changing_legacy_records(
    saved, tmp_path: Path, monkeypatch
) -> None:
    product_store, _, _, _ = saved
    run_store = RunStore(tmp_path / "runs")
    run_ids = [_run(run_store, graph_reached=True) for _ in range(2)]
    proofs = {
        run_id: _projection(run_id, index, established=index == 2)
        for index, run_id in enumerate(run_ids, 1)
    }
    comparison = compare_runs(run_store, run_ids, capability_objectives=proofs)
    bindings = [
        {
            "run_id": run_id,
            "bundle_hash": run_store.validate_bundle(run_id)["manifest"]["bundle_hash"],
            "capability_objective_digest": content_hash(proofs[run_id]),
        }
        for run_id in run_ids
    ]
    snapshot = comparison_snapshot_store.save(product_store, comparison, bindings)
    assert (
        comparison_snapshot_store.get(product_store, snapshot["snapshot_id"])["source_bindings"]
        == bindings
    )

    changed = deepcopy(bindings)
    changed[0]["capability_objective_digest"] = content_hash("different proof")
    with pytest.raises(ProductStoreError, match="capability objective binding"):
        comparison_snapshot_store.save(product_store, comparison, changed)

    monkeypatch.setattr(
        composition_comparison,
        "projections",
        lambda _service, selected: {
            run_id: (
                _projection(run_id, 1, established=True) if run_id == run_ids[0] else proofs[run_id]
            )
            for run_id in selected
        },
    )
    fake_service = SimpleNamespace(store=run_store, product_store=product_store)
    reopened = service_module.BlueFireService.comparison_snapshot(
        fake_service, snapshot["snapshot_id"]
    )
    assert reopened["comparison"] == comparison
    assert reopened["source_integrity"] == {
        "status": "unavailable",
        "runs": [
            {"run_id": run_ids[0], "status": "changed"},
            {"run_id": run_ids[1], "status": "verified"},
        ],
    }
