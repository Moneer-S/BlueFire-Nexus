"""Immutable saved comparison explanations with real bundles and mocked providers."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.ai import redact_for_model
from bluefire.ai_assistance import GRAPH, PURPOSE
from bluefire.assistance_comparison_context import (
    LIMITATIONS,
    MAX_SUMMARY_BYTES,
    context,
    selection,
)
from bluefire.comparison_snapshot_store import save
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_comparison import _run
from tests_platform.test_graph_ai_jobs import setup as setup
from tests_platform.test_s3_comparison import (
    comparison_service,
    journey,
)
from tests_platform.test_s3_comparison import (
    stable_identities as stable_identities,
)


def saved(service, count=2, *, repeated=False):
    identifiers = []
    for index in range(count):
        step = {
            "step_id": "private-step-name",
            "behavior_id": "sandbox.first.v1" if index == 0 else "sandbox.other.v1",
            "action_id": "sandbox.record.v1",
            "status": "success",
            "policy": {"status": "allowed"},
            "telemetry": ["private-telemetry-name"],
        }
        steps = [step, {**step, "status": "failed"}] if repeated else [step]
        identifiers.append(
            _run(
                service.store,
                objective=True,
                observed=0,
                detection_matches=0,
                benign_matches=0,
                autonomy="off",
                steps=steps,
                evidence=[
                    {
                        "evidence_id": "private-evidence-name",
                        "provenance": "observed",
                        "producer": "private-producer-name",
                        "step_id": step["step_id"],
                        "content": {
                            "artifact_type": "saved-record",
                            "path": "logs/private-person-name.jsonl",
                            "private_payload": "private-file-content",
                        },
                    }
                ],
            )
        )
    return service.compare({"run_ids": identifiers})["saved_snapshot"]


def block_effects(service, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Explanation recomputed or performed an effect")

    monkeypatch.setattr(service, "compare", forbidden)
    monkeypatch.setattr(service.detection_lab, "evaluate_run", forbidden)
    for name in ("execute", "readiness", "environments"):
        monkeypatch.setattr(service.s3_access.executor, name, forbidden)
    monkeypatch.setattr(service.s3_access, "retained_operations", forbidden)


@pytest.fixture
def snapshot(tmp_path):
    with comparison_service(tmp_path) as (service, _executor):
        metadata = saved(service)
        yield service, metadata


def chosen(metadata):
    return {
        "kind": "comparison_snapshot",
        "snapshot_id": metadata["snapshot_id"],
        "snapshot_digest": metadata["digest"],
    }


def resave(service, metadata, change):
    original = service.comparison_snapshot(metadata["snapshot_id"])
    comparison = deepcopy(original["comparison"])
    change(comparison)
    comparison["comparison_id"] = (
        "comparison-"
        + content_hash({key: value for key, value in comparison.items() if key != "comparison_id"})[
            7:27
        ]
    )
    return save(service.product_store, comparison, original["source_bindings"])


def test_real_snapshot_facts_are_minimized_and_read_only(snapshot, monkeypatch):
    service, metadata = snapshot
    before = service.product_store.path.read_bytes()
    source = service.comparison_snapshot(metadata["snapshot_id"])
    block_effects(service, monkeypatch)
    value = service.comparison_assistance_context(metadata["snapshot_id"])
    assert value["selected"] == chosen(metadata)
    assert (
        value["analysis_only"] is True
        and value["capabilities"] == []
        and value["limitations"] == LIMITATIONS
    )
    assert value["context_digest"] == content_hash(
        {key: val for key, val in value.items() if key != "context_digest"}
    )
    facts = value["reference_summary"]["saved_comparison"]
    assert facts["run_count"] == 2 and facts["baseline_position"] == 1
    assert [row["position"] for row in facts["runs"]] == [1, 2]
    assert facts["runs"][0]["observations"]["observed_artifacts"] == 1
    assert facts["runs"][0]["observations"]["evidence_records"]["observed"] == 1
    assert facts["changes"][0]["objective_relation"] == "same_recorded_result"
    assert facts["changes"][0]["divergence_kind"] == "method"
    assert facts["legitimate_use"] == {"state": "not_recorded"}
    text = json.dumps(value)
    for private in (
        "private-step-name",
        "private-telemetry-name",
        "private-evidence-name",
        "private-producer-name",
        "private-person-name",
        "private-file-content",
        "logs/",
        *source["comparison"]["run_ids"],
    ):
        assert private not in text
    assert service.product_store.path.read_bytes() == before
    assert service.comparison_snapshot(metadata["snapshot_id"]) == source


def test_missing_sources_keep_historical_facts_and_separate_current_integrity(
    snapshot, monkeypatch
):
    service, metadata = snapshot
    before = context(service, chosen(metadata))
    original = service.store.validate_bundle
    target = service.comparison_snapshot(metadata["snapshot_id"])["comparison"]["run_ids"][0]

    def missing(run_id):
        if run_id == target:
            raise RunStoreError(f"unknown run: {run_id}")
        return original(run_id)

    monkeypatch.setattr(service.store, "validate_bundle", missing)
    after = context(service, chosen(metadata))
    assert (
        before["reference_summary"]["saved_comparison"]
        == after["reference_summary"]["saved_comparison"]
    )
    assert after["reference_summary"]["source_integrity"] == {
        "status": "unavailable",
        "runs": [{"position": 1, "status": "missing"}, {"position": 2, "status": "verified"}],
    }
    assert after["context_digest"] != before["context_digest"]


def test_repeated_attempts_do_not_forward_aggregate_final_step_outcomes(tmp_path):
    with comparison_service(tmp_path) as (service, _executor):
        metadata = saved(service, repeated=True)
        facts = context(service, chosen(metadata))["reference_summary"]["saved_comparison"]
        assert all(
            row["repeated_step_ids"] is True and row["recorded_attempts"] == 2
            for row in facts["runs"]
        )
        assert "outcomes" not in facts["runs"][0] and "outcome_counts" not in facts["runs"][0]


def test_absent_counts_remain_null_and_mode_relation_stays_unknown(snapshot):
    service, metadata = snapshot

    def remove(comparison):
        row = comparison["summaries"][1]
        for key in (
            "mode",
            "objective_reached",
            "path",
            "execution_path",
            "evidence_provenance",
            "evidence_details",
            "detection_matches",
            "observed_detection_matches",
            "fixture_detection_matches",
            "benign_matches",
            "cleanup",
            "cleanup_success",
        ):
            row.pop(key, None)

    altered = resave(service, metadata, remove)
    facts = context(service, chosen(altered))["reference_summary"]["saved_comparison"]
    row = facts["runs"][1]
    assert (
        row["mode"]
        is row["objective_reached"]
        is row["recorded_attempts"]
        is row["repeated_step_ids"]
        is None
    )
    assert all(value is None for value in row["observations"].values())
    assert all(value is None for value in row["detection"].values())
    assert facts["changes"][0]["objective_relation"] == "mixed_or_unreported_modes"


@pytest.mark.parametrize(
    "bad",
    [
        "order",
        "delta_identity",
        "negative_count",
        "boolean_count",
        "infinite_count",
        "oversized_count",
        "bad_mode",
        "bad_cleanup",
        "bad_path",
        "bad_execution",
        "bad_stop",
        "bad_divergence",
        "private_material",
        "bad_artifact",
        "bad_s3",
    ],
)
def test_digest_valid_but_malformed_nested_facts_are_rejected(snapshot, bad):
    service, metadata = snapshot

    def alter(comparison):
        row, delta = comparison["summaries"][0], comparison["deltas"][0]
        if bad == "order":
            comparison["summaries"].reverse()
        elif bad == "delta_identity":
            delta["to_run_id"] = comparison["run_ids"][0]
        elif bad in {"negative_count", "boolean_count", "infinite_count", "oversized_count"}:
            row["detection_matches"] = {
                "negative_count": -1,
                "boolean_count": True,
                "infinite_count": float("inf"),
                "oversized_count": 2**53,
            }[bad]
        elif bad == "bad_mode":
            row["mode"] = "private-host-path"
        elif bad == "bad_cleanup":
            row["cleanup"]["state"] = "private-credential"
        elif bad == "bad_path":
            row["path"] = [None]
        elif bad == "bad_execution":
            row["execution_path"][0]["step_id"] = "other-step"
        elif bad == "bad_stop":
            row["first_block"] = {
                "step_id": 1,
                "behavior_id": None,
                "action_id": None,
                "status": "blocked",
                "policy_status": None,
            }
        elif bad == "bad_divergence":
            delta["first_path_divergence"] = True
        elif bad == "private_material":
            delta["material_changes"] = ["private-file-content"]
        elif bad == "bad_artifact":
            row["evidence_details"]["observed_artifacts"] = [None]
        else:
            comparison["s3_access"] = {
                "schema_version": "bluefire.s3-access-comparison.v1",
                "state": "unavailable",
                "reason": "private-host-path",
                "proof_scope": "saved_read_results_only",
            }

    with pytest.raises((ProductStoreError, ValueError)):
        altered = resave(service, metadata, alter)
        context(service, chosen(altered))


@pytest.mark.parametrize(
    "variant",
    ["paired_denied", "legitimate_denied", "unknown_cleanup", "failed_legitimate", "retest_only"],
)
def test_saved_s3_rows_preserve_legitimate_use_provenance_and_gaps(
    tmp_path, stable_identities, monkeypatch, variant
):
    with comparison_service(tmp_path) as (service, executor):
        _, _, ids = journey(service, executor, variant)
        if variant == "retest_only":
            ids = ids[2:]
        metadata = service.compare({"run_ids": ids})["saved_snapshot"]
        raw = service.comparison_snapshot(metadata["snapshot_id"])["comparison"]["s3_access"]
        block_effects(service, monkeypatch)
        result = context(service, chosen(metadata))["reference_summary"]["saved_comparison"][
            "legitimate_use"
        ]
        assert result["state"] == "saved_s3_read_results"
        assert result["comparison_state"] == raw["state"] and result["gaps"] == raw["gaps"]
        assert result["effective_access_claim"] is result["defensive_effectiveness_claim"] is False
        for index, row in enumerate(result["rows"]):
            for phase in ("baseline", "retest"):
                assert row[phase] == {
                    key: raw["rows"][index][phase][key]
                    for key in ("state", "provenance", "cleanup")
                }
        assert result["rows"][1]["retest"]["state"] == (
            "service_denied"
            if variant == "legitimate_denied"
            else (
                "unreported"
                if variant == "failed_legitimate"
                else "not_recorded" if variant == "unknown_cleanup" else "read"
            )
        )
        if variant == "paired_denied":
            for field in ("reader", "purpose", "provenance", "cleanup", "state"):

                def corrupt(comparison, field=field):
                    row = comparison["s3_access"]["rows"][0]
                    target = row if field in {"reader", "purpose"} else row["retest"]
                    target[field] = "private-host-identity"

                altered = resave(service, metadata, corrupt)
                with pytest.raises(ProductStoreError):
                    context(service, chosen(altered))


@pytest.fixture
def explanation(setup, monkeypatch, request):
    service, access, body = setup
    metadata = saved(service, getattr(request, "param", 2))
    native = service.comparison_assistance_context(metadata["snapshot_id"])
    body.update(
        selection=native["selected"],
        context_digest=native["context_digest"],
        message="Explain the saved comparison and evidence limits.",
    )
    block_effects(service, monkeypatch)
    supplied, options = [], {"steps": [], "after": lambda: None}

    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        assert len(body) <= 262144
        access.calls.append(PURPOSE)
        supplied.append(json.loads(wire.get("input") or wire["messages"][1]["content"]))
        options["after"]()
        output = json.dumps(
            {
                "message": "Recorded outcomes match; method choice changed. This does not establish causation.",
                "steps": options["steps"],
            }
        )
        response = {"id": "comparison-unit-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": output}}
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=output,
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    monkeypatch.setattr(access, "post", post)
    return service, access, body, native, supplied, options


def finished(service, body):
    value = service.submit_assistance_turn(body)
    service.job_controller.wait(value["job"]["job_id"], timeout=15)
    return service.assistance_turn(value["job"]["job_id"])


@pytest.mark.parametrize("autonomy", ["off", "assist", "auto"])
def test_durable_analysis_replay_is_idempotent_without_children(explanation, autonomy):
    service, access, body, native, supplied, _ = explanation
    body["autonomy"] = autonomy
    result = finished(service, body)
    assert result["job"]["state"] == "completed" and result["turn"]["status"] == (
        "off" if autonomy == "off" else "completed"
    )
    assert (
        result["turn"]["plan"] == result["turn"]["results"] == []
        and result["turn"]["active_child"] is None
    )
    assert result["job"]["request"]["context"] == native and not result["job"]["progress"].get(
        "children"
    )
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == ([] if autonomy == "off" else [PURPOSE])
    if supplied:
        policy = service._runtime_ai().provider(body["provider_id"]).redaction
        assert supplied[0]["reference_summary"] == redact_for_model(
            native["reference_summary"], policy
        )
        observations = supplied[0]["reference_summary"]["saved_comparison"]["runs"][0][
            "observations"
        ]
        assert (
            observations["evidence_records"]
            == observations["evidence_gaps"]
            == "[EVIDENCE CONTENT OMITTED]"
        )
        assert observations["observed_artifacts"] == 1


def test_forged_capability_cannot_dispatch(explanation):
    service, access, body, _, _, options = explanation
    options["steps"] = [
        {"capability_id": GRAPH, "detector_ref": "none", "reason": "Run another experiment."}
    ]
    result = finished(service, body)
    assert (
        result["job"]["state"] == "failed"
        and result["turn"]["status"] == "blocked"
        and access.calls == [PURPOSE]
    )
    assert result["turn"]["active_child"] is None and not result["job"]["progress"].get("children")


@pytest.mark.parametrize("phase", ["during", "final"])
def test_source_integrity_drift_withholds_answer_and_retains_captured_history(
    explanation, monkeypatch, phase
):
    service, access, body, native, _, options = explanation
    original = service.store.validate_bundle
    target = service.comparison_snapshot(body["selection"]["snapshot_id"])["comparison"]["run_ids"][
        0
    ]

    def changed(run_id):
        if run_id == target:
            raise RunStoreError(f"unknown run: {run_id}")
        return original(run_id)

    def alter():
        monkeypatch.setattr(service.store, "validate_bundle", changed)

    if phase == "during":
        options["after"] = alter
    else:
        advance = service.assistance._advance

        def final(parent_id, **kwargs):
            alter()
            return advance(parent_id, **kwargs)

        monkeypatch.setattr(service.assistance, "_advance", final)
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["job"]["request"][
        "context"
    ] == native and "Recorded outcomes match" not in json.dumps(result["job"]["progress"])
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"][
        "job_id"
    ] and access.calls == [PURPOSE]


@pytest.mark.parametrize("change", ["provider", "authorization"])
def test_provider_binding_and_data_authorization_remain_enforced(explanation, change):
    service, access, body, native, _, options = explanation

    def alter():
        if change == "provider":
            config = service._runtime_ai_config
            service._runtime_ai_config = replace(
                config,
                providers=tuple(
                    (
                        replace(provider, model="changed-model")
                        if provider.id == body["provider_id"]
                        else provider
                    )
                    for provider in config.providers
                ),
            )
        else:
            for grant in service.ai_authorizations()["authorizations"]:
                service.revoke_ai_authorization(grant["authorization_id"], {})

    options["after"] = alter
    result = finished(service, body)
    assert result["job"]["state"] in {"failed", "cancelled"} and access.calls == [PURPOSE]
    assert result["job"]["request"][
        "context"
    ] == native and "Recorded outcomes match" not in json.dumps(result["job"]["progress"])


@pytest.mark.parametrize("explanation", [32], indirect=True)
def test_maximum_ordered_comparison_fits_unchanged_provider_envelope(explanation):
    service, access, body, native, supplied, _ = explanation
    assert len(canonical_json_bytes(native["reference_summary"])) <= MAX_SUMMARY_BYTES
    body["message"] = "\U0001f642" * 1000
    result = finished(service, body)
    assert result["job"]["state"] == "completed" and access.calls == [PURPOSE]
    assert supplied[0]["reference_summary"]["saved_comparison"]["run_count"] == 32


def test_selection_requires_exact_canonical_snapshot_binding(snapshot):
    service, metadata = snapshot
    value = chosen(metadata)
    assert selection(value) == value
    for change in (
        {"instructions": "private-file-content"},
        {"snapshot_id": "comparison-" + "a" * 20},
        {"snapshot_digest": "sha256:" + "0" * 64},
    ):
        with pytest.raises(ProductStoreError):
            context(service, {**value, **change})


@pytest.mark.parametrize("flag", [True, False, None])
def test_legacy_material_flag_is_copied_without_inventing_detail(snapshot, flag):
    service, metadata = snapshot

    def change(comparison):
        delta = comparison["deltas"][0]
        if flag is None:
            delta.pop("material_changed")
        else:
            delta["material_changed"] = flag
            delta.pop("material_changes")

    altered = resave(service, metadata, change)
    result = context(service, chosen(altered))["reference_summary"]["saved_comparison"]["changes"][
        0
    ]
    assert result["material_changed"] is flag
    if flag is not None:
        assert result["material_changes"] is None
    else:
        assert isinstance(result["material_changes"], list) and result["material_changes"]


@pytest.mark.parametrize("flag", [False, 1, None])
def test_inconsistent_or_nonboolean_saved_material_flag_is_refused(snapshot, flag):
    service, metadata = snapshot
    altered = resave(
        service, metadata, lambda comparison: comparison["deltas"][0].update(material_changed=flag)
    )
    with pytest.raises(ProductStoreError):
        context(service, chosen(altered))


def test_authoritative_cleanup_not_needed_remains_not_attempted(tmp_path):
    with comparison_service(tmp_path) as (service, _executor):
        ids = [
            _run(
                service.store,
                objective=True,
                observed=0,
                detection_matches=0,
                benign_matches=0,
                autonomy="off",
                cleanup={"attempted": False, "success": None, "outstanding_receipt_count": 0},
            )
            for _ in range(2)
        ]
        metadata = service.compare({"run_ids": ids})["saved_snapshot"]
        result = context(service, chosen(metadata))["reference_summary"]["saved_comparison"]["runs"]
        assert all(
            row["cleanup"]
            == {
                "source": "run_result",
                "authoritative": True,
                "state": "not_attempted",
                "success": None,
            }
            for row in result
        )
