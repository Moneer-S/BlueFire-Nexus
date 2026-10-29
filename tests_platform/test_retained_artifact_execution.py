"""Owned temporary byte custody and execution-adapter tests; no native or model calls."""

import io
import json
import zipfile
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import SimpleNamespace

import pytest

from bluefire import retained_artifacts as retained
from bluefire.application_errors import APIError
from bluefire.capability_composition import compile_initial_graph, compile_revision
from bluefire.capability_facts import seal_facts, validate_facts
from bluefire.capability_grant import create_grant
from bluefire.capability_resources import METHODS, CapabilityContractError
from bluefire.composition_authority import GrantExecution, native_envelope
from bluefire.composition_jobs import CompositionJobs
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.evidence import EvidenceProvenance, EvidenceRecord, SandboxObserver
from bluefire.orchestrator import Orchestrator
from bluefire.planner import DeterministicPlanner
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_bundle_export import export_run_bundle
from bluefire.run_store import RunStore, RunStoreError
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError
from bluefire.runner_contracts import _verified_grant_attempt, build_runner_profile
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_owner_acl import _windows_extended_path
from tests_platform.test_capability_composition import proposal
from tests_platform.test_capability_composition import state as state
from tests_platform.test_composition_runtime import profile

OWNER_ID = "job-" + "c" * 32


def generated_bytes():
    return (
        canonical_json_bytes(
            {
                "record_id": "synthetic-001",
                "synthetic": True,
                "template": "telemetry-seed",
                "value": "synthetic-redacted",
            }
        )
        + b"\n"
    )


def v2_state(state):
    state = deepcopy(state)
    state["implementation_digests"][retained.METHOD] = content_hash(retained.METHOD)
    old = state["grant"]
    state["grant"] = create_grant(
        pack=retained.PACK,
        registry=state["registry"],
        implementation_digests=state["implementation_digests"],
        **{
            key: old[key]
            for key in (
                "objective",
                "environment",
                "limits",
                "grant_id",
                "approved_by",
                "created_at_ms",
                "expires_at_ms",
            )
        },
    )
    state["expected_grant_digest"] = state["grant"]["grant_digest"]
    return state


def sealed_source(tmp_path):
    store = RunStore(tmp_path / "runs")
    handle = store.create_run(scenario={}, plan={"autonomy": "off"}, policy={}, profile={})
    claim = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        "grant_id": "grant-" + "a" * 32,
        "grant_digest": content_hash("grant"),
        "attempt_id": "attempt-" + "b" * 32,
        "run_id": handle.run_id,
        "lease_digest": content_hash("lease"),
        "compiled_digest": content_hash("compiled"),
        "plan_digest": content_hash({"autonomy": "off"}),
        "native_envelope_digest": content_hash("envelope"),
        "issued_at": "2026-10-03T00:00:00Z",
        "expires_at": "2026-10-03T00:01:00Z",
    }
    store.write_json(handle.run_id, "policy.json", {"grant_attempt": claim})
    root = tmp_path / "source-workspace"
    (root / "staged").mkdir(parents=True)
    payload = generated_bytes()
    path = root / "staged/bundle.jsonl"
    path.write_bytes(payload)
    step = SimpleNamespace(step_id="stage", action_id=METHODS[4])
    artifact = {
        "type": "artifact.sandbox.bundle.v1",
        "format": "jsonl",
        "path": "staged/bundle.jsonl",
        "sha256": sha256(payload).hexdigest(),
        "size": len(payload),
        "receipt_ids": ["a" * 64],
    }
    executed = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id=METHODS[4],
        action_id=METHODS[4],
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="test-profile",
        target_scope_ref="runner-profile:test-profile",
        content={"runner_status": "success", "request_hash": content_hash("stage")},
    )
    captured = []
    observer = SandboxObserver(root)
    observed = observer.observe_file(
        relative_path="staged/bundle.jsonl",
        run_id=handle.run_id,
        step_id="stage",
        behavior_id=METHODS[4],
        action_id=METHODS[4],
        runner_profile_id="test-profile",
        parent_evidence_ids=(executed.evidence_id,),
        _validated_content_sink=captured.append,
    )
    source = retained.capture(
        store,
        run_id=handle.run_id,
        attempt_id="attempt-" + "b" * 32,
        lineage_id="lineage-1",
        step=step,
        artifact=artifact,
        payload=captured[0],
        evidence_id=executed.evidence_id,
        observation_id=observed.evidence_id,
    )
    # Source workspace cleanup does not remove the separately reviewed retention.
    path.unlink()
    store.finalize(
        handle.run_id,
        result={
            "status": "failed",
            "mode": "execute",
            "steps": [
                {
                    "step_id": "stage",
                    "action_id": METHODS[4],
                    "status": "success",
                    "artifacts": {"bundle": artifact},
                    "request_hash": content_hash("stage"),
                    "runner_task_id": "task-stage",
                    "evidence_ids": [executed.evidence_id, observed.evidence_id],
                },
                {
                    "step_id": "send",
                    "action_id": METHODS[5],
                    "status": "failed",
                    "request_hash": content_hash("send"),
                    "runner_task_id": "task-send",
                },
            ],
            "cleanup": {"success": True, "outstanding_receipt_count": 0},
        },
        evidence=[executed.to_dict(), observed.to_dict()],
        detections=[],
    )
    return store, source, payload


def trusted_jobs(store, source, grant):
    run = store.get_run(source["run_id"], require_finalized=True)
    claim = run["policy"]["grant_attempt"]
    capture = {
        "schema_version": "bluefire.retained-artifact-capture.v1",
        "source": source,
        "producer_record_hash": run["evidence"]["records"][0]["record_hash"],
        "observation_record_hash": run["evidence"]["records"][1]["record_hash"],
    }
    child = {
        "kind": "composition.attempt",
        "request": {
            "composition_attempt": {
                "parent_job_id": OWNER_ID,
                **{key: claim[key] for key in ("attempt_id", "run_id", "grant_id", "grant_digest")},
            }
        },
        "progress": {
            "receiver_closed": True,
            "retained_artifact_capture": {**capture, "capture_digest": content_hash(capture)},
        },
    }
    owner = {
        "kind": "composition.objective",
        "state": "completed",
        "request": {"grant_id": grant["grant_id"], "grant_digest": grant["grant_digest"]},
        "progress": {"admission": {"accepted": True, "problem": None}},
    }
    attempt = {
        "state": "settled",
        "lease": {**claim, "lineage_id": "lineage-1", "job_id": "job-source"},
        "compiled": {"scenario": {}, "semantic_digest": content_hash("earlier-prefix")},
        "claim": {"document": claim, "document_digest": content_hash(claim)},
        "tasks": [
            {"step_id": "stage", "task_id": "task-stage", "request_hash": content_hash("stage")},
            {"step_id": "send", "task_id": "task-send", "request_hash": content_hash("send")},
        ],
    }

    @contextmanager
    def connection():
        yield SimpleNamespace(
            execute=lambda *args: SimpleNamespace(
                fetchall=lambda: [{"attempt_id": source["attempt_id"]}]
            )
        )

    product = SimpleNamespace(
        _connection=connection,
        get_capability_grant=lambda *args, **kwargs: {"lineage_id": "lineage-1", "document": grant},
        get_capability_attempt=lambda _: attempt,
        get_job=lambda identifier: owner if identifier == OWNER_ID else child,
    )
    return (
        SimpleNamespace(
            store=product,
            clock=lambda: 2000,
            service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=store)),
        ),
        attempt,
        child,
    )


def materialize_proposal(source):
    graph = proposal(redact=True)
    graph["title"] = "Reuse and redact the completed collection"
    graph["start"] = "reuse"
    graph["steps"][0] = {
        "id": "reuse",
        "behavior_id": retained.METHOD,
        "parameters": {"source_ref": source["source_ref"]},
    }
    graph["edges"][0]["from_step"] = "reuse"
    graph["rationale"] = (
        "Reuse the earlier successful collection and apply the required redaction before delivery."
    )
    return graph


def test_pinned_capture_survives_source_cleanup_without_public_payload(tmp_path):
    store, source, payload = sealed_source(tmp_path)
    assert retained.resolve(store, source) == payload
    run = store.get_run(source["run_id"], require_finalized=True)
    assert "artifacts.json" in run["manifest"]["files"]
    assert "payload_hex" not in str(run)
    metadata = store.read_json(source["run_id"], "artifacts.json")
    assert "payload_hex" not in str(metadata)
    assert metadata["artifacts"][0]["payload"]["export"] == "excluded"
    with zipfile.ZipFile(io.BytesIO(export_run_bundle(store, source["run_id"]))) as archive:
        assert all("/retained/" not in name for name in archive.namelist())
        exported_manifest = json.loads(archive.read(source["run_id"] + "/manifest.json"))
        assert exported_manifest == run["manifest"]


@pytest.mark.parametrize("change", ["missing", "tampered", "wrong_type", "wrong_size"])
def test_unavailable_or_changed_source_is_refused_never_regenerated(tmp_path, change):
    store, source, _ = sealed_source(tmp_path)
    if change in {"missing", "tampered"}:
        path = store.root / source["run_id"] / "artifacts.json"
        path.unlink() if change == "missing" else path.write_text("{}", encoding="utf-8")
    else:
        source = {
            **source,
            "artifact_type" if change == "wrong_type" else "size_bytes": (
                "arbitrary" if change == "wrong_type" else 1
            ),
        }
    with pytest.raises((CapabilityContractError, RunStoreError)):
        retained.resolve(store, source)
    assert not (tmp_path / "source-workspace/staged/bundle.jsonl").exists()


def test_v2_has_explicit_bounded_retention_and_v1_is_unchanged(state):
    legacy = deepcopy(state["grant"])
    new = v2_state(state)["grant"]
    assert legacy["snapshot"]["artifact_context"]["materialization"] == "fresh_attempt"
    assert "retention" not in legacy["snapshot"]["artifact_context"]
    assert new["snapshot"]["artifact_context"]["retention"] == retained.POLICY
    assert new["snapshot"]["methods"][-1]["parameter_domains"] == {
        "source_ref": {"kind": "sealed_same_lineage_generated_jsonl"}
    }
    assert legacy == state["grant"]


def test_new_node_is_the_real_typed_producer_and_has_no_prefix_replay(state, tmp_path):
    store, source, payload = sealed_source(tmp_path)
    params = v2_state(state)
    graph = materialize_proposal(source)
    with pytest.raises(CapabilityContractError, match="verified source"):
        compile_initial_graph(graph, **params)
    with pytest.raises(CapabilityContractError):
        compile_initial_graph(graph, **state, retained_source_resolver=lambda _: source)
    compiled = compile_initial_graph(graph, **params, retained_source_resolver=lambda _: source)
    assert [row["behavior_id"] for row in compiled["scenario"]["steps"]] == [
        retained.METHOD,
        METHODS[1],
        METHODS[2],
        METHODS[4],
        METHODS[5],
        METHODS[6],
    ]
    assert compiled["scenario"]["steps"][1]["inputs"]["workspace"] == {
        "from_step": "reuse",
        "artifact": "workspace",
    }
    assert compiled["retained_sources"] == {"reuse": source}
    plan = DeterministicPlanner(params["registry"]).compile(
        ScenarioDefinition.from_mapping(compiled["scenario"]),
        mode=ExecutionMode.EXECUTE,
        profile=replace(profile(), enabled_actions=(*profile().enabled_actions, retained.METHOD)),
        autonomy="off",
        ai_enabled=False,
        action_implementations=compiled["action_implementations"],
    )
    step = next(row for row in plan.steps if row.step_id == "reuse")
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError, match="grant-owned bytes"):
        adapter.adapt(step, bound_inputs={}, receipt_ids=[])
    adapted = adapter.adapt(
        step,
        bound_inputs={},
        receipt_ids=[],
        _retained_material={"source": source, "payload": retained.resolve(store, source)},
    )
    assert bytes.fromhex("".join(adapted.params["payload_hex_chunks"])) == payload
    output = adapter.logical_outputs(
        step,
        bound_inputs={},
        receipt_ids=["c" * 64],
        runner_output={
            "artifact": "fixtures/input.jsonl",
            "format": "jsonl",
            "source_ref": source["source_ref"],
            "sha256": source["sha256"],
            "size": len(payload),
            "record_count": 1,
        },
    )
    assert output["workspace"]["receipt_ids"] == ["c" * 64]
    assert output["workspace"]["receipt_ids"] != ["a" * 64]
    assert output["workspace"]["historical_source_ref"] == source["source_ref"]
    with pytest.raises(RunnerAdapterError):
        adapter.logical_outputs(step, bound_inputs={}, receipt_ids=[], runner_output={})


def test_retention_count_and_non_generated_bytes_are_refused(tmp_path):
    store, source, payload = sealed_source(tmp_path)
    with pytest.raises(CapabilityContractError, match="count"):
        retained.capture(
            store,
            run_id=source["run_id"],
            attempt_id=source["attempt_id"],
            lineage_id=source["lineage_id"],
            step=SimpleNamespace(step_id="stage", action_id=METHODS[4]),
            artifact={
                "type": source["artifact_type"],
                "format": "jsonl",
                "path": "staged/bundle.jsonl",
                "sha256": source["sha256"],
                "size": len(payload),
                "receipt_ids": ["a" * 64],
            },
            payload=payload,
            evidence_id="evidence",
            observation_id="observation",
        )
    arbitrary = b'{"unreviewed":"arbitrary"}\n'
    with pytest.raises(ValueError):
        retained.validate_bytes(
            arbitrary, {"size_bytes": len(arbitrary), "sha256": sha256(arbitrary).hexdigest()}
        )


def test_source_requires_trusted_capture_anchor_and_settled_same_lineage(state, tmp_path):
    store, source, _ = sealed_source(tmp_path)
    jobs, attempt, child = trusted_jobs(store, source, v2_state(state)["grant"])
    assert (
        retained.resolve_for_grant(
            jobs, v2_state(state)["grant"], source["source_ref"], owner_id=OWNER_ID
        )
        == source
    )
    attempt["state"] = "claimed"
    with pytest.raises(CapabilityContractError, match="unavailable"):
        retained.resolve_for_grant(
            jobs, v2_state(state)["grant"], source["source_ref"], owner_id=OWNER_ID
        )
    attempt["state"] = "settled"
    child["progress"]["retained_artifact_capture"]["source"] = {**source, "lineage_id": "other"}
    with pytest.raises(CapabilityContractError, match="integrity"):
        retained.resolve_for_grant(
            jobs, v2_state(state)["grant"], source["source_ref"], owner_id=OWNER_ID
        )


def test_bundle_resealing_cannot_replace_the_original_captured_bytes(state, tmp_path):
    store, source, payload = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, _, _ = trusted_jobs(store, source, grant)
    document = store.read_json(source["run_id"], "artifacts.json")
    replacement = payload.replace(b"synthetic-redacted", b"telemetry-value-001")
    changed = {key: value for key, value in source.items() if key != "source_ref"}
    changed.update(sha256=sha256(replacement).hexdigest(), size_bytes=len(replacement))
    changed["source_ref"] = content_hash(changed)
    document["artifacts"][0].update(
        source=changed,
        payload={
            "path": "retained/bundle.jsonl",
            "sha256": changed["sha256"],
            "size_bytes": changed["size_bytes"],
            "export": "excluded",
        },
    )
    store.write_json(source["run_id"], "artifacts.json", document)
    run = store.read_json(source["run_id"], "result.json")
    evidence = store.read_json(source["run_id"], "evidence.json")["records"]
    # Even replacing the source envelope and recomputing the bundle seal cannot
    # replace the independently persisted controller capture reference.
    store.finalize(source["run_id"], result=run, evidence=evidence, detections=[])
    with pytest.raises(CapabilityContractError, match="integrity"):
        retained.available_sources(jobs, grant, owner_id=OWNER_ID)


def test_v2_failed_attempt_facts_keep_receiver_unknown_and_require_cleanup(state, tmp_path):
    store, source, _ = sealed_source(tmp_path)
    params = v2_state(state)
    jobs, attempt, child = trusted_jobs(store, source, params["grant"])
    result = retained.prior_failure(jobs, params["grant"], attempt, child, owner_id=OWNER_ID)
    assert result["retained_artifact_result"]["receiver_decision"] == "unknown"
    assert result["retained_artifact_result"]["prior_run_id"] == source["run_id"]
    assert result["cleanup"] == {"run": "complete", "receiver": "verified_closed"}
    child["progress"]["receiver_closed"] = False
    with pytest.raises(ValueError, match="cleanup"):
        retained.prior_failure(jobs, params["grant"], attempt, child, owner_id=OWNER_ID)


def test_same_environment_predicate_and_budget_lineage_do_not_share_other_objective_bytes(
    state, tmp_path
):
    store, source, _ = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, _, child = trusted_jobs(store, source, grant)
    assert retained.available_sources(jobs, grant, owner_id=OWNER_ID) == [source]
    child["request"]["composition_attempt"]["parent_job_id"] = "job-" + "f" * 32
    grant["objective"]["question"] = "An independently saved question about the same control."
    assert retained.available_sources(jobs, grant, owner_id=OWNER_ID) == []
    with pytest.raises(CapabilityContractError, match="outside"):
        retained.resolve_for_grant(jobs, grant, source["source_ref"], owner_id=OWNER_ID)


def test_repeated_continuation_keeps_original_source_after_materialized_attempt_fails(
    state, tmp_path
):
    store, source, _ = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, original, _ = trusted_jobs(store, source, grant)
    scenario = {
        "steps": [
            {
                "id": "reuse",
                "behavior_id": retained.METHOD,
                "parameters": {"source_ref": source["source_ref"]},
            }
        ]
    }
    handle = store.create_run(scenario=scenario, plan={"autonomy": "off"}, policy={}, profile={})
    claim = {
        **original["claim"]["document"],
        "run_id": handle.run_id,
        "attempt_id": "attempt-" + "e" * 32,
    }
    store.write_json(handle.run_id, "policy.json", {"grant_attempt": claim})
    rows = [
        {
            "step_id": "reuse",
            "action_id": retained.METHOD,
            "status": "success",
            "request_hash": content_hash("reuse"),
            "runner_task_id": "task-reuse",
            "artifacts": {
                "workspace": {
                    "historical_source": source,
                    "historical_source_ref": source["source_ref"],
                    "sha256": source["sha256"],
                    "size": source["size_bytes"],
                    "receipt_ids": ["f" * 64],
                }
            },
        },
        {
            "step_id": "send",
            "action_id": METHODS[5],
            "status": "failed",
            "request_hash": content_hash("resend"),
            "runner_task_id": "task-resend",
        },
    ]
    executed = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="reuse",
        behavior_id=retained.METHOD,
        action_id=retained.METHOD,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="test-profile",
        target_scope_ref="runner-profile:test-profile",
        content={
            "runner_status": "success",
            "request_hash": content_hash("reuse"),
            "output": {
                "source_ref": source["source_ref"],
                "sha256": source["sha256"],
                "size": source["size_bytes"],
            },
        },
    )
    store.finalize(
        handle.run_id,
        result={
            "status": "failed",
            "mode": "execute",
            "steps": rows,
            "cleanup": {"success": True, "outstanding_receipt_count": 0},
        },
        evidence=[executed.to_dict()],
        detections=[],
    )
    newer = {
        "state": "settled",
        "lease": {**claim, "job_id": "job-newer", "lineage_id": "lineage-1"},
        "compiled": {"scenario": scenario, "retained_sources": {"reuse": source}},
        "claim": {"document": claim, "document_digest": content_hash(claim)},
        "tasks": [
            {
                "step_id": row["step_id"],
                "task_id": row["runner_task_id"],
                "request_hash": row["request_hash"],
            }
            for row in rows
        ],
    }
    child = {
        "request": {"composition_attempt": {"parent_job_id": OWNER_ID}},
        "progress": {"receiver_closed": True},
    }
    result = retained.prior_failure(jobs, grant, newer, child, owner_id=OWNER_ID)
    assert result["retained_artifact_result"]["source"] == source
    assert result["retained_artifact_result"]["prior_run_id"] == handle.run_id
    assert (
        result["retained_artifact_result"]["source"]["attempt_id"] != newer["lease"]["attempt_id"]
    )
    newer["compiled"]["retained_sources"]["reuse"] = {
        **source,
        "source_ref": content_hash("other-source"),
    }
    with pytest.raises(ValueError, match="no verified retained output"):
        retained.prior_failure(jobs, grant, newer, child, owner_id=OWNER_ID)


def test_v2_failed_result_fact_compiles_revision_without_invented_receiver_refusal(state, tmp_path):
    store, source, _ = sealed_source(tmp_path)
    params = v2_state(state)
    jobs, attempt, child = trusted_jobs(store, source, params["grant"])
    result = retained.prior_failure(jobs, params["grant"], attempt, child, owner_id=OWNER_ID)
    facts = {key: value for key, value in params["facts"].items() if key != "facts_digest"}
    facts.update(
        prior_attempt_id=source["attempt_id"], prior_graph_digest=content_hash("earlier-prefix")
    )
    for identity, kind, value in [
        ("result", "retained_artifact_result", result["retained_artifact_result"]),
        ("cleanup", "cleanup", result["cleanup"]),
    ]:
        facts["facts"].append(
            {
                **deepcopy(facts["facts"][0]),
                "fact_id": identity,
                "kind": kind,
                "source": {
                    "kind": "run_evidence",
                    "id": source["run_id"],
                    "digest": content_hash(result["source_binding"]),
                },
                "attempt_id": source["attempt_id"],
                "value": value,
            }
        )
    params["facts"] = seal_facts(facts)
    params["expected_facts_digest"] = params["facts"]["facts_digest"]
    graph = materialize_proposal(source)
    graph["evidence_refs"] = ["policy", "result", "cleanup"]
    compiled = compile_revision(
        graph,
        **params,
        retained_source_resolver=lambda reference: retained.resolve_for_grant(
            jobs, params["grant"], reference, owner_id=OWNER_ID
        ),
    )
    assert compiled["prior_attempt_id"] == source["attempt_id"]
    assert len(compiled["scenario"]["steps"]) == 6
    params["facts"]["facts"][-1]["value"]["run"] = "unknown"
    params["facts"] = seal_facts(
        {key: value for key, value in params["facts"].items() if key != "facts_digest"}
    )
    with pytest.raises(CapabilityContractError, match="cleanup"):
        validate_facts(
            params["facts"],
            expected_digest=params["facts"]["facts_digest"],
            grant=params["grant"],
            now_ms=params["now_ms"],
            require_prior_result=True,
        )


def test_capture_bounds_are_checked_before_sink_and_private_json_decode(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "oversize").write_bytes(b"x" * 32)
    captured = []
    with pytest.raises(ValueError, match="byte limit"):
        SandboxObserver(root).observe_file(
            relative_path="oversize",
            run_id="run-test",
            step_id="stage",
            behavior_id=METHODS[4],
            action_id=METHODS[4],
            runner_profile_id="test-profile",
            _validated_content_sink=captured.append,
            _max_content_bytes=16,
        )
    assert captured == []
    store = RunStore(tmp_path / "runs")
    handle = store.create_run(scenario={}, plan={}, policy={}, profile={})
    store.write_json(handle.run_id, "artifacts.json", {"large": "x" * 100})
    with pytest.raises(RunStoreError, match="byte bound"):
        store.read_json(handle.run_id, "artifacts.json", _max_bytes=16)


def test_real_execution_path_dispatches_only_new_materialization_and_records_both_lineages(
    state, tmp_path, monkeypatch
):
    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "linux")
    store, source, payload = sealed_source(tmp_path)
    params = v2_state(state)
    compiled = compile_initial_graph(
        materialize_proposal(source), **params, retained_source_resolver=lambda _: source
    )
    selected_profile = replace(
        profile(), enabled_actions=(*profile().enabled_actions, retained.METHOD)
    )
    plan = DeterministicPlanner(params["registry"]).compile(
        ScenarioDefinition.from_mapping(compiled["scenario"]),
        mode=ExecutionMode.EXECUTE,
        profile=selected_profile,
        autonomy="off",
        ai_enabled=False,
        action_implementations=compiled["action_implementations"],
    )
    step = next(row for row in plan.steps if row.step_id == "reuse")
    envelope = native_envelope(plan, compiled)
    handle = store.create_run(
        scenario=compiled["scenario"], plan=plan.to_dict(), policy={}, profile={}
    )
    root = tmp_path / "fresh-attempt"
    root.mkdir()
    native_profile = build_runner_profile(
        selected_profile, sandbox_root=root, platform="linux", reviewed_execution=envelope
    )
    now = datetime.now(timezone.utc)
    document = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        "grant_id": params["grant"]["grant_id"],
        "grant_digest": params["grant"]["grant_digest"],
        "attempt_id": "attempt-" + "d" * 32,
        "lease_digest": content_hash("new-lease"),
        "compiled_digest": compiled["compiled_digest"],
        "plan_digest": content_hash(plan.to_dict()),
        "native_envelope_digest": content_hash(envelope),
        "run_id": handle.run_id,
        "issued_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    }
    calls = []

    class Runner:
        def execute_task(self, manifest, runner_profile, **kwargs):
            calls.append(manifest["action_id"])
            assert manifest["params"]["payload_hex_chunks"] == retained.wire_chunks(payload)
            assert manifest["grant_attempt"]["attempt_id"] != source["attempt_id"]
            (root / "fixtures").mkdir()
            (root / "fixtures/input.jsonl").write_bytes(payload)
            identity = {
                "schema_version": "bluefire.receipt/v1",
                "request_hash": manifest["request_hash"],
                "action_id": retained.METHOD,
                "runner_profile_id": runner_profile["profile_id"],
                "workspace_id": sha256(str(root.resolve()).replace("\\", "/").encode()).hexdigest(),
                "created_at": now.isoformat(),
                "paths": [
                    {
                        "relative_path": "fixtures/input.jsonl",
                        "kind": "file",
                        "sha256": source["sha256"],
                        "size": len(payload),
                    }
                ],
            }
            receipt_id = content_hash(identity)[7:]
            for directory, value in [
                ("receipts", {"receipt_id": receipt_id, **identity}),
                (
                    "receipt-commits",
                    {
                        "schema_version": "bluefire.receipt-commit/v1",
                        "receipt_id": receipt_id,
                        "runner_profile_id": runner_profile["profile_id"],
                        "workspace_id": identity["workspace_id"],
                        "committed_at": now.isoformat(),
                    },
                ),
            ]:
                parent = _windows_extended_path(root / ".bluefire" / directory)
                parent.mkdir(parents=True)
                (parent / (receipt_id + ".json")).write_bytes(canonical_json_bytes(value))
            return {
                "schema_version": "bluefire.runner-result.v1",
                **{
                    key: manifest[key]
                    for key in (
                        "request_id",
                        "run_id",
                        "step_id",
                        "behavior_id",
                        "action_id",
                        "runner_id",
                        "runner_profile_id",
                        "request_hash",
                    )
                },
                "policy_digest": runner_profile["policy_digest"],
                "platform": runner_profile["platform"],
                "status": "success",
                "output": {
                    "artifact": "fixtures/input.jsonl",
                    "format": "jsonl",
                    "sha256": source["sha256"],
                    "size": len(payload),
                    "record_count": 1,
                    "source_ref": source["source_ref"],
                },
                "stdout": {"bytes": 0, "truncated": False},
                "stderr": {"bytes": 0, "truncated": False},
                "evidence": [],
                "receipt_ids": [receipt_id],
                "cleanup": None,
                "error": None,
                "limitations": [],
            }

    execution = GrantExecution(
        _verified_grant_attempt(document, expected_document_digest=content_hash(document)),
        envelope,
        lambda: None,
        lambda _: None,
        lambda *args: None,
        lambda *args, **kwargs: None,
        lambda *args: None,
        materialize_retained=lambda selected: {
            "source": source,
            "payload": retained.resolve(store, source),
        },
    )
    engine = Orchestrator(params["registry"], store, runner=Runner(), grant_execution=execution)
    row, records, _, receipts = engine._execute_step(
        run_id=handle.run_id,
        step=step,
        bound_inputs={},
        parent_ids=(),
        profile=selected_profile,
        runner_profile=native_profile,
        observer=SandboxObserver(root),
        approved_by=None,
        approval_record=None,
        authorized_target_scope={"scope_refs": ["sandbox.workspace"]},
        receipt_ids=[],
    )
    assert row["status"] == "success", (row.get("policy"), row.get("error"))
    assert calls == [retained.METHOD]
    assert row["artifacts"]["workspace"]["historical_source"] == source
    assert row["artifacts"]["workspace"]["receipt_ids"] == list(receipts)
    assert receipts and receipts != ("a" * 64,)
    assert (root / "fixtures/input.jsonl").read_bytes() == payload
    assert all("payload_hex" not in str(record.to_dict()) for record in records)
    # The ordinary exact-plan/old grant path has no capability-owned resolver.
    old_document = {**document, "grant_digest": state["grant"]["grant_digest"]}
    engine.grant_execution = replace(
        execution,
        authority=_verified_grant_attempt(
            old_document, expected_document_digest=content_hash(old_document)
        ),
        materialize_retained=None,
    )
    refused, _, _, _ = engine._execute_step(
        run_id=handle.run_id,
        step=step,
        bound_inputs={},
        parent_ids=(),
        profile=selected_profile,
        runner_profile=native_profile,
        observer=SandboxObserver(root),
        approved_by=None,
        approval_record=None,
        authorized_target_scope={"scope_refs": ["sandbox.workspace"]},
        receipt_ids=[],
    )
    assert refused["status"] == "blocked"
    assert refused["error"]["code"] == "adapter_refused"
    assert calls == [retained.METHOD]


def test_materialization_wire_fits_unchanged_native_document_string_and_node_bounds():
    payload = b"x" * retained.MAX_BYTES
    chunks = retained.wire_chunks(payload)
    assert len(chunks) == retained.MAX_CHUNKS == 32
    assert all(len(chunk) == retained.HEX_CHUNK_CHARS == 16 * 1024 for chunk in chunks)
    assert bytes.fromhex("".join(chunks)) == payload
    assert len(canonical_json_bytes({"payload_hex_chunks": chunks})) < 1024 * 1024
    with pytest.raises(CapabilityContractError, match="byte bound"):
        retained.wire_chunks(payload + b"x")


@pytest.mark.parametrize("payload_state", ["missing", "wrong_bytes"])
def test_payload_loss_preserves_history_and_explicit_same_objective_fresh_approach(
    state, tmp_path, payload_state
):
    store, source, _ = sealed_source(tmp_path)
    params = v2_state(state)
    jobs, attempt, child = trusted_jobs(store, source, params["grant"])
    payload_path = store.root / source["run_id"] / "retained/bundle.jsonl"
    payload_path.unlink() if payload_state == "missing" else payload_path.write_bytes(b"changed")
    assert store.get_run(source["run_id"], require_finalized=True)["manifest"]["files"][
        "artifacts.json"
    ]
    assert retained.historical_sources(jobs, params["grant"], owner_id=OWNER_ID) == [source]
    assert retained.available_sources(jobs, params["grant"], owner_id=OWNER_ID) == []
    with pytest.raises(retained.PayloadUnavailable):
        retained.resolve(store, source)
    with pytest.raises(CapabilityContractError, match="unavailable"):
        retained.resolve_for_grant(jobs, params["grant"], source["source_ref"], owner_id=OWNER_ID)
    result = retained.prior_failure(jobs, params["grant"], attempt, child, owner_id=OWNER_ID)
    facts = {key: value for key, value in params["facts"].items() if key != "facts_digest"}
    facts.update(
        prior_attempt_id=source["attempt_id"],
        prior_graph_digest=content_hash("original-nonredacted-graph"),
    )
    for identity, kind, value in [
        ("result", "retained_artifact_result", result["retained_artifact_result"]),
        ("cleanup", "cleanup", result["cleanup"]),
    ]:
        facts["facts"].append(
            {
                **deepcopy(facts["facts"][0]),
                "fact_id": identity,
                "kind": kind,
                "source": {
                    "kind": "run_evidence",
                    "id": source["run_id"],
                    "digest": content_hash(result["source_binding"]),
                },
                "attempt_id": source["attempt_id"],
                "value": value,
            }
        )
    params["facts"] = seal_facts(facts)
    params["expected_facts_digest"] = params["facts"]["facts_digest"]
    fresh_graph = proposal(redact=True)
    fresh_graph["evidence_refs"] = ["policy", "result", "cleanup"]
    compiled = compile_revision(
        fresh_graph,
        **params,
        retained_source_resolver=lambda _: (_ for _ in ()).throw(
            AssertionError("Fresh approach must not resolve or recreate a lost payload")
        ),
    )
    assert compiled["prior_attempt_id"] == source["attempt_id"]
    assert compiled["grant_id"] == params["grant"]["grant_id"]
    assert compiled["scenario"]["steps"][0]["behavior_id"] == METHODS[0]
    assert "retained_sources" not in compiled
    assert not (tmp_path / "source-workspace/staged/bundle.jsonl").exists()
    # Metadata export remains useful without embedding any private payload.
    with zipfile.ZipFile(io.BytesIO(export_run_bundle(store, source["run_id"]))) as archive:
        assert all("/retained/" not in name for name in archive.namelist())


def test_corrupt_sealed_history_is_not_downgraded_to_payload_unavailability(state, tmp_path):
    store, source, _ = sealed_source(tmp_path)
    params = v2_state(state)
    jobs, attempt, child = trusted_jobs(store, source, params["grant"])
    (store.root / source["run_id"] / "artifacts.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CapabilityContractError, match="integrity"):
        retained.available_sources(jobs, params["grant"], owner_id=OWNER_ID)
    with pytest.raises((ValueError, APIError)):
        retained.prior_failure(jobs, params["grant"], attempt, child, owner_id=OWNER_ID)


def test_metadata_export_refuses_unknown_private_payload_inventory(tmp_path):
    store, source, _ = sealed_source(tmp_path)
    (store.root / source["run_id"] / "retained/unreviewed.txt").write_bytes(b"owned unit fixture")
    with pytest.raises(RunStoreError, match="Unexpected retained payload entry"):
        export_run_bundle(store, source["run_id"])


def test_v2_fact_projection_preserves_known_receiver_refusal_after_payload_loss(state, tmp_path):
    store, source, _ = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, attempt, _ = trusted_jobs(store, source, grant)
    # This unit projects a trusted verified-result boundary; receiver execution
    # itself remains the responsibility of the installed journey.
    grant["grant_digest"] = attempt["lease"]["grant_digest"]
    jobs.store.get_job(OWNER_ID)["request"]["grant_digest"] = grant["grant_digest"]
    (store.root / source["run_id"] / "retained/bundle.jsonl").unlink()
    expected = {
        "decision": "policy_refused",
        "policy_digest": grant["environment"]["policy_digest"],
        "record_count": 8,
        "redacted_record_count": 0,
        "retained_record_count": 8,
        "empty_record_count": 0,
    }
    controller = object.__new__(CompositionJobs)
    controller.store, controller.service, controller.clock = jobs.store, jobs.service, jobs.clock
    controller._verified_result = lambda _: {
        "run_id": source["run_id"],
        "source_binding": {"finalized_at": "1970-01-01T00:00:01Z"},
        "receiver_result": expected,
        "cleanup": {"run": "complete", "receiver": "verified_closed"},
    }
    facts = controller._facts(grant, source["attempt_id"], owner_id=OWNER_ID)
    result_fact = next(row for row in facts["facts"] if row["fact_id"] == "result")
    assert result_fact["kind"] == "receiver_result"
    assert result_fact["value"] == expected


@pytest.mark.parametrize(
    "observation",
    [
        {
            "schema_version": "bluefire.owned-receiver-observation.v1",
            "state": "verified",
            "terminal": {},
        },
        {
            "schema_version": "bluefire.owned-receiver-observation.v1",
            "state": "insufficient_evidence",
            "reason": "invalid authenticated binding",
            "terminal": {},
            "review_binding": {"digest": "wrong"},
        },
    ],
)
def test_invalid_receiver_binding_is_never_downgraded_to_unknown(
    state, tmp_path, monkeypatch, observation
):
    store, source, _ = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, attempt, child = trusted_jobs(store, source, grant)
    grant["grant_digest"] = attempt["lease"]["grant_digest"]
    jobs.store.get_job(OWNER_ID)["request"]["grant_digest"] = grant["grant_digest"]
    child["progress"]["receiver_observation"] = observation
    controller = object.__new__(CompositionJobs)
    controller.store, controller.service, controller.clock = jobs.store, jobs.service, jobs.clock
    expected = ProductStoreError("The authenticated receiver task binding differs.")
    controller._verified_result = lambda _: (_ for _ in ()).throw(expected)
    monkeypatch.setattr(
        retained,
        "prior_failure",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Invalid receiver evidence must not use unknown fallback")
        ),
    )
    with pytest.raises(ProductStoreError) as caught:
        controller._facts(grant, source["attempt_id"], owner_id=OWNER_ID)
    assert caught.value is expected


def test_explicit_absent_receiver_terminal_can_use_verified_late_failure_and_cleanup(
    state, tmp_path
):
    store, source, _ = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, attempt, child = trusted_jobs(store, source, grant)
    grant["grant_digest"] = attempt["lease"]["grant_digest"]
    jobs.store.get_job(OWNER_ID)["request"]["grant_digest"] = grant["grant_digest"]
    child["progress"]["receiver_observation"] = {
        "schema_version": "bluefire.owned-receiver-observation.v1",
        "state": "insufficient_evidence",
        "reason": "The exact owned receiver terminal is unavailable.",
    }
    controller = object.__new__(CompositionJobs)
    controller.store, controller.service, controller.clock = jobs.store, jobs.service, jobs.clock
    controller._verified_result = lambda _: (_ for _ in ()).throw(
        AssertionError("No terminal is available to verify")
    )
    facts = controller._facts(grant, source["attempt_id"], owner_id=OWNER_ID)
    result_fact = next(row for row in facts["facts"] if row["fact_id"] == "result")
    assert result_fact["kind"] == "retained_artifact_result"
    assert result_fact["value"]["receiver_decision"] == "unknown"
