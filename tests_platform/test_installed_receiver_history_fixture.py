"""Installed fixture boundary through real storage and filesystem-only projection.

All source records are generated here; no native runner, receiver or provider is used.
"""

import json
import uuid
from types import SimpleNamespace

from bluefire.ai_runtime_composition import format_request
from bluefire.capability_composition import compile_initial_graph, compile_revision
from bluefire.capability_facts import seal_facts
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.composition_evidence_context import validate_reconsideration
from bluefire.composition_knowledge import QUERY_SCHEMA, build_knowledge
from bluefire.run_store import RunStore
from bluefire.runner_contracts import _verified_grant_attempt
from bluefire.util import content_hash
from tests_platform import test_ai_receiver_inspection as provider_fixtures
from tests_platform import test_ai_runtime_composition as runtime_fixtures
from tests_platform import test_capability_composition as compiler_fixtures
from tests_platform import test_composition_evidence_context as history_fixtures
from tests_platform import test_product_store_capability_grants as store_fixtures
from tests_platform.test_collection_semantics import _payload
from tests_platform.test_installed_assistant_fixture import receiver_request
from tools.verify_installed_browser import _receiver_fixture_output_for_request


def test_receiver_history_fixture_uses_installed_filesystem_only_sealed_projection(tmp_path):
    state = compiler_fixtures.state.__wrapped__()
    saved = store_fixtures.saved.__wrapped__(state, tmp_path)
    initial = _receiver_fixture_output_for_request(receiver_request())
    compiled = compile_initial_graph(initial, **runtime_fixtures.compiler_args(state))
    saved = (saved[0], state, compiled, saved[3])
    provider = provider_fixtures.provider.__wrapped__(SimpleNamespace(param="openai_responses"))
    generator = runtime_fixtures.harness.__wrapped__(saved, provider)
    harness = next(generator)
    try:
        store = harness.service.product_store
        runs = RunStore(tmp_path / "runs")
        harness.service.detection_lab = SimpleNamespace(run_store=runs)
        token = uuid.uuid4().hex
        run_id = runs._new_run_id()
        plan = {"schema_version": "bluefire.plan.v1", "autonomy": "off", "steps": []}
        marker = {
            "parent_job_id": harness.owner,
            "grant_id": state["grant"]["grant_id"],
            "grant_digest": state["grant"]["grant_digest"],
            "attempt_id": "attempt-" + token,
            "compiled_digest": compiled["compiled_digest"],
            "run_id": run_id,
        }
        child_request = {"composition_attempt": marker}
        store.create_idempotent_job(
            "composition.attempt",
            child_request,
            submission_id=str(uuid.UUID(hex=token)),
            intent_digest=content_hash(child_request),
        )
        lease = store.reserve_capability_attempt(
            state["grant"]["grant_id"],
            compiled,
            expected_compiled_digest=compiled["compiled_digest"],
            attempt_id=marker["attempt_id"],
            job_id="job-" + token,
            run_id=run_id,
            plan_digest=content_hash(plan),
            native_envelope_digest=content_hash("authored envelope"),
            current_environment=state["current_environment"],
            now_ms=3000,
        )
        store_fixtures.claim(saved, lease, now_ms=3001)
        claim = store.get_capability_attempt(lease["attempt_id"])["claim"]
        run = runs.create_run(
            scenario=compiled["scenario"],
            plan=plan,
            profile=None,
            policy={
                "grant_attempt": _verified_grant_attempt(
                    claim["document"],
                    expected_document_digest=claim["document_digest"],
                ).to_dict()
            },
            _reserved_run_id=run_id,
        )
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "bundle.jsonl").write_bytes(_payload(count=8))
        # Match the installed journey's sole selected collector. This independent
        # observation proves artifact metadata, never aggregate record semantics.
        observed = (
            FilesystemCollector(workspace)
            .collect(
                CollectionRequest(
                    run_id=run_id,
                    step_id="stage_records",
                    behavior_id="sandbox.collection.stage.v1",
                    action_id="sandbox.collection.stage.v1",
                    settings={"paths": ["bundle.jsonl"]},
                    runner_profile_id="sandbox-endpoint-deep-lab.v1",
                    target_scope_ref="generated-fixture",
                )
            )
            .records
        )
        assert len(observed) == 1 and observed[0].provenance.value == "observed"
        runs.finalize(
            run.run_id,
            result={
                "schema_version": "bluefire.run-result.v1",
                "status": "failed",
                "mode": "execute",
            },
            evidence=[row.to_dict() for row in observed],
            detections=[],
        )
        store.settle_capability_attempt(lease["attempt_id"], store_fixtures.unused(lease))
        with store._connection(write=True) as connection:
            connection.execute("UPDATE jobs SET state='failed' WHERE job_id=?", (lease["job_id"],))
        revised = compiler_fixtures.revision_state(runtime_fixtures.compiler_args(state))
        facts = {key: value for key, value in revised["facts"].items() if key != "facts_digest"}
        facts["prior_attempt_id"] = lease["attempt_id"]
        facts["prior_graph_digest"] = compiled["semantic_digest"]
        for row in facts["facts"]:
            if row["kind"] != "retained_policy":
                row["attempt_id"] = lease["attempt_id"]
        revised["facts"] = seal_facts(facts)
        revised["expected_facts_digest"] = revised["facts"]["facts_digest"]
        state.update(revised)
        harness.context.update(runtime_fixtures.context(revised, initial=False))
        harness.context["initial_scenario"] = None
        query = history_fixtures.make_query(harness, lease["attempt_id"])
        context = harness.jobs.requested_context(harness.owner, query)
        wire, model = format_request(provider, context)
        findings = model["historical_context"]["attempts"][0]["findings"]
        assert [row["semantic_kind"] for row in findings] == ["observed_filesystem"]
        assert "record_count" not in findings[0]["summary"]
        assert "bundle.jsonl" not in wire.decode()
        assert str(workspace) not in wire.decode()
        assert model["historical_context"]["choices"] == context["historical_context"]["choices"]
        output = _receiver_fixture_output_for_request(json.loads(wire))
        selected = output["reconsideration"]["reconsidered_choices"][0]
        assert selected["step_id"] == "transform_fixture"
        assert selected["finding_refs"] == [
            {key: findings[0][key] for key in ("finding_id", "record_ref")}
        ]
        assert output["candidate"]["steps"][1]["parameters"] == {"redact_values": True}
        assert output["candidate"]["evidence_refs"] == ["policy", "refusal", "cleanup"]
        validate_reconsideration(output["reconsideration"], context)
        revised_graph = compile_revision(
            output["candidate"], **runtime_fixtures.compiler_args(state)
        )
        assert revised_graph["prior_attempt_id"] == lease["attempt_id"]
        knowledge = build_knowledge(
            harness.jobs,
            harness.owner,
            {
                "schema_version": QUERY_SCHEMA,
                "attempt_ids": [lease["attempt_id"]],
            },
        )
        assert knowledge["knowledge_digest"] == query["knowledge_digest"]
    finally:
        generator.close()
