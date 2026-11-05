"""Historical knowledge uses real sealed bundles, not live/native/provider proof."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.composition_knowledge import MAX_RESPONSE_BYTES, QUERY_SCHEMA, build_knowledge
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore
from bluefire.util import canonical_json_bytes, content_hash

OWNER = "job-" + "a" * 32
GRANT = "grant-" + "b" * 32
GRANT_DIGEST = content_hash("reviewed grant")


class ReadOnlyStore:
    def __init__(self):
        self.jobs = {
            OWNER: {
                "job_id": OWNER,
                "kind": "composition.objective",
                "state": "completed",
                "request": {"grant_id": GRANT, "grant_digest": GRANT_DIGEST},
                "progress": {"admission": {"accepted": True, "problem": None}, "stopped": True},
            }
        }
        self.attempts = {}

    def get_job(self, identifier):
        return deepcopy(self.jobs[identifier])

    def get_capability_attempt(self, identifier):
        return deepcopy(self.attempts[identifier])

    def __getattr__(self, name):
        raise AssertionError("Knowledge lookup must not invoke " + name)


@pytest.fixture
def saved(tmp_path):
    store = ReadOnlyStore()
    runs = RunStore(tmp_path / "runs")
    jobs = SimpleNamespace(
        store=store, service=SimpleNamespace(detection_lab=SimpleNamespace(run_store=runs))
    )
    return jobs, runs


def record(
    run_id,
    index=0,
    *,
    producer="collector.filesystem.sandbox.v1",
    provenance=EvidenceProvenance.OBSERVED,
    content=None,
):
    return EvidenceRecord.create(
        run_id=run_id,
        step_id="discover",
        behavior_id="sandbox.inspect.file.v1",
        action_id="sandbox.inspect.file.v1",
        provenance=provenance,
        producer=producer,
        content=(
            content
            if content is not None
            else {
                "artifact_type": "collector_observation",
                "observation_kind": "filesystem",
                "observed_fields": {
                    "path": "private-name.jsonl",
                    "size_bytes": 200 + index,
                    "sha256": content_hash("owned content"),
                    "permission_status": "available",
                    "effective_access": "not_evaluated",
                    "permission_mode_octal": "0640",
                },
            }
        ),
        timestamp="2026-10-01T00:00:00Z",
        target_scope_ref="generated-fixture",
        environment={"private": "never project environment"},
    )


def add_attempt(
    saved, *, number=1, records=None, status="failed", finalized=True, corrupt_record=False
):
    jobs, runs = saved
    attempt_id = "attempt-" + f"{number:032x}"
    job_id = "job-" + f"{number:032x}"
    run_id = runs._new_run_id()
    scenario = {
        "schema_version": "bluefire.scenario.v1",
        "id": "history",
        "steps": [{"id": "discover"}],
    }
    plan = {"schema_version": "bluefire.plan.v1", "autonomy": "off", "steps": []}
    compiled = {"grant_id": GRANT, "grant_digest": GRANT_DIGEST, "scenario": scenario}
    compiled["compiled_digest"] = content_hash(compiled)
    lease = {
        "attempt_id": attempt_id,
        "job_id": job_id,
        "run_id": run_id,
        "grant_id": GRANT,
        "grant_digest": GRANT_DIGEST,
        "compiled_digest": compiled["compiled_digest"],
        "plan_digest": content_hash(plan),
        "native_envelope_digest": content_hash("owned envelope"),
    }
    lease["lease_digest"] = content_hash(lease)
    claim = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        **{
            key: lease[key]
            for key in (
                "attempt_id",
                "run_id",
                "grant_id",
                "grant_digest",
                "compiled_digest",
                "plan_digest",
                "native_envelope_digest",
                "lease_digest",
            )
        },
        "issued_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-10-01T00:01:00Z",
    }
    handle = runs.create_run(
        scenario=scenario,
        plan=plan,
        policy={"grant_attempt": claim},
        profile=None,
        _reserved_run_id=run_id,
    )
    actual = records(run_id) if records is not None else [record(run_id)]
    evidence = [row.to_dict() for row in actual]
    if corrupt_record:
        evidence[0]["record_hash"] = content_hash("tampered")
    if finalized:
        runs.finalize(
            run_id,
            result={
                "schema_version": "bluefire.run-result.v1",
                "status": status,
                "mode": "execute",
            },
            evidence=evidence,
            detections=[],
        )
    jobs.store.jobs[job_id] = {
        "job_id": job_id,
        "kind": "composition.attempt",
        "state": "failed",
        "request": {
            "composition_attempt": {
                "parent_job_id": OWNER,
                **{
                    key: lease[key]
                    for key in (
                        "attempt_id",
                        "run_id",
                        "grant_id",
                        "grant_digest",
                        "compiled_digest",
                    )
                },
            }
        },
        "progress": {"failure": "late route dead end"},
    }
    jobs.store.attempts[attempt_id] = {
        "lease": lease,
        "compiled": compiled,
        "state": "settled",
        "claim": {"document": claim, "document_digest": content_hash(claim)},
    }
    return attempt_id, handle, actual


def query(*identities):
    return {"schema_version": QUERY_SCHEMA, "attempt_ids": list(identities)}


def test_failed_finalized_findings_remain_useful_and_original_state_is_unchanged(saved):
    jobs, _ = saved
    attempt_id, handle, records = add_attempt(saved)
    before_files = {path.name: path.read_bytes() for path in handle.path.iterdir()}
    before_store = deepcopy(jobs.store.__dict__)
    result = build_knowledge(jobs, OWNER, query(attempt_id))
    attempt = result["attempts"][0]
    assert attempt["source_status"] == "verified"
    assert (attempt["state"], attempt["job_state"], attempt["run_status"]) == (
        "settled",
        "failed",
        "failed",
    )
    finding = attempt["findings"][0]
    assert finding["semantic_kind"] == "observed_filesystem"
    assert finding["summary"] == {
        "size_bytes": 200,
        "sha256": content_hash("owned content"),
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": "0640",
    }
    assert finding["applicability"] == {
        "status": "historical_only",
        "reason": "current_state_not_verified",
    }
    assert finding["record_ref"] == {
        "owner_id": OWNER,
        "attempt_id": attempt_id,
        "job_id": "job-" + f"{1:032x}",
        "run_id": handle.run_id,
        "evidence_id": records[0].evidence_id,
        "record_hash": records[0].record_hash,
        "source_binding_digest": content_hash(attempt["source_binding"]),
    }
    assert finding["finding_id"] == "finding-" + content_hash(finding["record_ref"]).split(":")[1]
    assert result["knowledge_digest"] == content_hash(
        {key: value for key, value in result.items() if key != "knowledge_digest"}
    )
    assert before_files == {path.name: path.read_bytes() for path in handle.path.iterdir()}
    assert before_store == jobs.store.__dict__


def test_multiple_attempts_preserve_order_and_distinct_source_identity(saved):
    jobs, _ = saved
    first, _, _ = add_attempt(saved)
    second, _, _ = add_attempt(saved, number=2, status="completed")
    result = build_knowledge(jobs, OWNER, query(second, first))
    assert [row["attempt_id"] for row in result["attempts"]] == [second, first]
    assert [row["run_status"] for row in result["attempts"]] == ["completed", "failed"]
    assert len({row["findings"][0]["finding_id"] for row in result["attempts"]}) == 2


def test_changed_environment_and_revoked_grant_do_not_promote_historical_bytes(saved):
    jobs, _ = saved
    attempt_id, _, _ = add_attempt(saved)
    original = build_knowledge(jobs, OWNER, query(attempt_id))
    jobs.service.current_environment = {"generation": "replacement", "permission": "denied"}
    jobs.store.jobs[OWNER]["progress"].update(stopped=True, grant_status="revoked")
    assert build_knowledge(jobs, OWNER, query(attempt_id)) == original
    assert original["attempts"][0]["findings"][0]["applicability"]["status"] == "historical_only"


@pytest.mark.parametrize(
    "change",
    [
        lambda store, key: store.jobs["job-" + f"{1:032x}"]["request"][
            "composition_attempt"
        ].update(parent_job_id="job-" + "f" * 32),
        lambda store, key: store.attempts[key]["lease"].update(grant_id="grant-" + "f" * 32),
        lambda store, key: store.attempts[key]["lease"].update(
            grant_digest=content_hash("other grant")
        ),
        lambda store, key: store.attempts[key]["lease"].update(attempt_id="attempt-" + "f" * 32),
        lambda store, key: store.jobs["job-" + f"{1:032x}"]["request"][
            "composition_attempt"
        ].update(run_id="run-other"),
        lambda store, key: store.attempts[key]["compiled"].update(grant_id="grant-" + "f" * 32),
        lambda store, key: store.jobs["job-" + f"{1:032x}"].update(kind="unrelated"),
    ],
)
def test_cross_objective_or_mismatched_membership_is_refused_before_source_read(
    saved, change, monkeypatch
):
    jobs, _ = saved
    attempt_id, _, _ = add_attempt(saved)
    change(jobs.store, attempt_id)
    monkeypatch.setattr(
        "bluefire.composition_knowledge._source",
        lambda *_: pytest.fail("source read before membership validation"),
    )
    with pytest.raises(ProductStoreError):
        build_knowledge(jobs, OWNER, query(attempt_id))


@pytest.mark.parametrize(
    "query_value",
    [
        {},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": []},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": ["attempt-" + "1" * 32] * 2},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": [f"attempt-{i:032x}" for i in range(9)]},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": ["../other"]},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": [None]},
        {
            "schema_version": "bluefire.composition-knowledge-query.v2",
            "attempt_ids": ["attempt-" + "1" * 32],
        },
        {"schema_version": QUERY_SCHEMA, "attempt_ids": ["attempt-" + "1" * 32], "current": True},
        {"schema_version": QUERY_SCHEMA, "attempt_ids": "attempt-" + "1" * 32},
    ],
)
def test_query_is_exact_bounded_and_contains_no_caller_facts(saved, query_value):
    with pytest.raises(ProductStoreError):
        build_knowledge(saved[0], OWNER, query_value)


@pytest.mark.parametrize(
    "problem",
    [
        "unfinalized",
        "missing_manifest",
        "tampered_file",
        "tampered_record",
        "claim",
        "plan",
        "scenario",
        "policy",
        "claim_identity",
    ],
)
def test_unverifiable_sources_are_explicitly_unavailable_without_findings(saved, problem):
    jobs, runs = saved
    attempt_id, handle, _ = add_attempt(
        saved, finalized=problem != "unfinalized", corrupt_record=problem == "tampered_record"
    )
    if problem == "missing_manifest":
        (handle.path / "manifest.json").unlink()
    elif problem == "tampered_file":
        (handle.path / "evidence.json").write_text("{}", encoding="utf-8")
    elif problem == "claim":
        jobs.store.attempts[attempt_id]["claim"]["document_digest"] = content_hash("bad claim")
    elif problem == "claim_identity":
        claim = jobs.store.attempts[attempt_id]["claim"]
        claim["document"]["attempt_id"] = "attempt-" + "f" * 32
        claim["document_digest"] = content_hash(claim["document"])
    elif problem == "plan":
        jobs.store.attempts[attempt_id]["lease"]["plan_digest"] = content_hash("other plan")
    elif problem == "scenario":
        jobs.store.attempts[attempt_id]["compiled"]["scenario"] = {"id": "other"}
    elif problem == "policy":
        runs.write_json(handle.run_id, "policy.json", {"grant_attempt": {}})
        run = json.loads((handle.path / "result.json").read_text())
        records = json.loads((handle.path / "evidence.json").read_text())["records"]
        runs.finalize(handle.run_id, result=run, evidence=records, detections=[])
    response = build_knowledge(jobs, OWNER, query(attempt_id))["attempts"][0]
    assert response["source_status"] == "unavailable"
    assert response["source_binding"] is None and response["run_status"] is None
    assert response["findings"] == [] and response["findings_total"] == 0
    assert response["findings_truncated"] is False
    assert (
        response["problem"]
        == "The finalized source and its original attempt could not be verified."
    )


def test_cap_truncation_is_explicit_and_metadata_has_no_raw_payloads(saved):
    jobs, _ = saved
    attempt_id, _, _ = add_attempt(saved, records=lambda run: [record(run, i) for i in range(40)])
    result = build_knowledge(jobs, OWNER, query(attempt_id))
    attempt = result["attempts"][0]
    assert len(attempt["findings"]) == 32
    assert attempt["findings_total"] == 40 and attempt["findings_truncated"] is True
    encoded = canonical_json_bytes(result)
    assert len(encoded) < MAX_RESPONSE_BYTES
    assert b"private-name" not in encoded and b"never project" not in encoded
    assert [row["summary"]["size_bytes"] for row in attempt["findings"]] == list(range(200, 232))


def test_same_shape_is_not_same_semantics_and_optional_outputs_are_not_invented(saved):
    def values(run):
        return [
            record(run, producer="unknown-research-tool"),
            record(
                run,
                provenance=EvidenceProvenance.EXECUTED,
                producer="bluefire-rust-runner",
                content={
                    "runner_status": "failed",
                    "stderr": {"text": "secret log"},
                    "output": None,
                },
            ),
            record(
                run,
                provenance=EvidenceProvenance.UNKNOWN,
                content={"artifact_type": "evidence_gap", "reason": "private failure path"},
            ),
            record(
                run,
                provenance=EvidenceProvenance.OBSERVED,
                producer="collector.fixture-log.v1",
                content={
                    "artifact_type": "fixture_log_event",
                    "event": {"password": "not model context"},
                },
            ),
        ]

    attempt_id, _, _ = add_attempt(saved, records=values)
    response = build_knowledge(saved[0], OWNER, query(attempt_id))
    findings = response["attempts"][0]["findings"]
    assert [row["semantic_kind"] for row in findings] == [
        "record_metadata",
        "runner_result",
        "evidence_gap",
        "record_metadata",
    ]
    assert [row["summary"] for row in findings] == [
        {},
        {"runner_status": "failed"},
        {"observation_available": False},
        {},
    ]
    assert [row["provenance"] for row in findings] == [
        "observed",
        "executed",
        "unknown",
        "observed",
    ]
    assert b"secret log" not in canonical_json_bytes(response)
    assert b"private failure" not in canonical_json_bytes(response)
    assert b"password" not in canonical_json_bytes(response)


def test_overlarge_or_wrongly_typed_summary_fields_are_omitted_not_coerced(saved):
    content = {
        "artifact_type": "collector_observation",
        "observation_kind": "filesystem",
        "observed_fields": {
            "size_bytes": True,
            "sha256": "x" * 100000,
            "permission_mode_octal": "77777",
            "effective_access": "allowed",
            "non_owner_write_bit": "false",
            "permission_status": "available",
        },
    }
    attempt_id, _, _ = add_attempt(saved, records=lambda run: [record(run, content=content)])
    result = build_knowledge(saved[0], OWNER, query(attempt_id))
    assert result["attempts"][0]["findings"][0]["summary"] == {"permission_status": "available"}
    assert len(canonical_json_bytes(result)) < 5000


def test_unsettled_interrupted_attempt_does_not_lose_finalized_observations(saved):
    jobs, _ = saved
    attempt_id, _, _ = add_attempt(saved, status="interrupted")
    jobs.store.attempts[attempt_id]["state"] = "claimed"
    jobs.store.jobs["job-" + f"{1:032x}"]["state"] = "interrupted"
    result = build_knowledge(jobs, OWNER, query(attempt_id))["attempts"][0]
    assert result["source_status"] == "verified" and len(result["findings"]) == 1
    assert result["state"] == "claimed" and result["run_status"] == "interrupted"


@pytest.mark.parametrize("malformed_kind", [[], {"kind": "filesystem"}, None])
def test_unknown_semantic_discriminator_does_not_erase_other_valid_findings(saved, malformed_kind):
    def values(run):
        good = record(run)
        malformed = record(
            run,
            content={"artifact_type": "collector_observation", "observation_kind": malformed_kind},
        )
        return [good, malformed]

    attempt_id, _, _ = add_attempt(saved, records=values)
    response = build_knowledge(saved[0], OWNER, query(attempt_id))["attempts"][0]
    assert response["source_status"] == "verified"
    assert [row["semantic_kind"] for row in response["findings"]] == [
        "observed_filesystem",
        "record_metadata",
    ]
    assert response["findings"][0]["summary"]["size_bytes"] == 200


@pytest.mark.parametrize("state", ["planning", "paused", "awaiting_approval"])
def test_existing_job_states_do_not_hide_finalized_history(saved, state):
    jobs, _ = saved
    attempt_id, _, _ = add_attempt(saved, status="incomplete")
    jobs.store.jobs["job-" + f"{1:032x}"]["state"] = state
    response = build_knowledge(jobs, OWNER, query(attempt_id))["attempts"][0]
    assert response["source_status"] == "verified"
    assert response["job_state"] == state and response["run_status"] == "incomplete"


def test_known_collector_fields_retain_their_distinct_meanings(saved):
    def values(run):
        return [
            record(
                run,
                producer=producer,
                content={
                    "artifact_type": "collector_observation",
                    "observation_kind": kind,
                    "observed_fields": fields,
                },
            )
            for producer, kind, fields in (
                (
                    "collector.collection-semantics.sandbox.v1",
                    "collection_semantics",
                    {
                        "container": "gzip",
                        "record_count": 12,
                        "redacted_record_count": 5,
                        "sha256": content_hash("archive"),
                        "record_values": ["never retain values"],
                    },
                ),
                (
                    "collector.process.native.v1",
                    "process",
                    {
                        "process_id": 40,
                        "parent_process_id": 39,
                        "platform": "linux",
                        "command_line": "never retain command",
                        "environment": {"token": "private"},
                    },
                ),
                (
                    "collector.network.loopback-receiver.v1",
                    "network",
                    {
                        "sha256": content_hash("received"),
                        "bytes_received": 17,
                        "receiver_process_id": 32,
                        "payload": "never retain packet",
                    },
                ),
            )
        ]

    attempt_id, _, _ = add_attempt(saved, records=values)
    response = build_knowledge(saved[0], OWNER, query(attempt_id))
    rows = response["attempts"][0]["findings"]
    assert [row["semantic_kind"] for row in rows] == [
        "observed_collection",
        "observed_process_snapshot",
        "observed_receiver_binding",
    ]
    assert rows[0]["summary"]["record_count"] == 12
    assert rows[1]["summary"] == {"process_id": 40, "parent_process_id": 39, "platform": "linux"}
    assert rows[2]["summary"]["bytes_received"] == 17
    assert b"never retain" not in canonical_json_bytes(response)


def test_file_access_runner_report_is_not_relabelled_independent_observation(saved):
    def values(run):
        return [
            EvidenceRecord.create(
                run_id=run,
                step_id="probe",
                behavior_id="file_access.probe.non_owner.v1",
                action_id="file_access.probe.non_owner.v1",
                provenance=EvidenceProvenance.EXECUTED,
                producer="bluefire-rust-runner",
                target_scope_ref="generated-fixture",
                content={
                    "runner_status": "success",
                    "output": {
                        "observation": {
                            "schema_version": "bluefire.file-access-observation.v1",
                            "reader": "non_owner",
                            "outcome": "permission_denied",
                            "mode": "0600",
                            "control_revision": 2,
                            "record_count": None,
                            "sha256": None,
                            "challenge": "never project challenge",
                        }
                    },
                },
            )
        ]

    attempt_id, _, _ = add_attempt(saved, records=values)
    response = build_knowledge(saved[0], OWNER, query(attempt_id))
    row = response["attempts"][0]["findings"][0]
    assert row["semantic_kind"] == "runner_result" and row["provenance"] == "executed"
    assert row["summary"] == {
        "runner_status": "success",
        "reported_reader": "non_owner",
        "reported_outcome": "permission_denied",
        "reported_mode": "0600",
        "reported_control_revision": 2,
    }
    assert "reported_sha256" not in row["summary"] and "reported_record_count" not in row["summary"]
    assert row["applicability"]["status"] == "historical_only"
