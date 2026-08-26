from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.ai import AIProposal
from bluefire.contracts import load_scenario
from bluefire.detections import DetectionCandidate
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "scenarios" / "sandbox_research_chain.yaml"


def _expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()


def _review_proposal() -> dict[str, object]:
    return AIProposal.from_mapping(
        {
            "schema_version": "bluefire.ai-proposal.v2",
            "proposal_type": "select_registered",
            "selected_step_id": "next_step",
            "selected_behavior_id": "sandbox.discovery.v1",
            "selected_action_id": None,
            "selected_edge": None,
            "parameter_changes": [],
            "rationale": "registered alternate",
            "alternatives": [],
            "confidence": 0.8,
            "requires_operator_review": True,
        }
    ).to_dict()


def _review_record(proposal: dict[str, object], *, suffix: str) -> dict[str, object]:
    policy = {
        "schema_version": "bluefire.ai-proposal-policy.v1",
        "mode": "simulate",
        "maximum_adaptive_retries": 1,
    }
    return {
        "schema_version": "bluefire.ai-proposal-record.v2",
        "run_id": f"run-20260824T00000{suffix}Z-" + suffix * 16,
        "application_status": "awaiting_operator_approval",
        "autonomy": "assist",
        "state_digest": "sha256:" + "1" * 64,
        "plan_digest": "sha256:" + "2" * 64,
        "proposal_digest": content_hash(proposal),
        "proposal_policy": policy,
        "proposal_policy_digest": content_hash(policy),
        "proposal_policy_evaluation": {
            "status": "permitted",
            "policy_digest": content_hash(policy),
        },
        "allowed_step_ids": ["next_step"],
        "allowed_behavior_ids": ["sandbox.discovery.v1"],
        "allowed_action_ids": [],
        "allowed_edges": [],
        "allowed_parameter_schemas": {},
        "retryable_step_ids": [],
        "registered_options": [
            {
                "role": "next",
                "step_id": "next_step",
                "behavior_ids": ["sandbox.discovery.v1"],
                "action_ids_by_behavior": {"sandbox.discovery.v1": []},
                "parameter_schemas": {},
                "edge": None,
            }
        ],
        "proposal": proposal,
    }


def test_store_migrates_and_persists_secret_safe_settings(tmp_path: Path) -> None:
    path = tmp_path / "state" / "bluefire.db"
    store = ProductStore(path)

    assert store.schema_version == 5
    store.set_setting(
        "ai.provider",
        {"endpoint": "https://api.example.test/v1", "api_key": {"env": "BLUEFIRE_API_KEY"}},
    )
    assert ProductStore(path).get_setting("ai.provider")["api_key"] == {"env": "BLUEFIRE_API_KEY"}

    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        store.set_setting(
            "ai.provider",
            {"api_key": "plaintext-secret"},  # pragma: allowlist secret
        )


def test_scenario_versions_are_content_addressed_and_retrievable(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    original = load_scenario(SCENARIO).to_dict()

    first = store.save_scenario(original)
    duplicate = store.save_scenario(original)
    changed = dict(original, title="Neutral sandbox research chain — revision")
    second = store.save_scenario(changed)

    assert first["version"] == duplicate["version"] == 1
    assert second["version"] == 2
    assert store.get_scenario(str(first["scenario_id"]))["version"] == 2
    assert (
        store.get_scenario(str(first["scenario_id"]), 1)["document"]["title"] == original["title"]
    )
    assert len(store.list_scenarios()) == 1


def test_resources_round_trip_and_reject_plaintext_credentials(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    saved = store.save_resource(
        "research_source",
        "mitre.attack.enterprise",
        {
            "name": "MITRE ATT&CK Enterprise",
            "version": "19.2",
            "license": "ATT&CK Terms of Use",
            "enabled": True,
        },
    )

    assert saved["digest"].startswith("sha256:")
    assert (
        store.get_resource("research_source", "mitre.attack.enterprise")["document"]["version"]
        == "19.2"
    )
    assert len(store.list_resources("research_source")) == 1
    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        store.save_resource(
            "model_provider",
            "provider.local",
            {"credentials": "do-not-store"},
        )


def test_failed_detection_revision_builder_does_not_reserve_an_ordinal(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    origin = DetectionCandidate.hypothesis(
        behavior_id="sandbox.collection.stage.v1",
        title="Origin",
        target_language="internal",
        logsource={"category": "file_event", "product": "generic"},
        selection={"path|contains": "staged/"},
        provenance={"source": "operator-authored", "license": "MIT"},
    )
    store.save_resource(
        "detection",
        origin.candidate_id,
        origin.to_dict(),
        status=origin.state.value,
    )

    def fail_builder(_revision: int) -> dict[str, object]:
        raise RuntimeError("simulated builder failure")

    with pytest.raises(RuntimeError, match="simulated builder failure"):
        store.save_detection_revision(
            origin.candidate_id,
            fail_builder,
            max_revisions=8,
        )

    def valid_builder(revision: int) -> dict[str, object]:
        return DetectionCandidate.hypothesis(
            behavior_id=origin.behavior_id,
            title="First durable clone",
            target_language=origin.target_language,
            logsource=origin.logsource,
            selection=origin.selection,
            provenance=origin.provenance,
            revision=revision,
            revision_root_id=origin.candidate_id,
            parent_candidate_id=origin.candidate_id,
            revision_kind="clone",
        ).to_dict()

    saved = store.save_detection_revision(
        origin.candidate_id,
        valid_builder,
        max_revisions=8,
    )

    assert saved["document"]["revision"] == 2
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "SELECT revision FROM detection_revisions ORDER BY revision"
        ).fetchall()
    assert rows == [(1,), (2,)]


@pytest.mark.parametrize(
    "field",
    [
        "access_token",
        "refreshToken",
        "client_secret_value",
        "bearer",
        "auth",
        "nested-password",
    ],
)
def test_nested_secret_shaped_fields_cannot_persist_plaintext(
    tmp_path: Path,
    field: str,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        store.set_setting("provider.private", {"nested": {field: "plaintext-value"}})

    stored = store.set_setting(
        "provider.reference",
        {"nested": {field: {"env": "BLUEFIRE_TEST_CREDENTIAL"}}},
    )
    assert stored["value"]["nested"][field] == {"env": "BLUEFIRE_TEST_CREDENTIAL"}


@pytest.mark.parametrize(
    "credential",
    [
        "ghp_FAKECREDENTIALVALUE123456789",  # pragma: allowlist secret
        "github_pat_FAKE_CREDENTIAL_VALUE_123456789",  # pragma: allowlist secret
        "sk-FAKECREDENTIALVALUE1234567890",  # pragma: allowlist secret
        "xoxb-FAKE-CREDENTIAL-1234567890",  # pragma: allowlist secret
        "AKIAFAKECREDENTIAL12",  # pragma: allowlist secret
        "eyJFAKEHEADER.eyJFAKEPAYLOAD.eyJFAKESIGNATURE",  # pragma: allowlist secret
        "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",  # pragma: allowlist secret
        "https://operator:plaintext@example.test/v1",  # pragma: allowlist secret
    ],
)
def test_credential_shaped_values_cannot_hide_under_benign_fields(
    tmp_path: Path,
    credential: str,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")

    with pytest.raises(ProductStoreError, match="credential-shaped plaintext value"):
        store.save_resource(
            "collector",
            "collector.secret-scan.v1",
            {"label": credential},
        )


def test_secret_value_scan_allows_noncredential_near_misses(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    saved = store.save_resource(
        "collector",
        "collector.safe-values.v1",
        {
            "label": "sk-short",
            "endpoint": "https://collector.example.test/v1",
            "opaque_identifier": "eyJ.not-a-jwt",
        },
    )

    assert saved["document"]["label"] == "sk-short"


def test_schema_v1_database_migrates_to_claimable_approvals(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-08-23T00:00:00Z');
        CREATE TABLE approval_requests (
            approval_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            state_digest TEXT NOT NULL,
            plan_digest TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            target_scope_digest TEXT NOT NULL,
            maximum_tier TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_at TEXT,
            approved_by TEXT,
            nonce TEXT UNIQUE,
            consumed_at TEXT
        );
        """)
    connection.commit()
    connection.close()

    store = ProductStore(path)

    assert store.schema_version == 5
    columns = {
        row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(approval_requests)")
    }
    assert "claimed_at" in columns


def test_approval_is_bound_to_exact_state_and_consumed_once(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    pending = store.create_approval_request(
        run_id="run-01",
        state_digest="sha256:state",
        plan_digest="sha256:plan",
        profile_id="sandbox-execute.v1",
        target_scope_digest="sha256:scope",
        maximum_tier="controlled",
        expires_at=_expiry(),
    )

    with pytest.raises(ProductStoreError, match="exact plan and target scope"):
        store.approve(
            str(pending["approval_id"]),
            approved_by="operator",
            expected_state_digest="sha256:changed",
            expected_plan_digest="sha256:plan",
            expected_target_scope_digest="sha256:scope",
        )

    approved = store.approve(
        str(pending["approval_id"]),
        approved_by="operator",
        expected_state_digest="sha256:state",
        expected_plan_digest="sha256:plan",
        expected_target_scope_digest="sha256:scope",
    )
    assert approved["status"] == "approved"
    assert approved["nonce"]

    consumed = store.consume_approval(
        str(pending["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest="sha256:state",
        expected_plan_digest="sha256:plan",
        expected_target_scope_digest="sha256:scope",
    )
    assert consumed["status"] == "consumed"
    with pytest.raises(ProductStoreError, match="already been consumed"):
        store.consume_approval(
            str(pending["approval_id"]),
            nonce=str(approved["nonce"]),
            expected_state_digest="sha256:state",
            expected_plan_digest="sha256:plan",
            expected_target_scope_digest="sha256:scope",
        )

    claimed = store.claim_consumed_approval(
        str(pending["approval_id"]),
        nonce=str(approved["nonce"]),
        approved_by="operator",
        expected_state_digest="sha256:state",
        expected_plan_digest="sha256:plan",
        expected_target_scope_digest="sha256:scope",
        expected_profile_id="sandbox-execute.v1",
        expected_maximum_tier="controlled",
    )
    assert claimed["status"] == "claimed"
    assert claimed["claimed_at"]
    recovery_expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    renewed = store.renew_claimed_approval_for_cleanup(
        str(pending["approval_id"]),
        expires_at=recovery_expiry,
        expected_state_digest="sha256:state",
        expected_plan_digest="sha256:plan",
        expected_target_scope_digest="sha256:scope",
        expected_profile_id="sandbox-execute.v1",
        expected_maximum_tier="controlled",
    )
    assert renewed["expires_at"] == recovery_expiry

    workspace = tmp_path / "sandbox" / ".bluefire-executions" / str(pending["approval_id"])
    workspace.mkdir(parents=True)
    bound = store.bind_execution_workspace(
        str(pending["approval_id"]),
        profile_id="sandbox-execute.v1",
        workspace_path=workspace,
        runner_identity={"transport": "test.runner", "cleanup_action_digest": "sha256:test"},
        recovery_context={"scenario": {"id": "scenario.test.v1"}},
    )
    assert bound["workspace_path"] == str(workspace.resolve())
    assert bound["state"] == "active"
    assert store.list_execution_workspaces(states={"active"}) == [bound]

    run_id = "run-20260824T000000Z-" + "a" * 16
    attached = store.transition_execution_workspace(
        str(pending["approval_id"]),
        "active",
        run_id=run_id,
    )
    assert attached["run_id"] == run_id
    completed = store.transition_execution_workspace(
        str(pending["approval_id"]),
        "completed",
        run_id=run_id,
        outcome={"status": "completed", "remaining_receipt_count": 0},
    )
    assert completed["state"] == "completed"
    with pytest.raises(ProductStoreError, match="immutable"):
        store.transition_execution_workspace(
            str(pending["approval_id"]),
            "active",
            run_id=run_id,
        )
    with pytest.raises(ProductStoreError, match="already claimed"):
        store.claim_consumed_approval(
            str(pending["approval_id"]),
            nonce=str(approved["nonce"]),
            approved_by="operator",
            expected_state_digest="sha256:state",
            expected_plan_digest="sha256:plan",
            expected_target_scope_digest="sha256:scope",
            expected_profile_id="sandbox-execute.v1",
            expected_maximum_tier="controlled",
        )


def test_jobs_have_strict_transitions_and_restart_recovery(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    job = store.create_job("scenario.run", {"mode": "simulate"})
    job = store.transition_job(str(job["job_id"]), "planning")
    job = store.transition_job(str(job["job_id"]), "running", progress={"step": 1})

    assert job["progress"] == {"step": 1}
    assert ProductStore(tmp_path / "bluefire.db").recover_interrupted_jobs() == 1
    assert store.get_job(str(job["job_id"]))["state"] == "interrupted"
    with pytest.raises(ProductStoreError, match="cannot transition"):
        store.transition_job(str(job["job_id"]), "completed")


def test_cancelling_job_requires_explicit_durable_completion_proof(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    job = store.create_job("scenario.run", {"mode": "execute"})
    job_id = str(job["job_id"])
    store.transition_job(job_id, "planning")
    store.transition_job(job_id, "running")
    store.transition_job(job_id, "cancelling")

    with pytest.raises(ProductStoreError, match="confirmed durable completion"):
        store.transition_job(job_id, "completed")

    completed = store.transition_job(
        job_id,
        "completed",
        result_ref="run-example-01",
        completion_confirmed=True,
    )
    assert completed["state"] == "completed"
    assert completed["result_ref"] == "run-example-01"


def test_ai_proposal_reviews_bind_exact_digests_and_are_one_time(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    job = store.create_job("scenario.run", {"mode": "simulate"})
    proposal = _review_proposal()
    record = _review_record(proposal, suffix="0")

    review = store.create_ai_proposal_review(
        job_id=str(job["job_id"]),
        source_run_id=str(record["run_id"]),
        record=record,
    )
    duplicate = store.create_ai_proposal_review(
        job_id=str(job["job_id"]),
        source_run_id=str(record["run_id"]),
        record=record,
    )

    assert review["proposal_record_id"] == duplicate["proposal_record_id"]
    assert review["status"] == "pending"
    resolved = store.resolve_ai_proposal_review(
        str(review["proposal_record_id"]),
        job_id=str(job["job_id"]),
        decision="accepted",
        decided_by="operator",
        expected_state_digest=str(review["state_digest"]),
        expected_plan_digest=str(review["plan_digest"]),
        expected_proposal_digest=str(review["proposal_digest"]),
        resolution={"decision": "accepted", "approval_request_id": None},
    )
    assert resolved["status"] == "accepted"
    assert resolved["decided_by"] == "operator"
    with pytest.raises(ProductStoreError, match="stale or already resolved"):
        store.resolve_ai_proposal_review(
            str(review["proposal_record_id"]),
            job_id=str(job["job_id"]),
            decision="rejected",
            decided_by="operator",
            expected_state_digest=str(review["state_digest"]),
            expected_plan_digest=str(review["plan_digest"]),
            expected_proposal_digest=str(review["proposal_digest"]),
            resolution={"decision": "rejected"},
        )


def test_ai_proposal_review_rejects_tampered_or_executable_content(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    job = store.create_job("scenario.run", {"mode": "simulate"})
    proposal = _review_proposal()
    record = _review_record(proposal, suffix="1")
    proposal["command"] = "do-not-run"
    record["proposal_digest"] = content_hash(proposal)
    with pytest.raises(ProductStoreError, match="strict contract validation"):
        store.create_ai_proposal_review(
            job_id=str(job["job_id"]),
            source_run_id=str(record["run_id"]),
            record=record,
        )
    proposal.pop("command")
    with pytest.raises(ProductStoreError, match="strict contract validation"):
        store.create_ai_proposal_review(
            job_id=str(job["job_id"]),
            source_run_id=str(record["run_id"]),
            record=record,
        )
    proposal["selected_behavior_id"] = "unregistered.behavior.v1"
    record["proposal_digest"] = content_hash(proposal)
    with pytest.raises(ProductStoreError, match="strict contract validation"):
        store.create_ai_proposal_review(
            job_id=str(job["job_id"]),
            source_run_id=str(record["run_id"]),
            record=record,
        )


@pytest.mark.parametrize("state", ["queued", "planning", "awaiting_approval"])
def test_restart_recovery_interrupts_jobs_whose_callbacks_were_lost(
    tmp_path: Path, state: str
) -> None:
    store = ProductStore(tmp_path / f"{state}.db")
    job = store.create_job("scenario.run", {"mode": "execute"})
    job_id = str(job["job_id"])
    if state != "queued":
        store.transition_job(job_id, "planning")
    if state == "awaiting_approval":
        store.transition_job(job_id, "awaiting_approval")

    assert ProductStore(store.path).recover_interrupted_jobs() == 1
    assert store.get_job(job_id)["state"] == "interrupted"


def test_run_index_is_paginated_and_keeps_exactly_two_modes(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    base = {
        "scenario_id": "scenario.example.v1",
        "status": "completed",
        "objective_reached": True,
        "created_at": "2026-08-24T00:00:00Z",
    }
    store.index_run(dict(base, run_id="run-a", mode="simulate"))
    store.index_run(dict(base, run_id="run-b", mode="execute"))

    assert {item["mode"] for item in store.list_runs()} == {"simulate", "execute"}
    assert len(store.list_runs(limit=1)) == 1
    with pytest.raises(ProductStoreError, match="simulate or execute"):
        store.index_run(dict(base, run_id="run-c", mode="preview"))
