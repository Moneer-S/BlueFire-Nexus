"""Pure checks for retained hooks extracted from the composition coordinator."""

from types import SimpleNamespace

from bluefire import retained_artifacts as retained
from bluefire.capability_resources import METHODS
from bluefire.evidence import EvidenceProvenance, EvidenceRecord, SandboxObserver
from tests_platform.test_capability_composition import state as state
from tests_platform.test_retained_artifact_execution import (
    OWNER_ID,
    sealed_source,
    trusted_jobs,
    v2_state,
)


def test_callbacks_keep_source_binding_and_publish_capture_to_claimed_job(state, tmp_path):
    store, source, payload = sealed_source(tmp_path)
    grant = v2_state(state)["grant"]
    jobs, _, _ = trusted_jobs(store, source, grant)
    new_run = store.create_run(scenario={}, plan={}, policy={}, profile={})
    lease = {
        "run_id": new_run.run_id,
        "attempt_id": "attempt-" + "f" * 32,
        "lineage_id": source["lineage_id"],
        "job_id": "job-claimed-capture",
    }
    captured_job = {"progress": {}}
    original_get_job = jobs.store.get_job
    jobs.store.get_job = lambda identifier: (
        captured_job if identifier == lease["job_id"] else original_get_job(identifier)
    )
    published = []

    def publish(identifier, values):
        published.append(identifier)
        captured_job["progress"].update(values)

    jobs._publish = publish
    checks = []
    materialize, retain_output = retained.execution_callbacks(
        jobs,
        marker={"attempt_id": lease["attempt_id"], "parent_job_id": OWNER_ID},
        compiled={"retained_sources": {"reuse": source}},
        grant=grant,
        current={"profile": SimpleNamespace(id="test-profile")},
        lease=lease,
        check=lambda: checks.append(True),
    )
    assert materialize(
        SimpleNamespace(step_id="reuse", parameters={"source_ref": source["source_ref"]})
    ) == {"source": source, "payload": payload}
    root = tmp_path / "callback-workspace"
    (root / "staged").mkdir(parents=True)
    (root / "staged/bundle.jsonl").write_bytes(payload)
    step = SimpleNamespace(step_id="stage", behavior_id=METHODS[4], action_id=METHODS[4])
    executed = EvidenceRecord.create(
        run_id=new_run.run_id,
        step_id="stage",
        behavior_id=METHODS[4],
        action_id=METHODS[4],
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="test-profile",
        target_scope_ref="runner-profile:test-profile",
        content={"runner_status": "success"},
    )
    artifact = {
        "type": source["artifact_type"],
        "path": "staged/bundle.jsonl",
        "format": "jsonl",
        "size": len(payload),
        "sha256": source["sha256"],
        "receipt_ids": ["d" * 64],
    }
    _, new_source = retain_output(step, artifact, SandboxObserver(root), executed)
    assert new_source["attempt_id"] == lease["attempt_id"]
    assert new_source["run_id"] == lease["run_id"]
    assert published == [lease["job_id"]]
    assert captured_job["progress"]["retained_artifact_capture"]["source"] == new_source
    assert len(checks) == 3
    assert retained.execution_callbacks(
        jobs, marker={}, compiled={}, grant=state["grant"], current={}, lease={}, check=lambda: None
    ) == (None, None)
