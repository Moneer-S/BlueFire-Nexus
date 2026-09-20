"""Observed local-file/query tests; no external adapter or live lab proof."""

from __future__ import annotations

import sys

import pytest

from bluefire import evidence as evidence_module
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.detection_backends import SQLITE_LOG_FIELDS
from tests_platform.test_detection_evaluations import evaluate, observed_run, query_candidate
from tests_platform.test_detection_evaluations import service as service


def test_permission_query_preserves_the_fixed_column_budget():
    assert len(SQLITE_LOG_FIELDS) == len(set(SQLITE_LOG_FIELDS)) == 64
    assert {"permission_status", "non_owner_write_bit"} <= set(SQLITE_LOG_FIELDS)


def test_absent_permission_bits_are_insufficient_not_a_negative_detection(
    service, tmp_path, monkeypatch
):
    # Deterministic unsupported-platform projection, not a Windows ACL claim.
    monkeypatch.setattr(
        evidence_module,
        "observed_permission_fields",
        lambda metadata: {
            "permission_status": "unavailable_windows",
            "effective_access": "not_evaluated",
        },
    )
    candidate_id = query_candidate(service, "non_owner_write_bit = 1")
    run_id, _ = observed_run(service, tmp_path)
    report = evaluate(service, candidate_id, run_id)
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["missing_fields"] == ["non_owner_write_bit"]
    assert report["result"]["match_count"] is None
    assert "required_observation_fields_unavailable" in report["result"]["diagnostic_codes"]


@pytest.mark.skipif(
    sys.platform not in {"linux", "darwin"}, reason="real POSIX metadata observation"
)
def test_query_distinguishes_relaxed_write_bits_from_benign_read_bits(service, tmp_path):
    candidate_id = query_candidate(
        service, "permission_status = 'available' AND non_owner_write_bit = 1"
    )
    reports = []
    for mode in (0o640, 0o666, 0o660):
        handle = service.store.create_run(
            scenario={"schema_version": "test"},
            plan={"schema_version": "test"},
            policy={"schema_version": "test"},
            profile={"id": "profile.unit"},
        )
        root = tmp_path / handle.run_id
        root.mkdir(mode=0o700)
        path = root / "permission-sample.txt"
        path.write_bytes(b"public observation test data")
        path.chmod(mode)
        records = (
            FilesystemCollector(root)
            .collect(
                CollectionRequest(
                    run_id=handle.run_id,
                    step_id="observe",
                    behavior_id="sandbox.collection.stage.v1",
                    runner_profile_id="profile.unit",
                    target_scope_ref="runner-profile:profile.unit",
                    settings={"paths": [path.name]},
                )
            )
            .records
        )
        service.store.finalize(
            handle.run_id,
            result={"status": "completed", "mode": "execute", "steps": []},
            evidence=[record.to_dict() for record in records],
            detections=[],
        )
        reports.append(evaluate(service, candidate_id, handle.run_id))
    assert [report["result"]["state"] for report in reports] == [
        "not_matched",
        "matched",
        "matched",
    ]
    assert all(report["backend"]["executed"] for report in reports)
    assert all(not report["result"]["missing_fields"] for report in reports)
