"""Use native snapshot fields without inventing a process-creation event."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from bluefire.collectors import CollectionRequest, CollectorReadiness, NativeProcessCollector
from bluefire.detection_backends import (
    DetectionBackendError,
    ExternalDetectionValidator,
    execute_sqlite_query,
)
from bluefire.detections import DetectionCandidate, DetectionState
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.service import BlueFireService

QUERY = (
    "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation' "
    "AND observation_kind = 'process' "
    "AND \"observed_fields.executable_name\" LIKE 'python%' "
    'AND "observed_fields.process_id" > 0'
)
FIELDS = (
    "platform",
    "native_api",
    "process_id",
    "parent_process_id",
    "executable_name",
    "creation_identity",
)


def fixture(name: str = "python3.12") -> dict[str, Any]:
    return {
        "fixture_id": "synthetic-process",
        "artifact_type": "collector_observation",
        "observation_kind": "process",
        "observed_fields": {
            "platform": "linux",
            "native_api": "/proc/<pid>/stat",
            "process_id": 321,
            "parent_process_id": 123,
            "executable_name": name,
            "creation_identity": "174800",
        },
    }


def candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="endpoint.discovery.processes.v1",
        title="Python process snapshot",
        target_language="sqlite",
        logsource={"category": "process_snapshot"},
        selection={"observed_fields.executable_name|startswith": "python"},
        predicted_fields=("observed_fields.executable_name", "observed_fields.process_id"),
        provenance={"source": "operator-authored", "license": "MIT"},
    )


def test_native_fields_keep_their_nested_names_and_scalar_values() -> None:
    columns = ", ".join(f'"observed_fields.{field}"' for field in FIELDS)
    result = execute_sqlite_query(
        f"SELECT fixture_id, {columns} FROM logs "
        "WHERE \"observed_fields.platform\" = 'linux' "
        "AND \"observed_fields.native_api\" = '/proc/<pid>/stat' "
        'AND "observed_fields.process_id" = 321 '
        'AND "observed_fields.parent_process_id" = 123 '
        "AND \"observed_fields.executable_name\" = 'python3.12' "
        "AND \"observed_fields.creation_identity\" = '174800'",
        [fixture()],
    )
    assert result["matched_fixture_ids"] == ["synthetic-process"]
    assert result["mapped_fixture_fields"] == sorted(
        ["artifact_type", "observation_kind", *(f"observed_fields.{field}" for field in FIELDS)]
    )
    assert result["unsupported_fixture_fields"] == []


@pytest.mark.parametrize(
    "name,matches", [("python.exe", True), ("python3.12", True), ("sleep", False)]
)
def test_query_uses_actual_nested_process_name(name: str, matches: bool) -> None:
    result = execute_sqlite_query(QUERY, [fixture(name)])
    assert result["matched_fixture_ids"] == (["synthetic-process"] if matches else [])


def test_native_snapshot_does_not_manufacture_vendor_fields_or_command_lines() -> None:
    row = fixture()
    row["observed_fields"]["command_line"] = "unavailable invented input"
    result = execute_sqlite_query(
        "SELECT fixture_id FROM logs WHERE Image IS NOT NULL OR CommandLine IS NOT NULL "
        'OR ProcessId IS NOT NULL OR "process.executable" IS NOT NULL',
        [row],
    )
    assert result["matched_fixture_ids"] == []
    assert result["unsupported_fixture_fields"] == ["observed_fields.command_line"]


def test_conflicting_flat_and_nested_identity_is_refused() -> None:
    row = fixture()
    row["observed_fields.process_id"] = 999
    with pytest.raises(DetectionBackendError, match="more than once"):
        execute_sqlite_query(QUERY, [row])


@pytest.mark.parametrize("observed_dataset", [False, True])
def test_existing_select_star_fits_the_explicit_schema_limit(observed_dataset: bool) -> None:
    result = execute_sqlite_query(
        "SELECT * FROM logs", [fixture()], observed_dataset=observed_dataset
    )
    assert result["matched_fixture_ids"] == ["synthetic-process"]
    assert len(result["result_fields"]) == result["limits"]["result_fields"] == 70


def test_missing_snapshot_fields_are_unknown_not_zero_or_a_match() -> None:
    row = fixture()
    row["observed_fields"].pop("process_id")
    assert execute_sqlite_query(QUERY, [row])["matched_fixture_ids"] == []


def collect_owned_child(run_id: str) -> EvidenceRecord:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    child = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(15)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    try:
        result = NativeProcessCollector({child.pid: os.getpid()}).collect(
            CollectionRequest(
                run_id=run_id,
                step_id="observe",
                behavior_id="endpoint.discovery.processes.v1",
                runner_profile_id="profile.test",
                target_scope_ref="runner-profile:profile.test",
                settings={"process_id": child.pid, "expected_parent_process_id": os.getpid()},
            )
        )
    finally:
        child.terminate()
        child.wait(timeout=5)

    assert result.health.readiness is CollectorReadiness.READY
    assert len(result.records) == 1
    record = result.records[0]
    assert record.provenance is EvidenceProvenance.OBSERVED
    assert record.producer == "collector.process.native.v1"
    assert record.content["observed_fields"]["process_id"] == child.pid
    assert child.poll() is not None
    return record


@pytest.mark.skipif(
    sys.platform not in {"win32", "linux"},
    reason="the native snapshot collector supports Windows and Linux only",
)
def test_real_owned_child_observation_executes_in_sqlite() -> None:
    record = collect_owned_child("run-native-detection")
    validator = ExternalDetectionValidator()
    parsed = validator.parse_sqlite(candidate(), QUERY)
    assert parsed.state is DetectionState.PARSED
    observed = validator.exercise_query_observed(parsed, [record])
    assert observed.state is DetectionState.OBSERVED_EXERCISED
    assert observed.observed_evidence_ids == (record.evidence_id,)
    assert observed.match_count == 1
    assert observed.validation["source_rule_executed"] is True
    assert "observed_fields.executable_name" in observed.observed_fields


@pytest.mark.skipif(
    sys.platform not in {"win32", "linux"},
    reason="the native snapshot collector supports Windows and Linux only",
)
def test_native_observation_lifecycle_persists_source_and_benign_limit(tmp_path: Path) -> None:
    options = {
        "project_root": Path(__file__).resolve().parents[1],
        "runs_dir": tmp_path / "runs",
        "product_db_path": tmp_path / "product.sqlite3",
    }
    service = BlueFireService(**options)
    try:
        run = service.store.create_run(
            scenario={"schema_version": "test"},
            plan={"schema_version": "test"},
            policy={"schema_version": "test"},
            profile={"id": "profile.test"},
        )
        record = collect_owned_child(run.run_id)
        service.store.finalize(
            run.run_id,
            result={"schema_version": "test", "status": "completed"},
            evidence=[record.to_dict()],
            detections=[],
        )
        definition = candidate().to_dict()
        created = service.upsert_detection_hypothesis(
            {
                key: definition[key]
                for key in (
                    "behavior_id",
                    "title",
                    "target_language",
                    "logsource",
                    "selection",
                    "predicted_fields",
                    "provenance",
                )
            }
        )
        candidate_id = created["candidate"]["id"]
        service.parse_detection_candidate(candidate_id, {"source": QUERY})
        observed = service.exercise_detection_observed(
            candidate_id,
            {"run_id": run.run_id, "evidence_ids": [record.evidence_id]},
        )["candidate"]["document"]
        assert observed["state"] == "observed_exercised"
        assert observed["observed_evidence_ids"] == [record.evidence_id]
        assert observed["match_count"] == 1
        benign = fixture("python3.12")
        benign["fixture_id"] = "benign-interpreter"
        evaluated = service.evaluate_detection_benign(
            candidate_id,
            {
                "fixtures": [benign],
                "notes": [
                    "Synthetic benign interpreter also matches; process identity alone does not establish malicious activity."
                ],
            },
        )["candidate"]["document"]
        assert evaluated["benign_match_count"] == 1
        assert evaluated["state"] == "benign_evaluated"
        report = service.evaluate_detection_run(
            candidate_id,
            {
                "run_id": run.run_id,
                "question": "Does this query match the deliberately launched benign interpreter?",
                "case_role": "benign",
            },
        )["evaluation"]
        assert report["result"]["match_count"] == 1
        assert report["result"]["missing_fields"] == []
    finally:
        service.close()

    restored = BlueFireService(**options)
    try:
        saved = restored.detection_candidate(candidate_id)["candidate"]["document"]
        assert saved["observed_evidence_ids"] == [record.evidence_id]
        assert saved["benign_match_count"] == 1
        assert saved["lifecycle_history"] == evaluated["lifecycle_history"]
    finally:
        restored.close()
