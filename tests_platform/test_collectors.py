from __future__ import annotations

import json
from pathlib import Path

import pytest

from bluefire.collectors import (
    CollectionRequest,
    CollectorError,
    CollectorReadiness,
    CollectorRegistry,
    FilesystemCollector,
    JsonLinesFixtureCollector,
    UnavailableCollector,
    optional_collector_descriptors,
)
from bluefire.evidence import EvidenceProvenance


def _request(**overrides) -> CollectionRequest:
    values = {
        "run_id": "run-collector",
        "step_id": "observe",
        "behavior_id": "collection.stage_fixture.v1",
        "action_id": "sandbox.collection.stage.v1",
        "runner_profile_id": "profile.test",
        "target_scope_ref": "runner-profile:profile.test",
    }
    values.update(overrides)
    return CollectionRequest(**values)


def test_registry_reports_ready_and_unavailable_collectors(tmp_path: Path) -> None:
    optional = optional_collector_descriptors()[0]
    registry = CollectorRegistry(
        (
            FilesystemCollector(tmp_path),
            UnavailableCollector(optional, "Sysmon is not configured on this host"),
        )
    )

    health = {row.collector_id: row for row in registry.health()}

    assert health["collector.filesystem.sandbox.v1"].readiness is CollectorReadiness.READY
    assert health[optional.id].readiness is CollectorReadiness.UNAVAILABLE
    assert registry.descriptors()[0].id == "collector.filesystem.sandbox.v1"


def test_registry_rejects_duplicate_and_unknown_collectors(tmp_path: Path) -> None:
    collector = FilesystemCollector(tmp_path)
    with pytest.raises(CollectorError, match="duplicate"):
        CollectorRegistry((collector, collector))

    with pytest.raises(CollectorError, match="unknown"):
        CollectorRegistry().collect("missing", _request())


def test_filesystem_collector_preserves_observed_and_unknown_provenance(tmp_path: Path) -> None:
    (tmp_path / "present.txt").write_text("observable", encoding="utf-8")
    collector = FilesystemCollector(tmp_path)

    result = collector.collect(_request(settings={"paths": ["present.txt", "missing.txt"]}))

    assert [row.provenance for row in result.records] == [
        EvidenceProvenance.OBSERVED,
        EvidenceProvenance.UNKNOWN,
    ]
    assert result.records[0].producer == "collector.filesystem.sandbox.v1"
    assert result.records[0].content["collector_id"] == "collector.filesystem.sandbox.v1"
    assert result.records[0].environment["collector_version"] == "1.0.0"
    assert result.records[1].content["artifact_type"] == "evidence_gap"
    assert result.health.readiness is CollectorReadiness.DEGRADED


def test_fixture_collector_reads_bounded_json_lines(tmp_path: Path) -> None:
    log = tmp_path / "network.jsonl"
    rows = [{"destination": "fixture.local", "port": 443}, {"bytes": 12}]
    log.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    result = JsonLinesFixtureCollector(tmp_path).collect(
        _request(settings={"relative_path": "network.jsonl"})
    )

    assert len(result.records) == 2
    assert all(row.provenance is EvidenceProvenance.OBSERVED for row in result.records)
    assert result.records[0].content["event"] == rows[0]


def test_fixture_collector_records_invalid_input_as_evidence_gap(tmp_path: Path) -> None:
    (tmp_path / "invalid.jsonl").write_text("not-json\n", encoding="utf-8")

    result = JsonLinesFixtureCollector(tmp_path).collect(
        _request(settings={"relative_path": "invalid.jsonl"})
    )

    assert result.health.readiness is CollectorReadiness.DEGRADED
    assert result.records[-1].provenance is EvidenceProvenance.UNKNOWN
    assert result.records[-1].content["reason"] == "fixture log contains invalid JSON"


def test_unavailable_collector_returns_unknown_evidence() -> None:
    descriptor = optional_collector_descriptors()[-1]
    result = UnavailableCollector(descriptor, "provider is not configured").collect(_request())

    assert result.health.readiness is CollectorReadiness.UNAVAILABLE
    assert result.records[0].provenance is EvidenceProvenance.UNKNOWN
    assert result.records[0].producer == descriptor.id
