from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from bluefire.collectors import (
    CollectionRequest,
    CollectionSession,
    CollectorDescriptor,
    CollectorError,
    CollectorReadiness,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    JsonLinesFixtureCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
    UnavailableCollector,
    filesystem_observation_key,
    optional_collector_descriptors,
    reconcile_observations,
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


class _ReceiverSource:
    host = "127.0.0.1"
    port = 4317
    process_id = 4242
    session_id = "7" * 64
    accepted_artifact_bindings = (
        {
            "task_id": "execute-" + "1" * 64,
            "sha256": "2" * 64,
            "bytes_received": 19,
        },
    )


def test_runtime_settings_invoke_only_enabled_backends_and_verify_session(
    tmp_path: Path,
) -> None:
    (tmp_path / "observed.txt").write_text("observed", encoding="utf-8")
    receiver = LoopbackReceiverCollector(_ReceiverSource())
    registry = CollectorRegistry((FilesystemCollector(tmp_path), receiver))
    settings = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {"paths": ["observed.txt"]},
            },
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": False,
                "settings": {
                    "task_ids": [_ReceiverSource.accepted_artifact_bindings[0]["task_id"]]
                },
            },
        }
    )

    session = registry.collect_configured(settings, _request())

    assert set(session.results) == {FilesystemCollector.descriptor.id}
    assert CollectionSession.from_mapping(session.to_dict()) == session
    original_hash = settings.settings_hash
    exported = settings.to_dict()
    exported["collectors"][FilesystemCollector.descriptor.id]["settings"]["paths"].append(
        "mutated.txt"
    )
    assert settings.settings_hash == original_hash
    assert settings.to_dict()["collectors"][FilesystemCollector.descriptor.id]["settings"][
        "paths"
    ] == ["observed.txt"]
    with pytest.raises(TypeError):
        settings.collectors[FilesystemCollector.descriptor.id]["enabled"] = False  # type: ignore[index]
    corrupted = copy.deepcopy(session.to_dict())
    corrupted["results"][FilesystemCollector.descriptor.id]["records"][0]["content"][
        "path"
    ] = "changed.txt"
    with pytest.raises(CollectorError, match="evidence is invalid"):
        CollectionSession.from_mapping(corrupted)


def test_source_free_gap_does_not_suppress_independent_enabled_collectors(
    tmp_path: Path,
) -> None:
    (tmp_path / "observed.txt").write_text("observed", encoding="utf-8")
    registry = CollectorRegistry(
        (
            FilesystemCollector(tmp_path),
            LoopbackReceiverCollector(_ReceiverSource()),
        )
    )
    settings = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {"paths": ["observed.txt"]},
            },
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": True,
                "settings": {"task_ids": []},
            },
        }
    )

    session = registry.collect_configured(
        settings,
        _request(),
        source_free_gaps={
            LoopbackReceiverCollector.descriptor.id: "scheduled_runner_effect_not_executed"
        },
    )

    filesystem = session.results[FilesystemCollector.descriptor.id]
    receiver = session.results[LoopbackReceiverCollector.descriptor.id]
    assert filesystem.health.readiness is CollectorReadiness.READY
    assert filesystem.records[0].provenance is EvidenceProvenance.OBSERVED
    assert receiver.health.readiness is CollectorReadiness.DEGRADED
    assert receiver.health.details["source_read"] is False
    assert receiver.records[0].provenance is EvidenceProvenance.UNKNOWN


def test_filesystem_collector_propagates_the_shared_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "observed.txt").write_text("observed", encoding="utf-8")
    collector = FilesystemCollector(tmp_path)
    original = collector._observer.observe_file
    observed_deadlines: list[float | None] = []

    def observe_with_deadline(**kwargs):
        observed_deadlines.append(kwargs.get("deadline_monotonic"))
        return original(**kwargs)

    monkeypatch.setattr(collector._observer, "observe_file", observe_with_deadline)
    started = time.monotonic()
    result = collector.collect(
        _request(
            settings={"paths": ["observed.txt"]},
            timeout_seconds=0.25,
        )
    )

    assert result.health.readiness is CollectorReadiness.READY
    assert len(observed_deadlines) == 1
    assert observed_deadlines[0] is not None
    assert started < observed_deadlines[0] <= started + 0.3


def test_registry_refuses_backend_that_changes_its_registered_descriptor(
    tmp_path: Path,
) -> None:
    delegate = FilesystemCollector(tmp_path)

    class DescriptorChangingCollector:
        descriptor = FilesystemCollector.descriptor

        def health(self):
            return delegate.health()

        def collect(self, request: CollectionRequest):
            result = delegate.collect(request)
            return replace(
                result,
                descriptor=CollectorDescriptor(
                    **{
                        **result.descriptor.to_dict(),
                        "version": "9.9.9",
                        "capabilities": result.descriptor.capabilities,
                        "platforms": result.descriptor.platforms,
                        "requirements": result.descriptor.requirements,
                    }
                ),
            )

    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {"paths": []},
            }
        }
    )
    registry = CollectorRegistry((DescriptorChangingCollector(),))

    with pytest.raises(CollectorError, match="descriptor changed"):
        registry.collect_configured(runtime, _request())


def test_registry_rejects_noncanonical_descriptor_for_builtin_id(tmp_path: Path) -> None:
    delegate = FilesystemCollector(tmp_path)

    class AlteredBuiltinDescriptorCollector:
        descriptor = replace(
            FilesystemCollector.descriptor,
            capabilities=("file_metadata",),
        )

        def health(self):
            return delegate.health()

        def collect(self, request: CollectionRequest):
            return delegate.collect(request)

    with pytest.raises(CollectorError, match="canonical built-in"):
        CollectorRegistry((AlteredBuiltinDescriptorCollector(),))


def test_registry_refuses_current_descriptor_drift_after_registration(
    tmp_path: Path,
) -> None:
    collector = FilesystemCollector(tmp_path)
    registry = CollectorRegistry((collector,))
    collector.descriptor = replace(  # type: ignore[misc]
        FilesystemCollector.descriptor, version="9.9.9"
    )

    with pytest.raises(CollectorError, match="descriptor changed"):
        registry.collect(FilesystemCollector.descriptor.id, _request(settings={"paths": []}))


@pytest.mark.skipif(
    sys.platform not in {"win32", "linux"},
    reason="native process identity backend is implemented for Windows and Linux",
)
def test_native_process_collector_observes_exact_control_plane_child() -> None:
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
            _request(
                settings={
                    "process_id": child.pid,
                    "expected_parent_process_id": os.getpid(),
                }
            )
        )
    finally:
        child.terminate()
        child.wait(timeout=5)

    assert result.health.readiness is CollectorReadiness.READY
    assert len(result.records) == 1
    assert result.records[0].provenance is EvidenceProvenance.OBSERVED
    assert result.records[0].content["observed_fields"]["process_id"] == child.pid
    assert result.records[0].content["mechanism"] in {
        "CreateToolhelp32Snapshot/GetProcessTimes",
        "/proc/<pid>/stat",
    }


def test_native_process_collector_refuses_reused_pid_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = iter(
        [
            {"creation_identity": "pinned"},
            {"creation_identity": "replacement"},
        ]
    )
    monkeypatch.setattr(
        "bluefire.collectors.observe_native_process",
        lambda *_args, **_kwargs: next(observations),
    )
    collector = NativeProcessCollector({1234: 5678})

    result = collector.collect(
        _request(settings={"process_id": 1234, "expected_parent_process_id": 5678})
    )

    assert result.health.readiness is CollectorReadiness.DEGRADED
    assert result.records[0].provenance is EvidenceProvenance.UNKNOWN
    assert "creation identity" in result.records[0].content["reason"]


def test_receiver_collector_and_field_reconciliation_are_path_free() -> None:
    task_id = _ReceiverSource.accepted_artifact_bindings[0]["task_id"]
    result = LoopbackReceiverCollector(_ReceiverSource()).collect(
        _request(settings={"task_ids": [task_id]})
    )
    report = reconcile_observations(
        {
            f"network/authenticated-receiver/{task_id}": {
                "task_id": task_id,
                "sha256": "2" * 64,
                "missing_field": True,
            }
        },
        result.records,
    )

    assert result.health.readiness is CollectorReadiness.READY
    assert result.records[0].content["source"] == "receiver/authenticated-loopback"
    assert report["field_comparisons"][0]["missing_fields"] == ["missing_field"]
    assert report["field_comparisons"][0]["unexpected_fields"] == [
        "bytes_received",
        "receiver_process_id",
        "receiver_session_id",
    ]


def test_receiver_collector_assigns_unique_keys_to_multiple_bindings() -> None:
    class TwoBindingSource(_ReceiverSource):
        accepted_artifact_bindings = (
            *_ReceiverSource.accepted_artifact_bindings,
            {
                "task_id": "execute-" + "3" * 64,
                "sha256": "4" * 64,
                "bytes_received": 23,
            },
        )

    task_ids = [str(binding["task_id"]) for binding in TwoBindingSource.accepted_artifact_bindings]
    result = LoopbackReceiverCollector(TwoBindingSource()).collect(
        _request(settings={"task_ids": task_ids})
    )

    keys = [str(record.content["observation_key"]) for record in result.records]
    assert len(keys) == len(set(keys)) == 2
    report = reconcile_observations(
        {
            key: dict(record.content["observed_fields"])
            for key, record in zip(keys, result.records, strict=True)
        },
        result.records,
    )
    assert report["missing_observations"] == []
    assert report["unexpected_observations"] == []


def test_receiver_collector_filters_cumulative_source_to_executed_task() -> None:
    prior_task_id = str(_ReceiverSource.accepted_artifact_bindings[0]["task_id"])
    current_task_id = "execute-" + "5" * 64

    class CumulativeSource(_ReceiverSource):
        accepted_artifact_bindings = (
            *_ReceiverSource.accepted_artifact_bindings,
            {
                "task_id": current_task_id,
                "sha256": "6" * 64,
                "bytes_received": 29,
            },
        )

    result = LoopbackReceiverCollector(CumulativeSource()).collect(
        _request(execution_binding={"runner_task_id": current_task_id})
    )

    assert [record.content["observed_fields"]["task_id"] for record in result.records] == [
        current_task_id
    ]
    assert prior_task_id not in json.dumps(result.to_dict(), sort_keys=True)


def test_reconciliation_preserves_multiple_observed_retry_attempts(tmp_path: Path) -> None:
    (tmp_path / "observed.txt").write_text("observed", encoding="utf-8")
    collector = FilesystemCollector(tmp_path)
    first = collector.collect(_request(settings={"paths": ["observed.txt"]}))
    second = collector.collect(_request(settings={"paths": ["observed.txt"]}))
    observed_fields = dict(first.records[0].content["observed_fields"])

    report = reconcile_observations(
        {filesystem_observation_key("observed.txt"): observed_fields},
        (*first.records, *second.records),
    )

    assert report["observation_attempt_counts"] == {filesystem_observation_key("observed.txt"): 2}
    assert len(report["field_comparisons"]) == 2
    assert {row["attempt_index"] for row in report["field_comparisons"]} == {1, 2}


@pytest.mark.parametrize("path", ["Logs/Event.JSON", "a--b/foo..json"])
def test_filesystem_observation_keys_are_case_preserving_and_reconcilable(
    tmp_path: Path,
    path: str,
) -> None:
    target = tmp_path / PurePosixPath(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("observed", encoding="utf-8")
    result = FilesystemCollector(tmp_path).collect(_request(settings={"paths": [path]}))
    key = filesystem_observation_key(path)

    report = reconcile_observations(
        {key: dict(result.records[0].content["observed_fields"])},
        result.records,
    )

    assert result.records[0].content["observation_key"] == key
    assert bytes.fromhex(key.removeprefix("filesystem/path-utf8-")).decode() == path
    assert report["missing_observations"] == []


def test_optional_collector_contracts_cover_platform_security_surfaces() -> None:
    descriptors = optional_collector_descriptors()
    kinds = {descriptor.kind for descriptor in descriptors}
    capabilities = {
        capability for descriptor in descriptors for capability in descriptor.capabilities
    }

    assert {"host_audit", "cloud_identity_audit", "siem", "edr"} <= kinds
    assert {"windows_event_log", "runtime_logs", "identity_events", "bounded_query"} <= capabilities
