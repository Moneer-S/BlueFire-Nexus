from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

import bluefire.collectors as collectors_module
from bluefire.collection_semantics import MAX_COLLECTION_BYTES, parse_collection_semantics
from bluefire.collectors import (
    CollectionRequest,
    CollectionSemanticsCollector,
    CollectionSession,
    CollectorError,
    CollectorReadiness,
    CollectorRegistry,
    CollectorRuntimeSettings,
)
from bluefire.contracts import ExecutionMode
from bluefire.detection_backends import execute_sqlite_query
from bluefire.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from bluefire.observation_integrity import evaluate_observation_integrity
from bluefire.service import APIError, BlueFireService, _default_collector_registry_factory

COLLECTOR_ID = CollectionSemanticsCollector.descriptor.id
ARTIFACT = "staged/collection/bundle.jsonl"
ROOT = Path(__file__).resolve().parents[1]


def _payload(*, redacted: bool = False, count: int = 3) -> bytes:
    return b"".join(
        json.dumps(
            {
                "record_id": f"synthetic-{ordinal:03}",
                "synthetic": True,
                "template": "telemetry-seed",
                "value": "synthetic-redacted" if redacted else f"telemetry-value-{ordinal:03}",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for ordinal in range(1, count + 1)
    )


def _ustar(
    payload: bytes, *, name: str = "fixtures/transformed.jsonl", kind: bytes = tarfile.REGTYPE
) -> bytes:
    # Python's independent USTAR writer must match the reviewed native wire format.
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o644
    member.uname = member.gname = "bluefire"
    member.type = kind
    return member.tobuf(tarfile.USTAR_FORMAT) + payload + bytes(-len(payload) % 512) + bytes(1024)


def _settings(paths: list[str] | None = None) -> dict:
    return {"paths": paths or [ARTIFACT], "collect_after_step": "stage_records"}


def _runtime(settings: dict | None = None) -> CollectorRuntimeSettings:
    return CollectorRuntimeSettings(
        collectors={COLLECTOR_ID: {"enabled": True, "settings": settings or _settings()}}
    )


def _request(settings: dict | None = None) -> CollectionRequest:
    return CollectionRequest(
        run_id="run-semantic",
        step_id="stage_records",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        runner_profile_id="profile.test",
        target_scope_ref="runner-profile:profile.test",
        settings=settings if settings is not None else _settings(),
    )


def _write(root: Path, payload: bytes, path: str = ARTIFACT) -> Path:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


@pytest.mark.parametrize("container", ["jsonl", "ustar"])
@pytest.mark.parametrize("redacted", [False, True])
def test_semantic_observation_binds_aggregate_counts_to_actual_file_bytes(
    tmp_path: Path, container: str, redacted: bool
) -> None:
    payload = _payload(redacted=redacted)
    if container == "ustar":
        payload = _ustar(payload)
    _write(tmp_path, payload)
    collector = CollectionSemanticsCollector(tmp_path)
    result = collector.collect(_request())
    assert result.health.readiness is CollectorReadiness.READY
    assert len(result.records) == 1
    observed = result.records[0]
    assert observed.provenance is EvidenceProvenance.OBSERVED
    assert observed.producer == COLLECTOR_ID
    expected = {
        "path": ARTIFACT,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "container": container,
        "record_count": 3,
        "redacted_record_count": 3 if redacted else 0,
        "retained_record_count": 0 if redacted else 3,
        "empty_record_count": 0,
    }
    assert observed.content["observed_fields"] == expected
    assert all(observed.content[key] == value for key, value in expected.items())
    assert observed.content["observation_kind"] == "collection_semantics"
    encoded = json.dumps(result.to_dict())
    assert "telemetry-value-" not in encoded and "synthetic-redacted" not in encoded
    session = CollectorRegistry((collector,)).collect_configured(_runtime(), _request())
    assert CollectionSession.from_mapping(session.to_dict()).to_dict() == session.to_dict()


def test_all_reviewed_templates_have_disjoint_count_categories() -> None:
    rows = [
        {
            "record_id": "synthetic-001",
            "synthetic": True,
            "template": "harmless-document",
            "value": "document-value-001",
        },
        {"record_id": "synthetic-002", "synthetic": True, "template": "empty", "value": ""},
        {
            "record_id": "synthetic-003",
            "synthetic": True,
            "template": "empty",
            "value": "synthetic-redacted",
        },
    ]
    result = parse_collection_semantics(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    assert result == {
        "container": "jsonl",
        "record_count": 3,
        "redacted_record_count": 1,
        "retained_record_count": 1,
        "empty_record_count": 1,
    }
    assert parse_collection_semantics(_payload(count=100))["record_count"] == 100


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json\n",
        b"\xff\n",
        _payload()[:-1],
        _payload() + b"\n",
        _payload(count=101),
        _payload().replace(b'"synthetic":true', b'"synthetic":1'),
        _payload().replace(b'"synthetic":true', b'"synthetic":true,"synthetic":true'),
        _payload().replace(b'"telemetry-value-001"', b'"private-value-must-never-leak"'),
        _payload().replace(b'"telemetry-value-001"', b"NaN"),
        _payload().replace(b'"synthetic-002"', b'"synthetic-001"'),
        _payload().replace(b'"telemetry-seed"', b'"unsupported"'),
        _payload().replace(b'"value":', b'"extra":true,"value":'),
        _ustar(_payload())[:-1],
        _ustar(_payload()) + bytes(512),
        _ustar(_payload(), name="../outside.jsonl"),
        _ustar(_payload(), name="fixtures/other.jsonl"),
        _ustar(_payload(), kind=tarfile.SYMTYPE),
        _ustar(_payload(), kind=tarfile.LNKTYPE),
        _ustar(_payload())[:-1024] + _ustar(_payload()),
        _ustar(_payload()).replace(b"bluefire", b"eviluser", 1),
        b"x" * (MAX_COLLECTION_BYTES + 1),
    ],
    ids=lambda payload: hashlib.sha256(payload).hexdigest()[:10],
)
def test_malformed_or_unsupported_artifacts_become_unknown_without_values(
    tmp_path: Path, payload: bytes
) -> None:
    _write(tmp_path, payload)
    result = CollectionSemanticsCollector(tmp_path).collect(_request())
    assert result.health.readiness is CollectorReadiness.DEGRADED
    assert len(result.records) == 1
    gap = result.records[0]
    assert gap.provenance is EvidenceProvenance.UNKNOWN
    assert gap.content["artifact_type"] == "evidence_gap"
    assert "record_count" not in gap.content and "sha256" not in gap.content
    assert "private-value-must-never-leak" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "path", [ARTIFACT, "../outside.jsonl", "/absolute.jsonl", "a/../b.jsonl", "a\\b.jsonl"]
)
def test_missing_and_uncontained_paths_are_unknown(tmp_path: Path, path: str) -> None:
    result = CollectionSemanticsCollector(tmp_path).collect(_request(_settings([path])))
    assert result.records[0].provenance is EvidenceProvenance.UNKNOWN


def test_semantics_and_hash_use_one_read_even_if_path_changes_before_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _payload()
    target = _write(tmp_path, original)
    collector = CollectionSemanticsCollector(tmp_path)
    opened: list[tuple[str, ...]] = []
    original_open = collector._observer._open_file

    def record_open(path: tuple[str, ...]) -> int:
        opened.append(path)
        return original_open(path)

    def analyze(captured: bytes) -> dict:
        target.write_bytes(_payload(redacted=True))
        return parse_collection_semantics(captured)

    monkeypatch.setattr(collector._observer, "_open_file", record_open)
    monkeypatch.setattr(collectors_module, "parse_collection_semantics", analyze)
    observed = collector.collect(_request()).records[0]
    assert opened == [tuple(ARTIFACT.split("/"))]
    assert observed.content["sha256"] == hashlib.sha256(original).hexdigest()
    assert observed.content["retained_record_count"] == 3
    assert parse_collection_semantics(target.read_bytes())["redacted_record_count"] == 3


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"paths": [ARTIFACT]},
        {"collect_after_step": "stage_records"},
        {"paths": [], "collect_after_step": "stage_records"},
        _settings([ARTIFACT] * 2),
        _settings([f"{i}.jsonl" for i in range(17)]),
        {**_settings(), "collect_after_step": "other_step"},
        {**_settings(), "glob": "**/*"},
    ],
)
def test_collector_requires_explicit_bounded_paths_and_matching_episode(
    tmp_path: Path, settings: dict
) -> None:
    with pytest.raises(CollectorError):
        CollectionSemanticsCollector(tmp_path).collect(_request(settings))


@pytest.mark.parametrize("maximum", [0, True, MAX_COLLECTION_BYTES + 1])
def test_collector_byte_bound_cannot_be_enlarged(tmp_path: Path, maximum: int) -> None:
    with pytest.raises(CollectorError):
        CollectionSemanticsCollector(tmp_path, max_file_bytes=maximum)


def test_default_managed_runtime_registers_canonical_observer_and_replay_authority(
    tmp_path: Path,
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    try:
        request = {"collector_runtime": _runtime().to_dict()}
        selected, runtime = service._collector_configuration(request, mode=ExecutionMode.EXECUTE)
        assert selected == () and runtime == _runtime()
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        registry = _default_collector_registry_factory(sandbox)
        authority = registry.authority_snapshot(runtime, expected_sandbox=sandbox)
        source = authority["backends"][0]["source_authority"]
        assert source["max_file_bytes"] == MAX_COLLECTION_BYTES
        _write(sandbox, _payload())
        session = registry.collect_configured(runtime, _request())
        assert (
            service._source_collector_authority(
                {"policy": {"approval_context": {"collector_registry_authority": authority}}},
                runtime=runtime,
                session=session,
            )
            == authority
        )
        assert service._valid_collector_source_authority(COLLECTOR_ID, source, runtime)
        assert not service._valid_collector_source_authority(
            COLLECTOR_ID, {**source, "max_file_bytes": MAX_COLLECTION_BYTES + 1}, runtime
        )
        with pytest.raises(APIError, match="Simulate"):
            service._collector_configuration(request, mode=ExecutionMode.SIMULATE)
        with pytest.raises(APIError):
            service._collector_configuration(
                {"collector_runtime": _runtime({"paths": [ARTIFACT]}).to_dict()},
                mode=ExecutionMode.EXECUTE,
            )
    finally:
        service.close()


def test_subclass_cannot_claim_canonical_collector_authority(tmp_path: Path) -> None:
    class CounterfeitCollector(CollectionSemanticsCollector):
        pass

    with pytest.raises(CollectorError, match="canonical"):
        CollectorRegistry((CounterfeitCollector(tmp_path),)).authority_snapshot(
            _runtime(), expected_sandbox=tmp_path
        )


def _execution(observed: EvidenceRecord, *, digest: str | None = None) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id=observed.run_id,
        step_id="stage_records",
        behavior_id=observed.behavior_id,
        action_id=observed.action_id,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id=observed.runner_profile_id,
        target_scope_ref=observed.target_scope_ref,
        timestamp="2026-09-01T00:00:00Z",
        content={
            "runner_status": "success",
            "expected_observable_paths": [ARTIFACT],
            "output": {
                "artifact": ARTIFACT,
                "sha256": digest or observed.content["sha256"],
                "size": observed.content["size_bytes"],
            },
        },
    )


def test_semantic_observation_requires_same_writer_identity_and_episode(tmp_path: Path) -> None:
    _write(tmp_path, _payload())
    observed = CollectionSemanticsCollector(tmp_path).collect(_request()).records[0]
    first = _execution(observed)
    assert evaluate_observation_integrity([first, observed])["satisfied"]
    conflict = evaluate_observation_integrity([_execution(observed, digest="b" * 64), observed])
    assert conflict["satisfied"] is False
    assert conflict["file_postconditions"][0]["state"] == "conflicting_observation"
    second = replace(first, evidence_id="second-write", timestamp="2026-09-02T00:00:00Z")
    missing = evaluate_observation_integrity([first, second, observed])
    assert missing["satisfied"] is False
    assert missing["file_postconditions"][0]["state"] == "observation_unavailable"
    assert missing["file_postconditions"][1]["state"] == "verified"


def test_sql_can_evaluate_collection_semantics_independently_of_container(tmp_path: Path) -> None:
    fixtures = []
    for name, payload in (
        ("raw", _payload()),
        ("archive", _ustar(_payload())),
        ("redacted", _ustar(_payload(redacted=True))),
    ):
        _write(tmp_path, payload)
        observed = CollectionSemanticsCollector(tmp_path).collect(_request()).records[0]
        fixtures.append({"fixture_id": name, **observed.content})
    result = execute_sqlite_query(
        "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation' "
        "AND observation_kind = 'collection_semantics' AND record_count = 3 "
        "AND retained_record_count > 0 AND redacted_record_count = 0 AND empty_record_count = 0 "
        "AND size_bytes > 0 AND length(sha256) = 64",
        fixtures,
    )
    assert result["matched_fixture_ids"] == ["archive", "raw"]
    assert {
        "retained_record_count",
        "redacted_record_count",
        "container",
        "size_bytes",
        "sha256",
    } <= set(result["mapped_fixture_fields"])


def test_parser_error_never_exposes_record_content() -> None:
    with pytest.raises(
        EvidenceError, match="^collection artifact is malformed, unsupported, or incomplete$"
    ):
        parse_collection_semantics(b'{"private":"sensitive-record-value"}\n')
