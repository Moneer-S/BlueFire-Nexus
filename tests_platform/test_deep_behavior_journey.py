from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.deep_behavior_journey as journey
import bluefire.deep_behavior_secret_scan as secret_scan
import tools.run_deep_behavior_gate_journey as journey_helper
from bluefire.cross_platform_linux_bundle_validation import (
    PRIMARY_SCENARIO_VARIANT,
    REGISTERED_ALTERNATE_SCENARIO_VARIANT,
)
from bluefire.cross_platform_readiness import WSL_DISTRIBUTION_ID
from bluefire.run_store import RunStore
from bluefire.util import content_hash
from tools.run_cross_platform_linux_worker import _scenario_document


def _acceptance_binding(monkeypatch: pytest.MonkeyPatch) -> Mapping[str, str]:
    values = {
        "acceptance_id": "gate03-deep-behavior-journey-test",
        "gate_id": "GATE-03",
        "contract_sha256": "sha256:" + "3" * 64,
        "repository_commit": "4" * 40,
        "repository_tree": "5" * 40,
        "release": "true",
    }
    names = {
        "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
        "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
        "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
        "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
        "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
        "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
    }
    for field, name in names.items():
        monkeypatch.setenv(name, values[field])
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        **values,
    }


def _wsl_facts(state: str) -> Mapping[str, Any]:
    configured, version = {
        "absent": (False, None),
        "incompatible": (True, "1"),
        "ready": (True, "2"),
    }[state]
    facts = {
        "provider": "wsl2",
        "probe_state": state,
        "configured": configured,
        "distribution_id": WSL_DISTRIBUTION_ID,
        "version": version,
    }
    return {**facts, "facts_digest": content_hash(facts)}


def _create_canonical_test_bundle(evidence: Path, label: str) -> str:
    store = RunStore(evidence / "runs")
    handle = store.create_run(
        scenario={"schema_version": "test.v1", "label": label},
        plan={"schema_version": "test.v1", "steps": []},
        policy={"schema_version": "test.v1", "authorized": True},
        profile={"schema_version": "test.v1", "profile_id": label},
    )
    store.finalize(
        handle.run_id,
        result={"schema_version": "test.v1", "status": "succeeded"},
        evidence=({"label": label, "passed": True},),
        detections=(),
    )
    assert store.validate_bundle(handle.run_id)["valid"] is True
    return handle.run_id


def test_aws_aggregate_creates_two_bound_bundles_and_exact_manual_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _acceptance_binding(monkeypatch)
    credential = bytes(range(64))

    report = journey._run_cloud_pack(tmp_path, credential)

    assert set(report) == {
        "schema_version",
        "passed",
        "proof_kind",
        "pack_id",
        "profile",
        "credential_binding",
        "manual_smoke",
        "simulate",
        "execute",
        "run_bundles",
    }
    assert report["schema_version"] == journey.AWS_REPORT_SCHEMA
    assert report["passed"] is True
    assert report["proof_kind"] == "dynamic"
    assert report["credential_binding"] == {
        "handle_prefix": "credential-",
        "opaque": True,
        "raw_material_persisted": False,
        "handle_revoked": True,
    }
    assert report["manual_smoke"] == {
        "schema_version": journey.MANUAL_SMOKE_CONTRACT_SCHEMA,
        "credential_reference": "aws-profile://bluefire-disposable-lab",
        "operations": [
            "GetCallerIdentity",
            "GetRole",
            "ListRoleTagsBefore",
            "TagRole",
            "ListRoleTagsAfter",
            "UntagRole",
            "ListRoleTagsCleanup",
            "LookupEvents",
        ],
        "shell": False,
        "timeout_seconds": 20,
        "external_execution": False,
    }
    assert [item["mode"] for item in (report["simulate"], report["execute"])] == [
        "simulate",
        "execute",
    ]
    assert report["simulate"]["credential_revoked"] is False
    assert report["execute"]["credential_revoked"] is True
    assert all(
        item["acceptance_binding"] == binding
        and item["cleanup_verified"] is True
        and item["audit_verified"] is True
        for item in (report["simulate"], report["execute"])
    )

    bundle_roots = tuple(tmp_path / item["path"] for item in report["run_bundles"])
    assert len(bundle_roots) == 2
    assert len({item["run_id"] for item in report["run_bundles"]}) == 2
    assert all(path.is_dir() for path in bundle_roots)
    runtime_scan = secret_scan.scan_runtime_secret_material(bundle_roots, (credential,))
    assert runtime_scan["passed"] is True
    assert runtime_scan["matches"] == 0
    assert runtime_scan["secret_count"] == 1


def test_producer_aggregates_exactly_five_bundles_and_scans_runtime_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _acceptance_binding(monkeypatch)
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    runtime_parent = tmp_path / "runtime-parent"
    repository.mkdir()
    evidence.mkdir()
    runtime_parent.mkdir()
    facts = _wsl_facts("ready")
    variants: list[str] = []
    runtimes: list[Path] = []
    observed_scan: dict[str, Any] = {}

    def fake_linux(
        _repository: Path,
        destination: Path,
        runtime: Path,
        wsl: Mapping[str, Any],
        *,
        scenario_variant: str,
    ) -> Mapping[str, Any]:
        assert wsl == facts
        assert runtime.is_dir()
        variants.append(scenario_variant)
        runtimes.append(runtime)
        run_id = _create_canonical_test_bundle(destination, f"linux-{scenario_variant}")
        return {
            "schema_version": "test.linux.v1",
            "passed": True,
            "run_id": run_id,
            "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
        }

    def fake_endpoint(
        _repository: Path,
        destination: Path,
        runtime: Path,
    ) -> Mapping[str, Any]:
        assert runtime.is_dir()
        run_id = _create_canonical_test_bundle(destination, "endpoint")
        return {
            "schema_version": "test.endpoint.v1",
            "passed": True,
            "run_id": run_id,
            "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
        }

    def scanning_wrapper(
        roots: tuple[Path, ...],
        secrets: tuple[bytes, ...],
    ) -> Mapping[str, Any]:
        observed_scan["roots"] = roots
        observed_scan["secrets"] = secrets
        return secret_scan.scan_runtime_secret_material(roots, secrets)

    source_report = {
        "schema_version": secret_scan.SOURCE_SCAN_SCHEMA,
        "passed": True,
        "files_scanned": 1,
    }
    monkeypatch.setattr(journey, "probe_wsl2", lambda: facts)
    monkeypatch.setattr(journey, "linux_wheelhouse_unavailable", lambda _root: False)
    monkeypatch.setattr(journey, "runtime_temp_parent", lambda: runtime_parent)
    monkeypatch.setattr(journey, "run_linux_journey", fake_linux)
    monkeypatch.setattr(journey, "run_endpoint_pack_journey", fake_endpoint)
    monkeypatch.setattr(
        journey,
        "official_pack_inventory",
        lambda _root: {"schema_version": "test.pack-inventory.v1", "passed": True},
    )
    monkeypatch.setattr(journey, "audit_deep_behavior_sources", lambda _root: source_report)
    monkeypatch.setattr(journey, "scan_runtime_secret_material", scanning_wrapper)

    summary = journey.produce_deep_behavior_gate_evidence(repository, evidence)

    assert summary == {
        "schema_version": journey.HELPER_SCHEMA,
        "status": "passed",
        "blocking_check": None,
        "reports": list(journey.JOURNEY_REPORT_PATHS),
        "run_count": 5,
    }
    assert variants == [PRIMARY_SCENARIO_VARIANT, REGISTERED_ALTERNATE_SCENARIO_VARIANT]
    assert runtimes and all(not runtime.exists() for runtime in runtimes)
    assert {path.name for path in (evidence / "runs").iterdir()} == {
        path.name for path in observed_scan["roots"]
    }
    assert len(observed_scan["roots"]) == 5
    assert len(observed_scan["secrets"]) == 1
    assert type(observed_scan["secrets"][0]) is bytes
    assert len(observed_scan["secrets"][0]) == 64
    store = RunStore(evidence / "runs")
    assert all(store.validate_bundle(path.name)["valid"] is True for path in observed_scan["roots"])
    assert {path.name for path in evidence.iterdir()} == {
        "runs",
        *journey.JOURNEY_REPORT_PATHS,
    }
    aggregate = json.loads((evidence / journey.SECRET_SCAN_REPORT).read_text(encoding="utf-8"))
    assert aggregate["schema_version"] == journey.SECRET_SCAN_AGGREGATE_SCHEMA
    assert aggregate["source"] == source_report
    assert aggregate["runtime"]["passed"] is True
    assert aggregate["runtime"]["matches"] == 0


@pytest.mark.parametrize("state", ["absent", "incompatible"])
def test_producer_fails_closed_before_wsl_execution_when_boundary_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    facts = _wsl_facts(state)
    monkeypatch.setattr(journey, "probe_wsl2", lambda: facts)
    monkeypatch.setattr(
        journey,
        "linux_wheelhouse_unavailable",
        lambda _root: pytest.fail("wheelhouse preflight must not run without WSL2"),
    )
    monkeypatch.setattr(
        journey,
        "run_linux_journey",
        lambda *_args, **_kwargs: pytest.fail("Linux execution must not start"),
    )

    summary = journey.produce_deep_behavior_gate_evidence(repository, evidence)

    assert summary == {
        "schema_version": journey.HELPER_SCHEMA,
        "status": "failed",
        "blocking_check": "linux_primary",
        "reports": list(journey.JOURNEY_REPORT_PATHS),
        "run_count": 0,
    }
    assert {path.name for path in evidence.iterdir()} == {journey.LINUX_PRIMARY_REPORT}
    report = json.loads((evidence / journey.LINUX_PRIMARY_REPORT).read_text(encoding="utf-8"))
    expected_code = "wsl_distribution_absent" if state == "absent" else "wsl_distribution_not_v2"
    assert report["passed"] is False
    assert report["availability"] == {"state": "unavailable", "code": expected_code}
    assert report["boundary"]["probe_state"] == state
    assert report["scenario_variant"] == PRIMARY_SCENARIO_VARIANT


def test_producer_fails_closed_when_locked_linux_wheelhouse_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    facts = _wsl_facts("ready")
    checked: list[Path] = []
    monkeypatch.setattr(journey, "probe_wsl2", lambda: facts)
    monkeypatch.setattr(
        journey,
        "linux_wheelhouse_unavailable",
        lambda root: checked.append(root) or True,
    )
    monkeypatch.setattr(
        journey,
        "run_linux_journey",
        lambda *_args, **_kwargs: pytest.fail("Linux execution must not start"),
    )

    summary = journey.produce_deep_behavior_gate_evidence(repository, evidence)

    assert summary["status"] == "failed"
    assert summary["blocking_check"] == "linux_primary"
    assert summary["run_count"] == 0
    assert checked == [repository.resolve()]
    assert {path.name for path in evidence.iterdir()} == {journey.LINUX_PRIMARY_REPORT}
    report = json.loads((evidence / journey.LINUX_PRIMARY_REPORT).read_text(encoding="utf-8"))
    assert report["availability"] == {
        "state": "unavailable",
        "code": "linux_dependencies_unavailable",
    }
    assert report["scenario_variant"] == PRIMARY_SCENARIO_VARIANT


def test_producer_refuses_stale_owned_destination_before_any_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    (evidence / journey.PACK_REPORT).write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        journey,
        "probe_wsl2",
        lambda: pytest.fail("stale evidence must be refused before host probing"),
    )

    with pytest.raises(journey.DeepBehaviorJourneyError, match="stale owned artifacts"):
        journey.produce_deep_behavior_gate_evidence(repository, evidence)

    assert {path.name for path in evidence.iterdir()} == {journey.PACK_REPORT}


def test_fixed_helper_protocol_emits_one_exact_json_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    observed: list[tuple[Path, Path]] = []
    expected = {
        "schema_version": journey.HELPER_SCHEMA,
        "status": "passed",
        "blocking_check": None,
        "reports": list(journey.JOURNEY_REPORT_PATHS),
        "run_count": 5,
    }

    def producer(source: Path, destination: Path) -> Mapping[str, object]:
        observed.append((source, destination))
        for name in journey.JOURNEY_REPORT_PATHS:
            (destination / name).write_text("{}\n", encoding="utf-8")
        return expected

    monkeypatch.setattr(journey_helper, "produce_deep_behavior_gate_evidence", producer)

    exit_code = journey_helper.main(
        ["--repository", str(repository), "--evidence-dir", str(evidence)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.endswith("\n") and captured.out.count("\n") == 1
    assert json.loads(captured.out) == expected
    assert observed == [(repository, evidence.resolve())]


def test_fixed_helper_refuses_a_passed_summary_with_missing_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    monkeypatch.setattr(
        journey_helper,
        "produce_deep_behavior_gate_evidence",
        lambda _source, _destination: {
            "schema_version": journey.HELPER_SCHEMA,
            "status": "passed",
            "blocking_check": None,
            "reports": list(journey.JOURNEY_REPORT_PATHS),
            "run_count": 5,
        },
    )

    with pytest.raises(journey.DeepBehaviorJourneyError, match="omitted a required report"):
        journey_helper.run_deep_behavior_gate_journey(repository, evidence)


def test_registered_linux_alternate_selects_only_the_declared_behavior_document() -> None:
    repository = Path(__file__).resolve().parents[1]

    primary = _scenario_document(repository, PRIMARY_SCENARIO_VARIANT, 43171)
    alternate = _scenario_document(repository, REGISTERED_ALTERNATE_SCENARIO_VARIANT, 43172)
    primary_steps = {step["id"]: step for step in primary["steps"]}
    alternate_steps = {step["id"]: step for step in alternate["steps"]}

    assert primary_steps.keys() == alternate_steps.keys()
    assert primary_steps["enumerate_fixture"]["behavior_id"] == "sandbox.discovery.list.v1"
    assert primary_steps["enumerate_fixture"]["alternates"] == ["sandbox.discovery.metadata.v1"]
    assert alternate_steps["enumerate_fixture"]["behavior_id"] == ("sandbox.discovery.metadata.v1")
    assert alternate_steps["enumerate_fixture"]["alternates"] == ["sandbox.discovery.list.v1"]
    assert primary_steps["internal_transport"]["parameters"]["port"] == 43171
    assert alternate_steps["internal_transport"]["parameters"]["port"] == 43172
    for step_id in primary_steps.keys() - {"enumerate_fixture", "internal_transport"}:
        assert alternate_steps[step_id] == primary_steps[step_id]
