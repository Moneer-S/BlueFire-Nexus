from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from bluefire.collection_methods import (
    CollectionMethodError,
    collection_artifacts,
    collection_request,
    simulate_collection,
)
from bluefire.collection_semantics import MAX_COLLECTION_BYTES, parse_collection_semantics
from bluefire.contracts import load_scenario
from bluefire.evidence import EvidenceError
from bluefire.registry import load_builtin_registry
from bluefire.research import load_builtin_research_registry

ROOT = Path(__file__).resolve().parents[1]
METHOD = "sandbox.collection.atomic-gzip.v1"


def _payload(redacted: bool = False) -> bytes:
    return b"".join(
        json.dumps(
            {
                "record_id": f"synthetic-{number:03}",
                "synthetic": True,
                "template": "telemetry-seed",
                "value": "synthetic-redacted" if redacted else f"telemetry-value-{number:03}",
            }
        ).encode()
        + b"\n"
        for number in range(1, 9)
    )


def _source() -> dict:
    return {
        "records": [
            {
                "type": "artifact.sandbox.discovery.records.v1",
                "kind": "file",
                "path": "fixtures/transformed.jsonl",
                "record_count": 8,
                "sha256": hashlib.sha256(_payload()).hexdigest(),
                "content_hash": "sha256:" + "a" * 64,
            }
        ]
    }


@pytest.mark.parametrize("redacted", [False, True])
def test_independent_gzip_decoder_preserves_native_semantic_counts(redacted: bool) -> None:
    payload = _payload(redacted)
    native = parse_collection_semantics(payload)
    compressed = parse_collection_semantics(gzip.compress(payload, mtime=0))
    assert compressed == {**native, "container": "gzip"}
    assert compressed["record_count"] == 8
    assert compressed["retained_record_count"] == (0 if redacted else 8)
    assert compressed["redacted_record_count"] == (8 if redacted else 0)
    assert not any("telemetry-value" in str(value) for value in compressed.values())


@pytest.mark.parametrize(
    "corruption",
    ["crc", "size", "truncated", "concatenated", "trailing", "timestamp", "name", "bomb"],
)
def test_gzip_decoder_refuses_incomplete_or_unreviewed_streams(corruption: str) -> None:
    payload = gzip.compress(_payload(), mtime=0)
    if corruption == "crc":
        payload = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]
    elif corruption == "size":
        payload = payload[:-4] + bytes(4)
    elif corruption == "truncated":
        payload = payload[:-1]
    elif corruption == "concatenated":
        payload += payload
    elif corruption == "trailing":
        payload += b"\0"
    elif corruption == "timestamp":
        payload = payload[:4] + b"\x01" + payload[5:]
    elif corruption == "name":
        payload = payload[:3] + b"\x08" + payload[4:10] + b"fixture\0" + payload[10:]
    elif corruption == "bomb":
        payload = gzip.compress(b"x" * (MAX_COLLECTION_BYTES + 1), mtime=0)
    with pytest.raises(EvidenceError, match="malformed, unsupported, or incomplete"):
        parse_collection_semantics(payload)


@pytest.mark.parametrize("variant", ["primary", "heldout"])
def test_gzip_binding_requires_exact_tool_and_receipt_artifact(variant: str) -> None:
    source = _source()
    parameters = {"stage_variant": variant}
    request, scope, observable = collection_request(METHOD, parameters, source)
    directory = "staged/collection" if variant == "primary" else "staged/variation"
    assert scope == ("fixtures/transformed.jsonl", directory)
    assert observable == (f"{directory}/bundle.jsonl.gz",)
    assert request["expected_sha256"] == source["records"][0]["sha256"]
    output = {
        "artifact": observable[0],
        "container": "gzip",
        "input_count": 1,
        "source_sha256": request["expected_sha256"],
        "size": 200,
        "sha256": "b" * 64,
        "tool": {
            "executable": "/usr/bin/gzip",
            "sha256": "c" * 64,
            "arguments": ["-n", "-c"],
            "source_test": "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af",
        },
    }
    artifact = collection_artifacts(METHOD, parameters, source, output, ["receipt"])["bundle"]
    assert artifact["receipt_ids"] == ["receipt"]
    assert artifact["container"] == "gzip"
    for field, bad in [
        ("executable", "/tmp/gzip"),
        ("sha256", "bad"),
        ("arguments", ["-c", "a"]),
        ("source_test", "other"),
    ]:
        with pytest.raises(CollectionMethodError, match="executable identity"):
            collection_artifacts(
                METHOD, parameters, source, {**output, "tool": {**output["tool"], field: bad}}, []
            )
    for field, bad in [("input", "personal.txt"), ("executable", "gzip"), ("arguments", ["-c"])]:
        with pytest.raises(CollectionMethodError):
            collection_request(METHOD, {**parameters, field: bad}, source)
    simulated = simulate_collection(METHOD, parameters, source)["bundle"]
    assert simulated["path"] == f"synthetic/{observable[0]}"
    assert "sha256" not in simulated and "tool" not in simulated


def test_focused_example_keeps_native_alternatives_and_no_network() -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios/atomic_gzip_collection.yaml")
    registry.validate_scenario(scenario)
    assert len(scenario.steps) == 5
    assert scenario.steps[-1].behavior_id == "sandbox.cleanup.v1"
    assert scenario.step("stage_collection").alternates == (
        "sandbox.collection.records.v1",
        "sandbox.collection.archive.v1",
    )
    assert METHOD in registry.compatible_behaviors("sandbox.collection.records.v1")
    assert registry.get_action(METHOD).platforms == ("linux",)
    assert not any(
        "network" in capability
        for step in scenario.steps
        for capability in registry.get_behavior(step.behavior_id).capabilities
    )
    assert (ROOT / "scenarios/atomic_gzip_collection.yaml").read_bytes() == (
        ROOT / "bluefire/data/atomic_gzip_collection.yaml"
    ).read_bytes()


def test_adapted_source_record_preserves_exact_upstream_license() -> None:
    load_builtin_research_registry()
    license_bytes = (ROOT / "bluefire/data/atomic_red_team_LICENSE.txt").read_bytes()
    assert len(license_bytes) == 1078
    assert (
        hashlib.sha256(license_bytes).hexdigest()
        == "65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1"  # pragma: allowlist secret -- verified public Atomic Red Team MIT license SHA-256
    )
    assert b"Copyright (c) 2018 Red Canary, Inc." in license_bytes


def test_new_process_boundary_is_byte_bound_and_drift_fails_review() -> None:
    from tools.atomic_gzip_source_audit import reviewed_gzip_source
    from tools.provider_gate_source_audit import _native_command_source_inventory_is_fixed

    source = (ROOT / "runner/src/atomic_gzip.rs").read_bytes()
    assert reviewed_gzip_source(source)
    assert _native_command_source_inventory_is_fixed(ROOT)
    for before, after in (
        (b'.args(["-n", "-c"])', b'.args(["-n", "-c", "caller-file"])'),
        (b".env_clear()", b".envs(std::env::vars())"),
        (b"metadata.uid() != 0", b"false"),
        (b"let _ = child.0.kill();", b"let _ = ();"),
    ):
        changed = source.replace(before, after)
        assert changed != source
        assert not reviewed_gzip_source(changed)


@pytest.mark.parametrize("profile_id", ["sandbox-execute.v1", "sandbox-blocked-network.v1"])
@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_shared_profile_stays_ready_and_only_selected_gzip_requires_linux(
    profile_id: str, platform: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    from bluefire.contracts import ExecutionMode
    from bluefire.planner import DeterministicPlanner
    from bluefire.policy import PolicyEngine, PolicyStatus
    from bluefire.runner_contracts import build_runner_profile
    from bluefire.service import BlueFireService
    from tests_platform.test_service import ReadyInventoryRunner

    monkeypatch.setattr("tests_platform.test_service.current_platform", lambda: platform)
    runner = ReadyInventoryRunner()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        profile = service._profile(profile_id, ExecutionMode.EXECUTE)
        assert profile is not None
        _, _, readiness = service._execute_readiness_boundary(profile)
        assert readiness["platform"] == platform
        compiled = build_runner_profile(profile, sandbox_root=sandbox, platform=platform)
        assert METHOD in compiled["allowed_actions"]
        scenario = load_scenario(ROOT / "scenarios/atomic_gzip_collection.yaml")
        for method in (METHOD, "sandbox.collection.records.v1", "sandbox.collection.archive.v1"):
            selected = replace(
                scenario,
                steps=tuple(
                    replace(step, behavior_id=method) if step.id == "stage_collection" else step
                    for step in scenario.steps
                ),
            )
            plan = DeterministicPlanner(service.registry).compile(
                selected, mode=ExecutionMode.EXECUTE, profile=profile
            )
            step = next(row for row in plan.steps if row.step_id == "stage_collection")
            decision = PolicyEngine().evaluate(
                step=step,
                action=service.registry.get_action(method),
                mode=ExecutionMode.EXECUTE,
                profile=profile,
                platform=platform,
                target_scope={"scope_refs": ["sandbox.workspace"]},
                request_hash="a" * 64,
                approval=None,
            )
            platform_refused = method == METHOD and platform != "linux"
            assert any("platform" in reason for reason in decision.reasons) == platform_refused
            if platform_refused:
                assert decision.status is PolicyStatus.REFUSED
        assert runner.execute_calls == 0
    finally:
        service.close()
