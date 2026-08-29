from __future__ import annotations

from typing import Any, Mapping, Sequence

import pytest

from bluefire.contracts import SafetyTier
from bluefire.planner import PlanStep
from bluefire.runner_adapter import AdaptedAction, RunnerActionAdapter, RunnerAdapterError

ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "endpoint.discovery.system.v1",
    "endpoint.discovery.windows-version.v1",
    "endpoint.discovery.processes.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.execution.native-canary.v1",
    "sandbox.archive.tar.v1",
    "sandbox.collection.stage.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.network.loopback.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.observability.variant.v1",
    "sandbox.export.local.v1",
    "sandbox.restricted.persistence-marker.v1",
    "sandbox.cleanup.v1",
}
CONTROLLED_ACTIONS = {
    "sandbox.archive.tar.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
}
RECEIPT_CREATE = "a" * 64
RECEIPT_STAGE = "b" * 64
RECEIPT_RESTRICTED = "c" * 64


def _step(action_id: str, parameters: Mapping[str, Any] | None = None) -> PlanStep:
    return PlanStep(
        step_id="step",
        behavior_id=action_id,
        action_id=action_id,
        simulation_id=None,
        parameters=dict(parameters or {}),
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=(
            SafetyTier.RESTRICTED
            if action_id == "sandbox.restricted.persistence-marker.v1"
            else SafetyTier.CONTROLLED if action_id in CONTROLLED_ACTIONS else SafetyTier.SAFE
        ),
        alternates=(),
    )


@pytest.mark.parametrize(
    ("action_id", "parameters", "bound_inputs", "receipt_ids", "expected"),
    [
        pytest.param(
            "sandbox.fixture.create.v1",
            {"record_count": 8},
            {},
            (),
            AdaptedAction(
                params={
                    "path": "fixtures/input.jsonl",
                    "content_template": "telemetry-seed",
                    "record_count": 8,
                },
                filesystem_scope=("fixtures/input.jsonl",),
                observable_paths=("fixtures/input.jsonl",),
            ),
            id="fixture-create",
        ),
        pytest.param(
            "sandbox.fixture.transform.v1",
            {"redact_values": True},
            {"workspace": {"fixture_path": "fixtures/input.jsonl"}},
            (RECEIPT_CREATE,),
            AdaptedAction(
                params={
                    "input": "fixtures/input.jsonl",
                    "output": "fixtures/transformed.jsonl",
                    "redact_values": True,
                },
                filesystem_scope=("fixtures/input.jsonl", "fixtures/transformed.jsonl"),
                observable_paths=("fixtures/transformed.jsonl",),
            ),
            id="fixture-transform",
        ),
        pytest.param(
            "sandbox.discovery.list.v1",
            {},
            {"fixture": {"path": "fixtures/transformed.jsonl"}},
            (),
            AdaptedAction(
                params={"path": "fixtures/transformed.jsonl"},
                filesystem_scope=("fixtures/transformed.jsonl",),
            ),
            id="discovery-list",
        ),
        pytest.param(
            "sandbox.discovery.metadata.v1",
            {},
            {"fixture": {"path": "fixtures/transformed.jsonl"}},
            (),
            AdaptedAction(
                params={"path": "fixtures/transformed.jsonl"},
                filesystem_scope=("fixtures/transformed.jsonl",),
            ),
            id="discovery-metadata",
        ),
        pytest.param(
            "endpoint.discovery.system.v1",
            {},
            {},
            (),
            AdaptedAction(params={}, filesystem_scope=()),
            id="system-discovery",
        ),
        pytest.param(
            "endpoint.discovery.windows-version.v1",
            {},
            {},
            (),
            AdaptedAction(params={}, filesystem_scope=()),
            id="windows-version-discovery",
        ),
        pytest.param(
            "endpoint.discovery.processes.v1",
            {"record_limit": 7},
            {},
            (),
            AdaptedAction(params={"max_entries": 7}, filesystem_scope=()),
            id="process-discovery",
        ),
        pytest.param(
            "sandbox.discovery.recursive.v1",
            {"record_limit": 9, "max_depth": 4},
            {"workspace": {"root": "fixtures", "fixture_path": "fixtures/input.txt"}},
            (),
            AdaptedAction(
                params={"path": "fixtures", "max_entries": 9, "max_depth": 4},
                filesystem_scope=("fixtures",),
            ),
            id="recursive-discovery",
        ),
        pytest.param(
            "sandbox.archive.tar.v1",
            {},
            {
                "records": [
                    {"path": "fixtures/input.txt", "kind": "file"},
                    {"path": "fixtures/nested", "kind": "directory"},
                ]
            },
            (),
            AdaptedAction(
                params={
                    "inputs": ["fixtures/input.txt"],
                    "destination": "staged/discovery.tar",
                },
                filesystem_scope=("fixtures/input.txt", "staged/discovery.tar"),
                observable_paths=("staged/discovery.tar",),
            ),
            id="archive-tar",
        ),
        pytest.param(
            "sandbox.collection.stage.v1",
            {"bundle_format": "jsonl"},
            {
                "records": [
                    {"path": "fixtures/transformed.jsonl", "kind": "file"},
                ]
            },
            (),
            AdaptedAction(
                params={
                    "inputs": ["fixtures/transformed.jsonl"],
                    "destination_directory": "staged",
                    "bundle_format": "jsonl",
                },
                filesystem_scope=("fixtures/transformed.jsonl", "staged"),
                observable_paths=("staged/bundle.jsonl",),
            ),
            id="collection-stage",
        ),
        pytest.param(
            "sandbox.network.loopback.v1",
            {"port": 4317},
            {"bundle": {"path": "staged/bundle.jsonl"}},
            (),
            AdaptedAction(
                params={
                    "artifact": "staged/bundle.jsonl",
                    "destination": {"host": "127.0.0.1", "port": 4317},
                },
                filesystem_scope=("staged/bundle.jsonl",),
                network_destinations=({"host": "127.0.0.1", "port": 4317},),
            ),
            id="network-loopback",
        ),
        pytest.param(
            "sandbox.export.local.v1",
            {"retention_label": "ephemeral"},
            {"bundle": {"path": "staged/bundle.jsonl"}},
            (),
            AdaptedAction(
                params={
                    "source": "staged/bundle.jsonl",
                    "retention_label": "ephemeral",
                },
                filesystem_scope=("staged/bundle.jsonl", "exports/ephemeral/bundle.bin"),
                observable_paths=("exports/ephemeral/bundle.bin",),
            ),
            id="export-local",
        ),
        pytest.param(
            "sandbox.restricted.persistence-marker.v1",
            {"label": "persistence_detection_canary"},
            {},
            (),
            AdaptedAction(
                params={"label": "persistence_detection_canary"},
                filesystem_scope=("restricted/persistence-marker.json",),
                observable_paths=("restricted/persistence-marker.json",),
            ),
            id="restricted-persistence-marker",
        ),
        pytest.param(
            "sandbox.cleanup.v1",
            {"verify_removal": True},
            {},
            (RECEIPT_CREATE, RECEIPT_STAGE, RECEIPT_CREATE),
            AdaptedAction(
                params={"receipt_ids": [RECEIPT_STAGE, RECEIPT_CREATE]},
                filesystem_scope=(),
            ),
            id="cleanup",
        ),
    ],
)
def test_all_reviewed_actions_have_exact_runner_parameter_shapes(
    action_id: str,
    parameters: Mapping[str, Any],
    bound_inputs: Mapping[str, Any],
    receipt_ids: Sequence[str],
    expected: AdaptedAction,
) -> None:
    adapter = RunnerActionAdapter()
    assert adapter.action_ids == ACTION_IDS
    assert (
        adapter.adapt(
            _step(action_id, parameters),
            bound_inputs=bound_inputs,
            receipt_ids=receipt_ids,
        )
        == expected
    )


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "../outside.txt",
        "fixtures/../../outside.txt",
        "/absolute/outside.txt",
        "C:/absolute/outside.txt",
        r"fixtures\outside.txt",
        "fixtures//outside.txt",
        "fixtures/./outside.txt",
    ],
)
def test_artifact_paths_must_be_normalized_relative_sandbox_paths(path: str) -> None:
    with pytest.raises(RunnerAdapterError, match="normalized relative path|non-empty runner path"):
        RunnerActionAdapter().adapt(
            _step("sandbox.fixture.transform.v1"),
            bound_inputs={"workspace": {"fixture_path": path}},
            receipt_ids=(),
        )


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "localhost", "example.test"])
def test_network_translation_refuses_non_literal_loopback_before_connect(host: str) -> None:
    with pytest.raises(RunnerAdapterError, match="literal loopback"):
        RunnerActionAdapter().adapt(
            _step("sandbox.network.loopback.v1", {"port": 4317}),
            bound_inputs={"bundle": {"path": "staged/bundle.bin"}},
            receipt_ids=(),
            loopback_host=host,
        )


@pytest.mark.parametrize("port", [True, 0, 1023, 65536, "4317"])
def test_network_translation_rejects_invalid_ports(port: object) -> None:
    with pytest.raises(RunnerAdapterError, match="port must be an integer"):
        RunnerActionAdapter().adapt(
            _step("sandbox.network.loopback.v1", {"port": port}),
            bound_inputs={"bundle": {"path": "staged/bundle.bin"}},
            receipt_ids=(),
        )


def test_stage_and_cleanup_require_runner_owned_inputs() -> None:
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError, match="records must contain"):
        adapter.adapt(
            _step("sandbox.collection.stage.v1"),
            bound_inputs={"records": []},
            receipt_ids=(),
        )
    with pytest.raises(RunnerAdapterError, match="runner-issued receipt"):
        adapter.adapt(
            _step("sandbox.cleanup.v1"),
            bound_inputs={},
            receipt_ids=(),
        )
    with pytest.raises(RunnerAdapterError, match="64 lowercase hexadecimal"):
        adapter.adapt(
            _step("sandbox.cleanup.v1"),
            bound_inputs={},
            receipt_ids=("untrusted-receipt",),
        )


def test_new_action_outputs_are_typed_and_archive_accepts_only_file_records() -> None:
    adapter = RunnerActionAdapter()
    recursive_step = _step("sandbox.discovery.recursive.v1")
    records = adapter.logical_outputs(
        recursive_step,
        bound_inputs={"workspace": {"root": "fixtures"}},
        runner_output={
            "entries": [
                {"path": "fixtures/a.txt", "kind": "file", "size": 3, "depth": 1},
                {"path": "fixtures/nested", "kind": "directory", "size": 0, "depth": 1},
            ]
        },
        receipt_ids=(),
    )["records"]
    assert records[0]["type"] == "artifact.sandbox.filesystem.record.v1"

    archive = adapter.adapt(
        _step("sandbox.archive.tar.v1"),
        bound_inputs={"records": records},
        receipt_ids=(),
    )
    assert archive.params["inputs"] == ["fixtures/a.txt"]
    typed = adapter.logical_outputs(
        _step("sandbox.archive.tar.v1"),
        bound_inputs={"records": records},
        runner_output={"artifact": "staged/discovery.tar", "sha256": "sha256:value"},
        receipt_ids=(RECEIPT_STAGE,),
    )
    assert typed["bundle"]["type"] == "artifact.sandbox.archive.v1"

    restricted = adapter.logical_outputs(
        _step("sandbox.restricted.persistence-marker.v1"),
        bound_inputs={},
        runner_output={
            "artifact": "restricted/persistence-marker.json",
            "sha256": "sha256:value",
        },
        receipt_ids=(RECEIPT_RESTRICTED,),
    )
    assert restricted["workspace"]["root"] == "restricted"
    assert restricted["marker"] == {
        "type": "artifact.sandbox.restricted-marker.v1",
        "path": "restricted/persistence-marker.json",
        "sha256": "sha256:value",
        "receipt_ids": [RECEIPT_RESTRICTED],
    }


def test_restricted_marker_refuses_unreviewed_labels() -> None:
    with pytest.raises(RunnerAdapterError, match="label is not reviewed"):
        RunnerActionAdapter().adapt(
            _step("sandbox.restricted.persistence-marker.v1", {"label": "custom-path"}),
            bound_inputs={},
            receipt_ids=(),
        )


def test_windows_version_output_is_distinct_exact_and_typed() -> None:
    output = {
        "operating_system": "windows",
        "major_version": 10,
        "minor_version": 0,
        "build_number": 26100,
    }

    assert RunnerActionAdapter().logical_outputs(
        _step("endpoint.discovery.windows-version.v1"),
        bound_inputs={},
        runner_output=output,
        receipt_ids=(),
    ) == {
        "windows_version": {
            "type": "artifact.endpoint.windows-version.v1",
            "details": output,
        }
    }


@pytest.mark.parametrize(
    "runner_output",
    [
        {
            "operating_system": "windows",
            "major_version": True,
            "minor_version": 0,
            "build_number": 26100,
        },
        {
            "operating_system": "windows",
            "major_version": 10,
            "minor_version": False,
            "build_number": 26100,
        },
        {
            "operating_system": "windows",
            "major_version": 10,
            "minor_version": 0,
            "build_number": True,
        },
        {
            "operating_system": "windows",
            "major_version": 10,
            "minor_version": 0,
            "build_number": 26100,
            "architecture": "x86_64",
        },
    ],
)
def test_windows_version_output_rejects_booleans_and_extra_fields(
    runner_output: Mapping[str, Any],
) -> None:
    with pytest.raises(RunnerAdapterError):
        RunnerActionAdapter().logical_outputs(
            _step("endpoint.discovery.windows-version.v1"),
            bound_inputs={},
            runner_output=runner_output,
            receipt_ids=(),
        )


def test_windows_version_action_rejects_all_logical_parameters() -> None:
    with pytest.raises(RunnerAdapterError, match="contains unreviewed parameters"):
        RunnerActionAdapter().adapt(
            _step("endpoint.discovery.windows-version.v1", {"command": "systeminfo"}),
            bound_inputs={},
            receipt_ids=(),
        )


@pytest.mark.parametrize("value", [0, 101, True, "8"])
def test_fixture_record_count_is_strictly_bounded(value: object) -> None:
    with pytest.raises(
        RunnerAdapterError, match="record_count must be an integer between 1 and 100"
    ):
        RunnerActionAdapter().adapt(
            _step("sandbox.fixture.create.v1", {"record_count": value}),
            bound_inputs={},
            receipt_ids=(),
        )


@pytest.mark.parametrize(
    "action_id", ["sandbox.discovery.list.v1", "sandbox.discovery.metadata.v1"]
)
@pytest.mark.parametrize("parameters", [{"record_limit": 1}, {"max_entries": 1}])
def test_exact_fixture_discovery_rejects_obsolete_parameters(
    action_id: str, parameters: Mapping[str, Any]
) -> None:
    with pytest.raises(RunnerAdapterError, match="accepts no logical parameters"):
        RunnerActionAdapter().adapt(
            _step(action_id, parameters),
            bound_inputs={"fixture": {"path": "fixtures/transformed.jsonl"}},
            receipt_ids=(),
        )


@pytest.mark.parametrize(
    "action_id", ["sandbox.discovery.list.v1", "sandbox.discovery.metadata.v1"]
)
@pytest.mark.parametrize(
    "runner_output",
    [
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [],
            "returned_entries": 0,
            "target_cardinality": "one",
        },
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "file",
                    "size": 16,
                },
                {
                    "path": "fixtures/sibling.jsonl",
                    "name": "sibling.jsonl",
                    "kind": "file",
                    "size": 16,
                },
            ],
            "returned_entries": 2,
            "target_cardinality": "many",
        },
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/sibling.jsonl",
                    "name": "sibling.jsonl",
                    "kind": "file",
                    "size": 16,
                }
            ],
            "returned_entries": 1,
            "target_cardinality": "one",
        },
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "file",
                    "size": 16,
                }
            ],
            "returned_entries": True,
            "target_cardinality": "one",
        },
        {
            "path": "fixtures",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "file",
                    "size": 16,
                }
            ],
            "returned_entries": 1,
            "target_cardinality": "one",
        },
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "directory",
                    "size": 16,
                }
            ],
            "returned_entries": 1,
            "target_cardinality": "one",
        },
        {
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "file",
                    "size": 16,
                    "content": "must-not-cross-the-discovery-boundary",
                    "siblings": ["fixtures/other.jsonl"],
                }
            ],
            "returned_entries": 1,
            "target_cardinality": "one",
        },
    ],
)
def test_exact_fixture_discovery_rejects_widened_or_malformed_native_output(
    action_id: str, runner_output: Mapping[str, Any]
) -> None:
    with pytest.raises(
        RunnerAdapterError, match="exactly one|widened or malformed|must be an integer"
    ):
        RunnerActionAdapter().logical_outputs(
            _step(action_id),
            bound_inputs={
                "fixture": {
                    "path": "fixtures/transformed.jsonl",
                    "record_count": 8,
                    "sha256": "2" * 64,
                    "redact_values": True,
                }
            },
            runner_output=runner_output,
            receipt_ids=(),
        )


def test_list_and_metadata_accept_only_their_exact_reviewed_entry_shapes() -> None:
    adapter = RunnerActionAdapter()
    bound_inputs = {
        "fixture": {
            "path": "fixtures/transformed.jsonl",
            "record_count": 8,
            "sha256": "2" * 64,
            "redact_values": True,
        }
    }
    common_entry = {
        "path": "fixtures/transformed.jsonl",
        "name": "transformed.jsonl",
        "kind": "file",
        "size": 16,
    }
    common_output = {
        "path": "fixtures/transformed.jsonl",
        "returned_entries": 1,
        "target_cardinality": "one",
    }

    listed = adapter.logical_outputs(
        _step("sandbox.discovery.list.v1"),
        bound_inputs=bound_inputs,
        runner_output={**common_output, "entries": [common_entry]},
        receipt_ids=(),
    )
    metadata_entry = {**common_entry, "readonly": True}
    inspected = adapter.logical_outputs(
        _step("sandbox.discovery.metadata.v1"),
        bound_inputs=bound_inputs,
        runner_output={**common_output, "entries": [metadata_entry]},
        receipt_ids=(),
    )

    assert listed["records"][0]["metadata"] == common_entry
    assert inspected["records"][0]["metadata"] == metadata_entry


@pytest.mark.parametrize("readonly", [None, 1, "true"])
def test_metadata_discovery_requires_a_boolean_readonly_field(readonly: object) -> None:
    entry: dict[str, Any] = {
        "path": "fixtures/transformed.jsonl",
        "name": "transformed.jsonl",
        "kind": "file",
        "size": 16,
    }
    if readonly is not None:
        entry["readonly"] = readonly
    with pytest.raises(RunnerAdapterError, match="widened or malformed"):
        RunnerActionAdapter().logical_outputs(
            _step("sandbox.discovery.metadata.v1"),
            bound_inputs={
                "fixture": {
                    "path": "fixtures/transformed.jsonl",
                    "record_count": 8,
                    "sha256": "2" * 64,
                    "redact_values": True,
                }
            },
            runner_output={
                "path": "fixtures/transformed.jsonl",
                "entries": [entry],
                "returned_entries": 1,
                "target_cardinality": "one",
            },
            receipt_ids=(),
        )


def test_reviewed_parameters_materially_change_native_requests() -> None:
    adapter = RunnerActionAdapter()
    create_one = adapter.adapt(
        _step("sandbox.fixture.create.v1", {"record_count": 1}),
        bound_inputs={},
        receipt_ids=(),
    )
    create_eight = adapter.adapt(
        _step("sandbox.fixture.create.v1", {"record_count": 8}),
        bound_inputs={},
        receipt_ids=(),
    )
    assert create_one.params["record_count"] == 1
    assert create_eight.params["record_count"] == 8

    workspace = {"workspace": {"fixture_path": "fixtures/input.jsonl"}}
    redact = adapter.adapt(
        _step("sandbox.fixture.transform.v1", {"redact_values": True}),
        bound_inputs=workspace,
        receipt_ids=(),
    )
    preserve = adapter.adapt(
        _step("sandbox.fixture.transform.v1", {"redact_values": False}),
        bound_inputs=workspace,
        receipt_ids=(),
    )
    assert redact.params["redact_values"] is True
    assert preserve.params["redact_values"] is False

    records = {
        "records": [{"path": "fixtures/transformed.jsonl", "kind": "file", "record_count": 8}]
    }
    jsonl = adapter.adapt(
        _step("sandbox.collection.stage.v1", {"bundle_format": "jsonl"}),
        bound_inputs=records,
        receipt_ids=(),
    )
    json_bundle = adapter.adapt(
        _step("sandbox.collection.stage.v1", {"bundle_format": "json"}),
        bound_inputs=records,
        receipt_ids=(),
    )
    assert jsonl.params["bundle_format"] == "jsonl"
    assert jsonl.observable_paths == ("staged/bundle.jsonl",)
    assert json_bundle.params["bundle_format"] == "json"
    assert json_bundle.observable_paths == ("staged/bundle.json",)

    bundle = {"bundle": {"path": "staged/bundle.jsonl"}}
    ephemeral = adapter.adapt(
        _step("sandbox.export.local.v1", {"retention_label": "ephemeral"}),
        bound_inputs=bundle,
        receipt_ids=(),
    )
    review = adapter.adapt(
        _step("sandbox.export.local.v1", {"retention_label": "review"}),
        bound_inputs=bundle,
        receipt_ids=(),
    )
    assert ephemeral.observable_paths == ("exports/ephemeral/bundle.bin",)
    assert review.observable_paths == ("exports/review/bundle.bin",)


def test_fixture_success_outputs_require_exact_v2_contracts() -> None:
    adapter = RunnerActionAdapter()
    workspace = adapter.logical_outputs(
        _step("sandbox.fixture.create.v1", {"record_count": 8}),
        bound_inputs={},
        runner_output={
            "artifact": "fixtures/input.jsonl",
            "sha256": "1" * 64,
            "size": 512,
            "template": "telemetry-seed",
            "record_count": 8,
            "format": "jsonl",
        },
        receipt_ids=(RECEIPT_CREATE,),
    )["workspace"]
    assert workspace["record_count"] == 8
    assert workspace["fixture_path"] == "fixtures/input.jsonl"

    fixture = adapter.logical_outputs(
        _step("sandbox.fixture.transform.v1", {"redact_values": False}),
        bound_inputs={"workspace": workspace},
        runner_output={
            "artifact": "fixtures/transformed.jsonl",
            "sha256": "2" * 64,
            "size": 512,
            "record_count": 8,
            "redact_values": False,
            "redacted_value_count": 0,
            "format": "jsonl",
            "implementation": "in_process_reviewed_jsonl_transform",
        },
        receipt_ids=(RECEIPT_STAGE,),
    )["fixture"]
    assert fixture["record_count"] == 8
    assert fixture["redact_values"] is False
    assert fixture["sha256"] == "2" * 64


@pytest.mark.parametrize("runner_output", [None, [], "success", 1, True])
def test_successful_runner_output_must_be_an_object(runner_output: object) -> None:
    with pytest.raises(RunnerAdapterError, match="must be an object"):
        RunnerActionAdapter().logical_outputs(
            _step("sandbox.fixture.create.v1", {"record_count": 8}),
            bound_inputs={},
            runner_output=runner_output,
            receipt_ids=(RECEIPT_CREATE,),
        )


def test_success_outputs_reject_boolean_counts_and_redaction_claims() -> None:
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError, match="record_count must be an integer"):
        adapter.logical_outputs(
            _step("sandbox.fixture.create.v1", {"record_count": 8}),
            bound_inputs={},
            runner_output={
                "artifact": "fixtures/input.jsonl",
                "sha256": "1" * 64,
                "size": 512,
                "template": "telemetry-seed",
                "record_count": True,
                "format": "jsonl",
            },
            receipt_ids=(RECEIPT_CREATE,),
        )

    with pytest.raises(RunnerAdapterError, match="changed the reviewed request"):
        adapter.logical_outputs(
            _step("sandbox.fixture.transform.v1", {"redact_values": True}),
            bound_inputs={
                "workspace": {
                    "fixture_path": "fixtures/input.jsonl",
                    "record_count": 8,
                }
            },
            runner_output={
                "artifact": "fixtures/transformed.jsonl",
                "sha256": "2" * 64,
                "size": 512,
                "record_count": 8,
                "redact_values": "true",
                "redacted_value_count": 8,
                "format": "jsonl",
                "implementation": "in_process_reviewed_jsonl_transform",
            },
            receipt_ids=(RECEIPT_STAGE,),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_count", True),
        ("accepted_input_count", True),
        ("rejected_input_count", False),
        ("record_count", True),
        ("size", True),
        ("complete", 1),
    ],
)
def test_collection_success_rejects_boolean_counters_and_truthy_completion(
    field: str, value: object
) -> None:
    runner_output: dict[str, object] = {
        "artifact": "staged/bundle.jsonl",
        "format": "jsonl",
        "record_count": 8,
        "size": 512,
        "sha256": "3" * 64,
        "input_count": 1,
        "accepted_input_count": 1,
        "rejected_input_count": 0,
        "complete": True,
    }
    runner_output[field] = value
    with pytest.raises(RunnerAdapterError, match="integer|incomplete"):
        RunnerActionAdapter().logical_outputs(
            _step("sandbox.collection.stage.v1", {"bundle_format": "jsonl"}),
            bound_inputs={
                "records": [
                    {
                        "path": "fixtures/transformed.jsonl",
                        "kind": "file",
                        "record_count": 8,
                    }
                ]
            },
            runner_output=runner_output,
            receipt_ids=(RECEIPT_STAGE,),
        )


@pytest.mark.parametrize(
    ("action_id", "parameters", "bound_inputs", "message"),
    [
        (
            "sandbox.fixture.transform.v1",
            {"redact_values": "true"},
            {"workspace": {"fixture_path": "fixtures/input.jsonl"}},
            "redact_values must be a boolean",
        ),
        (
            "sandbox.collection.stage.v1",
            {"bundle_format": "yaml"},
            {"records": [{"path": "fixtures/transformed.jsonl", "kind": "file"}]},
            "bundle_format must be one of",
        ),
        (
            "sandbox.export.local.v1",
            {"retention_label": "forever"},
            {"bundle": {"path": "staged/bundle.jsonl"}},
            "retention_label must be one of",
        ),
        (
            "sandbox.cleanup.v1",
            {"verify_removal": False},
            {},
            "verify_removal must be true",
        ),
    ],
)
def test_semantic_parameters_reject_unreviewed_values(
    action_id: str,
    parameters: Mapping[str, Any],
    bound_inputs: Mapping[str, Any],
    message: str,
) -> None:
    with pytest.raises(RunnerAdapterError, match=message):
        RunnerActionAdapter().adapt(
            _step(action_id, parameters),
            bound_inputs=bound_inputs,
            receipt_ids=(RECEIPT_CREATE,),
        )


def test_bundle_metadata_and_export_outputs_remain_typed_and_policy_bound() -> None:
    adapter = RunnerActionAdapter()
    metadata = adapter.logical_outputs(
        _step("sandbox.discovery.metadata.v1"),
        bound_inputs={
            "fixture": {
                "path": "fixtures/transformed.jsonl",
                "record_count": 8,
                "sha256": "digest-transform",
                "redact_values": True,
            }
        },
        runner_output={
            "path": "fixtures/transformed.jsonl",
            "entries": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "name": "transformed.jsonl",
                    "kind": "file",
                    "size": 512,
                    "readonly": True,
                }
            ],
            "returned_entries": 1,
            "target_cardinality": "one",
        },
        receipt_ids=(),
    )
    assert metadata["records"][0]["path"] == "fixtures/transformed.jsonl"
    assert metadata["records"][0]["record_count"] == 8

    bundle = adapter.logical_outputs(
        _step("sandbox.collection.stage.v1", {"bundle_format": "json"}),
        bound_inputs={
            "records": [
                {
                    "path": "fixtures/transformed.jsonl",
                    "kind": "file",
                    "record_count": 8,
                }
            ]
        },
        runner_output={
            "artifact": "staged/bundle.json",
            "format": "json",
            "record_count": 8,
            "size": 512,
            "sha256": "3" * 64,
            "input_count": 1,
            "accepted_input_count": 1,
            "rejected_input_count": 0,
            "complete": True,
        },
        receipt_ids=(RECEIPT_STAGE,),
    )["bundle"]
    assert bundle == {
        "type": "artifact.sandbox.bundle.v1",
        "path": "staged/bundle.json",
        "sha256": "3" * 64,
        "format": "json",
        "record_count": 8,
        "size": 512,
        "receipt_ids": [RECEIPT_STAGE],
    }

    receipt = adapter.logical_outputs(
        _step("sandbox.export.local.v1", {"retention_label": "review"}),
        bound_inputs={"bundle": bundle},
        runner_output={
            "source": "staged/bundle.json",
            "artifact": "exports/review/bundle.bin",
            "size": 512,
            "retention_label": "review",
            "sha256": "3" * 64,
            "destination_policy": "runner_fixed_retention_destination",
        },
        receipt_ids=(RECEIPT_STAGE,),
    )["receipt"]
    assert receipt["retention_label"] == "review"

    with pytest.raises(RunnerAdapterError, match="does not match retention policy"):
        adapter.logical_outputs(
            _step("sandbox.export.local.v1", {"retention_label": "review"}),
            bound_inputs={"bundle": bundle},
            runner_output={
                "source": "staged/bundle.json",
                "artifact": "exports/ephemeral/bundle.bin",
                "size": 512,
                "retention_label": "ephemeral",
                "sha256": "3" * 64,
                "destination_policy": "runner_fixed_retention_destination",
            },
            receipt_ids=(),
        )


@pytest.mark.parametrize(("field", "value"), [("sha256", "4" * 64), ("size", 511)])
def test_export_output_must_match_the_bound_bundle(field: str, value: object) -> None:
    runner_output: dict[str, object] = {
        "source": "staged/bundle.json",
        "artifact": "exports/review/bundle.bin",
        "size": 512,
        "retention_label": "review",
        "sha256": "3" * 64,
        "destination_policy": "runner_fixed_retention_destination",
    }
    runner_output[field] = value

    with pytest.raises(RunnerAdapterError, match="does not match the bound bundle"):
        RunnerActionAdapter().logical_outputs(
            _step("sandbox.export.local.v1", {"retention_label": "review"}),
            bound_inputs={
                "bundle": {
                    "type": "artifact.sandbox.bundle.v1",
                    "path": "staged/bundle.json",
                    "sha256": "3" * 64,
                    "size": 512,
                }
            },
            runner_output=runner_output,
            receipt_ids=(RECEIPT_STAGE,),
        )


def test_network_output_must_match_the_bound_authenticated_request() -> None:
    adapter = RunnerActionAdapter()
    bound_inputs = {
        "bundle": {
            "type": "artifact.sandbox.bundle.v1",
            "path": "staged/bundle.jsonl",
            "sha256": "3" * 64,
            "size": 512,
        }
    }
    output: dict[str, object] = {
        "destination": {"host": "127.0.0.1", "port": 4317},
        "artifact": "staged/bundle.jsonl",
        "bytes_sent": 512,
        "sha256": "3" * 64,
        "http_status": 200,
        "receiver_acknowledged": True,
        "receiver_stored": False,
    }
    receipt = adapter.logical_outputs(
        _step("sandbox.network.loopback.v1", {"port": 4317}),
        bound_inputs=bound_inputs,
        runner_output=output,
        receipt_ids=(RECEIPT_STAGE,),
    )["receipt"]
    assert receipt["details"] == output

    mismatches = (
        {**output, "sha256": "4" * 64},
        {**output, "bytes_sent": 511},
        {**output, "artifact": "staged/other.jsonl"},
        {**output, "destination": {"host": "127.0.0.1", "port": 4318}},
        {**output, "receiver_acknowledged": False},
        {**output, "http_status": 201, "receiver_stored": False},
        {**output, "http_status": 200, "receiver_stored": True},
    )
    for mismatch in mismatches:
        with pytest.raises(RunnerAdapterError, match="does not match the bound request"):
            adapter.logical_outputs(
                _step("sandbox.network.loopback.v1", {"port": 4317}),
                bound_inputs=bound_inputs,
                runner_output=mismatch,
                receipt_ids=(RECEIPT_STAGE,),
            )

    for malformed in (
        {**output, "http_status": 300},
        {**output, "receiver_acknowledged": 1},
        {**output, "receiver_stored": 0},
        {**output, "destination": {"host": "127.0.0.1", "port": 4317.0}},
        {**output, "extra": True},
    ):
        with pytest.raises(RunnerAdapterError, match="integer|boolean|shape"):
            adapter.logical_outputs(
                _step("sandbox.network.loopback.v1", {"port": 4317}),
                bound_inputs=bound_inputs,
                runner_output=malformed,
                receipt_ids=(RECEIPT_STAGE,),
            )
