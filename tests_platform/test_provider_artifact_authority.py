"""Provider JSON must not become native evidence or filesystem authority."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire import action_provider_packages
from bluefire.action_packages import ActionPackageError, audit_action_package, verify_action_package
from bluefire.contracts import ActionDefinition
from bluefire.execution_contracts import (
    RESERVED_PROVIDER_ARTIFACT_PREFIXES,
    provider_artifact_type_allowed,
)
from bluefire.provider_runner_contracts import (
    ProviderRunnerContractError,
    canonical_provider_binding,
)
from bluefire.registry import load_builtin_registry
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError
from tests_platform.test_action_provider_packages import _payload, _signed, _trust
from tests_platform.test_provider_runner_adapter import _step
from tests_platform.test_provider_runner_contracts import _binding

RESERVED_TYPES = (
    "artifact.sandbox.filesystem.record.v1",
    "artifact.sandbox.bundle.v1",
    "artifact.sandbox.archive.v1",
    "artifact.sandbox.workspace.v2",
    "artifact.endpoint.process-records.v1",
    "artifact.file_access.probe.v1",
    "artifact.macos_file_access.probe.v1",
    "artifact.macos_file_access.verification.v1",
    "artifact.macos_file_access.attempt.v1",
    "artifact.macos_file_access.attempt_closure.v1",
    "artifact.permission.mode.v1",
    "artifact.research.hypothesis.v1",
)


@pytest.mark.parametrize("artifact_type", RESERVED_TYPES)
def test_preexisting_signed_provider_cannot_claim_native_artifacts(monkeypatch, artifact_type):
    payload = _payload()
    for definition in (payload["behaviors"][0], payload["actions"][0]["definition"]):
        definition["outputs"][0]["type"] = artifact_type
    action = payload["actions"][0]
    action["program"]["action_contract_digest"] = (
        action_provider_packages.provider_action_contract_digest(
            ActionDefinition.from_mapping(action["definition"])
        )
    )
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ActionPackageError, match="reserved artifact namespace"):
        _signed(private_key, payload=payload)
    # Model a previously signed package, then restore all current validation.
    with monkeypatch.context() as previous:
        previous.setattr(action_provider_packages, "validate_provider_action", lambda *_a: None)
        envelope = _signed(private_key, payload=payload)
    with pytest.raises(ActionPackageError, match="reserved artifact namespace"):
        verify_action_package(
            envelope,
            trusted_signers=_trust(private_key),
            bluefire_version="0.1.0",
            platform="windows",
        )
    with pytest.raises(ActionPackageError, match="reserved artifact namespace"):
        audit_action_package(envelope, trusted_signers=_trust(private_key))


@pytest.mark.parametrize("artifact_type", RESERVED_TYPES)
def test_runner_binding_refuses_reserved_namespace_before_digest_checks(artifact_type):
    binding, _ = _binding()
    binding["outputs"][0]["type"] = artifact_type
    with pytest.raises(ProviderRunnerContractError, match="reserved artifact namespace"):
        canonical_provider_binding(binding, context="provider binding")


@pytest.mark.parametrize("artifact_type", RESERVED_TYPES)
@pytest.mark.parametrize("multiple", [False, True])
def test_provider_result_never_reaches_native_consumers(artifact_type, multiple):
    step = _step()
    binding = dict(step.execution_binding)
    binding["outputs"] = [
        {"name": "result", "type": artifact_type, "required": True, "multiple": multiple}
    ]
    forged = {"type": artifact_type, "path": "unrelated.txt", "sha256": "0" * 64}
    with pytest.raises(RunnerAdapterError, match="reserved artifact namespace"):
        RunnerActionAdapter().logical_outputs(
            replace(step, execution_binding=binding),
            bound_inputs={},
            runner_output={
                "schema_version": "bluefire.provider-action-output.v1",
                "outputs": {"result": [forged] if multiple else forged},
            },
            receipt_ids=(),
        )


def test_builtin_ports_and_native_refusal_inventory_cannot_drift():
    registry = load_builtin_registry()
    types = {port.type for action in registry.actions for port in (*action.inputs, *action.outputs)}
    assert types and all(not provider_artifact_type_allowed(value) for value in types)
    source = (Path(__file__).resolve().parents[1] / "runner/src/provider_action.rs").read_text()
    literal = re.search(r"const RESERVED_PREFIXES:.*?= \[(.*?)\];", source, re.DOTALL)
    assert literal is not None
    assert tuple(re.findall(r'"([^"]+)"', literal.group(1))) == RESERVED_PROVIDER_ARTIFACT_PREFIXES


@pytest.mark.parametrize(
    "artifact_type",
    ["artifact.provider.result.v1", "artifact.acme.result.v1", "artifact.example.result.v1"],
)
def test_independent_provider_namespaces_remain_available(artifact_type):
    assert provider_artifact_type_allowed(artifact_type)
