"""Locked contract types and parsing for product release acceptance."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

CONTRACT_SCHEMA_VERSION = "bluefire.product-acceptance-contract.v1"
RECEIPT_SCHEMA_VERSION = "bluefire.product-gate-receipt.v1"
RELEASE_CONTRACT_SHA256 = (
    "87093ec71b2b564e74ae9a97e3d1682a6006abdd04bc8b5d593bd077ab2460eb"  # pragma: allowlist secret
)

EXPECTED_GATE_IDS = tuple(f"GATE-{index:02d}" for index in range(1, 13))
_ALLOWED_PROOF_KINDS = frozenset({"dynamic", "structural"})
_ALLOWED_PLACEHOLDERS = frozenset({"python", "repository", "run_dir", "gate_dir", "receipt"})
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class AcceptanceContractError(ValueError):
    """Raised when the locked release contract is invalid or changed."""


@dataclass(frozen=True)
class GateAssertion:
    assertion_id: str
    proof: str
    description: str


@dataclass(frozen=True)
class GateDefinition:
    gate_id: str
    title: str
    required: bool
    assertions: tuple[GateAssertion, ...]
    required_proof: tuple[str, ...]
    minimum_evidence_artifacts: int
    minimum_run_ids: int
    minimum_test_ids: int
    timeout_seconds: int
    command: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseContract:
    contract_id: str
    release_command: str
    receipt_schema_version: str
    result_schema: str
    gates: tuple[GateDefinition, ...]
    digest: str
    document: Mapping[str, Any]


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _resource_text(name: str) -> str:
    return importlib.resources.files("bluefire.data").joinpath(name).read_text(encoding="utf-8")


def load_release_contract(path: Path | None = None) -> ReleaseContract:
    """Load and verify the one canonical release contract."""

    text = (
        path.read_text(encoding="utf-8")
        if path is not None
        else _resource_text("product_acceptance.yaml")
    )
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AcceptanceContractError("release acceptance contract is not valid YAML") from exc
    contract = contract_from_mapping(document)
    if contract.digest != "sha256:" + RELEASE_CONTRACT_SHA256:
        raise AcceptanceContractError(
            "release acceptance contract digest changed; review may only preserve or strengthen gates"
        )
    return contract


def contract_from_mapping(document: Any) -> ReleaseContract:
    """Validate a contract mapping; used by the locked loader and focused tests."""

    if not isinstance(document, Mapping):
        raise AcceptanceContractError("release acceptance contract must be an object")
    if document.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise AcceptanceContractError("unsupported release acceptance contract schema")
    contract_id = _required_text(document, "contract_id")
    release_command = _required_text(document, "release_command")
    receipt_schema = _required_text(document, "receipt_schema_version")
    result_schema = _required_text(document, "result_schema")
    if receipt_schema != RECEIPT_SCHEMA_VERSION:
        raise AcceptanceContractError("unsupported gate receipt schema")

    policy = document.get("policy")
    required_policy = {
        "execute_sequentially": True,
        "require_clean_committed_tree": True,
        "require_dynamic_proof_for_every_gate": True,
        "structural_proof_cannot_replace_dynamic_proof": True,
        "documentation_is_not_gate_evidence": True,
    }
    if not isinstance(policy, Mapping) or any(
        policy.get(key) is not value for key, value in required_policy.items()
    ):
        raise AcceptanceContractError("release acceptance policy cannot be weakened")

    raw_gates = document.get("gates")
    if not isinstance(raw_gates, Sequence) or isinstance(raw_gates, (str, bytes)):
        raise AcceptanceContractError("release acceptance gates must be a list")
    gates = tuple(_gate_from_mapping(raw) for raw in raw_gates)
    gate_ids = tuple(gate.gate_id for gate in gates)
    if gate_ids != EXPECTED_GATE_IDS:
        raise AcceptanceContractError(
            "release acceptance must contain the exact ordered GATE-01..GATE-12 set"
        )
    if any(not gate.required or "dynamic" not in gate.required_proof for gate in gates):
        raise AcceptanceContractError(
            "every release gate must remain required and dynamically proven"
        )

    digest = _sha256_bytes(_canonical_json_bytes(document))
    return ReleaseContract(
        contract_id=contract_id,
        release_command=release_command,
        receipt_schema_version=receipt_schema,
        result_schema=result_schema,
        gates=gates,
        digest=digest,
        document=dict(document),
    )


def _required_text(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise AcceptanceContractError(f"contract field {key!r} must be non-empty text")
    return item


def _required_nonnegative_int(value: Mapping[str, Any], key: str) -> int:
    item = value.get(key)
    if type(item) is not int or item < 0:
        raise AcceptanceContractError(f"contract field {key!r} must be a non-negative integer")
    return item


def _gate_from_mapping(raw: Any) -> GateDefinition:
    if not isinstance(raw, Mapping):
        raise AcceptanceContractError("each release gate must be an object")
    gate_id = _required_text(raw, "id")
    title = _required_text(raw, "title")
    required = raw.get("required")
    if required is not True:
        raise AcceptanceContractError(f"{gate_id} must remain required")
    proof = raw.get("required_proof")
    if not isinstance(proof, Sequence) or isinstance(proof, (str, bytes)) or not proof:
        raise AcceptanceContractError(f"{gate_id} required_proof must be a list")
    required_proof = tuple(proof)
    if (
        len(required_proof) != len(set(required_proof))
        or not set(required_proof) <= _ALLOWED_PROOF_KINDS
    ):
        raise AcceptanceContractError(f"{gate_id} contains an invalid proof requirement")
    raw_assertions = raw.get("assertions")
    if not isinstance(raw_assertions, Sequence) or isinstance(raw_assertions, (str, bytes)):
        raise AcceptanceContractError(f"{gate_id} assertions must be a list")
    assertions = tuple(_assertion_from_mapping(item, gate_id) for item in raw_assertions)
    assertion_ids = tuple(assertion.assertion_id for assertion in assertions)
    if not assertions or len(assertion_ids) != len(set(assertion_ids)):
        raise AcceptanceContractError(f"{gate_id} assertions must be non-empty and unique")
    if {assertion.proof for assertion in assertions} != set(required_proof):
        raise AcceptanceContractError(f"{gate_id} proof requirements must match its assertions")

    timeout = _required_nonnegative_int(raw, "timeout_seconds")
    if not 1 <= timeout <= 7200:
        raise AcceptanceContractError(f"{gate_id} timeout must be between 1 and 7200 seconds")
    workflow = raw.get("workflow")
    command = workflow.get("command") if isinstance(workflow, Mapping) else None
    if not isinstance(command, Sequence) or isinstance(command, (str, bytes)) or not command:
        raise AcceptanceContractError(f"{gate_id} workflow command must be an argument list")
    tokens: list[str] = []
    for token in command:
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise AcceptanceContractError(f"{gate_id} workflow contains an invalid argument")
        unknown = set(_PLACEHOLDER.findall(token)) - _ALLOWED_PLACEHOLDERS
        if unknown:
            raise AcceptanceContractError(f"{gate_id} workflow contains unknown placeholders")
        tokens.append(token)

    return GateDefinition(
        gate_id=gate_id,
        title=title,
        required=True,
        assertions=assertions,
        required_proof=required_proof,
        minimum_evidence_artifacts=_required_nonnegative_int(raw, "minimum_evidence_artifacts"),
        minimum_run_ids=_required_nonnegative_int(raw, "minimum_run_ids"),
        minimum_test_ids=_required_nonnegative_int(raw, "minimum_test_ids"),
        timeout_seconds=timeout,
        command=tuple(tokens),
    )


def _assertion_from_mapping(raw: Any, gate_id: str) -> GateAssertion:
    if not isinstance(raw, Mapping):
        raise AcceptanceContractError(f"{gate_id} assertion must be an object")
    assertion_id = _required_text(raw, "id")
    proof = _required_text(raw, "proof")
    description = _required_text(raw, "description")
    if not assertion_id.startswith(gate_id + "-") or not _SAFE_IDENTIFIER.fullmatch(assertion_id):
        raise AcceptanceContractError(f"{gate_id} assertion ID is invalid")
    if proof not in _ALLOWED_PROOF_KINDS:
        raise AcceptanceContractError(f"{assertion_id} proof kind is invalid")
    if len(description) > 500:
        raise AcceptanceContractError(f"{assertion_id} description is too long")
    return GateAssertion(assertion_id, proof, description)


__all__ = [
    "AcceptanceContractError",
    "CONTRACT_SCHEMA_VERSION",
    "EXPECTED_GATE_IDS",
    "GateAssertion",
    "GateDefinition",
    "RECEIPT_SCHEMA_VERSION",
    "RELEASE_CONTRACT_SHA256",
    "ReleaseContract",
    "contract_from_mapping",
    "load_release_contract",
]
