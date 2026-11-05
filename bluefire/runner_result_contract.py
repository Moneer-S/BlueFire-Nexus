"""Pure identity and cleanup contracts for authenticated runner results."""

from __future__ import annotations

from typing import Any, Mapping


class RunnerResultContractError(ValueError):
    """A runner result does not match its reviewed request contract."""


def validate_runner_result_identity(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    expected = {
        "schema_version": "bluefire.runner-result.v1",
        "request_id": manifest["request_id"],
        "run_id": manifest["run_id"],
        "step_id": manifest["step_id"],
        "behavior_id": manifest["behavior_id"],
        "action_id": manifest["action_id"],
        "runner_id": manifest["runner_id"],
        "runner_profile_id": manifest["runner_profile_id"],
        "platform": profile["platform"],
        "request_hash": manifest["request_hash"],
        "policy_digest": profile["policy_digest"],
    }
    for field, value in expected.items():
        if result.get(field) != value:
            raise RunnerResultContractError(f"runner result {field} does not match its request")


def validated_receipt_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RunnerResultContractError("runner result receipt_ids must be a list")
    result: list[str] = []
    for receipt_id in value:
        if (
            not isinstance(receipt_id, str)
            or len(receipt_id) != 64
            or any(character not in "0123456789abcdef" for character in receipt_id)
        ):
            raise RunnerResultContractError("runner returned an invalid receipt ID")
        if receipt_id in result:
            raise RunnerResultContractError("runner returned duplicate receipt IDs")
        result.append(receipt_id)
    return tuple(result)


def validate_cleanup_result_contract(
    manifest: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    execution_binding = manifest.get("execution_binding")
    bound_opcode = (
        execution_binding.get("runner_opcode") if isinstance(execution_binding, Mapping) else None
    )
    if manifest.get("action_id") != "sandbox.cleanup.v1" and bound_opcode != ("sandbox.cleanup.v1"):
        return
    cleanup = result.get("cleanup")
    if not isinstance(cleanup, Mapping):
        raise RunnerResultContractError("cleanup result is missing its cleanup report")
    expected_cleanup_fields = {
        "requested_receipts",
        "removed_paths",
        "already_absent_receipts",
        "retained_paths",
        "errors",
        "verification_performed",
        "verified_removed_paths",
        "verified_absent_paths",
        "verified_receipts",
    }
    if set(cleanup) not in (
        expected_cleanup_fields,
        expected_cleanup_fields | {"verified_receipt_ids"},
    ):
        raise RunnerResultContractError("cleanup report shape is invalid")
    verified_ids = cleanup.get("verified_receipt_ids")
    if verified_ids is not None and (
        not isinstance(verified_ids, list)
        or any(
            not isinstance(receipt_id, str)
            or len(receipt_id) != 64
            or any(character not in "0123456789abcdef" for character in receipt_id)
            for receipt_id in verified_ids
        )
        or len(verified_ids) != len(set(verified_ids))
        or len(verified_ids) != cleanup.get("verified_receipts")
    ):
        raise RunnerResultContractError("cleanup verified receipt identities are invalid")
    for field in (
        "removed_paths",
        "already_absent_receipts",
        "retained_paths",
        "errors",
    ):
        values = cleanup.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise RunnerResultContractError("cleanup report lists are invalid")
    for field in (
        "requested_receipts",
        "verified_removed_paths",
        "verified_absent_paths",
        "verified_receipts",
    ):
        value = cleanup.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RunnerResultContractError("cleanup verification counters are invalid")
    output = result.get("output")
    if not isinstance(output, Mapping) or dict(output) != dict(cleanup):
        raise RunnerResultContractError("cleanup output does not match its authoritative report")
    params = manifest.get("params")
    requested = params.get("receipt_ids") if isinstance(params, Mapping) else None
    if not isinstance(requested, list):
        raise RunnerResultContractError("cleanup manifest has no receipt list")
    if result.get("status") != "success":
        return
    if cleanup.get("requested_receipts") != len(requested):
        raise RunnerResultContractError("cleanup report does not cover every requested receipt")
    if cleanup.get("errors") != [] or cleanup.get("retained_paths") != []:
        raise RunnerResultContractError("cleanup reported success with retained artifacts")
    if cleanup.get("verification_performed") is not True:
        raise RunnerResultContractError("cleanup success lacks verified postconditions")
    if cleanup.get("verified_receipts") != len(requested):
        raise RunnerResultContractError("cleanup did not verify every requested receipt")


__all__ = [
    "RunnerResultContractError",
    "validate_cleanup_result_contract",
    "validate_runner_result_identity",
    "validated_receipt_ids",
]
