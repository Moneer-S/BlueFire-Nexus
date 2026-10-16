"""Immutable task-payload provenance; these records are not dispatch permission."""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping

from .execution_contracts import execution_task_identity
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash, json_clone

_DIGEST_PREFIX = "sha256:"
_CLEANUP_ACTION_ID = "sandbox.cleanup.v1"
_MACOS_CLEANUP_ACTION_ID = "macos.file_access.close_attempt.v1"
_MACOS_CLEANUP_SCHEMA = "bluefire.macos-file-access-artifact-closure-claim.v1"
_MACOS_CLEANUP_FIELDS = {
    "schema_version",
    "attempt_id",
    "lease_digest",
    "compiled_digest",
    "run_id",
    "cleanup_step_id",
    "issued_at_ms",
    "expires_at_ms",
    "issued_monotonic_ns",
    "deadline_ns",
    "scope",
}


def _require_digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
        or any(character not in "0123456789abcdef" for character in value[len(_DIGEST_PREFIX) :])
    ):
        raise ProductStoreError(f"The retained {name} is invalid.")
    return value


def cleanup_step_id(compiled: Mapping[str, Any]) -> str:
    scenario = compiled.get("scenario")
    steps = scenario.get("steps") if isinstance(scenario, Mapping) else None
    if not isinstance(steps, list):
        raise ProductStoreError("The compiled scenario has no cleanup step list.")
    candidates = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and step.get("behavior_id") == _CLEANUP_ACTION_ID
        and step.get("action_id", _CLEANUP_ACTION_ID) == _CLEANUP_ACTION_ID
    ]
    if len(candidates) != 1:
        raise ProductStoreError("The compiled scenario must contain exactly one cleanup step.")
    step_id = candidates[0].get("id")
    if not isinstance(step_id, str) or not step_id:
        raise ProductStoreError("The compiled cleanup step has no stable step ID.")
    return step_id


def payload_document(
    *,
    purpose: str,
    task_id: str,
    attempt_id: str,
    lease: Mapping[str, Any],
    step_id: str,
    request_hash: str,
    manifest: Mapping[str, Any],
    runner_profile: Mapping[str, Any],
    attempt_claim: Mapping[str, Any],
    attempt_claim_digest: str,
    workspace: Mapping[str, Any],
    dependency: Mapping[str, Any],
    cleanup_claim: Mapping[str, Any] | None = None,
    cleanup_claim_digest: str | None = None,
    cleanup_obligation_digest: str | None = None,
    macos_cleanup_claim: Mapping[str, Any] | None = None,
    macos_cleanup_claim_digest: str | None = None,
) -> dict[str, Any]:
    if purpose not in {"business", "cleanup", "macos_cleanup"}:
        raise ProductStoreError("The task payload purpose is invalid.")
    if not isinstance(manifest, Mapping) or not isinstance(runner_profile, Mapping):
        raise ProductStoreError("The exact runner manifest and profile are required.")
    try:
        manifest_copy = dict(json_clone(dict(manifest)))
        profile_copy = dict(json_clone(dict(runner_profile)))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("The exact runner task payload is invalid.") from exc
    request_hash = _require_digest(request_hash, "task request hash")
    attempt_claim_digest = _require_digest(attempt_claim_digest, "attempt claim digest")
    dependency_digest = content_hash(dict(dependency))
    workspace_digest = content_hash(dict(workspace))

    try:
        task_identity, transport_hash = execution_task_identity(manifest_copy, profile_copy)
        manifest_request_hash = manifest_copy.get("request_hash")
        profile_policy_digest = profile_copy.get("policy_digest")
        manifest_body = dict(json_clone(manifest_copy))
        manifest_body["request_hash"] = ""
        for nested_key in ("approval", "grant_attempt", "grant_cleanup"):
            nested = manifest_body.get(nested_key)
            if isinstance(nested, dict) and "request_hash" in nested:
                nested["request_hash"] = ""
        profile_body = dict(profile_copy)
        profile_body["policy_digest"] = ""
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("The exact runner task payload is invalid.") from exc

    if (
        task_identity != task_id
        or manifest_request_hash != request_hash
        or manifest_copy.get("schema_version") != "bluefire.runner-manifest.v1"
        or content_hash(manifest_body) != request_hash
        or not isinstance(profile_policy_digest, str)
        or _require_digest(profile_policy_digest, "runner policy digest") != profile_policy_digest
        or content_hash(profile_body) != profile_policy_digest
        or profile_copy.get("schema_version") != "bluefire.runner-profile.v1"
        or not isinstance(profile_copy.get("sandbox_root"), str)
        or not profile_copy["sandbox_root"]
        or not isinstance(profile_copy.get("runner_id"), str)
        or not profile_copy["runner_id"]
        or not isinstance(profile_copy.get("profile_id"), str)
        or not profile_copy["profile_id"]
        or manifest_copy.get("run_id") != lease.get("run_id")
        or manifest_copy.get("step_id") != step_id
        or manifest_copy.get("runner_id") != profile_copy.get("runner_id")
        or manifest_copy.get("runner_profile_id") != profile_copy.get("profile_id")
        or manifest_copy.get("policy_digest") != profile_policy_digest
        or workspace.get("attempt_id") != attempt_id
        or workspace.get("lease_digest") != lease.get("lease_digest")
        or workspace.get("runner_policy_digest") != profile_policy_digest
        or workspace.get("workspace_path_digest")
        != content_hash({"sandbox_root": profile_copy.get("sandbox_root")})
        or attempt_claim.get("attempt_id") != attempt_id
        or attempt_claim.get("lease_digest") != lease.get("lease_digest")
        or attempt_claim.get("run_id") != lease.get("run_id")
    ):
        raise ProductStoreError("The runner payload differs from its exact capability attempt.")

    if purpose == "cleanup" and (
        step_id != manifest_copy.get("step_id")
        or manifest_copy.get("action_id") != _CLEANUP_ACTION_ID
        or manifest_copy.get("behavior_id") != _CLEANUP_ACTION_ID
    ):
        raise ProductStoreError("The cleanup manifest differs from its compiled cleanup step.")

    if purpose == "macos_cleanup":
        if (
            step_id != manifest_copy.get("step_id")
            or manifest_copy.get("action_id") != _MACOS_CLEANUP_ACTION_ID
            or manifest_copy.get("behavior_id") != _MACOS_CLEANUP_ACTION_ID
            or manifest_copy.get("platform") != "macos"
            or profile_copy.get("platform") != "macos"
            or manifest_copy.get("params") != {}
            or manifest_copy.get("approval") is not None
            or "grant_attempt" in manifest_copy
            or "grant_cleanup" in manifest_copy
            or macos_cleanup_claim is None
            or macos_cleanup_claim_digest is None
        ):
            raise ProductStoreError(
                "The Mac closure manifest mixes authority or changes its fixed task."
            )
        claim = dict(macos_cleanup_claim)
        macos_cleanup_claim_digest = _require_digest(
            macos_cleanup_claim_digest, "Mac attempt-closure claim digest"
        )
        if (
            set(claim) != _MACOS_CLEANUP_FIELDS
            or claim.get("schema_version") != _MACOS_CLEANUP_SCHEMA
            or claim.get("attempt_id") != attempt_id
            or claim.get("lease_digest") != lease.get("lease_digest")
            or claim.get("compiled_digest") != lease.get("compiled_digest")
            or claim.get("run_id") != lease.get("run_id")
            or claim.get("cleanup_step_id") != step_id
            or claim.get("scope") != "attempt_artifact_closure_only"
            or type(claim.get("issued_at_ms")) is not int
            or type(claim.get("expires_at_ms")) is not int
            or type(claim.get("issued_monotonic_ns")) is not int
            or type(claim.get("deadline_ns")) is not int
            or not claim["issued_at_ms"] < claim["expires_at_ms"]
            or not claim["issued_monotonic_ns"] < claim["deadline_ns"]
            or content_hash(claim) != macos_cleanup_claim_digest
            or manifest_copy.get("macos_file_access_cleanup") != claim
        ):
            raise ProductStoreError("The Mac attempt-closure claim differs from its payload.")
    elif macos_cleanup_claim is not None or macos_cleanup_claim_digest is not None:
        raise ProductStoreError("Only a Mac closure task can carry its artifact-closure claim.")

    if purpose == "macos_cleanup":
        if any(
            value is not None
            for value in (cleanup_claim, cleanup_claim_digest, cleanup_obligation_digest)
        ):
            raise ProductStoreError("A Mac closure task cannot carry generic cleanup authority.")
        embedded_claim = manifest_copy.get("macos_file_access_cleanup")
        claim_document = dict(macos_cleanup_claim or {})
        expected_embedded_claim = claim_document
    else:
        embedded_claim_key = "grant_attempt" if purpose == "business" else "grant_cleanup"
        embedded_claim = manifest_copy.get(embedded_claim_key)
        other_claim_key = "grant_cleanup" if purpose == "business" else "grant_attempt"
        if other_claim_key in manifest_copy or "macos_file_access_cleanup" in manifest_copy:
            raise ProductStoreError("The task manifest mixes business and cleanup claim authority.")
        claim_document = dict(attempt_claim)
    if purpose == "cleanup":
        if (
            cleanup_claim is None
            or cleanup_claim_digest is None
            or cleanup_obligation_digest is None
        ):
            raise ProductStoreError("Cleanup payload provenance lacks its exact cleanup claim.")
        cleanup_claim_digest = _require_digest(cleanup_claim_digest, "cleanup claim digest")
        cleanup_obligation_digest = _require_digest(
            cleanup_obligation_digest, "cleanup obligation digest"
        )
        claim_document = dict(cleanup_claim)
    elif any(
        value is not None
        for value in (cleanup_claim, cleanup_claim_digest, cleanup_obligation_digest)
    ):
        raise ProductStoreError("A business task cannot carry cleanup claim provenance.")
    from .runner_contracts import _canonical_grant_attempt, _canonical_grant_cleanup

    if purpose != "macos_cleanup":
        canonical_claim = (
            _canonical_grant_attempt(claim_document, wire=False)
            if purpose == "business"
            else _canonical_grant_cleanup(claim_document, wire=False)
        )
        expected_embedded_claim = {**canonical_claim, "request_hash": request_hash}
    if embedded_claim != expected_embedded_claim:
        raise ProductStoreError("The manifest does not carry the exact retained capability claim.")

    document = {
        "schema_version": "bluefire.capability-task-payload.v1",
        "purpose": purpose,
        "task_id": task_id,
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        "attempt_claim_digest": attempt_claim_digest,
        "run_id": lease["run_id"],
        "step_id": step_id,
        "request_hash": request_hash,
        "manifest_digest": content_hash(manifest_copy),
        "runner_profile_digest": content_hash(profile_copy),
        "transport_request_hash": transport_hash,
        "policy_digest": profile_policy_digest,
        "workspace_binding_digest": workspace_digest,
        "workspace_path_digest": workspace["workspace_path_digest"],
        "dependency_digest": dependency_digest,
        "manifest": manifest_copy,
        "runner_profile": profile_copy,
    }
    if purpose == "cleanup":
        document.update(
            cleanup_claim_digest=cleanup_claim_digest,
            cleanup_obligation_digest=cleanup_obligation_digest,
        )
    if purpose == "macos_cleanup":
        document["macos_cleanup_claim_digest"] = macos_cleanup_claim_digest
    return document


def insert_payload(
    connection: sqlite3.Connection,
    *,
    purpose: str,
    task_id: str,
    document: Mapping[str, Any],
) -> None:
    if purpose in {"business", "macos_cleanup"}:
        table = "capability_task_payloads"
    elif purpose == "cleanup":
        table = "capability_cleanup_task_payloads"
    else:
        raise ProductStoreError("The task payload purpose is invalid.")
    connection.execute(
        f"INSERT INTO {table}(task_id,payload_json,payload_digest) VALUES(?,?,?)",
        (task_id, canonical_json(dict(document)), content_hash(dict(document))),
    )
