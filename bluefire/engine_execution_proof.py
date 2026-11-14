"""Strict projection of controller-retained installed-engine execution proof.

The external engine and its report cannot set product truth.  This module reads
only the controller-owned result document from a finalized RunStore bundle,
checks its receipt and immutable attempt identities, and returns bounded inert
metadata for the existing experiment workspace.  A missing legacy proof is
reported as unverified; a present but malformed proof is refused.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Protocol, cast

from .engine_attempt_contract import AttemptState
from .engine_experiment import EngineAttemptEntry
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineExecutionProofError(ValueError):
    """A retained execution proof is malformed or belongs to another attempt."""


class FinalizedEngineRunSource(Protocol):
    """Read-only portion of RunStore used by the proof projector."""

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]: ...


_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_EVENT_ID = re.compile(r"^engine-tool-event-[0-9a-f]{24}$")
_FINDING_ID = re.compile(r"^engine-finding-[0-9a-f]{24}$")
_ARTIFACT_ID = re.compile(r"^artifact-[0-9a-f]{32}$")
_ENGINE_EVIDENCE_ID = re.compile(r"^engine-evidence-[0-9a-f]{24}$")
_OBSERVED_EVIDENCE_ID = re.compile(r"^evidence-[0-9a-f]{20}$")

_PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "run_id",
        "controller_receipt_ref",
        "runtime",
        "tool_execution",
        "target",
        "model",
        "protocol_provider",
        "artifact_manifest_ref",
        "artifacts",
        "findings",
    }
)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineExecutionProofError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, *, maximum: int = 300) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineExecutionProofError(f"{label} is invalid")
    return value


def _identifier(value: Any, pattern: re.Pattern[str], label: str) -> str:
    candidate = _text(value, label, maximum=180)
    if pattern.fullmatch(candidate) is None:
        raise EngineExecutionProofError(f"{label} is invalid")
    return candidate


def _digest(value: Any, label: str) -> str:
    return _identifier(value, _DIGEST, label)


def _nullable_digest(value: Any, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _integer(value: Any, label: str, *, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise EngineExecutionProofError(f"{label} is invalid")
    return value


def _nullable_integer(value: Any, label: str, *, maximum: int = 2**53 - 1) -> int | None:
    return None if value is None else _integer(value, label, maximum=maximum)


def _timestamp(value: Any, label: str) -> str:
    candidate = _text(value, label, maximum=40)
    try:
        parsed = parse_iso8601_datetime(candidate)
    except ValueError as exc:
        raise EngineExecutionProofError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != candidate:
        raise EngineExecutionProofError(f"{label} is not canonical")
    return candidate


def _unverified() -> dict[str, Any]:
    return {
        "execution_proof": {
            "status": "unverified",
            "controller_receipt_ref": None,
            "runtime_identity_ref": None,
            "image_identity_ref": None,
            "runtime_activation_ref": None,
            "runtime_closure_ref": None,
            "fixed_exec_receipt_ref": None,
            "startup_overlay_ref": None,
            "target_response_receipt_ref": None,
            "installed_service_started": False,
            "native_worker_started": False,
            "tool_execution_proven": False,
            "target_response_proven": False,
            "model": {
                "kind": "unverified",
                "live_model_proof": False,
                "lease_revocation_receipt_ref": None,
                "bearer_redaction_attested": False,
            },
            "protocol_provider": {
                "kind": "unverified",
                "identity_ref": None,
                "live_caido_proof": False,
            },
            "limitations": ["This saved run has no controller-bound installed execution proof."],
        },
        "usage": {
            "model_requests": None,
            "input_tokens": None,
            "output_tokens": None,
            "tool_calls": None,
            "cost_microusd": None,
        },
        "tool_events": None,
        "findings": None,
        "artifacts": None,
    }


def _event(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset({"event_id", "tool_name", "state", "receipt_ref", "occurred_at"}),
        "tool event",
    )
    state = row["state"]
    # Finalized proofs contain one terminal normalized record per invocation.
    # Lifecycle transitions belong in the controller audit trail, not this
    # bounded usage inventory, so they cannot double-count one tool call.
    if state not in {"completed", "failed", "refused", "cancelled"}:
        raise EngineExecutionProofError("tool event state is invalid")
    return {
        "event_id": _identifier(row["event_id"], _EVENT_ID, "tool event identity"),
        "tool_name": _text(row["tool_name"], "tool event name", maximum=120),
        "state": state,
        "receipt_ref": _digest(row["receipt_ref"], "tool event receipt"),
        "occurred_at": _timestamp(row["occurred_at"], "tool event time"),
    }


def _artifact(value: Any, attempt_id: str) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset({"artifact_id", "attempt_id", "name", "sha256", "bytes", "media_type", "access"}),
        "engine artifact",
    )
    if row["attempt_id"] != attempt_id:
        raise EngineExecutionProofError("engine artifact belongs to another attempt")
    access = row["access"]
    if access not in {"private", "reviewable"}:
        raise EngineExecutionProofError("engine artifact access is invalid")
    name = _text(row["name"], "artifact name", maximum=200)
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise EngineExecutionProofError("artifact name is invalid")
    return {
        "artifact_id": _identifier(row["artifact_id"], _ARTIFACT_ID, "artifact identity"),
        "attempt_id": attempt_id,
        "name": name,
        "sha256": _digest(row["sha256"], "artifact digest"),
        "bytes": _integer(row["bytes"], "artifact byte count", maximum=64 * 1024 * 1024),
        "media_type": _text(row["media_type"], "artifact media type", maximum=100),
        "access": access,
    }


def _finding(value: Any, attempt_id: str) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset(
            {
                "finding_id",
                "attempt_id",
                "title",
                "severity",
                "mechanism_digest",
                "status",
                "summary",
                "source_artifact_id",
                "evidence_ids",
            }
        ),
        "engine finding",
    )
    if row["attempt_id"] != attempt_id:
        raise EngineExecutionProofError("engine finding belongs to another attempt")
    severity = row["severity"]
    status = row["status"]
    if severity not in {"critical", "high", "medium", "low", "informational", "unknown"}:
        raise EngineExecutionProofError("engine finding severity is invalid")
    if status not in {"reported", "reproduced", "not_reproduced", "unknown"}:
        raise EngineExecutionProofError("engine finding status is invalid")
    raw_evidence = row["evidence_ids"]
    if not isinstance(raw_evidence, list) or len(raw_evidence) > 64:
        raise EngineExecutionProofError("engine finding evidence is invalid")
    evidence_ids = [
        _identifier(item, _ENGINE_EVIDENCE_ID, "finding evidence identity") for item in raw_evidence
    ]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise EngineExecutionProofError("engine finding evidence contains duplicates")
    return {
        "finding_id": _identifier(row["finding_id"], _FINDING_ID, "finding identity"),
        "attempt_id": attempt_id,
        "title": _text(row["title"], "finding title", maximum=200),
        "severity": severity,
        "mechanism_digest": _digest(row["mechanism_digest"], "finding mechanism"),
        "status": status,
        "summary": _text(row["summary"], "finding summary", maximum=1000),
        "source_artifact_id": _identifier(
            row["source_artifact_id"], _ARTIFACT_ID, "finding artifact identity"
        ),
        "evidence_ids": evidence_ids,
    }


def project_attempt_execution_proof(
    run: Mapping[str, Any] | None,
    *,
    attempt_id: str,
    run_id: str,
    engine_revision: str,
    engine_package_digest: str,
    model_provider: str,
    model_id: str,
    model_test_provider: bool,
    independent_evidence_refs: tuple[str, ...],
    engine_evidence_refs: tuple[str, ...],
    artifact_manifest_ref: str | None,
    artifact_byte_limit: int,
    action_limit: int,
) -> dict[str, Any]:
    """Return bounded UI metadata from one finalized controller result."""

    checked_attempt = _identifier(attempt_id, _ATTEMPT_ID, "attempt identity")
    checked_run = _identifier(run_id, _RUN_ID, "run identity")
    checked_revision = _identifier(engine_revision, _REVISION, "engine revision")
    checked_package = _digest(engine_package_digest, "engine package")
    checked_provider = _identifier(model_provider, _SOURCE_ID, "model provider")
    checked_model = _text(model_id, "model identity", maximum=160)
    if type(model_test_provider) is not bool:
        raise EngineExecutionProofError("configured model proof kind is invalid")
    if type(independent_evidence_refs) is not tuple or len(independent_evidence_refs) > 256:
        raise EngineExecutionProofError("independent evidence references are invalid")
    checked_independent = tuple(
        _identifier(item, _OBSERVED_EVIDENCE_ID, "independent evidence identity")
        for item in independent_evidence_refs
    )
    if len(set(checked_independent)) != len(checked_independent):
        raise EngineExecutionProofError("independent evidence references contain duplicates")
    if type(engine_evidence_refs) is not tuple or len(engine_evidence_refs) > 512:
        raise EngineExecutionProofError("engine evidence references are invalid")
    checked_engine_evidence = frozenset(
        _identifier(item, _ENGINE_EVIDENCE_ID, "engine evidence identity")
        for item in engine_evidence_refs
    )
    if len(checked_engine_evidence) != len(engine_evidence_refs):
        raise EngineExecutionProofError("engine evidence references contain duplicates")
    checked_manifest = _nullable_digest(artifact_manifest_ref, "artifact manifest")
    _integer(artifact_byte_limit, "artifact byte limit", maximum=64 * 1024 * 1024)
    _integer(action_limit, "action limit", maximum=512)

    if run is None:
        return _unverified()
    if not isinstance(run, Mapping) or run.get("run_id") != checked_run:
        raise EngineExecutionProofError("finalized run identity changed")
    raw = run.get("engine_execution_proof")
    if raw is None:
        return _unverified()
    row = _exact(raw, _PROOF_FIELDS, "installed engine execution proof")
    if row["schema_version"] != "bluefire.installed-engine-execution-proof.v1":
        raise EngineExecutionProofError("installed engine execution proof is unsupported")
    if row["attempt_id"] != checked_attempt or row["run_id"] != checked_run:
        raise EngineExecutionProofError("installed engine execution proof identity changed")

    runtime = _exact(
        row["runtime"],
        frozenset(
            {
                "engine_id",
                "engine_revision",
                "engine_package_digest",
                "runtime_identity_ref",
                "image_identity_ref",
                "runtime_activation_ref",
                "runtime_closure_ref",
                "fixed_exec_receipt_ref",
                "startup_overlay_ref",
                "installed_service_started",
                "native_worker_started",
            }
        ),
        "installed runtime proof",
    )
    if (
        runtime["engine_id"] != "strix"
        or runtime["engine_revision"] != checked_revision
        or runtime["engine_package_digest"] != checked_package
        or type(runtime["installed_service_started"]) is not bool
        or type(runtime["native_worker_started"]) is not bool
    ):
        raise EngineExecutionProofError("installed runtime proof changed")
    runtime_identity = _digest(runtime["runtime_identity_ref"], "runtime identity")
    image_identity = _digest(runtime["image_identity_ref"], "image identity")
    runtime_activation = _digest(runtime["runtime_activation_ref"], "runtime activation")
    runtime_closure = _digest(runtime["runtime_closure_ref"], "runtime closure")
    fixed_exec_receipt = _digest(runtime["fixed_exec_receipt_ref"], "fixed exec receipt")
    startup_overlay = _digest(runtime["startup_overlay_ref"], "startup overlay")

    tool = _exact(
        row["tool_execution"],
        frozenset({"executed", "events"}),
        "tool execution proof",
    )
    raw_events = tool["events"]
    if type(tool["executed"]) is not bool or not isinstance(raw_events, list):
        raise EngineExecutionProofError("tool execution proof is invalid")
    if len(raw_events) > min(action_limit, 128):
        raise EngineExecutionProofError("tool execution proof exceeds its action bound")
    events = [_event(item) for item in raw_events]
    if len({item["event_id"] for item in events}) != len(events):
        raise EngineExecutionProofError("tool execution proof repeats an event identity")
    if bool(tool["executed"]) != any(item["state"] == "completed" for item in events):
        raise EngineExecutionProofError("tool execution truth changed")

    target = _exact(
        row["target"],
        frozenset({"response_observed", "response_receipt_ref", "independent_evidence_refs"}),
        "target response proof",
    )
    raw_refs = target["independent_evidence_refs"]
    if type(target["response_observed"]) is not bool or not isinstance(raw_refs, list):
        raise EngineExecutionProofError("target response proof is invalid")
    proof_refs = tuple(
        _identifier(item, _OBSERVED_EVIDENCE_ID, "target evidence identity") for item in raw_refs
    )
    response_receipt = _nullable_digest(target["response_receipt_ref"], "target response receipt")
    if proof_refs != checked_independent:
        raise EngineExecutionProofError("target evidence binding changed")
    response_proven = bool(target["response_observed"])
    if (
        response_proven != bool(response_receipt and proof_refs)
        or response_proven
        and not tool["executed"]
    ):
        raise EngineExecutionProofError("target response truth changed")

    model = _exact(
        row["model"],
        frozenset(
            {
                "kind",
                "provider",
                "id",
                "live_model_proof",
                "requests",
                "input_tokens",
                "output_tokens",
                "cost_microusd",
                "lease_revocation_receipt_ref",
                "bearer_redaction_attested",
            }
        ),
        "model execution proof",
    )
    model_kind = model["kind"]
    if (
        model_kind != ("test" if model_test_provider else "live")
        or model["provider"] != checked_provider
        or model["id"] != checked_model
        or type(model["live_model_proof"]) is not bool
        or type(model["bearer_redaction_attested"]) is not bool
        or (model_kind == "test" and model["live_model_proof"] is not False)
    ):
        raise EngineExecutionProofError("model execution proof changed")
    usage = {
        "model_requests": _nullable_integer(
            model["requests"], "model request count", maximum=10_000
        ),
        "input_tokens": _nullable_integer(model["input_tokens"], "model input tokens"),
        "output_tokens": _nullable_integer(model["output_tokens"], "model output tokens"),
        "tool_calls": len(events),
        "cost_microusd": _nullable_integer(model["cost_microusd"], "model cost"),
    }
    if model["live_model_proof"] and not usage["model_requests"]:
        raise EngineExecutionProofError("live model proof has no retained request")
    model_revocation = _digest(
        model["lease_revocation_receipt_ref"], "model lease revocation receipt"
    )
    if model["bearer_redaction_attested"] is not True:
        raise EngineExecutionProofError("model bearer redaction is not attested")

    protocol = _exact(
        row["protocol_provider"],
        frozenset({"kind", "identity_ref", "live_caido_proof"}),
        "protocol provider proof",
    )
    protocol_kind = protocol["kind"]
    if (
        protocol_kind not in {"test_caido_protocol", "live_caido", "unavailable"}
        or type(protocol["live_caido_proof"]) is not bool
    ):
        raise EngineExecutionProofError("protocol provider proof changed")
    protocol_identity = _nullable_digest(protocol["identity_ref"], "protocol provider identity")
    if (
        (protocol_kind == "unavailable") != (protocol_identity is None)
        or protocol_kind != "live_caido"
        and protocol["live_caido_proof"] is not False
    ):
        raise EngineExecutionProofError("protocol provider truth changed")

    proof_manifest = _nullable_digest(row["artifact_manifest_ref"], "proof artifact manifest")
    if proof_manifest != checked_manifest:
        raise EngineExecutionProofError("artifact manifest binding changed")
    raw_artifacts = row["artifacts"]
    raw_findings = row["findings"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > 128:
        raise EngineExecutionProofError("engine artifact index is invalid")
    if not isinstance(raw_findings, list) or len(raw_findings) > 64:
        raise EngineExecutionProofError("engine finding index is invalid")
    artifacts = [_artifact(item, checked_attempt) for item in raw_artifacts]
    findings = [_finding(item, checked_attempt) for item in raw_findings]
    if len({item["artifact_id"] for item in artifacts}) != len(artifacts):
        raise EngineExecutionProofError("engine artifact index repeats an identity")
    if len({item["finding_id"] for item in findings}) != len(findings):
        raise EngineExecutionProofError("engine finding index repeats an identity")
    if sum(cast(int, item["bytes"]) for item in artifacts) > artifact_byte_limit:
        raise EngineExecutionProofError("engine artifact index exceeds its byte bound")
    artifact_ids = {item["artifact_id"] for item in artifacts}
    evidence_ids = {
        item for finding in findings for item in cast(list[str], finding["evidence_ids"])
    }
    if any(finding["source_artifact_id"] not in artifact_ids for finding in findings):
        raise EngineExecutionProofError("engine finding source artifact is unavailable")
    if not evidence_ids.issubset(checked_engine_evidence):
        raise EngineExecutionProofError("engine finding evidence is unavailable")
    if artifacts and proof_manifest is None:
        raise EngineExecutionProofError("engine artifact index has no manifest")

    # This digest detects changes to the finalized projection. It does not
    # authenticate the referenced runtime, model, tool, or artifact records;
    # the controller writer must derive those claims from sealed source records.
    canonical = dict(cast(dict[str, Any], json_clone(row)))
    claimed_receipt = _digest(canonical.pop("controller_receipt_ref"), "execution proof receipt")
    expected_receipt = content_hash(
        {
            "schema_version": "bluefire.installed-engine-execution-receipt.v1",
            "proof": canonical,
        }
    )
    if claimed_receipt != expected_receipt:
        raise EngineExecutionProofError("installed engine execution receipt changed")

    runtime_started = bool(
        runtime["installed_service_started"] and runtime["native_worker_started"]
    )
    if not runtime_started:
        raise EngineExecutionProofError("installed runtime proof does not establish startup")
    status = (
        "target_observed"
        if response_proven
        else "tool_executed"
        if tool["executed"]
        else "runtime_started"
        if runtime_started
        else "unverified"
    )
    limitations: list[str] = []
    if model["live_model_proof"] is not True:
        limitations.append("This attempt does not establish live-model decision quality.")
    if protocol["live_caido_proof"] is not True:
        limitations.append("This attempt does not establish a live Caido service.")
    if not response_proven:
        limitations.append("No independently bound target response is proven for this attempt.")
    return {
        "execution_proof": {
            "status": status,
            "controller_receipt_ref": claimed_receipt,
            "runtime_identity_ref": runtime_identity,
            "image_identity_ref": image_identity,
            "runtime_activation_ref": runtime_activation,
            "runtime_closure_ref": runtime_closure,
            "fixed_exec_receipt_ref": fixed_exec_receipt,
            "startup_overlay_ref": startup_overlay,
            "target_response_receipt_ref": response_receipt if response_proven else None,
            "installed_service_started": runtime["installed_service_started"],
            "native_worker_started": runtime["native_worker_started"],
            "tool_execution_proven": tool["executed"],
            "target_response_proven": response_proven,
            "model": {
                "kind": model_kind,
                "live_model_proof": model["live_model_proof"],
                "lease_revocation_receipt_ref": model_revocation,
                "bearer_redaction_attested": model["bearer_redaction_attested"],
            },
            "protocol_provider": {
                "kind": protocol_kind,
                "identity_ref": protocol_identity,
                "live_caido_proof": protocol["live_caido_proof"],
            },
            "limitations": limitations,
        },
        "usage": usage,
        "tool_events": events,
        "findings": findings,
        "artifacts": artifacts,
    }


def load_attempt_execution_proof(
    source: FinalizedEngineRunSource,
    *,
    terminal: bool,
    attempt_id: str,
    run_id: str,
    engine_revision: str,
    engine_package_digest: str,
    model_provider: str,
    model_id: str,
    model_test_provider: bool,
    independent_evidence_refs: tuple[str, ...],
    engine_evidence_refs: tuple[str, ...],
    artifact_manifest_ref: str | None,
    artifact_byte_limit: int,
    action_limit: int,
) -> dict[str, Any]:
    """Open only a terminal finalized run; unavailable legacy state stays unverified."""

    run: Mapping[str, Any] | None = None
    if terminal:
        try:
            run = source.get_run(run_id, require_finalized=True)
        except (KeyError, OSError, TypeError, ValueError):
            run = None
    return project_attempt_execution_proof(
        run,
        attempt_id=attempt_id,
        run_id=run_id,
        engine_revision=engine_revision,
        engine_package_digest=engine_package_digest,
        model_provider=model_provider,
        model_id=model_id,
        model_test_provider=model_test_provider,
        independent_evidence_refs=independent_evidence_refs,
        engine_evidence_refs=engine_evidence_refs,
        artifact_manifest_ref=artifact_manifest_ref,
        artifact_byte_limit=artifact_byte_limit,
        action_limit=action_limit,
    )


def load_entry_execution_proof(
    source: FinalizedEngineRunSource,
    entry: EngineAttemptEntry,
    independent_evidence_refs: tuple[str, ...],
    *,
    model_test_provider: bool,
) -> dict[str, Any]:
    """Load proof using only immutable identities from one canonical entry."""

    if not isinstance(entry, EngineAttemptEntry):
        raise EngineExecutionProofError("engine attempt entry is invalid")
    binding = entry.record.binding
    terminal = entry.record.state in {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
    return load_attempt_execution_proof(
        source,
        terminal=terminal,
        attempt_id=binding.attempt_id,
        run_id=binding.run_id,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_test_provider=model_test_provider,
        independent_evidence_refs=independent_evidence_refs,
        engine_evidence_refs=tuple(item.evidence_id for item in entry.evidence),
        artifact_manifest_ref=entry.artifact_manifest_ref,
        artifact_byte_limit=binding.artifact_byte_limit,
        action_limit=binding.action_limit,
    )


def execution_proof_receipt(proof: Mapping[str, Any]) -> str:
    """Compute the receipt expected in a canonical proof mapping."""

    row = _exact(proof, _PROOF_FIELDS, "installed engine execution proof")
    canonical = dict(cast(dict[str, Any], json_clone(row)))
    canonical.pop("controller_receipt_ref", None)
    return content_hash(
        {
            "schema_version": "bluefire.installed-engine-execution-receipt.v1",
            "proof": canonical,
        }
    )
