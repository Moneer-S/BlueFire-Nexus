"""Pure identities for the original Linux file read and its changing target.

The caller must obtain ``VerifiedFileAccessBinding`` from the existing
controller/store/live-enrollment boundary.  Parsing a saved document or
checking its hash does not grant that provenance, execution, or model authority.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Mapping

from .execution_contracts import execution_task_identity
from .file_access_contract import (
    ACL_ABSENT_DIGEST,
    OWNER_ACTION,
    OWNER_UID,
    PROBE_ACTION,
    PROBE_UID,
    RESOURCE_PATH,
    VerifiedFileAccessBinding,
    canonical_file_access_binding,
)
from .file_access_method import outputs as file_access_outputs
from .file_access_observation import control_observation
from .file_access_plan import recipe as file_access_recipe
from .permission_method import adapt_permission_method, permission_outputs
from .runner_contracts import seal_manifest
from .runner_reviewed_execution import validate_reviewed_manifest
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

MECHANISM_SCHEMA = "bluefire.engine-file-access-read-mechanism.v1"
SNAPSHOT_SCHEMA = "bluefire.engine-file-access-target-snapshot.v1"
HISTORICAL_BASELINE = "historical_baseline"
CURRENT_HARDENED = "current_hardened"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"job-[0-9a-f]{32}\Z")
_MECHANISM_FIELDS = frozenset(
    {
        "schema_version",
        "enrollment_id",
        "enrollment_digest",
        "resource_id",
        "resource_generation",
        "resource_path",
        "probe_action_id",
        "owner_action_id",
        "probe_uid",
        "probe_gid",
        "owner_uid",
        "worker_identity_digest",
        "original_read_job_id",
        "original_read_evidence_digest",
    }
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "phase",
        "mechanism_ref",
        "enrollment_id",
        "enrollment_digest",
        "resource_id",
        "resource_generation",
        "resource_path",
        "control_owner_id",
        "control_revision",
        "control_digest",
        "prior_control_digest",
        "binding_digest",
        "resource_identity",
        "content",
        "acl",
        "mode",
        "baseline_evidence_digest",
        "source",
    }
)
_IDENTITY_FIELDS = frozenset(
    {
        "root_device",
        "root_inode",
        "parent_device",
        "parent_inode",
        "device",
        "inode",
        "owner_uid",
        "group_gid",
    }
)
_CONTENT_FIELDS = frozenset({"sha256", "size", "record_count"})
_ACL_FIELDS = frozenset({"acl_digest", "parent_acl_digest"})
_SOURCE_FIELDS = frozenset({"operation", "job_id", "evidence_digest"})
_BASELINE_FIELDS = frozenset(
    {"baseline_digest", "non_owner", "owner", "record_count", "sha256", "source_binding"}
)
_CONTROL_FIELDS = frozenset(
    {
        "schema_version",
        "control_owner_id",
        "enrollment_id",
        "revision",
        "status",
        "binding",
        "binding_digest",
        "source",
        "baseline",
    }
)
_PREPARATION_FIELDS = frozenset(
    {
        "schema_version",
        "job_id",
        "run_id",
        "context_digest",
        "enrollment_digest",
        "recipe",
        "plan",
        "source",
        "prior",
        "target_binding",
        "target_binding_digest",
        "revision",
        "roots",
        "profiles",
        "profile_document",
        "approval",
    }
)
_TASK_FIELDS = frozenset(
    {
        "job_id",
        "task_id",
        "step_id",
        "request_hash",
        "transport_request_hash",
        "manifest",
        "runner_profile",
    }
)
_TERMINAL_FIELDS = frozenset({"task_id", "request_hash", "result", "receipt_snapshot"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "run_id",
        "step_id",
        "behavior_id",
        "action_id",
        "mode",
        "runner_id",
        "runner_profile_id",
        "platform",
        "requested_at",
        "expires_at",
        "params",
        "target_scope",
        "required_capabilities",
        "safety_tier",
        "limits",
        "cleanup_action_id",
        "policy_digest",
        "approval",
        "evidence_refs",
        "request_hash",
        "reviewed_operation",
    }
)


class EngineFileAccessSnapshotError(ValueError):
    """A file-read mechanism or target snapshot changed identity."""


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineFileAccessSnapshotError(f"{label} has unsupported fields")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineFileAccessSnapshotError(f"{label} is not a canonical digest")
    return value


def _job_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _JOB_ID.fullmatch(value) is None:
        raise EngineFileAccessSnapshotError(f"{label} is invalid")
    return value


def _identifier(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or re.fullmatch(prefix + r"-[0-9a-f]{32}", value) is None:
        raise EngineFileAccessSnapshotError(f"{prefix} identity is invalid")
    return value


def _integer(value: Any, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise EngineFileAccessSnapshotError(f"{label} is outside its finite range")
    return value


def _binding(value: Any) -> dict[str, Any]:
    if type(value) is not VerifiedFileAccessBinding:
        raise EngineFileAccessSnapshotError("controller-verified file-access binding is required")
    try:
        return canonical_file_access_binding(value.to_dict())
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise EngineFileAccessSnapshotError("verified file-access binding changed") from exc


def _resource_path(binding: Mapping[str, Any]) -> str:
    return f"{binding['resource']['root']}/{RESOURCE_PATH}"


def _baseline(value: Any, binding: Mapping[str, Any]) -> Mapping[str, Any]:
    row = _exact(value, _BASELINE_FIELDS, "original baseline")
    source = _exact(
        row["source_binding"],
        frozenset({"operation_job_id", "evidence_digest"}),
        "original baseline source",
    )
    if (
        row["non_owner"] != "allowed"
        or row["owner"] != "allowed"
        or _integer(row["record_count"], 1, 100, "original record count")
        != binding["resource"]["record_count"]
        or _digest(row["sha256"], "original content") != binding["resource"]["sha256"]
        or _digest(row["baseline_digest"], "original baseline evidence")
        != _digest(source["evidence_digest"], "original baseline source evidence")
    ):
        raise EngineFileAccessSnapshotError("original read proof differs from the resource")
    _job_id(source["operation_job_id"], "original read job")
    return row


def _canonical_mechanism(value: Any) -> dict[str, Any]:
    row = _exact(value, _MECHANISM_FIELDS, "file-access read mechanism")
    if row["schema_version"] != MECHANISM_SCHEMA:
        raise EngineFileAccessSnapshotError("read mechanism schema is unsupported")
    _identifier(row["enrollment_id"], "file-enrollment")
    _digest(row["enrollment_digest"], "mechanism enrollment")
    _identifier(row["resource_id"], "file-resource")
    generation = _identifier(row["resource_generation"], "file-generation").rsplit("-", 1)[1]
    if row["resource_path"] != f"/run/bluefire-file-access/data/{generation}/{RESOURCE_PATH}":
        raise EngineFileAccessSnapshotError("read mechanism path is not the enrolled file")
    if (
        row["probe_action_id"] != PROBE_ACTION
        or row["owner_action_id"] != OWNER_ACTION
        or type(row["probe_uid"]) is not int
        or row["probe_uid"] != PROBE_UID
        or type(row["probe_gid"]) is not int
        or row["probe_gid"] != PROBE_UID
        or type(row["owner_uid"]) is not int
        or row["owner_uid"] != OWNER_UID
    ):
        raise EngineFileAccessSnapshotError("original read method or UID changed")
    _digest(row["worker_identity_digest"], "original worker identity")
    _job_id(row["original_read_job_id"], "original read job")
    _digest(row["original_read_evidence_digest"], "original read evidence")
    return dict(row)


def _canonical_snapshot(value: Any) -> dict[str, Any]:
    row = _exact(value, _SNAPSHOT_FIELDS, "file-access target snapshot")
    if row["schema_version"] != SNAPSHOT_SCHEMA:
        raise EngineFileAccessSnapshotError("target snapshot schema is unsupported")
    phase = row["phase"]
    if phase not in (HISTORICAL_BASELINE, CURRENT_HARDENED):
        raise EngineFileAccessSnapshotError("target snapshot phase is unsupported")
    _digest(row["mechanism_ref"], "snapshot mechanism")
    _identifier(row["enrollment_id"], "file-enrollment")
    _digest(row["enrollment_digest"], "snapshot enrollment")
    _identifier(row["resource_id"], "file-resource")
    generation = _identifier(row["resource_generation"], "file-generation").rsplit("-", 1)[1]
    if row["resource_path"] != f"/run/bluefire-file-access/data/{generation}/{RESOURCE_PATH}":
        raise EngineFileAccessSnapshotError("target path is not the enrolled file")
    _job_id(row["control_owner_id"], "retained control owner")
    _integer(row["control_revision"], 1, 2**31 - 1, "control revision")
    _digest(row["control_digest"], "retained control")
    if phase == HISTORICAL_BASELINE:
        if row["prior_control_digest"] is not None:
            raise EngineFileAccessSnapshotError("historical snapshot claims a harden preimage")
    else:
        _digest(row["prior_control_digest"], "harden control preimage")
    _digest(row["binding_digest"], "resource binding")

    identity = _exact(row["resource_identity"], _IDENTITY_FIELDS, "resource identity")
    for key in ("root_device", "parent_device", "device"):
        _integer(identity[key], 0, 2**64 - 1, key)
    for key in ("root_inode", "parent_inode", "inode"):
        _integer(identity[key], 1, 2**64 - 1, key)
    if (
        identity["root_device"] != identity["parent_device"]
        or identity["device"] != identity["root_device"]
        or type(identity["owner_uid"]) is not int
        or identity["owner_uid"] != OWNER_UID
        or type(identity["group_gid"]) is not int
        or identity["group_gid"] != PROBE_UID
    ):
        raise EngineFileAccessSnapshotError("resource identity changed or crossed a filesystem")
    content = _exact(row["content"], _CONTENT_FIELDS, "resource content")
    _digest(content["sha256"], "resource content")
    _integer(content["size"], 1, 1024 * 1024, "resource size")
    _integer(content["record_count"], 1, 100, "resource record count")
    acl = _exact(row["acl"], _ACL_FIELDS, "resource ACL")
    if any(acl[key] != ACL_ABSENT_DIGEST for key in _ACL_FIELDS):
        raise EngineFileAccessSnapshotError("resource ACL policy changed")
    if (phase, row["mode"]) not in (
        (HISTORICAL_BASELINE, "0640"),
        (CURRENT_HARDENED, "0600"),
    ):
        raise EngineFileAccessSnapshotError("target snapshot mode differs from its phase")
    _digest(row["baseline_evidence_digest"], "original baseline evidence")
    source = _exact(row["source"], _SOURCE_FIELDS, "snapshot source")
    operation = "baseline" if phase == HISTORICAL_BASELINE else "harden"
    if source["operation"] != operation:
        raise EngineFileAccessSnapshotError("snapshot source operation changed")
    _job_id(source["job_id"], "snapshot source job")
    _digest(source["evidence_digest"], "snapshot source evidence")
    if (
        phase == HISTORICAL_BASELINE
        and source["evidence_digest"] != row["baseline_evidence_digest"]
    ):
        raise EngineFileAccessSnapshotError("historical snapshot lost its original read proof")
    return dict(row)


class FileAccessReadMechanism:
    """Value identity of the original enrolled read method and baseline proof."""

    __slots__ = ("_document",)
    _document: bytes

    def __init__(self) -> None:
        raise TypeError("Use from_mapping or from_verified_binding")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("read mechanism identity is immutable")

    @classmethod
    def from_mapping(cls, value: Any) -> FileAccessReadMechanism:
        document = _canonical_mechanism(value)
        result = object.__new__(cls)
        object.__setattr__(result, "_document", canonical_json_bytes(document))
        return result

    @classmethod
    def from_verified_binding(
        cls, binding: VerifiedFileAccessBinding, *, baseline: Mapping[str, Any]
    ) -> FileAccessReadMechanism:
        document = _binding(binding)
        original = _baseline(baseline, document)
        return cls.from_mapping(
            {
                "schema_version": MECHANISM_SCHEMA,
                "enrollment_id": document["enrollment_id"],
                "enrollment_digest": document["enrollment_digest"],
                "resource_id": document["resource_id"],
                "resource_generation": document["resource_generation"],
                "resource_path": _resource_path(document),
                "probe_action_id": PROBE_ACTION,
                "owner_action_id": OWNER_ACTION,
                "probe_uid": document["worker"]["uid"],
                "probe_gid": document["worker"]["gid"],
                "owner_uid": document["resource"]["owner_uid"],
                "worker_identity_digest": content_hash(document["worker"]),
                "original_read_job_id": original["source_binding"]["operation_job_id"],
                "original_read_evidence_digest": original["baseline_digest"],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return _canonical_mechanism(json.loads(self._document))

    @property
    def mechanism_ref(self) -> str:
        return content_hash(self.to_dict())

    def matches_verified_binding(self, binding: VerifiedFileAccessBinding) -> None:
        document = _binding(binding)
        mechanism = self.to_dict()
        expected = {
            "enrollment_id": document["enrollment_id"],
            "enrollment_digest": document["enrollment_digest"],
            "resource_id": document["resource_id"],
            "resource_generation": document["resource_generation"],
            "resource_path": _resource_path(document),
            "probe_uid": document["worker"]["uid"],
            "probe_gid": document["worker"]["gid"],
            "owner_uid": document["resource"]["owner_uid"],
            "worker_identity_digest": content_hash(document["worker"]),
        }
        if any(mechanism[key] != value for key, value in expected.items()):
            raise EngineFileAccessSnapshotError("read mechanism differs from verified enrollment")


class FileAccessTargetSnapshot:
    """Value identity of one controller-bound resource revision, without authority."""

    __slots__ = ("_document",)
    _document: bytes

    def __init__(self) -> None:
        raise TypeError("Use from_mapping or from_verified_binding")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("target snapshot identity is immutable")

    @classmethod
    def from_mapping(cls, value: Any) -> FileAccessTargetSnapshot:
        document = _canonical_snapshot(value)
        result = object.__new__(cls)
        object.__setattr__(result, "_document", canonical_json_bytes(document))
        return result

    @classmethod
    def from_verified_binding(
        cls,
        binding: VerifiedFileAccessBinding,
        *,
        mechanism: FileAccessReadMechanism,
        control_owner_id: str,
        control_digest: str,
        source_operation_job_id: str,
        source_evidence_digest: str,
        phase: str,
        prior_control_digest: str | None = None,
    ) -> FileAccessTargetSnapshot:
        document = _binding(binding)
        if type(mechanism) is not FileAccessReadMechanism:
            raise EngineFileAccessSnapshotError("canonical original read mechanism is required")
        mechanism.matches_verified_binding(binding)
        original = mechanism.to_dict()
        resource = document["resource"]
        result = cls.from_mapping(
            {
                "schema_version": SNAPSHOT_SCHEMA,
                "phase": phase,
                "mechanism_ref": mechanism.mechanism_ref,
                "enrollment_id": document["enrollment_id"],
                "enrollment_digest": document["enrollment_digest"],
                "resource_id": document["resource_id"],
                "resource_generation": document["resource_generation"],
                "resource_path": _resource_path(document),
                "control_owner_id": control_owner_id,
                "control_revision": document["control_revision"],
                "control_digest": control_digest,
                "prior_control_digest": prior_control_digest,
                "binding_digest": content_hash(document),
                "resource_identity": {key: resource[key] for key in _IDENTITY_FIELDS},
                "content": {key: resource[key] for key in _CONTENT_FIELDS},
                "acl": {key: resource[key] for key in _ACL_FIELDS},
                "mode": document["mode"],
                "baseline_evidence_digest": original["original_read_evidence_digest"],
                "source": {
                    "operation": "baseline" if phase == HISTORICAL_BASELINE else "harden",
                    "job_id": source_operation_job_id,
                    "evidence_digest": source_evidence_digest,
                },
            }
        )
        result.matches_mechanism(mechanism)
        result.matches_verified_binding(binding)
        return result

    @classmethod
    def from_controller_records(
        cls,
        binding: VerifiedFileAccessBinding,
        *,
        mechanism: FileAccessReadMechanism,
        control_record: Mapping[str, Any],
        operation_records: Mapping[str, Any],
        phase: str,
    ) -> FileAccessTargetSnapshot:
        """Build from independently fetched immutable revision and operation rows.

        The caller still checks the current live enrollment, pending operation,
        and unsettled usages through the original controller boundary.
        """
        saved = _exact(
            control_record,
            frozenset({"job_id", "document", "document_digest"}),
            "stored control revision",
        )
        control = _exact(saved["document"], _CONTROL_FIELDS, "stored Linux control")
        operation = _exact(
            operation_records,
            frozenset(
                {
                    "document",
                    "control_owner_id",
                    "preparation",
                    "tasks",
                    "outcome",
                    "outcome_digest",
                }
            ),
            "original operation records",
        )
        outcome = _exact(
            operation["outcome"],
            (
                frozenset({"state", "evidence_digest", "control_digest", "verified_observation"})
                if phase == HISTORICAL_BASELINE
                else frozenset({"state", "evidence_digest", "control_digest"})
            ),
            "original operation outcome",
        )
        evidence = (
            mechanism.to_dict()["original_read_evidence_digest"]
            if phase == HISTORICAL_BASELINE
            else _digest(outcome["evidence_digest"], "harden operation evidence")
        )
        operation_document = operation["document"]
        if not isinstance(operation_document, Mapping) or not isinstance(
            operation_document.get("review"), Mapping
        ):
            raise EngineFileAccessSnapshotError("original operation review is absent")
        prior_control_digest = (
            None
            if phase == HISTORICAL_BASELINE
            else _digest(
                operation_document["review"].get("control_digest"), "harden control preimage"
            )
        )
        result = cls.from_verified_binding(
            binding,
            mechanism=mechanism,
            control_owner_id=control["control_owner_id"],
            control_digest=saved["document_digest"],
            source_operation_job_id=saved["job_id"],
            source_evidence_digest=evidence,
            phase=phase,
            prior_control_digest=prior_control_digest,
        )
        result.matches_control_revision(control_record, mechanism=mechanism, binding=binding)
        result.matches_operation_records(operation_records, binding=binding)
        if control["source"] != operation["preparation"]["source"]:
            raise EngineFileAccessSnapshotError("original retained source changed")
        return result

    def to_dict(self) -> dict[str, Any]:
        return _canonical_snapshot(json.loads(self._document))

    @property
    def target_snapshot_ref(self) -> str:
        return content_hash(self.to_dict())

    def matches_mechanism(self, mechanism: FileAccessReadMechanism) -> None:
        if type(mechanism) is not FileAccessReadMechanism:
            raise EngineFileAccessSnapshotError("canonical original read mechanism is required")
        target = self.to_dict()
        original = mechanism.to_dict()
        if (
            target["mechanism_ref"] != mechanism.mechanism_ref
            or target["baseline_evidence_digest"] != original["original_read_evidence_digest"]
            or any(
                target[key] != original[key]
                for key in (
                    "enrollment_id",
                    "enrollment_digest",
                    "resource_id",
                    "resource_generation",
                    "resource_path",
                )
            )
        ):
            raise EngineFileAccessSnapshotError(
                "target snapshot substituted its original read mechanism"
            )
        if target["phase"] == HISTORICAL_BASELINE and (
            target["source"]["job_id"] != original["original_read_job_id"]
            or target["source"]["evidence_digest"] != original["original_read_evidence_digest"]
        ):
            raise EngineFileAccessSnapshotError(
                "historical snapshot differs from original read proof"
            )
        if target["phase"] == CURRENT_HARDENED and (
            target["source"]["job_id"] == original["original_read_job_id"]
            or target["source"]["evidence_digest"] == original["original_read_evidence_digest"]
        ):
            raise EngineFileAccessSnapshotError("hardened snapshot reuses historical read evidence")

    def matches_verified_binding(self, binding: VerifiedFileAccessBinding) -> None:
        document = _binding(binding)
        target = self.to_dict()
        resource = document["resource"]
        expected = {
            "enrollment_id": document["enrollment_id"],
            "enrollment_digest": document["enrollment_digest"],
            "resource_id": document["resource_id"],
            "resource_generation": document["resource_generation"],
            "resource_path": _resource_path(document),
            "control_revision": document["control_revision"],
            "binding_digest": content_hash(document),
            "resource_identity": {key: resource[key] for key in _IDENTITY_FIELDS},
            "content": {key: resource[key] for key in _CONTENT_FIELDS},
            "acl": {key: resource[key] for key in _ACL_FIELDS},
            "mode": document["mode"],
        }
        if any(target[key] != value for key, value in expected.items()):
            raise EngineFileAccessSnapshotError(
                "target snapshot differs from verified control binding"
            )

    def matches_control_revision(
        self,
        record: Mapping[str, Any],
        *,
        mechanism: FileAccessReadMechanism,
        binding: VerifiedFileAccessBinding,
    ) -> None:
        """Check an independently fetched immutable Linux revision record.

        The caller must obtain this record through the controller's trusted
        ``get_linux_file_access_revision_record`` path and independently check
        the current revision and operation outcome where applicable.
        """
        self.matches_mechanism(mechanism)
        self.matches_verified_binding(binding)
        row = _exact(
            record,
            frozenset({"job_id", "document", "document_digest"}),
            "stored control revision",
        )
        control = _exact(row["document"], _CONTROL_FIELDS, "stored Linux control")
        target = self.to_dict()
        original = mechanism.to_dict()
        bound = _binding(binding)
        expected_status = (
            "baseline_verified" if target["phase"] == HISTORICAL_BASELINE else "hardened"
        )
        baseline = _baseline(control["baseline"], bound)
        try:
            control_binding = canonical_file_access_binding(control["binding"])
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise EngineFileAccessSnapshotError("stored control binding is invalid") from exc
        _integer(control["revision"], 1, 2**31 - 1, "stored control revision")
        if (
            control["schema_version"] != "bluefire.retained-file-control.v1"
            or row["job_id"] != target["source"]["job_id"]
            or _digest(row["document_digest"], "stored control digest") != content_hash(control)
            or row["document_digest"] != target["control_digest"]
            or control["control_owner_id"] != target["control_owner_id"]
            or control["enrollment_id"] != target["enrollment_id"]
            or control["revision"] != target["control_revision"]
            or control["status"] != expected_status
            or content_hash(control_binding) != target["binding_digest"]
            or control["binding_digest"] != target["binding_digest"]
            or baseline["baseline_digest"] != target["baseline_evidence_digest"]
            or baseline["source_binding"]["operation_job_id"] != original["original_read_job_id"]
        ):
            raise EngineFileAccessSnapshotError(
                "target snapshot differs from stored control revision"
            )

    def matches_operation_records(
        self, records: Mapping[str, Any], *, binding: VerifiedFileAccessBinding
    ) -> None:
        """Replay the saved Linux recipe and native evidence without dispatch."""
        row = _exact(
            records,
            frozenset(
                {
                    "document",
                    "control_owner_id",
                    "preparation",
                    "tasks",
                    "outcome",
                    "outcome_digest",
                }
            ),
            "original operation records",
        )
        target = self.to_dict()
        bound = _binding(binding)
        self.matches_verified_binding(binding)
        original = _exact(
            row["document"],
            frozenset(
                {
                    "submitted_request",
                    "review",
                    "review_context",
                    "enrollment_digest",
                    "created_at_ms",
                }
            ),
            "original operation document",
        )
        review = _exact(
            original["review"],
            frozenset(
                {
                    "schema_version",
                    "operation",
                    "control_owner_id",
                    "context_digest",
                    "enrollment_digest",
                    "control_digest",
                    "expires_at_ms",
                    "effect",
                    "review_digest",
                }
            ),
            "original operation review",
        )
        expected_operation = "baseline" if target["phase"] == HISTORICAL_BASELINE else "harden"
        submitted = _exact(
            original["submitted_request"],
            frozenset({"submission_id", "review", "review_digest", "reviewed_by"}),
            "original submitted request",
        )
        review_context = _exact(
            original["review_context"],
            frozenset(
                {
                    "enrollment_digest",
                    "profile_digest",
                    "profile_id",
                    "implementations",
                    "control_digest",
                    "recipe",
                }
            ),
            "original review context",
        )
        preparation = _exact(row["preparation"], _PREPARATION_FIELDS, "original preparation")
        recipe = file_access_recipe(expected_operation)
        prior = _exact(preparation["prior"], _CONTROL_FIELDS, "original control preimage")
        try:
            prior_binding = canonical_file_access_binding(prior["binding"])
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise EngineFileAccessSnapshotError("original control binding changed") from exc
        _integer(prior["revision"], 1, 2**31 - 1, "original control revision")
        _integer(preparation["revision"], 1, 2**31 - 1, "prepared control revision")
        try:
            prepared_binding = canonical_file_access_binding(preparation["target_binding"])
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise EngineFileAccessSnapshotError("prepared binding is invalid") from exc
        expected_prior_binding = {
            **bound,
            "control_revision": target["control_revision"] - 1,
            "mode": "0640",
        }
        if (
            prior["schema_version"] != "bluefire.retained-file-control.v1"
            or prior["status"]
            != ("created" if target["phase"] == HISTORICAL_BASELINE else "baseline_verified")
            or content_hash(prior_binding) != content_hash(expected_prior_binding)
            or prior["binding_digest"] != content_hash(prior_binding)
            or content_hash(prior["source"]) != content_hash(preparation["source"])
        ):
            raise EngineFileAccessSnapshotError("original control preimage changed")
        if target["phase"] == HISTORICAL_BASELINE:
            if prior["baseline"] is not None:
                raise EngineFileAccessSnapshotError("created preimage claims an original baseline")
        elif (
            _baseline(prior["baseline"], prior_binding)["baseline_digest"]
            != target["baseline_evidence_digest"]
        ):
            raise EngineFileAccessSnapshotError("harden preimage lost original read evidence")
        plan = _exact(
            preparation["plan"],
            frozenset(
                {
                    "schema_version",
                    "scenario_id",
                    "objective",
                    "mode",
                    "ai_enabled",
                    "autonomy",
                    "ai_provider",
                    "runner_profile_id",
                    "scenario_digest",
                    "steps",
                    "edges",
                }
            ),
            "original execution plan",
        )
        if not isinstance(plan["steps"], list) or len(plan["steps"]) != len(recipe):
            raise EngineFileAccessSnapshotError("original execution plan changed")
        if any(
            not isinstance(step, Mapping)
            or any(
                step.get(field) != expected[field]
                for field in ("step_id", "behavior_id", "action_id")
            )
            or content_hash(step.get("parameters")) != content_hash(expected["parameters"])
            or step.get("inputs") != {}
            for step, expected in zip(plan["steps"], recipe, strict=True)
        ):
            raise EngineFileAccessSnapshotError("original execution plan step changed")
        approval_record = preparation["approval"]
        if not isinstance(approval_record, Mapping):
            raise EngineFileAccessSnapshotError("original approval record is absent")
        _integer(original["created_at_ms"], 1, 2**63 - 1, "operation creation time")
        _integer(review["expires_at_ms"], 1, 2**63 - 1, "review expiry")
        _digest(review["context_digest"], "review context")
        _digest(review["control_digest"], "reviewed control preimage")
        _digest(review["review_digest"], "operator review")
        _digest(submitted["review_digest"], "submitted review")
        try:
            submission_id = str(uuid.UUID(submitted["submission_id"]))
        except (ValueError, TypeError, AttributeError) as exc:
            raise EngineFileAccessSnapshotError("original submission ID is invalid") from exc
        if (
            review["schema_version"] != "bluefire.file-access-control-review.v1"
            or review["operation"] != expected_operation
            or review["control_owner_id"] != target["control_owner_id"]
            or review["enrollment_digest"] != target["enrollment_digest"]
            or review["expires_at_ms"] != bound["expires_at_ms"]
            or review["review_digest"]
            != content_hash({key: value for key, value in review.items() if key != "review_digest"})
            or review["context_digest"] != content_hash(review_context)
            or review_context["enrollment_digest"] != target["enrollment_digest"]
            or review_context["control_digest"] != review["control_digest"]
            or content_hash(review_context["recipe"]) != content_hash(recipe)
            or review_context["profile_digest"] != content_hash(preparation["profile_document"])
            or original["enrollment_digest"] != target["enrollment_digest"]
            or original["created_at_ms"] >= review["expires_at_ms"]
            or submitted["review"]
            != {"operation": expected_operation, "control_owner_id": target["control_owner_id"]}
            or submitted["review_digest"] != review["review_digest"]
            or submission_id != submitted["submission_id"]
            or "job-" + uuid.UUID(submission_id).hex != target["source"]["job_id"]
            or not isinstance(submitted["reviewed_by"], str)
            or not submitted["reviewed_by"]
            or preparation["schema_version"] != "bluefire.file-access-operation-preparation.v1"
            or preparation["job_id"] != target["source"]["job_id"]
            or preparation["context_digest"] != review["context_digest"]
            or preparation["enrollment_digest"] != target["enrollment_digest"]
            or content_hash(prepared_binding) != target["binding_digest"]
            or preparation["target_binding_digest"] != target["binding_digest"]
            or preparation["revision"] != target["control_revision"]
            or content_hash(preparation["recipe"]) != content_hash(recipe)
            or approval_record.get("approved_by") != submitted["reviewed_by"]
            or plan["schema_version"] != "bluefire.execution-plan.v1"
            or plan["mode"] != "execute"
            or plan["autonomy"] != "off"
            or plan["ai_enabled"] is not False
            or plan["ai_provider"] != {}
            or plan["edges"] != []
            or plan["runner_profile_id"] != review_context["profile_id"]
            or prior.get("control_owner_id") != target["control_owner_id"]
            or prior.get("enrollment_id") != target["enrollment_id"]
            or prior.get("revision") != target["control_revision"] - 1
            or content_hash(prior) != review["control_digest"]
            or (
                target["phase"] == CURRENT_HARDENED
                and review["control_digest"] != target["prior_control_digest"]
            )
            or row["control_owner_id"] != target["control_owner_id"]
        ):
            raise EngineFileAccessSnapshotError("original review or preparation changed identity")
        outcome = _exact(
            row["outcome"],
            (
                frozenset({"state", "evidence_digest", "control_digest", "verified_observation"})
                if target["phase"] == HISTORICAL_BASELINE
                else frozenset({"state", "evidence_digest", "control_digest"})
            ),
            "original operation outcome",
        )
        tasks = row["tasks"]
        if not isinstance(tasks, list) or len(tasks) != len(recipe):
            raise EngineFileAccessSnapshotError("original operation has the wrong task sequence")
        prepared_profiles = preparation["profiles"]
        prepared_roots = preparation["roots"]
        if not isinstance(prepared_profiles, Mapping) or not isinstance(prepared_roots, Mapping):
            raise EngineFileAccessSnapshotError("original task profiles are absent")
        if set(prepared_profiles) != {"retained", *[item["workspace"] for item in recipe]}:
            raise EngineFileAccessSnapshotError("original task workspaces changed")
        seen_ids: set[str] = set()
        read_artifacts: dict[str, Any] = {}
        for item, expected in zip(tasks, recipe, strict=True):
            pair = _exact(item, frozenset({"task", "terminal"}), "original task pair")
            task = _exact(pair["task"], _TASK_FIELDS, "original task claim")
            terminal = _exact(pair["terminal"], _TERMINAL_FIELDS, "original task terminal")
            manifest = _exact(task["manifest"], _MANIFEST_FIELDS, "original native manifest")
            action = expected["action_id"]
            step = expected["step_id"]
            workspace = expected["workspace"]
            profile = task["runner_profile"]
            if not isinstance(profile, Mapping):
                raise EngineFileAccessSnapshotError("original native profile is absent")
            if workspace == "observation":
                try:
                    profile_binding = canonical_file_access_binding(profile["file_access_binding"])
                except (ValueError, TypeError, KeyError, AttributeError) as exc:
                    raise EngineFileAccessSnapshotError(
                        "original read profile binding changed"
                    ) from exc
                if content_hash(profile_binding) != target["binding_digest"]:
                    raise EngineFileAccessSnapshotError("original read profile binding changed")
            elif "file_access_binding" in profile:
                raise EngineFileAccessSnapshotError("retained task claimed reader binding")
            receipt_snapshot = _exact(
                terminal["receipt_snapshot"],
                frozenset({"documents", "committed"}),
                "original terminal receipt snapshot",
            )
            result = terminal["result"]
            if not isinstance(result, Mapping):
                raise EngineFileAccessSnapshotError("original native result is absent")
            _digest(task["request_hash"], "original request seal")
            _digest(task["transport_request_hash"], "original transport request")
            expected_scope = {
                "filesystem": (
                    ["fixtures/access-probe.json"]
                    if step == "probe"
                    else (
                        ["fixtures/access-owner.json"]
                        if step == "owner"
                        else ["fixtures/transformed.jsonl"] if step == "mode" else []
                    )
                ),
                "network": [],
            }
            if (
                task["job_id"] != target["source"]["job_id"]
                or task["step_id"] != step
                or task["task_id"] in seen_ids
                or manifest["schema_version"] != "bluefire.runner-manifest.v1"
                or manifest["step_id"] != step
                or manifest["action_id"] != action
                or manifest["behavior_id"] != expected["behavior_id"]
                or manifest["run_id"] != preparation["run_id"]
                or manifest["mode"] != "execute"
                or manifest["platform"] != "linux"
                or manifest["cleanup_action_id"] != "sandbox.cleanup.v1"
                or manifest["evidence_refs"] != []
                or manifest["target_scope"] != expected_scope
                or manifest["runner_id"] != "bluefire-rust-runner.v1"
                or manifest["runner_profile_id"] != profile.get("profile_id")
                or manifest["policy_digest"] != profile.get("policy_digest")
                or manifest["limits"] != profile.get("limits")
                or profile.get("schema_version") != "bluefire.runner-profile.v1"
                or profile.get("profile_id") != review_context["profile_id"]
                or profile.get("platform") != "linux"
                or profile.get("runner_id") != manifest["runner_id"]
                or content_hash(profile) != content_hash(prepared_profiles.get(workspace))
                or profile.get("sandbox_root") != prepared_roots.get(workspace)
                or not isinstance(profile.get("reviewed_execution"), Mapping)
                or profile["reviewed_execution"].get("authorization_digest")
                != review["review_digest"]
                or task["request_hash"] != manifest["request_hash"]
                or terminal["task_id"] != task["task_id"]
                or terminal["request_hash"] != task["request_hash"]
                or result.get("status") != "success"
                or not isinstance(receipt_snapshot["documents"], Mapping)
                or not isinstance(receipt_snapshot["committed"], list)
            ):
                raise EngineFileAccessSnapshotError("original native task changed identity")
            try:
                if seal_manifest(manifest) != manifest:
                    raise EngineFileAccessSnapshotError("original native request seal changed")
                validate_reviewed_manifest(manifest, profile)
                calculated_id, calculated_transport = execution_task_identity(manifest, profile)
                requested_at = int(
                    parse_iso8601_datetime(manifest["requested_at"]).timestamp() * 1000
                )
                expires_at = int(parse_iso8601_datetime(manifest["expires_at"]).timestamp() * 1000)
                approval = _exact(
                    manifest["approval"],
                    frozenset({"approved_by", "approved_at", "expires_at", "request_hash"}),
                    "original task approval",
                )
                approved_at = int(
                    parse_iso8601_datetime(approval["approved_at"]).timestamp() * 1000
                )
                approval_expires = int(
                    parse_iso8601_datetime(approval["expires_at"]).timestamp() * 1000
                )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise EngineFileAccessSnapshotError(
                    "original native task is not canonical"
                ) from exc
            if (
                task["task_id"] != calculated_id
                or task["transport_request_hash"] != calculated_transport
                or approval["request_hash"] != task["request_hash"]
                or approval["approved_by"] != submitted["reviewed_by"]
                or not approved_at
                <= requested_at
                < expires_at
                <= min(approval_expires, review["expires_at_ms"], bound["expires_at_ms"])
            ):
                raise EngineFileAccessSnapshotError("original task request or approval changed")
            seen_ids.add(task["task_id"])
            if step in ("probe", "owner"):
                if manifest["params"] != {} or not isinstance(result.get("receipt_ids"), list):
                    raise EngineFileAccessSnapshotError("original read parameters changed")
                inputs = {} if step == "probe" else {"probe": read_artifacts["probe"]}
                try:
                    outputs = file_access_outputs(
                        action,
                        {},
                        bound_inputs=inputs,
                        runner_output=result.get("output"),
                        receipt_ids=result["receipt_ids"],
                    )
                except (ValueError, TypeError, KeyError, AttributeError) as exc:
                    raise EngineFileAccessSnapshotError(
                        "original native read report changed"
                    ) from exc
                read_artifacts[step] = outputs["probe" if step == "probe" else "verification"]
            elif step == "clean_observations":
                expected_receipts = [
                    read_artifacts["owner"]["receipt_ids"][0],
                    read_artifacts["probe"]["receipt_ids"][0],
                ]
                if manifest["params"] != {"receipt_ids": expected_receipts}:
                    raise EngineFileAccessSnapshotError("original observation cleanup changed")
            elif step == "mode":
                source = preparation["source"]
                if not isinstance(source, Mapping) or not isinstance(
                    source.get("fixture"), Mapping
                ):
                    raise EngineFileAccessSnapshotError("original fixture source is absent")
                if not isinstance(result.get("receipt_ids"), list):
                    raise EngineFileAccessSnapshotError("original chmod receipts are absent")
                try:
                    params = adapt_permission_method(
                        {"mode": "0600"},
                        bound_inputs={"fixture": source["fixture"]},
                        available_receipt_ids=result["receipt_ids"],
                    )
                    output = permission_outputs(
                        {"mode": "0600"},
                        bound_inputs={"fixture": source["fixture"]},
                        runner_output=result.get("output"),
                        available_receipt_ids=result["receipt_ids"],
                    )
                except (ValueError, TypeError, KeyError, AttributeError) as exc:
                    raise EngineFileAccessSnapshotError("original chmod proof changed") from exc
                if (
                    manifest["params"] != params
                    or output["fixture"]["before_mode"] != "0640"
                    or output["fixture"]["after_mode"] != "0600"
                    or "sha256:" + output["fixture"]["sha256"] != target["content"]["sha256"]
                    or output["fixture"]["size"] != target["content"]["size"]
                ):
                    raise EngineFileAccessSnapshotError("original chmod target changed")
        _digest(outcome["evidence_digest"], "original operation task evidence")
        _digest(row["outcome_digest"], "original operation outcome")
        if (
            outcome["state"] != "complete"
            or outcome["control_digest"] != target["control_digest"]
            or outcome["evidence_digest"] != content_hash(tasks)
            or row["outcome_digest"] != content_hash(outcome)
        ):
            raise EngineFileAccessSnapshotError("snapshot source differs from original operation")
        if target["phase"] == HISTORICAL_BASELINE:
            observation = _exact(
                outcome["verified_observation"],
                frozenset(
                    {
                        "schema_version",
                        "operation",
                        "non_owner",
                        "owner",
                        "resource_generation",
                        "record_count",
                        "sha256",
                        "mode",
                        "source_digest",
                        "observed_at_ms",
                    }
                ),
                "original read observation",
            )
            try:
                computed = control_observation(
                    "baseline", tasks, binding=bound, now_ms=observation["observed_at_ms"]
                )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise EngineFileAccessSnapshotError("original read observation is invalid") from exc
            if (
                observation != computed
                or observation["source_digest"] != target["source"]["evidence_digest"]
            ):
                raise EngineFileAccessSnapshotError("historical read source proof changed")
        elif target["source"]["evidence_digest"] != outcome["evidence_digest"]:
            raise EngineFileAccessSnapshotError("hardened source task evidence changed")


def verify_file_access_snapshot_pair(
    baseline: FileAccessTargetSnapshot,
    hardened: FileAccessTargetSnapshot,
    *,
    mechanism: FileAccessReadMechanism,
) -> None:
    """Require a 0640 historical read and a distinct 0600 current target."""
    if (
        type(baseline) is not FileAccessTargetSnapshot
        or type(hardened) is not FileAccessTargetSnapshot
    ):
        raise EngineFileAccessSnapshotError("canonical file-access snapshot pair is required")
    baseline.matches_mechanism(mechanism)
    hardened.matches_mechanism(mechanism)
    before, after = baseline.to_dict(), hardened.to_dict()
    stable = (
        "mechanism_ref",
        "enrollment_id",
        "enrollment_digest",
        "resource_id",
        "resource_generation",
        "resource_path",
        "control_owner_id",
        "resource_identity",
        "content",
        "acl",
        "baseline_evidence_digest",
    )
    if (
        before["phase"] != HISTORICAL_BASELINE
        or after["phase"] != CURRENT_HARDENED
        or any(before[key] != after[key] for key in stable)
        or after["control_revision"] != before["control_revision"] + 1
        or before["control_digest"] == after["control_digest"]
        or after["prior_control_digest"] != before["control_digest"]
        or before["binding_digest"] == after["binding_digest"]
        or baseline.target_snapshot_ref == hardened.target_snapshot_ref
    ):
        raise EngineFileAccessSnapshotError("file-access target transition is stale or substituted")


__all__ = [
    "CURRENT_HARDENED",
    "HISTORICAL_BASELINE",
    "EngineFileAccessSnapshotError",
    "FileAccessReadMechanism",
    "FileAccessTargetSnapshot",
    "verify_file_access_snapshot_pair",
]
