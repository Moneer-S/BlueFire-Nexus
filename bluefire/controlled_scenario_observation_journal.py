"""Protected intermediate evidence for one controlled Strix tool continuation.

The installed controller verifies the source records before calling ``retain``.
This journal makes that decision durable and byte-reopenable before the Test
provider receives another request. It is not a substitute for source custody
or the final, immutable RunStore bundle.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import sqlite3
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import strix_controlled_backend as backend
from .controlled_strix_scenario import ScenarioObservationRequest
from .evidence import EvidenceProvenance, EvidenceRecord
from .local_lock import (
    LocalLockError,
    owner_private_database_lock,
    pinned_regular_file_identity,
    prepare_owner_private_database_file,
)
from .strix_controlled_worker_channel import ControllerSettledCall
from .tenant_record_controller_contract import tenant_target_snapshot_ref
from .tenant_record_observer import TenantRecordObservationError, _response_headers_digest
from .util import canonical_json_bytes, content_hash, json_clone
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_open_descriptor,
    apply_owner_private_acl_path,
    verify_owner_private_acl,
)

SCHEMA = "bluefire.controlled-scenario-observation-retention.v1"
SEAL_SCHEMA = "bluefire.controlled-scenario-observation-seal.v1"
TOOL_SCHEMA = "bluefire.controlled-scenario-settled-exec.v1"
SOURCE_TERMINAL_SCHEMA = "bluefire.installed-strix-v2-source-collection-terminal.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_MAX_RECORDS = 64
_MAX_RECORD_BYTES = 256 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024


class ScenarioObservationJournalError(ValueError):
    """The intermediate observation is incomplete, changed, or unavailable."""


@dataclass(frozen=True, slots=True)
class ScenarioObservationLinks:
    """Exact controller source identities, without model-supplied authority."""

    attempt_id: str
    claim_ref: str
    activation_ref: str
    tool_request_id: str
    tool_receipt_ref: str
    tool_capture_ref: str
    execution_admission_ref: str
    dispatch_ref: str
    attachment_ref: str
    terminal_ref: str
    relay_request_id: str
    relay_operation_ref: str
    relay_receipt_ref: str
    relay_audit_ref: str
    admitted_target_url: str
    authorized_url_set_ref: str
    target_request_id: str
    target_audit_ref: str
    target_response_ref: str
    target_snapshot_ref: str
    service_generation: str

    def __post_init__(self) -> None:
        if _ATTEMPT.fullmatch(self.attempt_id) is None:
            raise ScenarioObservationJournalError("observation attempt is invalid")
        for value in (
            self.claim_ref,
            self.activation_ref,
            self.tool_receipt_ref,
            self.tool_capture_ref,
            self.execution_admission_ref,
            self.dispatch_ref,
            self.attachment_ref,
            self.terminal_ref,
            self.relay_operation_ref,
            self.relay_receipt_ref,
            self.relay_audit_ref,
            self.authorized_url_set_ref,
            self.target_audit_ref,
            self.target_response_ref,
            self.target_snapshot_ref,
        ):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise ScenarioObservationJournalError("observation source reference is invalid")
        if not all(
            isinstance(value, str) and 1 <= len(value) <= 512 and "\x00" not in value
            for value in (
                self.tool_request_id,
                self.relay_request_id,
                self.admitted_target_url,
                self.target_request_id,
                self.service_generation,
            )
        ):
            raise ScenarioObservationJournalError("observation source identity is invalid")

    def to_dict(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ScenarioObservationLinks:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ScenarioObservationJournalError("observation source fields differ")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ReopenedScenarioObservation:
    request_ref: str
    retention_ref: str
    request_identity: Mapping[str, Any]
    links: ScenarioObservationLinks
    evidence: EvidenceRecord
    source_documents: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ReopenedSettledExec:
    attempt_id: str
    operation_id: str
    request_id: str
    capture_ref: str
    document: Mapping[str, Any]


class ControllerScenarioObservationJournal:
    """Bounded append-only SQLite journal in an owner-private controller path."""

    def __init__(self, path: str | Path) -> None:
        if sys.platform == "darwin":
            raise ScenarioObservationJournalError(
                "macOS observation retention needs a separately verified ACL boundary"
            )
        candidate = Path(path).expanduser()
        self._verify_private_path(candidate.parent, directory=True)
        self._verify_ancestor_chain(candidate.parent)
        preexisting = candidate.exists()
        try:
            self.path, self._identity = prepare_owner_private_database_file(candidate)
        except LocalLockError as exc:
            raise ScenarioObservationJournalError("observation journal is not owner-private") from exc
        if os.name == "nt" and not preexisting:
            try:
                apply_owner_private_acl_path(self.path, directory=False)
            except WindowsOwnerAclError as exc:
                raise ScenarioObservationJournalError(
                    "observation journal could not be made owner-private"
                ) from exc
        self._verify_private_storage()
        self._lock = threading.RLock()
        with self._connection(write=True) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS observations (
                    request_ref TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    relay_request_id TEXT NOT NULL UNIQUE,
                    target_request_id TEXT NOT NULL UNIQUE,
                    evidence_ref TEXT NOT NULL UNIQUE,
                    retention_ref TEXT NOT NULL,
                    document BLOB NOT NULL,
                    UNIQUE (attempt_id, call_id)
                )"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS observations_no_update
                   BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS observations_no_delete
                   BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS attempt_seals (
                    attempt_id TEXT PRIMARY KEY,
                    seal_ref TEXT NOT NULL,
                    document BLOB NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS attempt_seals_no_update
                   BEFORE UPDATE ON attempt_seals BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS attempt_seals_no_delete
                   BEFORE DELETE ON attempt_seals BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS settled_execs (
                    attempt_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    capture_ref TEXT NOT NULL,
                    document BLOB NOT NULL,
                    PRIMARY KEY (attempt_id, operation_id)
                )"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS settled_execs_no_update
                   BEFORE UPDATE ON settled_execs BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS settled_execs_no_delete
                   BEFORE DELETE ON settled_execs BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS role_terminals (
                    attempt_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    owner_ref TEXT NOT NULL,
                    source_receipt_ref TEXT NOT NULL UNIQUE,
                    document BLOB NOT NULL,
                    PRIMARY KEY (attempt_id, role, owner_ref)
                )"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS role_terminals_no_update
                   BEFORE UPDATE ON role_terminals BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS role_terminals_no_delete
                   BEFORE DELETE ON role_terminals BEGIN SELECT RAISE(ABORT, 'immutable'); END"""
            )

    def _connection(self, *, write: bool):
        """Pin the exact private database around each short SQLite operation."""
        from contextlib import contextmanager

        @contextmanager
        def opened():
            with self._lock:
                try:
                    with owner_private_database_lock(self.path, expected=self._identity):
                        pinned_regular_file_identity(self.path, expected=self._identity)
                        self._verify_private_storage()
                        connection = sqlite3.connect(self.path, timeout=5)
                        try:
                            pinned_regular_file_identity(self.path, expected=self._identity)
                            connection.execute("PRAGMA busy_timeout=5000")
                            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
                            if mode != "delete":
                                raise ScenarioObservationJournalError(
                                    "observation rollback journal mode is unavailable"
                                )
                            connection.execute("PRAGMA synchronous=EXTRA")
                            if connection.execute("PRAGMA synchronous").fetchone()[0] != 3:
                                raise ScenarioObservationJournalError(
                                    "observation durability is unavailable"
                                )
                            if write:
                                connection.execute("BEGIN IMMEDIATE")
                            yield connection
                            if write:
                                connection.commit()
                        except BaseException:
                            if write:
                                connection.rollback()
                            raise
                        finally:
                            connection.close()
                except (LocalLockError, sqlite3.Error) as exc:
                    raise ScenarioObservationJournalError(
                        "observation journal is unavailable or changed"
                    ) from exc

        return opened()

    def _verify_private_storage(self) -> None:
        """Do not place raw generated target or shell bytes in a shared path."""
        self._verify_private_path(self.path.parent, directory=True)
        self._verify_ancestor_chain(self.path.parent)
        self._verify_private_path(self.path, directory=False)

    @staticmethod
    def _verify_ancestor_chain(root: Path) -> None:
        if os.name == "nt":
            return
        getuid = getattr(os, "geteuid", None)
        if not callable(getuid):
            raise ScenarioObservationJournalError("observation owner identity is unavailable")
        owner = getuid()
        child = root
        while True:
            parent = child.parent
            try:
                child_details = child.lstat()
                parent_details = parent.lstat()
            except OSError as exc:
                raise ScenarioObservationJournalError("observation ancestor is unavailable") from exc
            if (
                child.is_symlink()
                or parent.is_symlink()
                or not stat.S_ISDIR(child_details.st_mode)
                or not stat.S_ISDIR(parent_details.st_mode)
                or parent_details.st_uid not in {0, owner}
            ):
                raise ScenarioObservationJournalError("observation ancestor is unsafe")
            if parent_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                if not parent_details.st_mode & stat.S_ISVTX or child_details.st_uid != owner:
                    raise ScenarioObservationJournalError("observation ancestor permits replacement")
            if parent == child:
                return
            child = parent

    @staticmethod
    def _verify_private_path(path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(path, directory=directory)
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError) as exc:
                raise ScenarioObservationJournalError(
                    "observation journal path is not owner-private"
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return
        getuid = getattr(os, "geteuid", None)
        if not callable(getuid):
            raise ScenarioObservationJournalError("observation owner identity is unavailable")
        try:
            details = path.lstat()
        except OSError as exc:
            raise ScenarioObservationJournalError("observation journal path is unavailable") from exc
        if (
            path.is_symlink()
            or not (stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode))
            or stat.S_IMODE(details.st_mode) != (0o700 if directory else 0o600)
            or details.st_uid != getuid()
            or (not directory and details.st_nlink != 1)
        ):
            raise ScenarioObservationJournalError("observation journal path is not owner-private")

    @staticmethod
    def _request_identity(request: ScenarioObservationRequest) -> dict[str, Any]:
        return {
            "attempt_id": request.attempt_id,
            "scenario_ref": request.scenario_ref,
            "phase_id": request.phase_id,
            "call_id": request.call_id,
            "tool_name": request.tool_name,
            "arguments_digest": request.arguments_digest,
            "arguments_json": request.arguments_json,
            "target_url": request.target_url,
            "authorized_url_set_ref": request.authorized_url_set_ref,
            "model_result_digest": request.model_result_digest,
            "model_result_bytes": request.model_result_bytes,
            "model_result": request.model_result,
        }

    @staticmethod
    def _check_source_documents(
        request: ScenarioObservationRequest,
        links: ScenarioObservationLinks,
        evidence: EvidenceRecord,
        documents: Mapping[str, Any],
    ) -> None:
        for name, reference in (
            ("relay_operation", links.relay_operation_ref),
            ("relay_audit", links.relay_audit_ref),
            ("relay_receipt", links.relay_receipt_ref),
            ("target_audit", links.target_audit_ref),
        ):
            value = documents.get(name)
            if not isinstance(value, dict) or content_hash(value) != reference:
                raise ScenarioObservationJournalError("observation source bytes differ")
        operation = documents["relay_operation"]
        audit = documents["relay_audit"]
        receipt = documents["relay_receipt"]
        target_audit = documents["target_audit"]
        target_response = documents.get("target_response")
        tool = documents.get("tool")
        if (
            not isinstance(tool, dict)
            or content_hash(tool) != links.tool_capture_ref
            or tool.get("request_id") != links.tool_request_id
            or tool.get("binding", {}).get("attempt_id") != links.attempt_id
            or tool.get("binding", {}).get("claim_digest") != links.claim_ref
        ):
            raise ScenarioObservationJournalError("settled tool capture differs")
        try:
            arguments = json.loads(request.arguments_json)
            command = arguments["cmd"]
            words = shlex.split(command)
            stdout = base64.b64decode(tool["stdout_base64"], validate=True)
            decoded_stdout = stdout.decode("utf-8")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise ScenarioObservationJournalError("pending shell source is invalid") from exc
        if (
            not isinstance(arguments, dict)
            or set(arguments) != {"cmd", "yield_time_ms"}
            or canonical_json_bytes(arguments).decode("ascii") != request.arguments_json
            or arguments["yield_time_ms"] != 5000
            or not isinstance(command, str)
            or not words
            or words[0] != "curl"
            or words[-1] != request.target_url
            or words.count(request.target_url) != 1
            or tool.get("argv") != ["bash", "-lc", command]
            or tool.get("working_directory") != "/workspace"
            or not stdout
            or decoded_stdout != request.model_result
        ):
            raise ScenarioObservationJournalError("settled shell differs from pending tool")
        if not isinstance(target_response, dict) or set(target_response) != {
            "schema_version", "status", "headers", "body_base64", "target_observation_ref"
        } or target_response["schema_version"] != "bluefire.scenario-target-response.v1":
            raise ScenarioObservationJournalError("target response source is incomplete")
        try:
            response_body = base64.b64decode(target_response["body_base64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ScenarioObservationJournalError("target response bytes are invalid") from exc
        try:
            headers_digest = _response_headers_digest(target_response["headers"])
        except (TypeError, AttributeError, TenantRecordObservationError) as exc:
            raise ScenarioObservationJournalError("target response headers are invalid") from exc
        response_digest = "sha256:" + hashlib.sha256(response_body).hexdigest()
        environment = evidence.environment
        target_snapshot_ref = tenant_target_snapshot_ref(
            fixture_digest=environment.get("fixture_digest"),
            target_snapshot_id=evidence.content.get("target_snapshot_id"),
            service_generation=links.service_generation,
        )
        if (
            operation.get("attempt_id") != links.attempt_id
            or operation.get("request_id") != links.relay_request_id
            or audit.get("request_id") != links.relay_request_id
            or audit.get("status") != "succeeded"
            or audit.get("evidence_ref") != links.target_response_ref
            or receipt.get("request_id") != links.relay_request_id
            or receipt.get("audit_record_digest") != links.relay_audit_ref
            or receipt.get("operation") != operation.get("route_id")
            or target_audit.get("request_id") != links.target_request_id
            or target_audit.get("route") != operation.get("route_id")
            or target_audit.get("response_status") != receipt.get("response_status")
            or evidence.content.get("response_status") != target_audit.get("response_status")
            or evidence.content.get("service_generation") != links.service_generation
            or target_audit.get("target_snapshot_id") != evidence.content.get("target_snapshot_id")
            or target_audit.get("service_generation") != links.service_generation
            or target_snapshot_ref != links.target_snapshot_ref
            or target_response["status"] != receipt.get("response_status")
            or target_response["target_observation_ref"] != links.target_response_ref
            or response_digest != receipt.get("response_digest")
            or response_digest != target_audit.get("response_sha256")
            or response_digest != evidence.content.get("response_sha256")
            or len(response_body) != receipt.get("response_bytes")
            or len(response_body) != target_audit.get("response_bytes")
            or headers_digest != target_audit.get("response_headers_sha256")
            or headers_digest != evidence.content.get("response_headers_sha256")
        ):
            raise ScenarioObservationJournalError("observation source identities differ")

    def retain(
        self,
        *,
        request: ScenarioObservationRequest,
        links: ScenarioObservationLinks,
        evidence: EvidenceRecord,
        source_documents: Mapping[str, Any],
    ) -> ReopenedScenarioObservation:
        """Persist source-verified records, then reopen exact bytes before use."""
        if type(request) is not ScenarioObservationRequest or type(links) is not ScenarioObservationLinks:
            raise ScenarioObservationJournalError("observation inputs are invalid")
        result_bytes = request.model_result.encode("utf-8") if isinstance(request.model_result, str) else b""
        if (
            not result_bytes
            or len(result_bytes) != request.model_result_bytes
            or "sha256:" + hashlib.sha256(result_bytes).hexdigest() != request.model_result_digest
        ):
            raise ScenarioObservationJournalError("model-visible tool result differs")
        checked = EvidenceRecord.from_mapping(evidence.to_dict())
        if (
            links.attempt_id != request.attempt_id
            or links.admitted_target_url != request.target_url
            or links.authorized_url_set_ref != request.authorized_url_set_ref
            or checked.provenance is not EvidenceProvenance.OBSERVED
            or checked.content.get("attempt_id") != request.attempt_id
            or checked.content.get("request_id") != links.target_request_id
            or checked.content.get("audit_row_digest") != links.target_audit_ref
        ):
            raise ScenarioObservationJournalError("observation evidence and source differ")
        try:
            documents = json_clone(source_documents)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ScenarioObservationJournalError("observation source documents are invalid") from exc
        if not isinstance(documents, dict) or set(documents) != {
            "tool", "relay_operation", "relay_audit", "relay_receipt", "target_audit", "target_response"
        }:
            raise ScenarioObservationJournalError("observation source documents are incomplete")
        self._check_source_documents(request, links, checked, documents)
        body = {
            "schema_version": SCHEMA,
            "request_ref": request.digest,
            "request_identity": self._request_identity(request),
            "links": links.to_dict(),
            "evidence": checked.to_dict(),
            "source_documents": documents,
        }
        payload = canonical_json_bytes(body)
        if len(payload) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("observation exceeds its reviewed byte bound")
        retention_ref = content_hash(body)
        with self._connection(write=True) as connection:
            tool_row = connection.execute(
                "SELECT capture_ref, document FROM settled_execs WHERE attempt_id=? AND operation_id=?",
                (request.attempt_id, documents["tool"].get("operation_id")),
            ).fetchone()
            if tool_row != (links.tool_capture_ref, canonical_json_bytes(documents["tool"])):
                raise ScenarioObservationJournalError("settled tool bytes were not captured")
            if connection.execute(
                "SELECT 1 FROM attempt_seals WHERE attempt_id=?", (request.attempt_id,)
            ).fetchone() is not None:
                raise ScenarioObservationJournalError("observation attempt is sealed")
            existing = connection.execute(
                "SELECT document, retention_ref FROM observations WHERE request_ref=?", (request.digest,)
            ).fetchone()
            if existing is None:
                count, total = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(document)), 0) FROM observations"
                ).fetchone()
                if count >= _MAX_RECORDS or total + len(payload) > _MAX_TOTAL_BYTES:
                    raise ScenarioObservationJournalError("observation journal capacity is exhausted")
                try:
                    connection.execute(
                        "INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            request.digest,
                            request.attempt_id,
                            request.call_id,
                            links.relay_request_id,
                            links.target_request_id,
                            checked.record_hash,
                            retention_ref,
                            payload,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ScenarioObservationJournalError("observation source was reused") from exc
            elif existing[0] != payload or existing[1] != retention_ref:
                raise ScenarioObservationJournalError("observation retry differs from retained bytes")
        reopened = self.reopen(request.digest)
        if reopened.retention_ref != retention_ref or reopened.evidence.record_hash != checked.record_hash:
            raise ScenarioObservationJournalError("observation reopen differs")
        return reopened

    def reopen(self, request_ref: str) -> ReopenedScenarioObservation:
        if not isinstance(request_ref, str) or _DIGEST.fullmatch(request_ref) is None:
            raise ScenarioObservationJournalError("observation request reference is invalid")
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT attempt_id, call_id, relay_request_id, target_request_id, "
                "evidence_ref, retention_ref, document FROM observations WHERE request_ref=?",
                (request_ref,),
            ).fetchone()
        if row is None or type(row[6]) is not bytes or len(row[6]) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("observation is not retained")
        try:
            document = json.loads(row[6])
            if not isinstance(document, dict) or canonical_json_bytes(document) != row[6]:
                raise ValueError("noncanonical observation")
            if set(document) != {
                "schema_version", "request_ref", "request_identity", "links", "evidence", "source_documents"
            } or document["schema_version"] != SCHEMA or document["request_ref"] != request_ref:
                raise ValueError("observation shape")
            links = ScenarioObservationLinks.from_mapping(document["links"])
            evidence = EvidenceRecord.from_mapping(document["evidence"])
            identity = document["request_identity"]
            sources = document["source_documents"]
        except (TypeError, ValueError, KeyError, RecursionError) as exc:
            raise ScenarioObservationJournalError("observation bytes are invalid") from exc
        required_identity = {
            "attempt_id", "scenario_ref", "phase_id", "call_id", "tool_name", "arguments_digest", "arguments_json",
            "target_url", "authorized_url_set_ref", "model_result_digest", "model_result_bytes", "model_result"
        }
        if (
            not isinstance(identity, dict)
            or set(identity) != required_identity
            or not isinstance(sources, dict)
            or set(sources) != {"tool", "relay_operation", "relay_audit", "relay_receipt", "target_audit", "target_response"}
            or content_hash(document) != row[5]
            or identity["attempt_id"] != row[0]
            or identity["attempt_id"] != links.attempt_id
            or identity["call_id"] != row[1]
            or links.relay_request_id != row[2]
            or links.target_request_id != row[3]
            or evidence.record_hash != row[4]
            or identity["target_url"] != links.admitted_target_url
            or identity["authorized_url_set_ref"] != links.authorized_url_set_ref
            or evidence.content.get("request_id") != links.target_request_id
            or evidence.content.get("audit_row_digest") != links.target_audit_ref
            or ScenarioObservationRequest(**identity).digest != request_ref
        ):
            raise ScenarioObservationJournalError("observation source linkage changed")
        request = ScenarioObservationRequest(**identity)
        result_bytes = request.model_result.encode("utf-8")
        if (
            len(result_bytes) != request.model_result_bytes
            or "sha256:" + hashlib.sha256(result_bytes).hexdigest() != request.model_result_digest
        ):
            raise ScenarioObservationJournalError("model-visible result changed")
        self._check_source_documents(request, links, evidence, sources)
        return ReopenedScenarioObservation(request_ref, row[5], identity, links, evidence, sources)

    def capture_settled_exec(self, call: ControllerSettledCall) -> ReopenedSettledExec | None:
        """Capture bounded Test-scenario shell bytes before they reach the guest.

        The caller runs this blocking operation off the RPC event loop. Other
        worker methods are handled by the native receipt-retention sink.
        """
        if not isinstance(call, ControllerSettledCall):
            raise ScenarioObservationJournalError("settled worker call is invalid")
        if call.method != "exec_exact":
            return None
        request, receipt = call.request, call.receipt
        if (
            type(request) is not backend.ControlledExecRequest
            or type(receipt) is not backend.ControlledExecReceipt
            or request.handle.attempt_id != call.binding.attempt_id
            or receipt.request_digest != request.request_digest
            or receipt.identity_digest != request.identity_digest
            or receipt.resource_digest != request.handle.resource_digest
            or not receipt.complete
            or "sha256:" + hashlib.sha256(receipt.stdout).hexdigest() != receipt.stdout_digest
            or "sha256:" + hashlib.sha256(receipt.stderr).hexdigest() != receipt.stderr_digest
            or len(receipt.stdout) + len(receipt.stderr) > _MAX_RECORD_BYTES // 2
        ):
            raise ScenarioObservationJournalError("settled shell result is incomplete")
        body = {
            "schema_version": TOOL_SCHEMA,
            "binding": call.binding.wire(),
            "method": call.method,
            "request_id": call.request_id,
            "operation_id": request.operation_id,
            "request_digest": request.request_digest,
            "identity_digest": request.identity_digest,
            "resource_digest": request.handle.resource_digest,
            "argv": list(request.argv),
            "working_directory": request.working_directory,
            "exit_code": receipt.exit_code,
            "stdout_digest": receipt.stdout_digest,
            "stderr_digest": receipt.stderr_digest,
            "stdout_base64": base64.b64encode(receipt.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(receipt.stderr).decode("ascii"),
            "response_frame_digest": "sha256:" + hashlib.sha256(call.response_frame).hexdigest(),
            "responded_ns": call.responded_ns,
        }
        payload = canonical_json_bytes(body)
        if len(payload) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("settled shell capture exceeds its byte bound")
        capture_ref = content_hash(body)
        with self._connection(write=True) as connection:
            if connection.execute(
                "SELECT 1 FROM attempt_seals WHERE attempt_id=?", (call.binding.attempt_id,)
            ).fetchone() is not None:
                raise ScenarioObservationJournalError("observation attempt is sealed")
            existing = connection.execute(
                "SELECT capture_ref, document FROM settled_execs WHERE attempt_id=? AND operation_id=?",
                (call.binding.attempt_id, request.operation_id),
            ).fetchone()
            if existing is None:
                count, total = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(document)), 0) FROM settled_execs"
                ).fetchone()
                if count >= _MAX_RECORDS or total + len(payload) > _MAX_TOTAL_BYTES:
                    raise ScenarioObservationJournalError("settled shell capture capacity is exhausted")
                try:
                    connection.execute(
                        "INSERT INTO settled_execs VALUES (?, ?, ?, ?, ?)",
                        (call.binding.attempt_id, request.operation_id, call.request_id, capture_ref, payload),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ScenarioObservationJournalError("settled shell identity was reused") from exc
            elif existing != (capture_ref, payload):
                raise ScenarioObservationJournalError("settled shell retry differs")
        return self.reopen_settled_exec(call.binding.attempt_id, request.operation_id)

    def reopen_settled_exec(self, attempt_id: str, operation_id: str) -> ReopenedSettledExec:
        if (
            not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None
            or not isinstance(operation_id, str) or re.fullmatch(r"operation-[0-9a-f]{32}", operation_id) is None
        ):
            raise ScenarioObservationJournalError("settled shell identity is invalid")
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT request_id, capture_ref, document FROM settled_execs "
                "WHERE attempt_id=? AND operation_id=?", (attempt_id, operation_id),
            ).fetchone()
        if row is None or type(row[2]) is not bytes or len(row[2]) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("settled shell capture is unavailable")
        try:
            body = json.loads(row[2])
            if (
                not isinstance(body, dict)
                or body.get("schema_version") != TOOL_SCHEMA
                or body.get("method") != "exec_exact"
                or body.get("binding", {}).get("attempt_id") != attempt_id
                or body.get("operation_id") != operation_id
                or body.get("request_id") != row[0]
                or content_hash(body) != row[1]
                or canonical_json_bytes(body) != row[2]
            ):
                raise ValueError("settled shell bytes changed")
            for name in ("stdout", "stderr"):
                value = base64.b64decode(body[f"{name}_base64"], validate=True)
                if "sha256:" + hashlib.sha256(value).hexdigest() != body[f"{name}_digest"]:
                    raise ValueError("settled shell output changed")
            return ReopenedSettledExec(attempt_id, operation_id, row[0], row[1], body)
        except (KeyError, TypeError, ValueError, binascii.Error, RecursionError) as exc:
            raise ScenarioObservationJournalError("settled shell capture is invalid") from exc

    def reopen_attempt(self, attempt_id: str) -> tuple[ReopenedScenarioObservation, ...]:
        if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
            raise ScenarioObservationJournalError("observation attempt is invalid")
        with self._connection(write=False) as connection:
            refs = tuple(
                row[0] for row in connection.execute(
                    "SELECT request_ref FROM observations WHERE attempt_id=? ORDER BY rowid", (attempt_id,)
                ).fetchall()
            )
        return tuple(self.reopen(ref) for ref in refs)

    def seal_attempt(
        self, attempt_id: str, expected_request_refs: tuple[str, ...]
    ) -> str:
        """Freeze the exact controller-verified provider trace after worker stop."""
        if (
            not isinstance(attempt_id, str)
            or _ATTEMPT.fullmatch(attempt_id) is None
            or type(expected_request_refs) is not tuple
            or len(expected_request_refs) > _MAX_RECORDS
            or any(not isinstance(ref, str) or _DIGEST.fullmatch(ref) is None for ref in expected_request_refs)
            or len(set(expected_request_refs)) != len(expected_request_refs)
        ):
            raise ScenarioObservationJournalError("observation seal identity is invalid")
        with self._connection(write=True) as connection:
            rows = connection.execute(
                "SELECT request_ref, retention_ref, evidence_ref FROM observations "
                "WHERE attempt_id=? ORDER BY rowid", (attempt_id,)
            ).fetchall()
            if tuple(row[0] for row in rows) != expected_request_refs:
                raise ScenarioObservationJournalError("observation set differs from provider trace")
            body = {
                "schema_version": SEAL_SCHEMA,
                "attempt_id": attempt_id,
                "observations": [
                    {"request_ref": row[0], "retention_ref": row[1], "evidence_ref": row[2]}
                    for row in rows
                ],
            }
            payload = canonical_json_bytes(body)
            seal_ref = content_hash(body)
            existing = connection.execute(
                "SELECT seal_ref, document FROM attempt_seals WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO attempt_seals VALUES (?, ?, ?)", (attempt_id, seal_ref, payload)
                )
            elif existing != (seal_ref, payload):
                raise ScenarioObservationJournalError("observation seal retry differs")
        self.reopen_sealed_attempt(attempt_id)
        return seal_ref

    def reopen_sealed_attempt(
        self, attempt_id: str
    ) -> tuple[str, tuple[ReopenedScenarioObservation, ...]]:
        """Reopen the complete frozen set, not a partial in-flight prefix."""
        if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
            raise ScenarioObservationJournalError("observation attempt is invalid")
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT seal_ref, document FROM attempt_seals WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        if row is None or type(row[1]) is not bytes or len(row[1]) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("observation attempt is not sealed")
        try:
            body = json.loads(row[1])
            if (
                not isinstance(body, dict)
                or set(body) != {"schema_version", "attempt_id", "observations"}
                or body["schema_version"] != SEAL_SCHEMA
                or body["attempt_id"] != attempt_id
                or not isinstance(body["observations"], list)
                or len(body["observations"]) > _MAX_RECORDS
                or canonical_json_bytes(body) != row[1]
                or content_hash(body) != row[0]
            ):
                raise ValueError("seal bytes differ")
            reopened = tuple(self.reopen(item["request_ref"]) for item in body["observations"])
            if tuple(
                {
                    "request_ref": item.request_ref,
                    "retention_ref": item.retention_ref,
                    "evidence_ref": item.evidence.record_hash,
                }
                for item in reopened
            ) != tuple(body["observations"]):
                raise ValueError("sealed observations differ")
            return row[0], reopened
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise ScenarioObservationJournalError("observation seal is invalid") from exc

    def retain_role_terminal(self, document: Mapping[str, Any]) -> str:
        """Retain an already verified source-collection terminal receipt.

        This stores owner bytes for crash reopen. It does not independently
        decide that the worker stopped or that artifact publication settled.
        """
        try:
            checked = json_clone(document)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ScenarioObservationJournalError("role terminal document is invalid") from exc
        if not isinstance(checked, dict) or checked.get("schema_version") != SOURCE_TERMINAL_SCHEMA:
            raise ScenarioObservationJournalError("role terminal schema is unsupported")
        attempt_id = checked.get("attempt_id")
        owner_ref = checked.get("owner_ref")
        source_ref = checked.get("receipt_ref")
        if (
            not isinstance(attempt_id, str)
            or _ATTEMPT.fullmatch(attempt_id) is None
            or not isinstance(owner_ref, str)
            or _DIGEST.fullmatch(owner_ref) is None
            or not isinstance(source_ref, str)
            or _DIGEST.fullmatch(source_ref) is None
            or source_ref != content_hash({key: value for key, value in checked.items() if key != "receipt_ref"})
        ):
            raise ScenarioObservationJournalError("role terminal identity differs")
        payload = canonical_json_bytes(checked)
        if len(payload) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("role terminal receipt exceeds its byte bound")
        with self._connection(write=True) as connection:
            existing = connection.execute(
                "SELECT source_receipt_ref, document FROM role_terminals "
                "WHERE attempt_id=? AND role='source_collection' AND owner_ref=?",
                (attempt_id, owner_ref),
            ).fetchone()
            if existing is None:
                count, total = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(document)), 0) FROM role_terminals"
                ).fetchone()
                if count >= _MAX_RECORDS or total + len(payload) > _MAX_TOTAL_BYTES:
                    raise ScenarioObservationJournalError("role terminal capacity is exhausted")
                try:
                    connection.execute(
                        "INSERT INTO role_terminals VALUES (?, ?, ?, ?, ?)",
                        (attempt_id, "source_collection", owner_ref, source_ref, payload),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ScenarioObservationJournalError("role terminal identity was reused") from exc
            elif existing != (source_ref, payload):
                raise ScenarioObservationJournalError("role terminal retry differs")
        if self.reopen_role_terminal(source_ref) != checked:
            raise ScenarioObservationJournalError("role terminal reopen differs")
        return source_ref

    def reopen_role_terminal(self, source_receipt_ref: str) -> Mapping[str, Any]:
        if not isinstance(source_receipt_ref, str) or _DIGEST.fullmatch(source_receipt_ref) is None:
            raise ScenarioObservationJournalError("role terminal reference is invalid")
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT attempt_id, role, owner_ref, document FROM role_terminals "
                "WHERE source_receipt_ref=?", (source_receipt_ref,),
            ).fetchone()
        if row is None or type(row[3]) is not bytes or len(row[3]) > _MAX_RECORD_BYTES:
            raise ScenarioObservationJournalError("role terminal receipt is unavailable")
        try:
            checked = json.loads(row[3])
            if (
                not isinstance(checked, dict)
                or checked.get("schema_version") != SOURCE_TERMINAL_SCHEMA
                or checked.get("attempt_id") != row[0]
                or row[1] != "source_collection"
                or checked.get("owner_ref") != row[2]
                or checked.get("receipt_ref") != source_receipt_ref
                or source_receipt_ref != content_hash({key: value for key, value in checked.items() if key != "receipt_ref"})
                or canonical_json_bytes(checked) != row[3]
            ):
                raise ValueError("role terminal bytes changed")
            return checked
        except (TypeError, ValueError, RecursionError) as exc:
            raise ScenarioObservationJournalError("role terminal receipt is invalid") from exc

    def reopen_latest_role_terminal(
        self, attempt_id: str, role: str, owner_ref: str
    ) -> Mapping[str, Any] | None:
        if (
            not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None
            or role != "source_collection"
            or not isinstance(owner_ref, str) or _DIGEST.fullmatch(owner_ref) is None
        ):
            raise ScenarioObservationJournalError("role terminal owner identity is invalid")
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT source_receipt_ref FROM role_terminals "
                "WHERE attempt_id=? AND role=? AND owner_ref=?",
                (attempt_id, role, owner_ref),
            ).fetchone()
        return None if row is None else self.reopen_role_terminal(row[0])
