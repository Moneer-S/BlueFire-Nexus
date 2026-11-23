"""Bounded append-only S3 records outside the strict runner TLS trust root."""

from __future__ import annotations

import hashlib
import hmac
from contextlib import ExitStack
from typing import Any, Mapping

from .runner_private_files import _PinnedPrivateDirectory
from .runner_transport_security import enrollment_binding
from .runner_trust import RunnerEnrollment, _canonical_transition_path, load_local_enrollment
from .s3_access_contract import S3AccessError, digest, document
from .s3_access_extension_contract import MAX_BYTES, MAX_REVISIONS, SCHEMA, revision
from .util import canonical_json_bytes, content_hash, json_clone

_PENDING = ".pending.json"
_DOMAIN = b"bluefire.s3-extension-revision.v1\x00"


class S3ExtensionStore:
    """Local trusted-owner storage; JSON cannot select its root or enrollment."""

    def __init__(self, enrollment: RunnerEnrollment):
        if not isinstance(enrollment, RunnerEnrollment):
            raise S3AccessError("S3 extension requires its actual managed enrollment")
        self.enrollment = load_local_enrollment(
            enrollment.root,
            secret_provider=enrollment.secret_provider,
            verify_permissions_only=True,
        )
        if self.enrollment.metadata != enrollment.metadata:
            raise S3AccessError("S3 extension enrollment changed")
        issuer = enrollment_binding(
            self.enrollment, str(self.enrollment.metadata["server_fingerprint"])
        )
        self.binding = {
            key: issuer[key] for key in ("runner_id", "client_id", "enrollment_generation")
        }
        self.root = _canonical_transition_path(
            self.enrollment.root.parent / "s3-access", create_parent=False
        )

    def _assert_current(self) -> None:
        current = load_local_enrollment(
            self.enrollment.root,
            secret_provider=self.enrollment.secret_provider,
            verify_permissions_only=True,
        )
        if current.metadata != self.enrollment.metadata:
            raise S3AccessError("S3 extension enrollment changed")

    def _authentication(self, row: Mapping[str, Any]) -> str:
        unsigned = {key: value for key, value in row.items() if key != "authentication"}
        value = hmac.new(
            self.enrollment.hmac_key(), _DOMAIN + canonical_json_bytes(unsigned), hashlib.sha256
        ).hexdigest()
        return "sha256:" + value

    @staticmethod
    def _filename(sequence: int) -> str:
        return f"revision-{sequence:04d}.json"

    def _validate(
        self, raw: Any, sequence: int, previous: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        row = revision(raw, binding=self.binding, sequence=sequence, previous=previous)
        if not hmac.compare_digest(row["authentication"], self._authentication(row)):
            raise S3AccessError("S3 extension authentication is invalid")
        from .s3_access_configuration import validate_configuration

        validate_configuration(
            row["configuration"],
            runner_id=self.enrollment.runner_id,
            profile_ids=self.enrollment.allowed_profile_ids,
        )
        for entry in row["configuration"]["environments"]:
            descriptor = entry.get("fixture_lifecycle")
            if (
                descriptor
                and descriptor["generation_digest"] != self.binding["enrollment_generation"]
            ):
                raise S3AccessError("S3 fixture belongs to another enrollment generation")
        return row

    def _read(
        self, directory: _PinnedPrivateDirectory, *, allow_pending: bool = False
    ) -> dict[str, Any] | None:
        names = set(directory.names(maximum=MAX_REVISIONS + 1))
        if _PENDING in names:
            if not allow_pending:
                raise S3AccessError("S3 setup publication is incomplete")
            names.remove(_PENDING)
        expected = {self._filename(index) for index in range(1, len(names) + 1)}
        if names != expected or len(names) > MAX_REVISIONS:
            raise S3AccessError("S3 extension contains an unknown or missing record")
        latest = None
        for index in range(1, len(names) + 1):
            latest = self._validate(
                directory.read(self._filename(index), maximum=MAX_BYTES), index, latest
            )
        return latest

    def read(self) -> dict[str, Any] | None:
        self._assert_current()
        with ExitStack() as stack:
            try:
                directory = stack.enter_context(
                    _PinnedPrivateDirectory(self.root, verify_permissions_only=True)
                )
            except FileNotFoundError:
                self._assert_current()
                return None
            result = self._read(directory)
        self._assert_current()
        return result

    def _ensure_root(self):
        with _PinnedPrivateDirectory(self.root.parent, verify_permissions_only=True) as parent:
            if parent.has_name(self.root.name):
                with _PinnedPrivateDirectory(
                    self.root, parent=parent, verify_permissions_only=True
                ):
                    return
            identity, mount = parent.create_directory(self.root.name)
            # Only a newly created, identity-pinned directory receives private permissions.
            with _PinnedPrivateDirectory(
                self.root, parent=parent, expected_identity=identity, expected_mount_identity=mount
            ):
                pass
            parent.sync()

    def append(
        self,
        configuration: Mapping[str, Any],
        credentials: Mapping[str, Any],
        *,
        operation: str,
        expected_revision: str | None,
    ) -> dict[str, Any]:
        self._assert_current()
        self._ensure_root()
        with _PinnedPrivateDirectory(self.root, verify_permissions_only=True) as read:
            identity = read.directory_identity()
            previous = self._read(read)
        if (content_hash(previous) if previous else None) != expected_revision:
            raise S3AccessError("S3 setup revision changed; review again")
        sequence = previous["sequence"] + 1 if previous else 1
        if sequence > MAX_REVISIONS:
            raise S3AccessError("S3 setup revision allowance is exhausted")
        row = {
            "schema_version": SCHEMA,
            "sequence": sequence,
            "operation": operation,
            "previous_digest": expected_revision,
            "binding": self.binding,
            "configuration": json_clone(configuration),
            "credentials": json_clone(credentials),
        }
        row["authentication"] = self._authentication(row)
        row = self._validate(row, sequence, previous)
        payload = canonical_json_bytes(row)
        # The exact exclusive pending record is the writer claim, not a renewable lease.
        with _PinnedPrivateDirectory(self.root, expected_identity=identity) as write:
            self._assert_current()
            write.create(_PENDING, payload, maximum=MAX_BYTES, atomic_no_replace=True)
            with _PinnedPrivateDirectory(
                self.root, expected_identity=identity, verify_permissions_only=True
            ) as check:
                current = self._read(check, allow_pending=True)
            if (content_hash(current) if current else None) != expected_revision:
                raise S3AccessError("S3 setup changed before publication; pending record retained")
            self._assert_current()
            write.promote(
                _PENDING,
                self._filename(sequence),
                maximum=MAX_BYTES,
                expected=payload,
                permissions_already_private=True,
                atomic_no_replace=True,
            )
        committed = self.read()
        if committed != row:
            raise S3AccessError("S3 setup publication requires read-only reconciliation")
        return row

    def complete_publication(self, expected_record_digest: str) -> dict[str, Any]:
        """Finish only the original authenticated record, without creating a revision."""
        digest(expected_record_digest)
        self._assert_current()
        with _PinnedPrivateDirectory(self.root, verify_permissions_only=True) as directory:
            current = self._read(directory, allow_pending=True)
            if not directory.has_name(_PENDING):
                if current is None or content_hash(current) != expected_record_digest:
                    raise S3AccessError("S3 setup record changed; inspect again")
                self._assert_current()
                return {"status": "already_committed", "revision_digest": expected_record_digest}
            payload, identity, snapshot = directory.read_with_snapshot_identity(
                _PENDING, maximum=MAX_BYTES
            )
            pending = document(payload, limit=MAX_BYTES)
            if pending != current:
                self._validate(pending, current["sequence"] + 1 if current else 1, current)
            if content_hash(pending) != expected_record_digest:
                raise S3AccessError("S3 setup record changed; inspect again")
            self._assert_current()
            if pending == current:
                directory.unlink(
                    _PENDING,
                    maximum=MAX_BYTES,
                    expected=payload,
                    expected_identity=identity,
                    expected_snapshot=snapshot,
                    apply_permissions=False,
                )
            else:
                directory.promote(
                    _PENDING,
                    self._filename(pending["sequence"]),
                    maximum=MAX_BYTES,
                    expected=payload,
                    expected_identity=identity,
                    permissions_already_private=True,
                    atomic_no_replace=True,
                )
        committed = self.read()
        if committed != pending:
            raise S3AccessError("S3 setup publication requires read-only reconciliation")
        return {"status": "committed", "revision_digest": expected_record_digest}

    def publication_state(self, expected_record_digest: str | None = None) -> dict[str, Any]:
        """Inspect authenticated record metadata; never replay or decrypt material."""
        if expected_record_digest is not None:
            digest(expected_record_digest)
        self._assert_current()
        with ExitStack() as stack:
            try:
                directory = stack.enter_context(
                    _PinnedPrivateDirectory(self.root, verify_permissions_only=True)
                )
            except FileNotFoundError:
                self._assert_current()
                return (
                    {
                        "status": "not_found",
                        "record_digest": None,
                        "operation": None,
                        "sequence": None,
                    }
                    if expected_record_digest is None
                    else {"status": "not_found", "matches": False}
                )
            row = self._read(directory, allow_pending=True)
            incomplete = False
            if directory.has_name(_PENDING):
                pending = document(directory.read(_PENDING, maximum=MAX_BYTES), limit=MAX_BYTES)
                if pending != row:
                    self._validate(pending, (row["sequence"] + 1) if row else 1, row)
                row = pending
                incomplete = True
            self._assert_current()
            record_digest = content_hash(row) if row else None
            if expected_record_digest is None:
                return {
                    "status": "incomplete" if incomplete else "committed" if row else "not_found",
                    "record_digest": record_digest,
                    "operation": row["operation"] if row else None,
                    "sequence": row["sequence"] if row else None,
                }
            matches = record_digest == expected_record_digest
            return {
                "status": "incomplete" if incomplete else "committed" if matches else "not_found",
                "matches": matches,
            }
