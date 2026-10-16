"""Live attempt directory custody; serialized history cannot restore this guard."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, cast

from .capability_packs import MACOS_FILE_ACCESS_PACK, grant_pack
from .macos_attempt_workspace import MacOSAttemptWorkspaceGuard
from .product_store_capability_grants import _attempt_live, _claim_at, _grant_at, _insert_document
from .product_store_errors import ProductStoreError
from .util import content_hash


def initialize_schema(connection):
    if not connection.in_transaction:
        raise ProductStoreError("macOS workspace migration requires one transaction.")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS capability_macos_workspace_claims("
        "attempt_id TEXT PRIMARY KEY REFERENCES capability_attempts(attempt_id),"
        "document_json TEXT NOT NULL, document_digest TEXT NOT NULL)"
    )
    for operation in ("UPDATE", "DELETE"):
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS capability_macos_workspace_claims_no_{operation.lower()} "
            f"BEFORE {operation} ON capability_macos_workspace_claims BEGIN "
            "SELECT RAISE(ABORT, 'macOS workspace custody history is append-only'); END"
        )


@dataclass(frozen=True)
class MacOSWorkspaceClaim:
    attempt_id: str
    lease_digest: str
    compiled_digest: str
    configured_root_digest: str
    pid: int


class MacOSWorkspaceStoreMixin:
    def _initialize_macos_workspace_state(self):
        store = cast(Any, self)
        store._macos_attempt_workspaces = {}
        store._macos_workspace_claims = {}
        store._macos_workspace_pid = os.getpid()

    @staticmethod
    def _initialize_macos_workspace_schema(connection):
        from . import product_store_macos_composition

        product_store_macos_composition.initialize_schema(connection)
        initialize_schema(connection)

    def claim_macos_attempt_workspace(
        self, attempt_id, configured_root, *, now_ms, current_environment
    ):
        store = cast(Any, self)
        if store._macos_workspace_pid != os.getpid():
            raise ProductStoreError("The original live macOS workspace process is unavailable.")
        with store._connection(write=True) as connection:
            _, lease, compiled = _attempt_live(
                store, connection, attempt_id, now_ms, current_environment
            )
            _claim_at(connection, attempt_id, lease)
            _, grant, _ = _grant_at(connection, lease["grant_id"])
            if grant_pack(grant) != MACOS_FILE_ACCESS_PACK:
                raise ProductStoreError("The original macOS attempt is required.")
            if (
                attempt_id in store._macos_attempt_workspaces
                or connection.execute(
                    "SELECT 1 FROM capability_macos_workspace_claims WHERE attempt_id=?",
                    (attempt_id,),
                ).fetchone()
                or connection.execute(
                    "SELECT 1 FROM capability_workspace_bindings WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
            ):
                raise ProductStoreError(
                    "The attempt workspace was already claimed; do not re-adopt it."
                )
            _insert_document(
                connection,
                "INSERT INTO capability_macos_workspace_claims VALUES(?,?,?)",
                attempt_id,
                {
                    "schema_version": "bluefire.macos-attempt-workspace-claim.v1",
                    "attempt_id": attempt_id,
                    "lease_digest": lease["lease_digest"],
                    "compiled_digest": compiled["compiled_digest"],
                    "configured_root_digest": content_hash(
                        {"configured_root": str(configured_root)}
                    ),
                    "claimed_at_ms": now_ms,
                },
            )
        # Only this original-process token can attach a guard after the durable commit.
        with store._lock:
            claim = MacOSWorkspaceClaim(
                attempt_id,
                lease["lease_digest"],
                compiled["compiled_digest"],
                content_hash({"configured_root": str(configured_root)}),
                os.getpid(),
            )
            store._macos_workspace_claims[attempt_id] = claim
            return claim

    def attach_macos_attempt_workspace_guard(self, claim, configured_root, workspace, guard):
        store = cast(Any, self)
        # A fork copy may inherit a held lock; reject before touching it.
        if (
            store._macos_workspace_pid != os.getpid()
            or type(claim) is not MacOSWorkspaceClaim
            or claim.pid != os.getpid()
        ):
            if type(guard) is MacOSAttemptWorkspaceGuard:
                guard.close()
            raise ProductStoreError("The original live macOS workspace claim is unavailable.")
        with store._lock:
            original = (
                store._macos_workspace_claims.pop(claim.attempt_id, None)
                if type(claim) is MacOSWorkspaceClaim
                else None
            )
            try:
                if (
                    original is not claim
                    or type(claim) is not MacOSWorkspaceClaim
                    or claim.pid != os.getpid()
                    or claim.configured_root_digest
                    != content_hash({"configured_root": str(configured_root)})
                    or type(guard) is not MacOSAttemptWorkspaceGuard
                    or claim.attempt_id in store._macos_attempt_workspaces
                ):
                    raise ProductStoreError(
                        "The original live macOS workspace claim is unavailable."
                    )
                guard.validate_binding(
                    workspace,
                    attempt_id=claim.attempt_id,
                    lease_digest=claim.lease_digest,
                    compiled_digest=claim.compiled_digest,
                )
                store._macos_attempt_workspaces[claim.attempt_id] = guard
            except BaseException:
                if type(guard) is MacOSAttemptWorkspaceGuard:
                    guard.close()
                raise

    def _validate_macos_workspace_attestation(
        self, connection, attempt_id, lease, compiled, *, phase, proof
    ):
        store = cast(Any, self)
        guard = store._macos_attempt_workspaces.get(attempt_id)
        if type(guard) is not MacOSAttemptWorkspaceGuard:
            raise ProductStoreError("The original live macOS attempt workspace is unavailable.")
        workspace = store._capability_workspace_at(connection, attempt_id, lease)
        observed = guard.attest(phase)
        if (
            observed["attempt_id"] != attempt_id
            or observed["lease_digest"] != lease["lease_digest"]
            or observed["compiled_digest"] != compiled["compiled_digest"]
            or observed["workspace_path_digest"] != workspace["workspace_path_digest"]
            or (proof is not None and proof != observed)
        ):
            guard.close()
            raise ProductStoreError("The original attempt workspace inventory changed.")
        return observed

    def release_macos_attempt_workspace(self, attempt_id):
        store = cast(Any, self)
        if store._macos_workspace_pid != os.getpid():
            store._macos_workspace_claims.pop(attempt_id, None)
            inherited = store._macos_attempt_workspaces.pop(attempt_id, None)
            if type(inherited) is MacOSAttemptWorkspaceGuard:
                inherited.close()
            return
        with store._lock:
            store._macos_workspace_claims.pop(attempt_id, None)
            guard = store._macos_attempt_workspaces.pop(attempt_id, None)
            if guard is not None:
                guard.close()
