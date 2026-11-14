"""Private append-only source for exact installed Strix model lease terminals.

This source holds hash-only request audits and protected revocation results. It
is not a product resource, export, or model context. The V2 resource journal
may cite its receipt ref only after reopening this complete typed document.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from typing import TYPE_CHECKING

from .local_lock import LocalLockError, pinned_regular_file_identity
from .strix_installed_model_lease_custody import (
    InstalledModelLeaseCustodyError,
    InstalledModelLeaseTerminalReceipt,
)
from .util import canonical_json_bytes

if TYPE_CHECKING:
    from .product_store import ProductStore

_MAX_DOCUMENT_BYTES = 512 * 1024


def initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS strix_model_lease_terminals (
            receipt_ref TEXT PRIMARY KEY,
            attempt_id TEXT NOT NULL,
            lease_binding_ref TEXT NOT NULL,
            document_json TEXT NOT NULL,
            CHECK(length(document_json) <= 524288)
        )"""
    )
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS strix_model_lease_terminals_no_update
            BEFORE UPDATE ON strix_model_lease_terminals
            BEGIN SELECT RAISE(ABORT, 'model lease terminals are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS strix_model_lease_terminals_no_delete
            BEFORE DELETE ON strix_model_lease_terminals
            BEGIN SELECT RAISE(ABORT, 'model lease terminals are append-only'); END"""
    )


class ProductStoreModelLeaseTerminalSource:
    """Bounded private SQLite source with exact reopen across process restart."""

    def __init__(self, store: ProductStore) -> None:
        # ProductStore initialization pins a single-link owner-private file.
        if not hasattr(store, "_database_identity") or not hasattr(store, "_lock"):
            raise InstalledModelLeaseCustodyError("model terminal product store is unavailable")
        self._store = store

    def _connect(self, deadline: float) -> sqlite3.Connection:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InstalledModelLeaseCustodyError("model terminal source timed out")
        store = self._store
        try:
            pinned_regular_file_identity(store.path, expected=store._database_identity)
            connection = sqlite3.connect(store.path, timeout=remaining)
            pinned_regular_file_identity(store.path, expected=store._database_identity)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {max(1, int(remaining * 1000))}")
            return connection
        except (LocalLockError, OSError, sqlite3.Error) as exc:
            if "connection" in locals():
                connection.close()
            raise InstalledModelLeaseCustodyError("model terminal source is unavailable") from exc

    @staticmethod
    def _deadline(timeout_seconds: float) -> float:
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 10:
            raise InstalledModelLeaseCustodyError("model terminal source bound is invalid")
        return time.monotonic() + timeout_seconds

    def retain(
        self, receipt: InstalledModelLeaseTerminalReceipt, *, timeout_seconds: float
    ) -> None:
        if not isinstance(receipt, InstalledModelLeaseTerminalReceipt):
            raise InstalledModelLeaseCustodyError("model terminal receipt is invalid")
        receipt.validate()
        document = canonical_json_bytes(receipt.document())
        if len(document) > _MAX_DOCUMENT_BYTES:
            raise InstalledModelLeaseCustodyError("model terminal audit exceeds retention limit")
        deadline = self._deadline(timeout_seconds)
        lock = self._store._lock
        if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise InstalledModelLeaseCustodyError("model terminal source timed out")
        try:
            with closing(self._connect(deadline)) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    previous = connection.execute(
                        "SELECT document_json FROM strix_model_lease_terminals WHERE receipt_ref = ?",
                        (receipt.receipt_ref,),
                    ).fetchone()
                    if previous is not None:
                        if previous["document_json"] != document.decode("utf-8"):
                            raise InstalledModelLeaseCustodyError(
                                "model terminal identity conflicts"
                            )
                        return
                    connection.execute(
                        """INSERT INTO strix_model_lease_terminals
                        (receipt_ref, attempt_id, lease_binding_ref, document_json)
                        VALUES (?, ?, ?, ?)""",
                        (
                            receipt.receipt_ref,
                            receipt.attempt_id,
                            receipt.lease_binding_ref,
                            document.decode("utf-8"),
                        ),
                    )
        except sqlite3.Error as exc:
            raise InstalledModelLeaseCustodyError(
                "model terminal retention is unavailable"
            ) from exc
        finally:
            lock.release()

    def reopen(
        self, evidence_ref: str, *, timeout_seconds: float
    ) -> InstalledModelLeaseTerminalReceipt | None:
        deadline = self._deadline(timeout_seconds)
        lock = self._store._lock
        if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise InstalledModelLeaseCustodyError("model terminal source timed out")
        try:
            with closing(self._connect(deadline)) as connection:
                row = connection.execute(
                    """SELECT attempt_id, lease_binding_ref, document_json
                    FROM strix_model_lease_terminals WHERE receipt_ref = ?""",
                    (evidence_ref,),
                ).fetchone()
            if row is None:
                return None
            raw = row["document_json"]
            if type(raw) is not str or len(raw.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
                raise InstalledModelLeaseCustodyError("model terminal stored document changed")
            try:
                document = json.loads(raw)
                receipt = InstalledModelLeaseTerminalReceipt.from_document(document)
            except (ValueError, TypeError) as exc:
                raise InstalledModelLeaseCustodyError(
                    "model terminal stored document changed"
                ) from exc
            if (
                receipt.receipt_ref != evidence_ref
                or receipt.attempt_id != row["attempt_id"]
                or receipt.lease_binding_ref != row["lease_binding_ref"]
                or canonical_json_bytes(receipt.document()).decode("utf-8") != raw
            ):
                raise InstalledModelLeaseCustodyError("model terminal stored identity changed")
            return receipt
        except sqlite3.Error as exc:
            raise InstalledModelLeaseCustodyError("model terminal reopen is unavailable") from exc
        finally:
            lock.release()


__all__ = ["ProductStoreModelLeaseTerminalSource", "initialize_schema"]
