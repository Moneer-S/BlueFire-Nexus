"""Durable model-consent records and conservative atomic wire-attempt reservations."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .ai_live_authorization import COUNTERS, now_ms, refused, reserve_usage, validate_authorization
from .util import canonical_json_bytes


class AuthorizationStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise refused("live_store_unavailable")
    connection.execute("""CREATE TABLE IF NOT EXISTS ai_live_authorizations(
        authorization_id TEXT PRIMARY KEY, document_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','revoked','context_unavailable')),
        requests INTEGER NOT NULL DEFAULT 0, request_bytes INTEGER NOT NULL DEFAULT 0,
        reserved_output_tokens INTEGER NOT NULL DEFAULT 0)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS ai_live_request_reservations(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, authorization_id TEXT NOT NULL,
        reservation_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
        FOREIGN KEY(authorization_id) REFERENCES ai_live_authorizations(authorization_id))""")


def _row(row: sqlite3.Row, context_digest: str) -> dict[str, Any]:
    document = validate_authorization(json.loads(row["document_json"]), current=False)
    status = row["status"]
    if status == "active":
        if document["context"]["binding_digest"] != context_digest:
            status = "context_unavailable"
        elif now_ms() >= document["expires_at_ms"]:
            status = "expired"
    return {**document, "status": status, "usage": {name: row[name] for name in COUNTERS}}


def invalidate_prior_session(store: AuthorizationStore) -> None:
    """A new product access owner retains history but never resumes a prior grant."""
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE ai_live_authorizations SET status='context_unavailable' WHERE status='active'"
        )


def list_authorizations(store: AuthorizationStore, context_digest: str) -> list[dict[str, Any]]:
    with store._connection() as connection:
        rows = connection.execute(
            "SELECT * FROM ai_live_authorizations ORDER BY rowid DESC"
        ).fetchall()
    return [_row(row, context_digest) for row in rows]


def save_authorization(store: AuthorizationStore, document: Mapping[str, Any]) -> dict[str, Any]:
    document = validate_authorization(document)
    encoded = canonical_json_bytes(document).decode("utf-8")
    with store._connection(write=True) as connection:
        # An explicit new decision supersedes only this provider's prior active grant.
        for row in connection.execute(
            "SELECT authorization_id, document_json FROM ai_live_authorizations WHERE status='active'"
        ):
            prior = validate_authorization(json.loads(row["document_json"]), current=False)
            if prior["provider"]["id"] == document["provider"]["id"]:
                connection.execute(
                    "UPDATE ai_live_authorizations SET status='revoked' WHERE authorization_id=?",
                    (row["authorization_id"],),
                )
        connection.execute(
            "INSERT INTO ai_live_authorizations(authorization_id,document_json,status) VALUES (?,?,'active')",
            (document["authorization_id"], encoded),
        )
    return {**document, "status": "active", "usage": dict.fromkeys(COUNTERS, 0)}


def revoke_authorization(
    store: AuthorizationStore, authorization_id: str, context_digest: str
) -> dict[str, Any]:
    with store._connection(write=True) as connection:
        row = connection.execute(
            "SELECT * FROM ai_live_authorizations WHERE authorization_id=?", (authorization_id,)
        ).fetchone()
        if row is None:
            raise refused("live_authorization_invalid")
        connection.execute(
            "UPDATE ai_live_authorizations SET status='revoked' WHERE authorization_id=?",
            (authorization_id,),
        )
        row = connection.execute(
            "SELECT * FROM ai_live_authorizations WHERE authorization_id=?", (authorization_id,)
        ).fetchone()
    return _row(row, context_digest)


def current_authorization(
    store: AuthorizationStore, configuration_digest: str, context_digest: str
) -> dict[str, Any]:
    for row in list_authorizations(store, context_digest):
        if row["status"] == "active" and row["configuration_digest"] == configuration_digest:
            return row
    raise refused()


def reserve(
    store: AuthorizationStore,
    authorization_id: str,
    context_digest: str,
    reservation: Mapping[str, int],
) -> None:
    with store._connection(write=True) as connection:
        row = connection.execute(
            "SELECT * FROM ai_live_authorizations WHERE authorization_id=?", (authorization_id,)
        ).fetchone()
        if row is None or row["status"] != "active":
            raise refused()
        document = validate_authorization(
            json.loads(row["document_json"]), context_digest=context_digest
        )
        usage = reserve_usage(
            {name: row[name] for name in COUNTERS}, document["limits"], reservation
        )
        connection.execute(
            "UPDATE ai_live_authorizations SET requests=?, request_bytes=?, reserved_output_tokens=? WHERE authorization_id=?",
            (*usage.values(), authorization_id),
        )
        connection.execute(
            "INSERT INTO ai_live_request_reservations(authorization_id,reservation_json,created_at_ms) VALUES (?,?,?)",
            (authorization_id, canonical_json_bytes(dict(reservation)).decode("utf-8"), now_ms()),
        )
