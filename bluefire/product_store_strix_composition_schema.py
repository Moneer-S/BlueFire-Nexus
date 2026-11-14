"""Private v24 installed Strix composition authority and lifecycle storage.

DDL belongs to ProductStore's owning migration transaction. These tables are
deliberately separate from public resources and export projections.
"""

from __future__ import annotations

import sqlite3

from .product_store_errors import ProductStoreError


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("Strix composition migration requires one owning transaction")
    document_columns = """
        document_schema TEXT NOT NULL,
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
        document_digest TEXT NOT NULL UNIQUE,
        recorded_at TEXT NOT NULL
    """
    connection.execute(f"""CREATE TABLE IF NOT EXISTS strix_composition_prelaunch_records (
        attempt_id TEXT PRIMARY KEY NOT NULL,
        job_id TEXT NOT NULL,
        claim_ref TEXT NOT NULL UNIQUE,
        runtime_resolution_ref TEXT NOT NULL,
        admission_ref TEXT NOT NULL UNIQUE,
        prelaunch_ref TEXT NOT NULL UNIQUE,
        binding_digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        objective_ref TEXT NOT NULL,
        environment_ref TEXT NOT NULL,
        target_snapshot_ref TEXT NOT NULL,
        scope_ref TEXT NOT NULL,
        {document_columns}
    )""")
    connection.execute(f"""CREATE TABLE IF NOT EXISTS strix_composition_authority_records (
        attempt_id TEXT PRIMARY KEY NOT NULL
          REFERENCES strix_composition_prelaunch_records(attempt_id),
        job_id TEXT NOT NULL,
        claim_ref TEXT NOT NULL UNIQUE,
        runtime_resolution_ref TEXT NOT NULL,
        admission_ref TEXT NOT NULL,
        prelaunch_ref TEXT NOT NULL,
        activation_ref TEXT NOT NULL UNIQUE,
        resource_transaction_ref TEXT NOT NULL UNIQUE
          REFERENCES strix_composition_resource_transactions(transaction_ref),
        resource_receipt_ref TEXT NOT NULL,
        binding_digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        objective_ref TEXT NOT NULL,
        environment_ref TEXT NOT NULL,
        target_snapshot_ref TEXT NOT NULL,
        scope_ref TEXT NOT NULL,
        {document_columns}
    )""")
    connection.execute(f"""CREATE TABLE IF NOT EXISTS strix_composition_historical_records (
        reconciliation_ref TEXT PRIMARY KEY NOT NULL,
        attempt_id TEXT NOT NULL REFERENCES strix_composition_authority_records(attempt_id),
        claim_ref TEXT NOT NULL,
        runtime_resolution_ref TEXT NOT NULL,
        activation_ref TEXT NOT NULL,
        saved_record_ref TEXT NOT NULL,
        authority_ref TEXT NOT NULL UNIQUE,
        {document_columns}
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS strix_composition_resource_transactions (
        transaction_ref TEXT PRIMARY KEY NOT NULL,
        attempt_id TEXT NOT NULL REFERENCES strix_composition_prelaunch_records(attempt_id),
        authority_ref TEXT NOT NULL,
        activation_ref TEXT,
        action TEXT NOT NULL CHECK(action IN ('execution','reconciliation')),
        reconciliation_ref TEXT,
        state TEXT NOT NULL CHECK(state IN
          ('prepared','allocating','allocated','committing','active','stopping','closed',
           'cleanup_unknown')),
        generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 4096),
        head_event_digest TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        CHECK((generation=0 AND head_event_digest IS NULL)
          OR (generation>0 AND head_event_digest IS NOT NULL)),
        CHECK((action='execution' AND reconciliation_ref IS NULL AND activation_ref IS NULL)
          OR (action='reconciliation' AND reconciliation_ref IS NOT NULL
              AND activation_ref IS NOT NULL))
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS strix_composition_resource_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_ref TEXT NOT NULL
          REFERENCES strix_composition_resource_transactions(transaction_ref),
        tx_sequence INTEGER NOT NULL CHECK(tx_sequence BETWEEN 1 AND 4096),
        event_type TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN
          ('prepared','allocating','allocated','committing','active','stopping','closed',
           'cleanup_unknown')),
        role TEXT,
        owner_ref TEXT,
        binding_ref TEXT,
        receipt_ref TEXT,
        previous_digest TEXT REFERENCES strix_composition_resource_events(event_digest),
        document_schema TEXT NOT NULL,
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 262144),
        event_digest TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        UNIQUE(transaction_ref,tx_sequence),
        UNIQUE(transaction_ref,event_digest),
        CHECK((tx_sequence=1 AND previous_digest IS NULL)
          OR (tx_sequence>1 AND previous_digest IS NOT NULL))
    )""")
    keys = {
        "prelaunch_records": (
            "attempt_id",
            "claim_ref",
            "admission_ref",
            "prelaunch_ref",
            "document_digest",
        ),
        "authority_records": (
            "attempt_id",
            "claim_ref",
            "activation_ref",
            "resource_transaction_ref",
            "document_digest",
        ),
        "historical_records": ("reconciliation_ref", "authority_ref", "document_digest"),
        "resource_events": ("sequence", "event_digest"),
        "resource_transactions": ("transaction_ref",),
    }
    for suffix, columns in keys.items():
        table = "strix_composition_" + suffix
        collisions = " OR ".join(f"{column}=NEW.{column}" for column in columns)
        if suffix == "resource_events":
            collisions += (
                " OR (transaction_ref=NEW.transaction_ref AND tx_sequence=NEW.tx_sequence)"
            )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table} "
            f"WHEN EXISTS(SELECT 1 FROM {table} WHERE {collisions}) "
            "BEGIN SELECT RAISE(ABORT,'Strix composition records cannot be replaced'); END"
        )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table} "
            "BEGIN SELECT RAISE(ABORT,'Strix composition records cannot be deleted'); END"
        )
        if suffix != "resource_transactions":
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} "
                "BEGIN SELECT RAISE(ABORT,'Strix composition records are immutable'); END"
            )
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_composition_resource_events_chain
        BEFORE INSERT ON strix_composition_resource_events
        WHEN NEW.tx_sequence>1 AND NOT EXISTS (
          SELECT 1 FROM strix_composition_resource_events prior
          WHERE prior.transaction_ref=NEW.transaction_ref
            AND prior.tx_sequence=NEW.tx_sequence-1 AND prior.event_digest=NEW.previous_digest)
        BEGIN SELECT RAISE(ABORT,'invalid Strix composition event chain'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS strix_composition_resource_transactions_cas
        BEFORE UPDATE ON strix_composition_resource_transactions
        WHEN NEW.transaction_ref IS NOT OLD.transaction_ref
          OR NEW.attempt_id IS NOT OLD.attempt_id
          OR NEW.authority_ref IS NOT OLD.authority_ref
          OR NEW.activation_ref IS NOT OLD.activation_ref
          OR NEW.action IS NOT OLD.action
          OR NEW.reconciliation_ref IS NOT OLD.reconciliation_ref
          OR NEW.created_at IS NOT OLD.created_at
          OR NEW.generation != OLD.generation+1
          OR NOT EXISTS(SELECT 1 FROM strix_composition_resource_events e
            WHERE e.transaction_ref=OLD.transaction_ref AND e.tx_sequence=NEW.generation
              AND e.event_digest=NEW.head_event_digest AND e.state=NEW.state
              AND e.previous_digest IS OLD.head_event_digest)
        BEGIN SELECT RAISE(ABORT,'invalid Strix composition transaction head'); END""")
