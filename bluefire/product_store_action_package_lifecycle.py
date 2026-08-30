"""Action-package installation lifecycle over the durable product store."""

from __future__ import annotations

import uuid
from collections.abc import Collection
from typing import TYPE_CHECKING, Any, Mapping, cast

if TYPE_CHECKING:
    from .action_packages import VerifiedActionPackage


def install_action_package_version(
    store: Any,
    verified: VerifiedActionPackage,
    *,
    installed_by: str,
    occupied_behavior_ids: Collection[str] = (),
    occupied_action_ids: Collection[str] = (),
) -> Mapping[str, Any]:
    """Atomically persist one independently verified immutable package version."""

    from .action_packages import ActionPackageError, SemVer, verify_action_package
    from .product_store_contracts import occupied_package_ids, package_actor
    from .product_store_errors import ActionPackageConflictError, ActionPackageIntegrityError
    from .product_store_serialization import canonical_json, utc_now

    package = store._validated_verified_action_package(verified)
    actor = package_actor(installed_by, "action-package installation actor")
    occupied_behaviors = occupied_package_ids(occupied_behavior_ids, "occupied behavior IDs")
    occupied_actions = occupied_package_ids(occupied_action_ids, "occupied action IDs")
    package_id = str(package["package_id"])
    version = str(package["version"])
    now = utc_now()
    with store._connection(write=True) as connection:
        installed_behaviors, installed_actions = store._permanent_action_package_occupied_ids(
            connection,
            excluding_package_id=package_id,
        )
        occupied_behaviors = tuple(sorted(set(occupied_behaviors) | installed_behaviors))
        occupied_actions = tuple(sorted(set(occupied_actions) | installed_actions))
        trust_row = connection.execute(
            store._trusted_action_package_publisher_select_sql()
            + " WHERE p.publisher_id = ? AND p.key_id = ?",
            (package["publisher_id"], package["key_id"]),
        ).fetchone()
        if trust_row is None:
            raise ActionPackageIntegrityError(
                "action-package signer is not enrolled in local publisher trust"
            )
        trust = store._trusted_action_package_publisher_with_audit(connection, trust_row)
        if trust["trust_state"] != "trusted":
            raise ActionPackageIntegrityError(
                "action-package signer local trust is suspended or revoked"
            )
        if trust["key_fingerprint"] != package["signer_fingerprint"]:
            raise ActionPackageIntegrityError(
                "action-package signer fingerprint does not match local publisher trust"
            )
        try:
            independently_verified = verify_action_package(
                bytes(package["canonical_envelope_bytes"]),
                trusted_signers={
                    (str(package["publisher_id"]), str(package["key_id"])): bytes(
                        trust_row["public_key_bytes"]
                    )
                },
                bluefire_version=None,
                platform=None,
                occupied_behavior_ids=occupied_behaviors,
                occupied_action_ids=occupied_actions,
            )
        except ActionPackageError as exc:
            raise ActionPackageIntegrityError(
                "action package failed independent local cryptographic verification"
            ) from exc
        if independently_verified != verified:
            raise ActionPackageIntegrityError(
                "action-package verifier result does not exactly match local verification"
            )

        existing = connection.execute(
            """
            SELECT * FROM action_package_versions
            WHERE package_id = ? AND version = ?
            """,
            (package_id, version),
        ).fetchone()
        if existing is not None:
            requested_identity = (
                package["package_digest"],
                package["content_digest"],
                package["publisher_id"],
                package["key_id"],
                package["signer_fingerprint"],
                package["signature_b64u"],
                package["manifest_json"],
                package["canonical_envelope_bytes"],
                package["canonical_content_bytes"],
            )
            persisted_identity = (
                str(existing["package_digest"]),
                str(existing["content_digest"]),
                str(existing["publisher_id"]),
                str(existing["key_id"]),
                str(existing["signer_fingerprint"]),
                str(existing["signature_b64u"]),
                str(existing["manifest_json"]),
                bytes(existing["canonical_envelope_bytes"]),
                bytes(existing["canonical_content_bytes"]),
            )
            if persisted_identity != requested_identity:
                raise ActionPackageConflictError(
                    "action-package version already exists with different immutable content"
                )
            return cast(
                Mapping[str, Any],
                store._action_package_detail_from_connection(
                    connection,
                    package_id,
                    version,
                    include_bytes=True,
                ),
            )

        digest_owner = connection.execute(
            """
            SELECT package_id, version FROM action_package_versions
            WHERE package_digest = ?
            """,
            (package["package_digest"],),
        ).fetchone()
        if digest_owner is not None:
            raise ActionPackageConflictError(
                "action-package digest is already bound to another package version"
            )
        publisher_owner = connection.execute(
            """
            SELECT publisher_id FROM action_package_versions
            WHERE package_id = ? ORDER BY installed_at, version LIMIT 1
            """,
            (package_id,),
        ).fetchone()
        if (
            publisher_owner is not None
            and str(publisher_owner["publisher_id"]) != package["publisher_id"]
        ):
            raise ActionPackageConflictError(
                "action-package identity is already owned by another publisher"
            )

        new_precedence = SemVer.parse(version, "action-package version")
        version_rows = connection.execute(
            "SELECT version FROM action_package_versions WHERE package_id = ?",
            (package_id,),
        ).fetchall()
        for version_row in version_rows:
            installed_version = str(version_row["version"])
            installed_precedence = SemVer.parse(
                installed_version, "installed action-package version"
            )
            if (
                installed_version != version
                and not new_precedence < installed_precedence
                and not new_precedence > installed_precedence
            ):
                raise ActionPackageConflictError(
                    "distinct action-package versions cannot share SemVer precedence"
                )

        store._audit_action_package_activation_events(connection)
        previous_version = store._derived_action_package_installed_head(connection, package_id)
        selected_as_installed_head = previous_version is None or new_precedence > SemVer.parse(
            previous_version, "installed action-package version"
        )
        connection.execute(
            """
            INSERT INTO action_package_versions(
                package_id, version, package_digest, content_digest,
                publisher_id, key_id, signer_fingerprint, signature_b64u,
                occupied_behavior_ids_json, occupied_action_ids_json,
                manifest_json, canonical_envelope_bytes, canonical_content_bytes,
                installed_by, installed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                package_id,
                version,
                package["package_digest"],
                package["content_digest"],
                package["publisher_id"],
                package["key_id"],
                package["signer_fingerprint"],
                package["signature_b64u"],
                canonical_json(list(occupied_behaviors)),
                canonical_json(list(occupied_actions)),
                package["manifest_json"],
                package["canonical_envelope_bytes"],
                package["canonical_content_bytes"],
                actor,
                now,
            ),
        )
        selected_version = version if selected_as_installed_head else cast(str, previous_version)
        connection.execute(
            """
            INSERT INTO action_package_heads(
                package_id, installed_version, active_version, updated_at
            ) VALUES (?, ?, NULL, ?)
            ON CONFLICT(package_id) DO UPDATE SET
                installed_version = excluded.installed_version,
                updated_at = excluded.updated_at
            """,
            (package_id, selected_version, now),
        )
        event_details = {
            "schema_version": "bluefire.action-package-lifecycle-details.v1",
            "package_digest": package["package_digest"],
            "content_digest": package["content_digest"],
            "publisher_id": package["publisher_id"],
            "key_id": package["key_id"],
            "previous_installed_version": previous_version,
            "selected_as_installed_head": selected_as_installed_head,
        }
        connection.execute(
            """
            INSERT INTO action_package_lifecycle_events(
                event_id, package_id, version, event_type,
                actor, details_json, created_at
            ) VALUES (?, ?, ?, 'installed', ?, ?, ?)
            """,
            (
                f"action-package-event-{uuid.uuid4().hex}",
                package_id,
                version,
                actor,
                canonical_json(event_details),
                now,
            ),
        )
        return cast(
            Mapping[str, Any],
            store._action_package_detail_from_connection(
                connection,
                package_id,
                version,
                include_bytes=True,
            ),
        )


__all__ = ["install_action_package_version"]
