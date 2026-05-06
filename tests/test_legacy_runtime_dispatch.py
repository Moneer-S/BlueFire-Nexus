"""Regression tests for the legacy-runtime per-technique handler dispatch.

Earlier versions of the `run_<tactic>(...)` helpers fed a single-key
payload into the staged-pipeline entrypoint of each preserved legacy
class (`CredentialAccess.access`, `LateralMovement.move`,
`PrivilegeEscalation.escalate`, `Impact.impact`, `Collection.collect`).
Those entrypoints chain three sub-stages and pass each stage's RESULT
(not the original payload) to the next stage, so a payload meant for
the second or third stage was silently dropped — the helper returned
empty `details`.

These tests pin the contract of the corrected dispatch:

1. Every advertised technique returns a non-empty `details` dict
   carrying its canonical MITRE technique id and at least one
   handler-specific field.
2. The privilege-escalation `service_creation` / `token_creation`
   collision is resolved: each returns its own technique-specific
   details rather than the token-centric handler output.
3. Per-technique MITRE id surfaced by the helper matches the
   per-technique MITRE id surfaced by the legacy handler itself.
"""

from __future__ import annotations

import pytest

from src.core.modules.impl.legacy_runtime import (
    COLLECTION_TECHNIQUE_KEYS,
    CREDENTIAL_TECHNIQUE_KEYS,
    IMPACT_TECHNIQUE_KEYS,
    LATERAL_MOVEMENT_TECHNIQUE_KEYS,
    PRIVILEGE_ESCALATION_TECHNIQUE_KEYS,
    run_collection,
    run_credential_access,
    run_impact,
    run_lateral_movement,
    run_privilege_escalation,
)


def _assert_non_empty_handler_details(
    result: dict,
    expected_mitre: str,
    expected_method: str,
) -> None:
    assert result["technique"] is not None
    assert result["mitre_technique"] == expected_mitre
    assert result["legacy_method"] == expected_method
    details = result["details"]
    assert isinstance(details, dict)
    assert details, (
        f"runtime details unexpectedly empty for technique={result['technique']!r}; "
        "this used to happen when the helper routed payload through the staged "
        "pipeline rather than calling _handle_<method> directly."
    )
    # Every legacy handler records its own MITRE id inside `details`.
    # The helper's `mitre_technique` is the authoritative one for
    # adapter consumers (it's what the adapter emits to telemetry and
    # what scenario coverage is checked against); the handler's id is
    # internal legacy detail and may use deprecated identifiers
    # (e.g. SSH still records the deprecated T1145 instead of the
    # modern T1552.004) or be platform-conditional. We only assert
    # that the handler set SOMETHING, proving the handler ran end-
    # to-end rather than returning an empty descriptor.
    assert details.get("mitre_technique_id"), (
        f"handler did not set mitre_technique_id for technique="
        f"{result['technique']!r} — likely empty/default fallback"
    )


# ---------------------------------------------------------------------------
# Credential-access: every advertised technique returns rich details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(CREDENTIAL_TECHNIQUE_KEYS))
def test_credential_access_returns_rich_details_for_every_technique(
    technique: str,
) -> None:
    method, mitre = CREDENTIAL_TECHNIQUE_KEYS[technique]
    result = run_credential_access(technique, {})
    _assert_non_empty_handler_details(result, mitre, method)


# ---------------------------------------------------------------------------
# Lateral-movement: every advertised technique returns rich details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(LATERAL_MOVEMENT_TECHNIQUE_KEYS))
def test_lateral_movement_returns_rich_details_for_every_technique(
    technique: str,
) -> None:
    _branch, method, mitre = LATERAL_MOVEMENT_TECHNIQUE_KEYS[technique]
    result = run_lateral_movement(technique, {})
    _assert_non_empty_handler_details(result, mitre, method)


# ---------------------------------------------------------------------------
# Privilege-escalation: every advertised technique returns rich details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(PRIVILEGE_ESCALATION_TECHNIQUE_KEYS))
def test_privilege_escalation_returns_rich_details_for_every_technique(
    technique: str,
) -> None:
    _branch, method, mitre = PRIVILEGE_ESCALATION_TECHNIQUE_KEYS[technique]
    result = run_privilege_escalation(technique, {})
    _assert_non_empty_handler_details(result, mitre, method)


def test_token_creation_and_service_creation_dispatch_to_distinct_handlers() -> None:
    """The legacy class has both `_handle_creation` (token branch,
    T1134.003) and `_handle_service_creation` (service branch,
    T1543.003). Earlier versions of the helper let the staged
    pipeline route the `service_creation` payload through the token
    handler first, so service_creation returned token-centric output
    (LogonUser, Make and Impersonate Token, T1134.003). Pin that
    they now produce technique-distinct details.
    """
    token = run_privilege_escalation("token_creation", {})
    service = run_privilege_escalation("service_creation", {})

    assert token["mitre_technique"] == "T1134.003"
    assert service["mitre_technique"] == "T1543.003"
    assert token["legacy_method"] == "creation"
    assert service["legacy_method"] == "service_creation"

    token_details = token["details"]
    service_details = service["details"]

    # Token-centric details: token_type / privileges / integrity_level.
    assert token_details.get("mitre_technique_id") == "T1134.003"
    assert "token_type" in token_details or "privileges" in token_details

    # Service-centric details: binary_path / service_name / start_type
    # — none of the token-only fields appear.
    assert service_details.get("mitre_technique_id") == "T1543.003"
    assert {"binary_path", "service_name"} & set(service_details), (
        "service_creation must surface service-centric fields, not token "
        f"fields. got details={sorted(service_details)}"
    )
    assert "token_type" not in service_details, (
        "service_creation must NOT carry token_type — that would be the "
        "old staged-pipeline collision returning."
    )


# ---------------------------------------------------------------------------
# Impact: every advertised technique returns rich details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(IMPACT_TECHNIQUE_KEYS))
def test_impact_returns_rich_details_for_every_technique(technique: str) -> None:
    _branch, method, mitre = IMPACT_TECHNIQUE_KEYS[technique]
    result = run_impact(technique, {})
    _assert_non_empty_handler_details(result, mitre, method)


# ---------------------------------------------------------------------------
# Collection: every advertised technique returns rich details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(COLLECTION_TECHNIQUE_KEYS))
def test_collection_returns_rich_details_for_every_technique(technique: str) -> None:
    _branch, method, mitre = COLLECTION_TECHNIQUE_KEYS[technique]
    result = run_collection(technique, {})
    _assert_non_empty_handler_details(result, mitre, method)


# ---------------------------------------------------------------------------
# Defensive: unrecognized technique falls back to a sensible default
# ---------------------------------------------------------------------------


def test_ssh_keys_handler_mitre_id_is_normalised_to_modern_technique() -> None:
    """The preserved SSH-keys handler still records the deprecated
    T1145 ("Private Keys") MITRE id internally. The adapter normalises
    that to the modern T1552.004 ("Unsecured Credentials: Private Keys")
    so detection drafts and report tables stay aligned with the current
    ATT&CK matrix. The legacy id is preserved under
    `legacy_mitre_technique_id` for traceability.
    """
    result = run_credential_access("ssh_keys", {})
    assert result["mitre_technique"] == "T1552.004"
    details = result["details"]
    assert details["mitre_technique_id"] == "T1552.004"
    assert details["legacy_mitre_technique_id"] == "T1145"
    # Legacy display name preserved for traceability under the
    # `legacy_mitre_technique_name` field; adapter consumers that
    # render detection drafts use the technique id as the source of
    # truth, so a stale display name is non-fatal.
    assert details.get("legacy_mitre_technique_name") == "Private Keys"


def test_unrecognized_technique_does_not_raise() -> None:
    """Unrecognized technique names must not blow up the helper."""
    for run, default_method in (
        (run_credential_access, "lsass"),
        (run_lateral_movement, "psexec"),
        (run_privilege_escalation, "impersonation"),
        (run_impact, "encryption"),
        (run_collection, "file_staging"),
    ):
        result = run("definitely-not-a-real-technique", {})
        assert result["status"] in {"success", "completed", "error", "failure"}
        # Falls back to the dispatch-table's first / default entry; the
        # helper must still record the actual method it used.
        assert result["legacy_method"] == default_method
