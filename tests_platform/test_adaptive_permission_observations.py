"""Contract tests for projecting permission facts from independent observations.

These fixtures are authored evidence envelopes.  They do not invoke chmod,
inspect a host filesystem, or establish an external tool/provider result.
"""

from copy import deepcopy

import pytest

from bluefire.adaptive_observations import project_runtime_observations
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.file_permissions import PERMISSION_FIELDS, PERMISSION_LIMITATION


def _permissions(mode: str) -> dict[str, object]:
    bits = int(mode, 8)
    return {
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": mode,
        "group_write_bit": bool(bits & 0o020),
        "other_write_bit": bool(bits & 0o002),
        "non_owner_write_bit": bool(bits & 0o022),
    }


def _record(
    content: dict[str, object],
    *,
    provenance: EvidenceProvenance = EvidenceProvenance.OBSERVED,
) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id="run-authored-permissions",
        step_id="inspect-files",
        behavior_id="endpoint.discovery.system.v1",
        action_id="sandbox.discovery.list.v1",
        provenance=provenance,
        producer="authored-fixture",
        content=content,
        target_scope_ref="fixture-scope",
        timestamp="2026-09-20T00:00:00Z",
        limitations=("Authored fixture; no host observation.",),
    )


def _project(record: EvidenceRecord) -> dict[str, object]:
    return project_runtime_observations(
        steps=[
            {
                "step_id": "inspect-files",
                "behavior_id": record.behavior_id,
                "action_id": record.action_id,
                "status": "success",
                "evidence_ids": [record.evidence_id],
            }
        ],
        records=[record],
        alternatives=[],
        artifacts={},
        platform="linux",
        remaining_steps=2,
        remaining_seconds=10.0,
        retries_remaining=0,
    )


def _facts(projection: dict[str, object]) -> dict[str, object]:
    return projection["attempts"][0]["evidence"][0]["facts"]  # type: ignore[index]


@pytest.mark.parametrize("mode", ["0640", "0660", "0666"])
def test_observed_permission_modes_are_projected_as_typed_facts(mode: str) -> None:
    projection = _project(_record({"artifact_type": "file_observation", **_permissions(mode)}))
    facts = _facts(projection)
    assert {key: facts[key] for key in PERMISSION_FIELDS} == _permissions(mode)
    assert facts["artifact_type"] == "file_observation"
    assert PERMISSION_LIMITATION in projection["unknowns"]


def test_observed_fields_are_accepted_and_top_level_facts_are_not_required() -> None:
    fields = _permissions("0660")
    projection = _project(_record({"artifact_type": "file_observation", "observed_fields": fields}))
    assert {key: _facts(projection)[key] for key in PERMISSION_FIELDS} == fields


def test_filesystem_collector_permissions_are_projected_without_sensitive_extras() -> None:
    fields = _permissions("0660")
    content = {
        "artifact_type": "collector_observation",
        "observation_kind": "filesystem",
        **fields,
        "observed_fields": {**fields, "path": "private/fixture", "owner": "operator"},
        "output": {"secret": "must not project", "path": "/host/private"},
    }
    facts = _facts(_project(_record(content)))
    assert {key: facts[key] for key in PERMISSION_FIELDS} == fields
    assert not {"path", "owner", "secret"} & facts.keys()


@pytest.mark.parametrize("status", ["unavailable_windows", "unsupported_platform"])
def test_unavailable_permissions_preserve_status_without_inventing_bits(status: str) -> None:
    fields = {"permission_status": status, "effective_access": "not_evaluated"}
    facts = _facts(
        _project(_record({"artifact_type": "file_observation", "observed_fields": fields}))
    )
    assert {key: facts[key] for key in ("permission_status", "effective_access")} == fields
    assert not (set(PERMISSION_FIELDS) - {"permission_status", "effective_access"}) & facts.keys()


def test_unavailable_permission_status_with_extra_bits_is_invalid() -> None:
    fields = {
        "permission_status": "unavailable_windows",
        "effective_access": "not_evaluated",
        "other_write_bit": True,
    }
    facts = _facts(
        _project(_record({"artifact_type": "file_observation", "observed_fields": fields}))
    )
    assert facts["permission_status"] == "invalid_metadata"
    assert facts["effective_access"] == "not_evaluated"


@pytest.mark.parametrize(
    "bad_fields",
    [
        {**_permissions("0660"), "group_write_bit": "true"},
        {**_permissions("0660"), "group_write_bit": 1},
        {**_permissions("0660"), "non_owner_write_bit": False},
        {key: value for key, value in _permissions("0660").items() if key != "other_write_bit"},
        {**_permissions("0660"), "permission_mode_octal": "660"},
        {**_permissions("0660"), "permission_mode_octal": ["0660"]},
        {**_permissions("0660"), "effective_access": "allowed"},
    ],
)
def test_malformed_permission_metadata_is_redacted_to_invalid_status(
    bad_fields: dict[str, object],
) -> None:
    facts = _facts(
        _project(_record({"artifact_type": "file_observation", "observed_fields": bad_fields}))
    )
    assert facts["permission_status"] == "invalid_metadata"
    assert facts["effective_access"] == "not_evaluated"
    assert not any(
        key in facts
        for key in PERMISSION_FIELDS
        if key not in {"permission_status", "effective_access"}
    )


@pytest.mark.parametrize(
    "content",
    [
        {"artifact_type": "file_observation", "permission_status": "available"},
        {"artifact_type": "file_observation", "observed_fields": "not-a-mapping"},
    ],
)
def test_partial_or_nonmapping_permission_metadata_is_invalid(content: dict[str, object]) -> None:
    facts = _facts(_project(_record(content)))
    assert facts["permission_status"] == "invalid_metadata"
    assert facts["effective_access"] == "not_evaluated"
    assert not any(
        key in facts
        for key in PERMISSION_FIELDS
        if key not in {"permission_status", "effective_access"}
    )


@pytest.mark.parametrize(
    "top,observed",
    [
        (_permissions("0640"), _permissions("0666")),
        ({**_permissions("0660"), "group_write_bit": 1}, _permissions("0660")),
    ],
)
def test_conflicting_top_level_and_observed_fields_are_invalid_without_raw_values(
    top: dict[str, object], observed: dict[str, object]
) -> None:
    facts = _facts(
        _project(_record({"artifact_type": "file_observation", **top, "observed_fields": observed}))
    )
    assert {key: facts[key] for key in PERMISSION_FIELDS if key in facts} == {
        "permission_status": "invalid_metadata",
        "effective_access": "not_evaluated",
    }


def test_missing_permission_bundle_preserves_historical_facts_only() -> None:
    facts = _facts(_project(_record({"artifact_type": "file_observation", "file_count": 3})))
    assert facts["artifact_type"] == "file_observation"
    assert facts["file_count"] == 3
    assert not set(PERMISSION_FIELDS) & facts.keys()


@pytest.mark.parametrize(
    "provenance",
    [EvidenceProvenance.EXECUTED, EvidenceProvenance.SYNTHETIC, EvidenceProvenance.UNKNOWN],
)
def test_non_observed_records_never_gain_permission_facts(provenance: EvidenceProvenance) -> None:
    content = {
        "artifact_type": "file_observation",
        **_permissions("0666"),
        "output": {**_permissions("0666"), "nested_secret": "redact"},
        "observed_fields": {**_permissions("0666"), "owner": "redact"},
    }
    facts = _facts(_project(_record(content, provenance=provenance)))
    assert not set(PERMISSION_FIELDS) & facts.keys()


@pytest.mark.parametrize(
    "content",
    [
        {
            "artifact_type": "collector_observation",
            "observation_kind": "collection_semantics",
            **_permissions("0666"),
        },
        {
            "artifact_type": "collector_observation",
            "observation_kind": "process",
            "observed_fields": _permissions("0666"),
        },
        {"artifact_type": "evidence_gap", "observed_fields": _permissions("0666")},
    ],
)
def test_nonfilesystem_observations_do_not_project_permission_facts(
    content: dict[str, object],
) -> None:
    facts = _facts(_project(_record(content)))
    assert not set(PERMISSION_FIELDS) & facts.keys()


def test_projection_preserves_evidence_identity_provenance_and_input_bytes() -> None:
    content = {"artifact_type": "file_observation", **_permissions("0660")}
    original = deepcopy(content)
    record = _record(content)
    projection = _project(record)
    evidence = projection["attempts"][0]["evidence"][0]  # type: ignore[index]
    assert evidence["evidence_id"] == record.evidence_id
    assert evidence["record_hash"] == record.record_hash
    assert evidence["provenance"] == EvidenceProvenance.OBSERVED.value
    assert content == original


def test_projection_digest_is_stable_for_identical_authored_envelopes() -> None:
    first = _project(_record({"artifact_type": "file_observation", **_permissions("0666")}))
    second = _project(_record({"artifact_type": "file_observation", **_permissions("0666")}))
    assert first["projection_digest"] == second["projection_digest"]
