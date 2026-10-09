"""Host configuration uses fixed references, not runtime credential discovery."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from bluefire.runner_contracts import seal_profile
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_host_config import (
    public_environments,
    selected_environment,
    temporary_material,
    validate_configuration,
)
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_wire import NOW, credential_row, request_row


def configured():
    request = request_row("apply_policy")
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "owned_service_admission_v1.json").read_text(
            encoding="utf-8"
        )
    )
    profile = fixture["profile"]
    profile["allowed_actions"] = ["owned.aws.s3_access.v1"]
    profile["capabilities"] = ["cloud_aws_s3_access"]
    profile.pop("native_tool_installations", None)
    profile = seal_profile(profile)
    return {
        "schema_version": "bluefire.s3-host-environments.v1",
        "runner_id": profile["runner_id"],
        "environments": [
            {
                "environment_id": "test-environment",
                "display_name": "Owned test bucket",
                "profile": profile,
                "scope": request["scope"],
                "baseline_policy": request["policy_change"]["before"],
                "exclusive_writer_digest": request["exclusive_writer_digest"],
                "runtime_root": "/opt/bluefire/s3-runtime",
                "runtime_digest": request["runtime_digest"],
                "worker_generation": request["worker_generation"],
                "ledger_root": "/var/lib/bluefire-test/s3-ledger",
                "credential_reference": "s3-test-environment.secret",
            }
        ],
    }


def checked(value):
    entry = value["environments"][0]
    return validate_configuration(
        value, runner_id=value["runner_id"], profile_ids=(entry["profile"]["profile_id"],)
    )


def test_exact_configuration_has_only_a_safe_public_environment_projection():
    row = checked(configured())
    result = public_environments(row)
    assert set(result[0]) == {
        "environment_id",
        "display_name",
        "scope",
        "baseline_policy",
        "exclusive_writer_digest",
    }
    assert "secret" not in json.dumps(result)
    assert public_environments(None) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_root", "./relative"),
        ("runtime_root", "/opt/../tmp/runtime"),
        ("ledger_root", "/var/lib/bluefire-test//ledger"),
        ("ledger_root", "/tmp/ledger/"),
        ("credential_reference", "/var/lib/bluefire-test/.aws/credentials"),
        ("credential_reference", "s3-another-environment.secret"),
        ("environment_id", "../another"),
        ("display_name", "bad\nlabel"),
        ("runtime_digest", "unset"),
        ("worker_generation", "unset"),
    ],
)
def test_configured_environment_refuses_unsafe_or_ambient_references(field, value):
    row = configured()
    row["environments"][0][field] = value
    with pytest.raises(S3AccessError):
        checked(row)


@pytest.mark.parametrize("field", ["capabilities", "allowed_actions", "control_blocked_actions"])
def test_resealed_profile_cannot_omit_or_block_the_explicit_cloud_capability(field):
    row = configured()
    profile = row["environments"][0]["profile"]
    profile[field] = ["owned.aws.s3_access.v1"] if field == "control_blocked_actions" else []
    row["environments"][0]["profile"] = seal_profile(profile)
    with pytest.raises(S3AccessError):
        checked(row)


def test_duplicate_environment_or_shared_ledger_is_refused():
    row = configured()
    row["environments"].append(deepcopy(row["environments"][0]))
    with pytest.raises(S3AccessError):
        checked(row)
    row["environments"][1]["environment_id"] = "second"
    row["environments"][1]["credential_reference"] = "s3-second.secret"
    with pytest.raises(S3AccessError):
        checked(row)


def second_environment(row):
    entry = deepcopy(row["environments"][0])
    entry.update(
        environment_id="second",
        credential_reference="s3-second.secret",
        ledger_root="/var/lib/bluefire-test/different-journal",
    )
    entry["scope"]["expires_at"] = "2026-10-09T00:59:00Z"
    row["environments"].append(entry)
    return entry


def test_same_bucket_cannot_evade_native_barrier_with_new_scope_and_journal():
    row = configured()
    second_environment(row)
    assert content_hash(row["environments"][0]["scope"]) != content_hash(
        row["environments"][1]["scope"]
    )
    with pytest.raises(S3AccessError, match="one configured journal authority"):
        checked(row)


def test_distinct_named_bucket_remains_available_with_its_own_journal():
    row = configured()
    entry = second_environment(row)
    before = entry["scope"]["bucket"]
    entry["scope"]["bucket"] = "bluefire-owned-second"
    for statement in entry["baseline_policy"]["Statement"]:
        resources = statement["Resource"]
        if isinstance(resources, str):
            statement["Resource"] = resources.replace(
                f"arn:aws:s3:::{before}/", "arn:aws:s3:::bluefire-owned-second/"
            )
        else:
            statement["Resource"] = [
                value.replace(f"arn:aws:s3:::{before}/", "arn:aws:s3:::bluefire-owned-second/")
                for value in resources
            ]
    entry["scope"]["policy"]["baseline_digest"] = content_hash(entry["baseline_policy"])
    assert len(checked(row)["environments"]) == 2


def test_exact_request_selection_cannot_rebind_scope_profile_or_exclusive_writer():
    row = checked(configured())
    entry = row["environments"][0]
    request = S3WorkerRequest.from_mapping(request_row("apply_policy"))
    approval = {"environment_id": entry["environment_id"]}
    assert selected_environment(row, request, approval, entry["profile"]) == entry
    changed = deepcopy(entry["profile"])
    changed["limits"]["timeout_ms"] += 1
    with pytest.raises(S3AccessError):
        selected_environment(row, request, approval, changed)
    source = request.to_dict()
    source["exclusive_writer_digest"] = "sha256:" + "a" * 64
    with pytest.raises(S3AccessError):
        selected_environment(row, S3WorkerRequest.from_mapping(source), approval, entry["profile"])


def test_temporary_material_uses_only_exact_purpose_bound_synthetic_reference():
    row = checked(configured())
    calls = []

    class Enrollment:
        def _secret(self, filename, purpose):
            calls.append((filename, purpose))
            return canonical_json_bytes(credential_row())

    request = S3WorkerRequest.from_mapping(request_row("inspect_policy"))
    encoded = temporary_material(Enrollment(), row["environments"][0], request, lambda: NOW)
    assert json.loads(encoded) == credential_row()
    assert calls == [("s3-test-environment.secret", "s3-temporary:test-environment")]
