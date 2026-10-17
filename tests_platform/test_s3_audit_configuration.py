"""Explicit audit setup shapes only; no installation, credentials or AWS access."""

from copy import deepcopy

import pytest

from bluefire.s3_access_configuration import AUDIT_SCHEMA, BOUND_SCHEMA
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_host_config import public_environments
from bluefire.s3_access_results import environment
from tests_platform.test_s3_access_host_config import checked, configured
from tests_platform.test_s3_audit_collection_contract import source_row


def audit_configured():
    row = configured()
    row["schema_version"] = AUDIT_SCHEMA
    entry = row["environments"][0]
    entry["managed_profile_digest"] = "sha256:" + "a" * 64
    descriptor = source_row(S3AccessScope.from_mapping(entry["scope"]))
    descriptor.update(
        managed_profile_digest=entry["managed_profile_digest"],
        protected_runtime_digest=entry["runtime_digest"],
        worker_generation=entry["worker_generation"],
    )
    entry["audit_source"] = descriptor
    return row


def test_audit_configuration_requires_explicit_new_version_and_exact_bindings():
    row = audit_configured()
    original = deepcopy(row)
    assert checked(row) == original
    public = public_environments(checked(row))[0]
    assert environment(public) == public
    assert public["audit_source"] == row["environments"][0]["audit_source"]
    assert set(public) == {
        "environment_id",
        "display_name",
        "scope",
        "baseline_policy",
        "exclusive_writer_digest",
        "audit_source",
    }
    assert "credential_reference" not in public
    assert "runtime_root" not in public
    assert "ledger_root" not in public
    assert row == original


@pytest.mark.parametrize("schema", ["bluefire.s3-host-environments.v1", BOUND_SCHEMA])
def test_legacy_configuration_does_not_implicitly_acquire_audit_source(schema):
    row = audit_configured()
    row["schema_version"] = schema
    if schema != BOUND_SCHEMA:
        del row["environments"][0]["managed_profile_digest"]
    with pytest.raises(S3AccessError, match="fields"):
        checked(row)
    del row["environments"][0]["audit_source"]
    assert checked(row) == row
    assert "audit_source" not in public_environments(row)[0]


@pytest.mark.parametrize("missing", ["audit_source", "managed_profile_digest"])
def test_new_configuration_cannot_omit_its_source_or_profile_binding(missing):
    row = audit_configured()
    del row["environments"][0][missing]
    with pytest.raises(S3AccessError, match="fields"):
        checked(row)


@pytest.mark.parametrize(
    "binding", ["managed_profile_digest", "protected_runtime_digest", "worker_generation"]
)
def test_audit_source_cannot_select_a_different_profile_runtime_or_generation(binding):
    row = audit_configured()
    row["environments"][0]["audit_source"][binding] = "sha256:" + "f" * 64
    with pytest.raises(S3AccessError, match="enrolled profile or runtime"):
        checked(row)


def test_saved_environment_validates_source_instead_of_accepting_arbitrary_metadata():
    public = public_environments(audit_configured())[0]
    public["audit_source"]["unreviewed"] = True
    with pytest.raises(S3AccessError, match="fields"):
        environment(public)


def test_saved_source_cannot_claim_another_experiment_scope():
    public = public_environments(audit_configured())[0]
    public["audit_source"]["experiment_scope_digest"] = "sha256:" + "f" * 64
    with pytest.raises(S3AccessError, match="experiment"):
        environment(public)
