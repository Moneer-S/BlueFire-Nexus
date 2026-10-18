"""Shared handcrafted golden metadata, not enrollment or native/cloud proof."""

import json
from pathlib import Path

from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_contract import S3AccessScope, digest
from bluefire.util import canonical_json_bytes, content_hash


def test_shared_audit_workflow_vector_matches_literal_documents_and_digests():
    path = Path(__file__).resolve().parents[1] / "runner/tests/fixtures/s3_audit_workflow_v1.json"
    raw = path.read_bytes()
    assert 0 < len(raw) <= 16 * 1024
    vector = json.loads(raw)
    assert vector["schema_version"] == "bluefire.s3-audit-workflow-vector.v1"
    assert vector["origin"] == "handcrafted_synthetic_consistency_only"
    scope = S3AccessScope.from_mapping(vector["scope"])
    source = audit.source(scope, vector["source"])
    workflow = audit.build_workflow(
        scope,
        source,
        workflow_job_id=vector["workflow"]["workflow_job_id"],
        environment_id=vector["workflow"]["environment_id"],
    )
    expected = vector["expected"]
    digest(expected["source_digest"])
    digest(expected["workflow_digest"])
    assert canonical_json_bytes(scope.to_dict()) == canonical_json_bytes(vector["scope"])
    assert canonical_json_bytes(source) == canonical_json_bytes(vector["source"])
    assert canonical_json_bytes(workflow) == canonical_json_bytes(vector["workflow"])
    assert canonical_json_bytes(vector["workflow"]["source"]) == canonical_json_bytes(
        vector["source"]
    )
    assert content_hash(source) == expected["source_digest"]
    assert content_hash(workflow) == expected["workflow_digest"]
    assert audit.workflow(scope, canonical_json_bytes(vector["workflow"])) == workflow
