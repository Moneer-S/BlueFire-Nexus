"""Shared native/Python consistency corpus; no native execution or cloud authority."""

import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode

import pytest

from bluefire.s3_access_wire import S3WorkerRequest, operation_plan, permit_request
from bluefire.util import canonical_json_bytes
from tests_platform.test_s3_access_wire import NOW, request_row

CORPUS = Path(__file__).parents[1] / "runner/tests/fixtures/s3_access_binding_v1.json"


def planned_sends(request):
    row = request.to_dict()
    sends = []
    for service, call, role in operation_plan(request):
        resource = {}
        body = b""
        method = "POST" if service == "sts" else "GET"
        if service == "sts":
            parameters = {"Action": call, "Version": "2011-06-15"}
            if call == "AssumeRole":
                reader = "probe" if row["operation"] == "probe_read" else "legitimate"
                resource = {
                    "role_arn": row["scope"]["roles"][reader],
                    "session_name": f"bf-{row['request_id'][:32]}-{reader}",
                }
                parameters.update(
                    RoleArn=resource["role_arn"],
                    RoleSessionName=resource["session_name"],
                    DurationSeconds="900",
                )
            body = urlencode(parameters).encode("ascii")
        else:
            resource["bucket"] = row["scope"]["bucket"]
            if call == "GetObject":
                resource["key"] = row["scope"]["objects"][len(sends) - 3]["key"]
            elif call == "PutBucketPolicy":
                method = "PUT"
                body = canonical_json_bytes(
                    row["policy_change"][
                        "before" if row["operation"] == "rollback_policy" else "after"
                    ]
                )
        sends.append(
            {
                "service": service,
                "operation": call,
                "role": role,
                "method": method,
                "host": f"{service}.{row['scope']['region']}.amazonaws.com",
                "resource": resource,
                "payload_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            }
        )
    return sends


def corpus_rows():
    rows = []
    for operation in (
        "inspect_policy",
        "apply_policy",
        "rollback_policy",
        "probe_read",
        "legitimate_read",
    ):
        request = S3WorkerRequest.from_mapping(request_row(operation))
        row = request.to_dict()
        resources = []
        for service, call, _role in operation_plan(request):
            resource = {}
            if service == "s3":
                resource["bucket"] = row["scope"]["bucket"]
                if call == "GetObject":
                    resource["key"] = row["scope"]["objects"][len(resources) - 3]["key"]
            elif call == "AssumeRole":
                reader = "probe" if operation == "probe_read" else "legitimate"
                resource = {
                    "role_arn": row["scope"]["roles"][reader],
                    "session_name": f"bf-{row['request_id'][:32]}-{reader}",
                }
            resources.append(resource)
        rows.append(
            {
                "request": row,
                "request_digest": request.digest,
                "plan": [
                    dict(zip(("service", "operation", "role"), call, strict=True))
                    for call in operation_plan(request)
                ],
                "resources": resources,
                "sends": planned_sends(request),
                "send_frames": [
                    permit_request(request, index + 1, send)
                    for index, send in enumerate(planned_sends(request))
                ],
                "policy_payload_digest": (
                    row["policy_change"][
                        "before_digest" if operation == "rollback_policy" else "after_digest"
                    ]
                    if row["policy_change"] is not None
                    else None
                ),
            }
        )
    return rows


def test_shared_corpus_matches_python_canonical_contract():
    corpus = json.loads(CORPUS.read_bytes())
    assert corpus["schema_version"] == "bluefire.s3-native-binding-fixtures.v1"
    assert corpus["now"] == NOW.isoformat().replace("+00:00", "Z")
    assert corpus["cases"] == corpus_rows()
    for case in corpus["cases"]:
        request = S3WorkerRequest.from_mapping(case["request"])
        assert request.digest == case["request_digest"]
        request.assert_current(lambda: NOW)
        assert canonical_json_bytes(request.to_dict()) == canonical_json_bytes(case["request"])


@pytest.mark.parametrize("operation", ["inspect_policy", "apply_policy", "probe_read"])
def test_native_inputs_use_normalized_utc_only(operation):
    request = S3WorkerRequest.from_mapping(request_row(operation)).to_dict()
    assert request["deadline"].endswith("Z")
    assert request["scope"]["created_at"].endswith("Z")
    assert request["scope"]["expires_at"].endswith("Z")
