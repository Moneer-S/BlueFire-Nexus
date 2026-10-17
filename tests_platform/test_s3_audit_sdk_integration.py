"""Opt-in pinned official SDK parsing/signing with synthetic, socket-denied transport."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from bluefire.s3_access_wire import S3WorkerRequest
from tests_platform.test_s3_access_audit import event
from tests_platform.test_s3_access_sdk_integration import offline_runtime as offline_runtime
from tests_platform.test_s3_access_sdk_offline_worker import AUDIT_OFFLINE_FILES
from tests_platform.test_s3_access_wire import credential_row
from tests_platform.test_s3_audit_wire import request_row


def source_pins(repository):
    result = {}
    for name in AUDIT_OFFLINE_FILES:
        path = repository / name
        assert path.is_file() and not path.is_symlink()
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        assert len(raw) <= 1024 * 1024
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def matching_log(row):
    records = []
    for original in row["audit"]["original_pair"]["reads"]:
        request = S3WorkerRequest.from_mapping(original["request"])
        for index in range(1 if original["reader"] == "probe" else 2):
            record = event(request, index=index)
            record["eventID"] = f"00000000-0000-4000-8000-{len(records) + 1:012d}"
            record["requestID"] = original["result"]["calls"][index + 3]["request_id"]
            records.append(record)
    return json.dumps({"Records": records}, separators=(",", ":"))


@pytest.mark.parametrize("scenario", ["normal", "truncated", "precondition", "wrong_ack"])
def test_pinned_official_audit_sdk_protocol_with_inert_transport(scenario, offline_runtime):
    executable = offline_runtime
    repository = Path(__file__).absolute().parents[1]
    before = source_pins(repository)
    row = request_row()
    log = matching_log(row)
    payload = {
        "repository": str(repository),
        "request": row,
        "now": row["audit"]["issued_at"].replace("Z", "+00:00"),
        "credentials": credential_row(),
        "policy": {},
        "objects": [],
        "scenario": "fixed_session",
        "audit_scenario": scenario,
        "audit_log": log,
        "source_pins": before,
    }
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    environment.update(
        HOME=str(executable.parent),
        USERPROFILE=str(executable.parent),
        AWS_EC2_METADATA_DISABLED="true",
        BLUEFIRE_TEST_ORIGINAL_HOME=os.environ.get("USERPROFILE", ""),
    )
    try:
        completed = subprocess.run(
            [
                str(executable),
                "-I",
                "-B",
                str(Path(__file__).with_name("test_s3_access_sdk_offline_worker.py")),
            ],
            input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env=environment,
        )
    finally:
        assert source_pins(repository) == before
    assert completed.returncode == 0, "offline official audit SDK compatibility probe failed"
    assert len(completed.stdout) < 16 * 1024 and not completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["sdk_version"] == "1.43.110"
    assert observed["production_runtime_admitted"] is False
    assert observed["transport_mode"] == "official-sdk-with-inert-connection"
    assert observed["session_configuration"] == "fixed-runtime"
    assert observed["counters"] == {
        "socket_construction_denied": 1,
        "network_connection_denied": 0,
        "ambient_reads_denied": 0,
        "credential_resolver_denied": 0,
    }
    checks = observed["audit_checks"]
    assert checks["sts_bodies_verified"] == 3
    assert all(
        checks[name] is True
        for name in (
            "all_bodies_closed",
            "all_bodies_eof",
            "wire_body_receipts_match",
            "source_before_after_unchanged",
        )
    )
    experiment_region = row["scope"]["region"]
    bucket_region = row["audit"]["source"]["audit_bucket_region"]
    assert experiment_region != bucket_region
    assert (
        checks["signing"][:3]
        == [
            {
                "service": "sts",
                "region": experiment_region,
                "host": f"sts.{experiment_region}.amazonaws.com",
            }
        ]
        * 3
    )
    assert all(
        value
        == {"service": "s3", "region": bucket_region, "host": f"s3.{bucket_region}.amazonaws.com"}
        for value in checks["signing"][3:]
    )
    result = observed["result"]
    expected_calls = 4 if scenario == "wrong_ack" else 5
    assert (
        observed["http_calls"]
        == observed["permits"]
        == result["send_permits_consumed"]
        == expected_calls
    )
    assert checks["conditional_gets"] == (0 if scenario == "wrong_ack" else 1)
    assert checks["discovery_acknowledged"] is (scenario != "wrong_ack")
    if scenario in {"precondition", "wrong_ack"}:
        assert result["outcome"] == "failed" and result["data"] is None
        if scenario == "precondition":
            assert result["calls"][-1]["http_status"] == 412
        return
    assert result["outcome"] == "observed"
    data = result["data"]
    assert data["discovery"]["listings"][0]["body_sha256"] == checks["list_body_sha256"]
    assert data["objects"][0]["compressed_sha256"] == checks["compressed_sha256"]
    assert data["objects"][0]["expanded_sha256"] == checks["expanded_sha256"]
    assert checks["expanded_sha256"] == "sha256:" + hashlib.sha256(log.encode()).hexdigest()
    assert data["usage"]["events"] == 3 and data["usage"]["files"] == 1
    assert data["delivery_state"] == ("truncated" if scenario == "truncated" else "incomplete")
    assert data["discovery"]["truncated"] is (scenario == "truncated")
    assert not data["effective_access_claim"] and not data["log_integrity_proven"]
    for reader, correlation in data["correlations"].items():
        assert correlation["independent_collection_proven"] is False
        assert correlation["effective_access_claim"] is False
        assert len(correlation["reads"]) == (1 if reader == "probe" else 2)
        assert all(
            read["status"] == "matched" and not read["full_object_bytes_proven"]
            for read in correlation["reads"]
        )
